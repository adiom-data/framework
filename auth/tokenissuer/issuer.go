package tokenissuer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

const (
	DefaultKeyID = "current"
	DefaultTTL   = 10 * time.Minute
)

// Config configures a standard auth token issuer.
type Config struct {
	Issuer     string
	Audience   string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	TTL        time.Duration
}

// Issuer mints and verifies short-lived EdDSA access tokens.
type Issuer struct {
	issuer     string
	audience   string
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	ttl        time.Duration
	now        func() time.Time
}

// Claims are standard access-token claims plus normalized identity data.
type Claims struct {
	Scope      string            `json:"scope,omitempty"`
	Scopes     []string          `json:"scopes,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	josejwt.Claims
}

// New returns a configured token issuer.
func New(cfg Config) (*Issuer, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("tokenissuer: issuer is required")
	}
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("tokenissuer: private key must be %d bytes", ed25519.PrivateKeySize)
	}
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" {
		keyID = DefaultKeyID
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	publicKey, ok := cfg.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("tokenissuer: invalid public key")
	}
	return &Issuer{
		issuer:     strings.TrimRight(cfg.Issuer, "/"),
		audience:   cfg.Audience,
		keyID:      keyID,
		privateKey: cfg.PrivateKey,
		publicKey:  publicKey,
		ttl:        ttl,
		now:        time.Now,
	}, nil
}

// NewFromBase64 returns an issuer from a base64-encoded Ed25519 private key or seed.
func NewFromBase64(cfg Config, privateKeyBase64 string) (*Issuer, error) {
	privateKey, err := DecodePrivateKey(privateKeyBase64)
	if err != nil {
		return nil, err
	}
	cfg.PrivateKey = privateKey
	return New(cfg)
}

// NewFromFile returns an issuer from a file containing a base64-encoded key.
func NewFromFile(cfg Config, privateKeyFile string) (*Issuer, error) {
	if strings.TrimSpace(privateKeyFile) == "" {
		return nil, errors.New("tokenissuer: private key file is required")
	}
	data, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return NewFromBase64(cfg, strings.TrimSpace(string(data)))
}

// GeneratePrivateKey returns a new Ed25519 private key.
func GeneratePrivateKey() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	return privateKey, err
}

// EncodePrivateKey encodes an Ed25519 private key for config storage.
func EncodePrivateKey(privateKey ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(privateKey)
}

// DecodePrivateKey decodes a base64 Ed25519 private key or seed.
func DecodePrivateKey(value string) (ed25519.PrivateKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("tokenissuer: private key is required")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, err
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("tokenissuer: ed25519 private key must be %d-byte private key or %d-byte seed", ed25519.PrivateKeySize, ed25519.SeedSize)
	}
}

// Mint signs a short-lived access token for identity.
func (i *Issuer) Mint(ctx context.Context, identity auth.Identity) (string, time.Time, error) {
	_ = ctx
	if i == nil {
		return "", time.Time{}, errors.New("tokenissuer: issuer is not configured")
	}
	if strings.TrimSpace(identity.Subject) == "" {
		return "", time.Time{}, errors.New("tokenissuer: subject is required")
	}
	now := i.now()
	expiresAt := now.Add(i.ttl)
	scopes := auth.NormalizeScopes(identity.Scopes)
	claims := Claims{
		Scope:      strings.Join(scopes, " "),
		Scopes:     scopes,
		Attributes: identity.Attributes,
		Claims: josejwt.Claims{
			Issuer:   i.issuer,
			Subject:  identity.Subject,
			IssuedAt: josejwt.NewNumericDate(now),
			Expiry:   josejwt.NewNumericDate(expiresAt),
		},
	}
	if i.audience != "" {
		claims.Audience = josejwt.Audience{i.audience}
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader("kid", i.keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: i.privateKey}, opts)
	if err != nil {
		return "", time.Time{}, err
	}
	token, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// Verify validates a token minted by this issuer.
func (i *Issuer) Verify(token string) (*Claims, error) {
	if i == nil {
		return nil, errors.New("tokenissuer: issuer is not configured")
	}
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, err
	}
	claims := &Claims{}
	if err := parsed.Claims(i.publicKey, &claims.Claims, claims); err != nil {
		return nil, err
	}
	expected := josejwt.Expected{
		Issuer: i.issuer,
		Time:   i.now(),
	}
	if i.audience != "" {
		expected.AnyAudience = josejwt.Audience{i.audience}
	}
	if err := claims.Claims.Validate(expected); err != nil {
		return nil, err
	}
	return claims, nil
}

// JWKSHandler publishes the issuer public key as a JWKS.
func (i *Issuer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(i.JWKS())
	})
}

// JWKS returns the issuer public key as a JSON Web Key Set.
func (i *Issuer) JWKS() map[string]any {
	return map[string]any{
		"keys": []map[string]string{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": i.keyID,
				"use": "sig",
				"alg": string(jose.EdDSA),
				"x":   base64.RawURLEncoding.EncodeToString(i.publicKey),
			},
		},
	}
}
