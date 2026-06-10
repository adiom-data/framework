package tokenissuer

import (
	"bytes"
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

const DefaultTTL = 10 * time.Minute

// Config configures a standard auth token issuer.
type Config struct {
	Issuer      string
	Audience    string
	ActiveKeyID string
	Keys        []SigningKey
	TTL         time.Duration
}

// SigningKey is an Ed25519 signing key published in the issuer JWKS.
type SigningKey struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

type issuerKey struct {
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// Issuer mints and verifies short-lived EdDSA access tokens.
type Issuer struct {
	issuer    string
	audience  string
	activeKey issuerKey
	keys      []issuerKey
	keysByID  map[string]issuerKey
	ttl       time.Duration
	now       func() time.Time
}

// Claims are standard access-token claims plus normalized identity data.
type Claims struct {
	Scope      string            `json:"scope,omitempty"`
	Scopes     []string          `json:"scopes,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	josejwt.Claims
}

// Metadata is minimal OpenID Connect discovery metadata for this issuer.
type Metadata struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

// New returns a configured token issuer.
func New(cfg Config) (*Issuer, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("tokenissuer: issuer is required")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	keys, activeKey, err := normalizeKeys(cfg)
	if err != nil {
		return nil, err
	}
	return &Issuer{
		issuer:    strings.TrimRight(cfg.Issuer, "/"),
		audience:  cfg.Audience,
		activeKey: activeKey,
		keys:      keys,
		keysByID:  keysByID(keys),
		ttl:       ttl,
		now:       time.Now,
	}, nil
}

// NewFromBase64 appends a base64-encoded Ed25519 signing key and returns an issuer.
func NewFromBase64(cfg Config, keyID string, privateKeyBase64 string) (*Issuer, error) {
	privateKey, err := DecodePrivateKey(privateKeyBase64)
	if err != nil {
		return nil, err
	}
	cfg.Keys = append(cfg.Keys, SigningKey{KeyID: keyID, PrivateKey: privateKey})
	return New(cfg)
}

// NewFromFile appends a signing key from a file containing a base64-encoded key.
func NewFromFile(cfg Config, keyID string, privateKeyFile string) (*Issuer, error) {
	if strings.TrimSpace(privateKeyFile) == "" {
		return nil, errors.New("tokenissuer: private key file is required")
	}
	data, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return NewFromBase64(cfg, keyID, strings.TrimSpace(string(data)))
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
	opts.WithHeader("kid", i.activeKey.keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: i.activeKey.privateKey}, opts)
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
	keyID := signedKeyID(parsed)
	if keyID != "" {
		key, ok := i.keysByID[keyID]
		if !ok {
			return nil, fmt.Errorf("tokenissuer: unknown key id %q", keyID)
		}
		if err := parsed.Claims(key.publicKey, &claims.Claims, claims); err != nil {
			return nil, err
		}
	} else {
		var verifyErr error
		for _, key := range i.keys {
			claims = &Claims{}
			if err := parsed.Claims(key.publicKey, &claims.Claims, claims); err != nil {
				verifyErr = err
				continue
			}
			verifyErr = nil
			break
		}
		if verifyErr != nil {
			return nil, verifyErr
		}
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

func signedKeyID(token *josejwt.JSONWebToken) string {
	if token == nil || len(token.Headers) == 0 {
		return ""
	}
	return token.Headers[0].KeyID
}

// JWKSHandler publishes the issuer public key as a JWKS.
func (i *Issuer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(i.JWKS())
	})
}

// MetadataHandler publishes minimal OIDC discovery metadata for JWT verifiers.
func (i *Issuer) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(i.Metadata())
	})
}

// Metadata returns minimal OIDC discovery metadata for this issuer.
func (i *Issuer) Metadata() Metadata {
	return Metadata{
		Issuer:                           i.issuer,
		JWKSURI:                          i.issuer + "/.well-known/jwks.json",
		IDTokenSigningAlgValuesSupported: []string{string(jose.EdDSA)},
	}
}

// JWKS returns the issuer public key as a JSON Web Key Set.
func (i *Issuer) JWKS() map[string]any {
	keys := make([]map[string]string, 0, len(i.keys))
	for _, key := range i.keys {
		keys = append(keys, map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": key.keyID,
			"use": "sig",
			"alg": string(jose.EdDSA),
			"x":   base64.RawURLEncoding.EncodeToString(key.publicKey),
		})
	}
	return map[string]any{
		"keys": keys,
	}
}

func normalizeKeys(cfg Config) ([]issuerKey, issuerKey, error) {
	signingKeys := cfg.Keys
	if len(signingKeys) == 0 {
		return nil, issuerKey{}, errors.New("tokenissuer: at least one signing key is required")
	}
	keys := make([]issuerKey, 0, len(signingKeys))
	seen := map[string]struct{}{}
	for _, signingKey := range signingKeys {
		keyID := strings.TrimSpace(signingKey.KeyID)
		if keyID == "" {
			return nil, issuerKey{}, errors.New("tokenissuer: key id is required")
		}
		if _, ok := seen[keyID]; ok {
			return nil, issuerKey{}, fmt.Errorf("tokenissuer: duplicate key id %q", keyID)
		}
		seen[keyID] = struct{}{}
		publicKey := signingKey.PublicKey
		privateKey := signingKey.PrivateKey
		if len(privateKey) != 0 {
			if len(privateKey) != ed25519.PrivateKeySize {
				return nil, issuerKey{}, fmt.Errorf("tokenissuer: private key %q must be %d bytes", keyID, ed25519.PrivateKeySize)
			}
			derivedPublicKey, ok := privateKey.Public().(ed25519.PublicKey)
			if !ok {
				return nil, issuerKey{}, fmt.Errorf("tokenissuer: invalid public key for %q", keyID)
			}
			if len(publicKey) == 0 {
				publicKey = derivedPublicKey
			}
			if !bytes.Equal(publicKey, derivedPublicKey) {
				return nil, issuerKey{}, fmt.Errorf("tokenissuer: public key does not match private key for %q", keyID)
			}
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, issuerKey{}, fmt.Errorf("tokenissuer: public key %q must be %d bytes", keyID, ed25519.PublicKeySize)
		}
		keys = append(keys, issuerKey{
			keyID:      keyID,
			privateKey: privateKey,
			publicKey:  publicKey,
		})
	}
	activeKeyID := strings.TrimSpace(cfg.ActiveKeyID)
	if activeKeyID == "" {
		return nil, issuerKey{}, errors.New("tokenissuer: active key id is required")
	}
	for _, key := range keys {
		if key.keyID == activeKeyID {
			if len(key.privateKey) != ed25519.PrivateKeySize {
				return nil, issuerKey{}, fmt.Errorf("tokenissuer: active key %q requires a private key", activeKeyID)
			}
			return keys, key, nil
		}
	}
	return nil, issuerKey{}, fmt.Errorf("tokenissuer: active key %q not found", activeKeyID)
}

func keysByID(keys []issuerKey) map[string]issuerKey {
	byID := make(map[string]issuerKey, len(keys))
	for _, key := range keys {
		byID[key.keyID] = key
	}
	return byID
}
