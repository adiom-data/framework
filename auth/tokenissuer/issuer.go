package tokenissuer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	Algorithm   jose.SignatureAlgorithm
	ActiveKeyID string
	Keys        []SigningKey
	TTL         time.Duration
}

// SigningKey is a signing key published in the issuer JWKS.
type SigningKey struct {
	KeyID         string
	Algorithm     jose.SignatureAlgorithm
	PrivateKey    ed25519.PrivateKey
	PublicKey     ed25519.PublicKey
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey
}

type issuerKey struct {
	keyID      string
	algorithm  jose.SignatureAlgorithm
	privateKey any
	publicKey  any
}

// Issuer mints and verifies short-lived access tokens.
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
	Custom     map[string]any    `json:"-"`
	josejwt.Claims
}

// MarshalJSON merges registered, framework, and custom top-level claims.
func (c Claims) MarshalJSON() ([]byte, error) {
	if err := validateCustomClaims(c.Custom); err != nil {
		return nil, err
	}
	type frameworkClaims struct {
		Scope      string            `json:"scope,omitempty"`
		Scopes     []string          `json:"scopes,omitempty"`
		Attributes map[string]string `json:"attributes,omitempty"`
		josejwt.Claims
	}
	registered, err := json.Marshal(frameworkClaims{
		Scope:      c.Scope,
		Scopes:     c.Scopes,
		Attributes: c.Attributes,
		Claims:     c.Claims,
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(registered, &out); err != nil {
		return nil, err
	}
	for key, value := range c.Custom {
		out[key] = value
	}
	return json.Marshal(out)
}

// UnmarshalJSON stores custom top-level claims while decoding known claims.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type frameworkClaims struct {
		Scope      string            `json:"scope,omitempty"`
		Scopes     []string          `json:"scopes,omitempty"`
		Attributes map[string]string `json:"attributes,omitempty"`
		josejwt.Claims
	}
	var known frameworkClaims
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	all := map[string]any{}
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for key := range all {
		if isReservedClaim(key) {
			delete(all, key)
		}
	}
	*c = Claims{
		Scope:      known.Scope,
		Scopes:     known.Scopes,
		Attributes: known.Attributes,
		Custom:     all,
		Claims:     known.Claims,
	}
	return nil
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
	cfg.Keys = append(cfg.Keys, SigningKey{KeyID: keyID, Algorithm: jose.EdDSA, PrivateKey: privateKey})
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

// GenerateRSAPrivateKey returns a new RSA private key for RS256 signing.
func GenerateRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
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
		Custom:     copyCustomClaims(identity.Claims),
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
	if err := validateCustomClaims(claims.Custom); err != nil {
		return "", time.Time{}, err
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader("kid", i.activeKey.keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: i.activeKey.algorithm, Key: i.activeKey.privateKey}, opts)
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
	parsed, err := josejwt.ParseSigned(token, i.supportedAlgorithms())
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

func (i *Issuer) supportedAlgorithms() []jose.SignatureAlgorithm {
	seen := map[jose.SignatureAlgorithm]struct{}{}
	var algorithms []jose.SignatureAlgorithm
	for _, key := range i.keys {
		if _, ok := seen[key.algorithm]; ok {
			continue
		}
		seen[key.algorithm] = struct{}{}
		algorithms = append(algorithms, key.algorithm)
	}
	return algorithms
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
		IDTokenSigningAlgValuesSupported: i.supportedAlgorithmNames(),
	}
}

func (i *Issuer) supportedAlgorithmNames() []string {
	algorithms := i.supportedAlgorithms()
	out := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		out = append(out, string(algorithm))
	}
	return out
}

// JWKS returns the issuer public key as a JSON Web Key Set.
func (i *Issuer) JWKS() map[string]any {
	keys := make([]map[string]any, 0, len(i.keys))
	for _, key := range i.keys {
		keys = append(keys, key.jwk())
	}
	return map[string]any{
		"keys": keys,
	}
}

func (k issuerKey) jwk() map[string]any {
	key := jose.JSONWebKey{
		Key:       k.publicKey,
		KeyID:     k.keyID,
		Algorithm: string(k.algorithm),
		Use:       "sig",
	}
	data, err := json.Marshal(key)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func normalizeKeys(cfg Config) ([]issuerKey, issuerKey, error) {
	signingKeys := cfg.Keys
	if len(signingKeys) == 0 {
		return nil, issuerKey{}, errors.New("tokenissuer: at least one signing key is required")
	}
	defaultAlgorithm := signingAlgorithm(cfg.Algorithm)
	if err := validateSigningAlgorithm(defaultAlgorithm); err != nil {
		return nil, issuerKey{}, err
	}
	keys := make([]issuerKey, 0, len(signingKeys))
	seen := map[string]struct{}{}
	for _, signingKey := range signingKeys {
		key, err := normalizeSigningKey(signingKey, defaultAlgorithm)
		if err != nil {
			return nil, issuerKey{}, err
		}
		if _, ok := seen[key.keyID]; ok {
			return nil, issuerKey{}, fmt.Errorf("tokenissuer: duplicate key id %q", key.keyID)
		}
		seen[key.keyID] = struct{}{}
		keys = append(keys, key)
	}
	activeKeyID := strings.TrimSpace(cfg.ActiveKeyID)
	if activeKeyID == "" {
		return nil, issuerKey{}, errors.New("tokenissuer: active key id is required")
	}
	for _, key := range keys {
		if key.keyID == activeKeyID {
			if key.privateKey == nil {
				return nil, issuerKey{}, fmt.Errorf("tokenissuer: active key %q requires a private key", activeKeyID)
			}
			return keys, key, nil
		}
	}
	return nil, issuerKey{}, fmt.Errorf("tokenissuer: active key %q not found", activeKeyID)
}

func normalizeSigningKey(signingKey SigningKey, defaultAlgorithm jose.SignatureAlgorithm) (issuerKey, error) {
	keyID := strings.TrimSpace(signingKey.KeyID)
	if keyID == "" {
		return issuerKey{}, errors.New("tokenissuer: key id is required")
	}
	algorithm := signingAlgorithm(signingKey.Algorithm)
	if signingKey.Algorithm == "" {
		algorithm = defaultAlgorithm
	}
	if err := validateSigningAlgorithm(algorithm); err != nil {
		return issuerKey{}, err
	}
	switch algorithm {
	case jose.EdDSA:
		return normalizeEdDSAKey(keyID, signingKey)
	case jose.RS256:
		return normalizeRS256Key(keyID, signingKey)
	default:
		return issuerKey{}, fmt.Errorf("tokenissuer: unsupported signing algorithm %q", algorithm)
	}
}

func normalizeEdDSAKey(keyID string, signingKey SigningKey) (issuerKey, error) {
	publicKey := signingKey.PublicKey
	privateKey := signingKey.PrivateKey
	if len(privateKey) != 0 {
		if len(privateKey) != ed25519.PrivateKeySize {
			return issuerKey{}, fmt.Errorf("tokenissuer: private key %q must be %d bytes", keyID, ed25519.PrivateKeySize)
		}
		derivedPublicKey, ok := privateKey.Public().(ed25519.PublicKey)
		if !ok {
			return issuerKey{}, fmt.Errorf("tokenissuer: invalid public key for %q", keyID)
		}
		if len(publicKey) == 0 {
			publicKey = derivedPublicKey
		}
		if !bytes.Equal(publicKey, derivedPublicKey) {
			return issuerKey{}, fmt.Errorf("tokenissuer: public key does not match private key for %q", keyID)
		}
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return issuerKey{}, fmt.Errorf("tokenissuer: public key %q must be %d bytes", keyID, ed25519.PublicKeySize)
	}
	var private any
	if len(privateKey) > 0 {
		private = privateKey
	}
	return issuerKey{
		keyID:      keyID,
		algorithm:  jose.EdDSA,
		privateKey: private,
		publicKey:  publicKey,
	}, nil
}

func normalizeRS256Key(keyID string, signingKey SigningKey) (issuerKey, error) {
	publicKey := signingKey.RSAPublicKey
	privateKey := signingKey.RSAPrivateKey
	if privateKey != nil {
		if err := privateKey.Validate(); err != nil {
			return issuerKey{}, fmt.Errorf("tokenissuer: RSA private key %q is invalid: %w", keyID, err)
		}
		derivedPublicKey := &privateKey.PublicKey
		if publicKey == nil {
			publicKey = derivedPublicKey
		}
		if !equalRSAPublicKeys(publicKey, derivedPublicKey) {
			return issuerKey{}, fmt.Errorf("tokenissuer: RSA public key does not match private key for %q", keyID)
		}
	}
	if publicKey == nil {
		return issuerKey{}, fmt.Errorf("tokenissuer: RSA public key %q is required", keyID)
	}
	return issuerKey{
		keyID:      keyID,
		algorithm:  jose.RS256,
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func signingAlgorithm(algorithm jose.SignatureAlgorithm) jose.SignatureAlgorithm {
	if algorithm == "" {
		return jose.EdDSA
	}
	return algorithm
}

func validateSigningAlgorithm(algorithm jose.SignatureAlgorithm) error {
	switch algorithm {
	case jose.EdDSA, jose.RS256:
		return nil
	default:
		return fmt.Errorf("tokenissuer: unsupported signing algorithm %q", algorithm)
	}
}

func equalRSAPublicKeys(a, b *rsa.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.E == b.E && a.N.Cmp(b.N) == 0
}

func keysByID(keys []issuerKey) map[string]issuerKey {
	byID := make(map[string]issuerKey, len(keys))
	for _, key := range keys {
		byID[key.keyID] = key
	}
	return byID
}

func copyCustomClaims(claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return nil
	}
	out := make(map[string]any, len(claims))
	for key, value := range claims {
		out[key] = value
	}
	return out
}

func validateCustomClaims(claims map[string]any) error {
	for key := range claims {
		if strings.TrimSpace(key) == "" {
			return errors.New("tokenissuer: custom claim name is required")
		}
		if isReservedClaim(key) {
			return fmt.Errorf("tokenissuer: custom claim %q is reserved", key)
		}
	}
	return nil
}

func isReservedClaim(name string) bool {
	switch name {
	case "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope", "scopes", "attributes":
		return true
	default:
		return false
	}
}
