package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

const CredentialIDPrefix = "apic_"
const DefaultAPIKeyIssuer = "api-key"

// APIKeyClaims are optional claims on an API key or signed API assertion.
type APIKeyClaims struct {
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	josejwt.Claims
}

// APIKeyRecord is returned by APIKeyLookup.
type APIKeyRecord struct {
	ID        string
	PublicKey ed25519.PublicKey
	Claims    map[string]any
}

// APIKeyLookup loads an API key record by credential ID.
type APIKeyLookup func(context.Context, string) (APIKeyRecord, error)

// APIKeyExchanger verifies Ed25519 API key credentials.
type APIKeyExchanger struct {
	Lookup APIKeyLookup
	Issuer string
	Now    func() time.Time
}

// Keypair is a generated Ed25519 API credential keypair.
type Keypair struct {
	ID         string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeypair returns a new API credential keypair.
func GenerateKeypair() (Keypair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, err
	}
	id, err := randomID()
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{ID: id, PublicKey: publicKey, PrivateKey: privateKey}, nil
}

// EncodePrivateKey encodes an Ed25519 private key for display/storage.
func EncodePrivateKey(privateKey ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(privateKey)
}

// EncodePublicKey encodes an Ed25519 public key for storage.
func EncodePublicKey(publicKey ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(publicKey)
}

// DecodePublicKey decodes a base64 Ed25519 public key.
func DecodePublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("credential: ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// SignAPIKey signs a long-lived API key credential.
func SignAPIKey(id string, privateKey ed25519.PrivateKey) (string, error) {
	return signAPIKey(id, privateKey, APIKeyClaims{})
}

// SignAssertion signs a short-lived API credential assertion.
func SignAssertion(id string, privateKey ed25519.PrivateKey, requestedScopes []string, expiresAt time.Time) (string, error) {
	claims := APIKeyClaims{RequestedScopes: auth.NormalizeScopes(requestedScopes)}
	if !expiresAt.IsZero() {
		claims.Expiry = josejwt.NewNumericDate(expiresAt)
	}
	return signAPIKey(id, privateKey, claims)
}

// CredentialID returns the key ID from a signed API credential.
func CredentialID(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var header struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", false
	}
	id := strings.TrimSpace(header.KeyID)
	return id, strings.HasPrefix(id, CredentialIDPrefix)
}

// ExchangeCredential implements Exchanger.
func (e APIKeyExchanger) ExchangeCredential(ctx context.Context, credential string) (Result, error) {
	token := tokenValue(credential)
	id, ok := CredentialID(token)
	if !ok {
		return Result{}, ErrUnsupported
	}
	if e.Lookup == nil {
		return Result{}, ErrUnsupported
	}
	record, err := e.Lookup(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if record.ID == "" {
		record.ID = id
	}
	if record.ID != id {
		return Result{}, ErrInvalid
	}
	claims, err := VerifyAPIKey(token, record.PublicKey, e.now())
	if err != nil {
		return Result{}, err
	}
	external := auth.ExternalIdentity{
		Issuer:  e.issuer(),
		Subject: record.ID,
		Claims:  copyClaims(record.Claims),
	}
	if len(claims.RequestedScopes) > 0 {
		external.Claims["requested_scopes"] = auth.NormalizeScopes(claims.RequestedScopes)
	}
	return Result{
		ExternalIdentity: external,
		RequestedScopes:  auth.NormalizeScopes(claims.RequestedScopes),
	}, nil
}

// VerifyAPIKey verifies an API key credential with publicKey.
func VerifyAPIKey(token string, publicKey ed25519.PublicKey, now time.Time) (*APIKeyClaims, error) {
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, err
	}
	claims := &APIKeyClaims{}
	if err := parsed.Claims(publicKey, &claims.Claims, claims); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := claims.Claims.Validate(josejwt.Expected{Time: now}); err != nil {
		return nil, err
	}
	return claims, nil
}

func (e APIKeyExchanger) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e APIKeyExchanger) issuer() string {
	issuer := strings.TrimSpace(e.Issuer)
	if issuer == "" {
		return DefaultAPIKeyIssuer
	}
	return issuer
}

func copyClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims)+1)
	for key, value := range claims {
		out[key] = value
	}
	return out
}

func signAPIKey(id string, privateKey ed25519.PrivateKey, claims APIKeyClaims) (string, error) {
	id = strings.TrimSpace(id)
	if !strings.HasPrefix(id, CredentialIDPrefix) {
		return "", errors.New("credential: API credential id is required")
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader("kid", id)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, opts)
	if err != nil {
		return "", err
	}
	return josejwt.Signed(signer).Claims(claims).Serialize()
}

func randomID() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return CredentialIDPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
