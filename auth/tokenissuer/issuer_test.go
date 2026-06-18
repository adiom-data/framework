package tokenissuer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/httpapp/jwtauth"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestIssuerMintsAndVerifiesToken(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:      "https://auth.example.com/",
		Audience:    "service",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuer.now = func() time.Time { return now }

	token, expiresAt, err := issuer.Mint(context.Background(), auth.Identity{
		Subject:    "user-1",
		Scopes:     []string{"write", "read", "read"},
		Attributes: map[string]string{"tenant": "t1"},
		Claims: map[string]any{
			"email":      "user@example.com",
			"tenant_ids": []string{"t1", "t2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("expiresAt=%s want %s", expiresAt, now.Add(time.Minute))
	}

	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", claims.Subject)
	}
	if claims.Scope != "read write" {
		t.Fatalf("scope=%q want read write", claims.Scope)
	}
	if claims.Attributes["tenant"] != "t1" {
		t.Fatalf("tenant=%q want t1", claims.Attributes["tenant"])
	}
	if claims.Custom["email"] != "user@example.com" {
		t.Fatalf("email=%v want user@example.com", claims.Custom["email"])
	}
	tenantIDs, ok := claims.Custom["tenant_ids"].([]any)
	if !ok || len(tenantIDs) != 2 || tenantIDs[0] != "t1" || tenantIDs[1] != "t2" {
		t.Fatalf("tenant_ids=%#v", claims.Custom["tenant_ids"])
	}
	var payload map[string]any
	mustDecodePayload(t, token, &payload)
	if payload["email"] != "user@example.com" {
		t.Fatalf("payload email=%v want user@example.com", payload["email"])
	}
	if _, ok := payload["custom"]; ok {
		t.Fatal("payload included internal custom claim field")
	}
}

func TestIssuerRejectsReservedCustomClaims(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:      "https://auth.example.com/",
		Audience:    "service",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = issuer.Mint(context.Background(), auth.Identity{
		Subject: "user-1",
		Claims:  map[string]any{"sub": "other-user"},
	})
	if err == nil {
		t.Fatal("expected reserved custom claim to be rejected")
	}
}

func TestIssuerAllowsMissingAudienceWhenUnconfigured(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestIssuerJWKSHandler(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	issuer.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/jwks", nil))

	var jwks map[string][]map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	if got := jwks["keys"][0]["kid"]; got != "test-key" {
		t.Fatalf("kid=%q want test-key", got)
	}
}

func TestIssuerMetadataHandler(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	issuer.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	var metadata Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Issuer != "https://auth.example.com" {
		t.Fatalf("issuer=%q want https://auth.example.com", metadata.Issuer)
	}
	if metadata.JWKSURI != "https://auth.example.com/.well-known/jwks.json" {
		t.Fatalf("jwks_uri=%q", metadata.JWKSURI)
	}
}

func TestIssuerTokensVerifyWithJWTAUTH(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	issuer, err := New(Config{
		Issuer:      server.URL,
		Audience:    "service",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/.well-known/openid-configuration", issuer.MetadataHandler())
	mux.Handle("/.well-known/jwks.json", issuer.JWKSHandler())

	verifier, err := jwtauth.NewVerifier(jwtauth.Config{
		Issuer:           server.URL,
		AllowedAudiences: []string{"service"},
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", claims.Subject)
	}
}

func TestIssuerSupportsMultipleKeys(t *testing.T) {
	t.Parallel()

	oldKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	oldIssuer, err := New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "old",
		Keys:        []SigningKey{{KeyID: "old", PrivateKey: oldKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	oldToken, _, err := oldIssuer.Mint(context.Background(), auth.Identity{Subject: "old-user"})
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "new",
		Keys: []SigningKey{
			{KeyID: "old", PublicKey: oldKey.Public().(ed25519.PublicKey)},
			{KeyID: "new", PrivateKey: newKey},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	newToken, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "new-user"})
	if err != nil {
		t.Fatal(err)
	}
	oldClaims, err := issuer.Verify(oldToken)
	if err != nil {
		t.Fatal(err)
	}
	if oldClaims.Subject != "old-user" {
		t.Fatalf("old subject=%q want old-user", oldClaims.Subject)
	}
	newClaims, err := issuer.Verify(newToken)
	if err != nil {
		t.Fatal(err)
	}
	if newClaims.Subject != "new-user" {
		t.Fatalf("new subject=%q want new-user", newClaims.Subject)
	}
	jwks := issuer.JWKS()
	keys := jwks["keys"].([]map[string]string)
	if len(keys) != 2 {
		t.Fatalf("keys=%d want 2", len(keys))
	}
}

func TestIssuerUsesSignedKeyIDWhenVerifying(t *testing.T) {
	t.Parallel()

	oldKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "new",
		Keys: []SigningKey{
			{KeyID: "old", PublicKey: oldKey.Public().(ed25519.PublicKey)},
			{KeyID: "new", PrivateKey: newKey},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader("kid", "wrong")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: oldKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:   "https://auth.example.com",
		Subject:  "user-1",
		IssuedAt: josejwt.NewNumericDate(time.Now()),
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(token); err == nil {
		t.Fatal("expected unknown key id error")
	}
}

func TestIssuerMultipleKeysRequireActiveKeyID(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		Issuer: "https://auth.example.com",
		Keys: []SigningKey{
			{KeyID: "key-1", PrivateKey: privateKey},
		},
	})
	if err == nil {
		t.Fatal("expected active key error")
	}
}

func TestIssuerRequiresKeyID(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "key-1",
		Keys:        []SigningKey{{PrivateKey: privateKey}},
	})
	if err == nil {
		t.Fatal("expected key id error")
	}
}

func mustDecodePayload(t *testing.T, token string, out any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, out); err != nil {
		t.Fatal(err)
	}
}
