package tokenissuer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth"
)

func TestIssuerMintsAndVerifiesToken(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:     "https://auth.example.com/",
		Audience:   "service",
		KeyID:      "test-key",
		PrivateKey: privateKey,
		TTL:        time.Minute,
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
}

func TestIssuerAllowsMissingAudienceWhenUnconfigured(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{Issuer: "https://auth.example.com", PrivateKey: privateKey})
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
	issuer, err := New(Config{Issuer: "https://auth.example.com", KeyID: "test-key", PrivateKey: privateKey})
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
