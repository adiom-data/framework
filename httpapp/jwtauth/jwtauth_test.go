package jwtauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{name: "bearer", header: "Bearer abc", want: "abc"},
		{name: "lowercase", header: "bearer abc", want: "abc"},
		{name: "trim token", header: "Bearer  abc  ", want: "abc"},
		{name: "missing token", header: "Bearer", want: ""},
		{name: "wrong scheme", header: "Basic abc", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := BearerToken(tt.header); got != tt.want {
				t.Fatalf("BearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifierVerify(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)

	verifier, err := NewVerifier(Config{
		Issuer:           issuer + "/",
		AllowedAudiences: []string{"service"},
	})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, key, map[string]any{
		"iss":       issuer,
		"sub":       "user-1",
		"aud":       []string{"service"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"client_id": "client",
		"email":     "dev@example.com",
	})
	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
	if claims.String("email") != "dev@example.com" {
		t.Fatalf("email = %q, want dev@example.com", claims.String("email"))
	}
}

func TestVerifierRejectsInvalidAudience(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)

	verifier, err := NewVerifier(Config{
		Issuer:           issuer,
		AllowedAudiences: []string{"expected"},
	})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, key, map[string]any{
		"iss": issuer,
		"aud": []string{"other"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify() succeeded, want error")
	}
}

func TestVerifierAllowsAnyConfiguredAudience(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)

	verifier, err := NewVerifier(Config{
		Issuer:           issuer,
		AllowedAudiences: []string{"web-client", "mobile-client"},
	})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, key, map[string]any{
		"iss": issuer,
		"sub": "user-1",
		"aud": []string{"mobile-client"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
}

func TestVerifierRejectsWhenNoConfiguredAudienceMatches(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)

	verifier, err := NewVerifier(Config{
		Issuer:           issuer,
		AllowedAudiences: []string{"web-client", "mobile-client"},
	})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, key, map[string]any{
		"iss": issuer,
		"aud": []string{"other-client"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify() succeeded, want error")
	}
}

func TestVerifierAllowsMissingAudienceWhenUnconfigured(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)

	verifier, err := NewVerifier(Config{Issuer: issuer})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, key, map[string]any{
		"iss": issuer,
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
}

func TestVerifierAllowsDifferentAudienceWhenUnconfigured(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)

	verifier, err := NewVerifier(Config{Issuer: issuer})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, key, map[string]any{
		"iss": issuer,
		"aud": []string{"other"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestMiddlewareStoresClaims(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)

	verifier, err := NewVerifier(Config{
		Issuer:           issuer,
		AllowedAudiences: []string{"service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, key, map[string]any{
		"iss": issuer,
		"sub": "user-1",
		"aud": []string{"service"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	handler := Middleware(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Fatal("claims missing from context")
		}
		if claims.Subject != "user-1" {
			t.Fatalf("Subject = %q, want user-1", claims.Subject)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNoContent)
	}
}

func TestMiddlewareRejectsMissingBearer(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	issuer := testIssuer(t, key)
	verifier, err := NewVerifier(Config{
		Issuer:           issuer,
		AllowedAudiences: []string{"service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := Middleware(verifier)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler called")
	}))

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/", nil))

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
}

func testIssuer(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if err := json.NewEncoder(w).Encode(map[string]string{
				"issuer":   issuer,
				"jwks_uri": issuer + "/jwks",
			}); err != nil {
				t.Fatal(err)
			}
		case "/jwks":
			if err := json.NewEncoder(w).Encode(testJWKS(key)); err != nil {
				t.Fatal(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = server.URL
	t.Cleanup(server.Close)
	return issuer
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("JWT")
	options.WithHeader("kid", "test-key")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testJWKS(key *rsa.PrivateKey) map[string]any {
	public := key.PublicKey
	return map[string]any{
		"keys": []map[string]string{
			{
				"kid": "test-key",
				"kty": "RSA",
				"alg": string(jose.RS256),
				"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigEndian(public.E)),
			},
		},
	}
}

func bigEndian(value int) []byte {
	var out []byte
	for value > 0 {
		out = append([]byte{byte(value)}, out...)
		value >>= 8
	}
	return out
}
