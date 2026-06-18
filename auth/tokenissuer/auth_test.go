package tokenissuer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
)

func TestBearerAuthenticatorStoresClaimsIdentityAndAuthValue(t *testing.T) {
	t.Parallel()

	issuer := testTokenIssuer(t)
	token := mintTestToken(t, issuer, auth.Identity{
		Subject:    "user-1",
		Scopes:     []string{"read"},
		Attributes: map[string]string{"email": "dev@example.com"},
		Claims:     map[string]any{"tenant_id": "tenant-1"},
	})
	type appUser struct {
		ID    string
		Email string
	}
	authenticator := NewBearerAuthenticator(
		issuer,
		RequireScopes("read"),
		WithAuthValue(func(_ context.Context, claims *Claims) (appUser, error) {
			return appUser{ID: claims.Subject, Email: claims.Attributes["email"]}, nil
		}),
	)

	ctx, err := authenticator.Authenticate(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("claims missing from context")
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", claims.Subject)
	}
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		t.Fatal("identity missing from context")
	}
	if identity.Subject != "user-1" {
		t.Fatalf("identity subject=%q want user-1", identity.Subject)
	}
	if identity.Attributes["email"] != "dev@example.com" {
		t.Fatalf("identity email=%q want dev@example.com", identity.Attributes["email"])
	}
	if identity.Claims["tenant_id"] != "tenant-1" {
		t.Fatalf("identity tenant_id=%v want tenant-1", identity.Claims["tenant_id"])
	}
	user, ok := AuthValueFromContext[appUser](ctx)
	if !ok {
		t.Fatal("auth value missing from context")
	}
	if user.ID != "user-1" || user.Email != "dev@example.com" {
		t.Fatalf("auth value=%+v", user)
	}
}

func TestBearerAuthenticatorRequiresBearerTokenByDefault(t *testing.T) {
	t.Parallel()

	_, err := NewBearerAuthenticator(testTokenIssuer(t)).Authenticate(context.Background(), "")
	if !errors.Is(err, ErrMissingBearerToken) {
		t.Fatalf("err=%v want missing bearer token", err)
	}
}

func TestBearerAuthenticatorCanAllowMissingBearerToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	got, err := NewBearerAuthenticator(testTokenIssuer(t), AllowMissingBearerToken()).Authenticate(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != ctx {
		t.Fatal("optional auth should return original context when token is missing")
	}
}

func TestBearerAuthenticatorRejectsInvalidBearerToken(t *testing.T) {
	t.Parallel()

	_, err := NewBearerAuthenticator(testTokenIssuer(t)).Authenticate(context.Background(), "Bearer nope")
	if !errors.Is(err, ErrInvalidBearerToken) {
		t.Fatalf("err=%v want invalid bearer token", err)
	}
}

func TestBearerAuthenticatorRequiresScopes(t *testing.T) {
	t.Parallel()

	issuer := testTokenIssuer(t)
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user-1", Scopes: []string{"read"}})

	_, err := NewBearerAuthenticator(issuer, RequireScopes("write")).Authenticate(context.Background(), "Bearer "+token)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err=%v want permission denied", err)
	}
}

func TestBearerAuthenticatorUsesRemoteJWKSVerifier(t *testing.T) {
	t.Parallel()

	issuer, server := testRemoteTokenIssuer(t, "service")
	token := mintTestToken(t, issuer, auth.Identity{
		Subject:    "user-1",
		Scopes:     []string{"read"},
		Attributes: map[string]string{"email": "dev@example.com"},
		Claims:     map[string]any{"tenant_id": "tenant-1"},
	})
	verifier, err := NewRemoteVerifier(context.Background(), RemoteVerifierConfig{
		Issuer:           server.URL,
		AllowedAudiences: []string{"service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewBearerAuthenticatorFromVerifier(verifier, RequireScopes("read"))

	ctx, err := authenticator.Authenticate(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("claims missing from context")
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", claims.Subject)
	}
	if claims.Attributes["email"] != "dev@example.com" {
		t.Fatalf("email=%q want dev@example.com", claims.Attributes["email"])
	}
	if claims.Custom["tenant_id"] != "tenant-1" {
		t.Fatalf("tenant_id=%v want tenant-1", claims.Custom["tenant_id"])
	}
}

func TestRemoteVerifierRejectsInvalidAudience(t *testing.T) {
	t.Parallel()

	issuer, server := testRemoteTokenIssuer(t, "service")
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user-1", Scopes: []string{"read"}})
	verifier, err := NewRemoteVerifier(context.Background(), RemoteVerifierConfig{
		Issuer:           server.URL,
		AllowedAudiences: []string{"other-service"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("expected invalid audience")
	}
}

func TestRemoteVerifierSkipsAudienceWhenUnconfigured(t *testing.T) {
	t.Parallel()

	issuer, server := testRemoteTokenIssuer(t, "service")
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user-1", Scopes: []string{"read"}})
	verifier, err := NewRemoteVerifier(context.Background(), RemoteVerifierConfig{
		Issuer: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestLazyRemoteVerifierDoesNotDiscoverAtConstruction(t *testing.T) {
	t.Parallel()

	verifier := NewLazyRemoteVerifier(RemoteVerifierConfig{
		Issuer: "http://127.0.0.1:1",
	})
	if verifier == nil {
		t.Fatal("verifier is nil")
	}
}

func TestLazyRemoteVerifierFailsClosedUntilIssuerAvailable(t *testing.T) {
	t.Parallel()

	var issuer *Issuer
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	ready := false
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			http.NotFound(w, r)
			return
		}
		issuer.MetadataHandler().ServeHTTP(w, r)
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			http.NotFound(w, r)
			return
		}
		issuer.JWKSHandler().ServeHTTP(w, r)
	})
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = New(Config{
		Issuer:      server.URL,
		Audience:    "service",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user-1"})
	verifier := NewLazyRemoteVerifier(RemoteVerifierConfig{
		Issuer:           server.URL,
		AllowedAudiences: []string{"service"},
	})

	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("expected verification to fail while issuer metadata is unavailable")
	}
	ready = true
	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", claims.Subject)
	}
}

func TestLazyRemoteVerifierCachesSuccessfulInitialization(t *testing.T) {
	t.Parallel()

	issuer, server := testRemoteTokenIssuer(t, "service")
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user-1"})
	verifier := NewLazyRemoteVerifier(RemoteVerifierConfig{
		Issuer:           server.URL,
		AllowedAudiences: []string{"service"},
	})
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	server.Close()
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("verifier did not reuse initialized key set: %v", err)
	}
}

func TestConnectAuthMapsErrorsAndStoresContext(t *testing.T) {
	t.Parallel()

	issuer := testTokenIssuer(t)
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user-1", Scopes: []string{"read"}})
	interceptor := ConnectAuth(NewBearerAuthenticator(issuer, RequireScopes("read")))
	called := false
	next := interceptor.WrapUnary(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		if _, ok := ClaimsFromContext(ctx); !ok {
			t.Fatal("claims missing from context")
		}
		return connect.NewResponse(&struct{}{}), nil
	})

	req := connect.NewRequest(&struct{}{})
	req.Header().Set("Authorization", "Bearer "+token)
	if _, err := next(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("next was not called")
	}
}

func TestConnectAuthMapsMissingBearerToken(t *testing.T) {
	t.Parallel()

	next := ConnectAuth(NewBearerAuthenticator(testTokenIssuer(t))).WrapUnary(
		func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			t.Fatal("next should not be called")
			return nil, nil
		},
	)
	_, err := next(context.Background(), connect.NewRequest(&struct{}{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code=%v want unauthenticated err=%v", connect.CodeOf(err), err)
	}
}

func TestConnectAuthMapsPermissionDenied(t *testing.T) {
	t.Parallel()

	issuer := testTokenIssuer(t)
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user-1", Scopes: []string{"read"}})
	next := ConnectAuth(NewBearerAuthenticator(issuer, RequireScopes("write"))).WrapUnary(
		func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			t.Fatal("next should not be called")
			return nil, nil
		},
	)
	req := connect.NewRequest(&struct{}{})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := next(context.Background(), req)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code=%v want permission denied err=%v", connect.CodeOf(err), err)
	}
}

func testTokenIssuer(t *testing.T) *Issuer {
	t.Helper()
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := New(Config{
		Issuer:      "https://auth.example.com",
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func testRemoteTokenIssuer(t *testing.T, audience string) (*Issuer, *httptest.Server) {
	t.Helper()
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	issuer, err := New(Config{
		Issuer:      server.URL,
		Audience:    audience,
		ActiveKeyID: "test-key",
		Keys:        []SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/.well-known/openid-configuration", issuer.MetadataHandler())
	mux.Handle("/.well-known/jwks.json", issuer.JWKSHandler())
	return issuer, server
}

func mintTestToken(t *testing.T, issuer *Issuer, identity auth.Identity) string {
	t.Helper()
	token, _, err := issuer.Mint(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
