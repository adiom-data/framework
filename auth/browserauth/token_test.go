package browserauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
)

func TestTokenEndpointMintsFromSession(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{
		Issuer:     "https://auth.example.com",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	store := memorySessionStore{
		"sess_1": {
			ID:           "sess_1",
			Issuer:       "https://idp.example.com",
			Subject:      "upstream-1",
			RefreshToken: "refresh",
			Claims:       map[string]any{"email": "user@example.com"},
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}
	endpoint := TokenEndpoint{
		Store:  store,
		Cookie: SessionCookie{},
		Authorizer: auth.AuthorizerFunc(func(_ context.Context, external auth.ExternalIdentity) (auth.Identity, error) {
			if external.Issuer != "https://idp.example.com" || external.Subject != "upstream-1" {
				t.Fatalf("external=%+v", external)
			}
			return auth.Identity{Subject: "user-1", Scopes: []string{"read"}}, nil
		}),
		Issuer: issuer,
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	req.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: "sess_1"})
	token, err := endpoint.Mint(req)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", claims.Subject)
	}
}

func TestTokenEndpointRefreshesSession(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{
		Issuer:     "https://auth.example.com",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := memorySessionStore{
		"sess_1": {
			ID:           "sess_1",
			Issuer:       "https://idp.example.com",
			Subject:      "upstream-1",
			RefreshToken: "refresh-1",
			Claims:       map[string]any{"email": "old@example.com"},
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}
	endpoint := TokenEndpoint{
		Store: store,
		Refresher: refresherFunc(func(_ context.Context, session Session) (Session, error) {
			session.RefreshToken = "refresh-2"
			session.Claims = map[string]any{"email": "new@example.com"}
			return session, nil
		}),
		Authorizer: auth.AuthorizerFunc(func(_ context.Context, external auth.ExternalIdentity) (auth.Identity, error) {
			if external.Claims["email"] != "new@example.com" {
				t.Fatalf("email claim=%v want new@example.com", external.Claims["email"])
			}
			return auth.Identity{Subject: "user-1"}, nil
		}),
		Issuer: issuer,
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: "sess_1"})
	if _, err := endpoint.Mint(req); err != nil {
		t.Fatal(err)
	}
	if got := store["sess_1"].RefreshToken; got != "refresh-2" {
		t.Fatalf("refresh token=%q want refresh-2", got)
	}
}

func TestTokenEndpointHandlerReportsMisconfigurationAsServerError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	TokenEndpoint{}.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestTokenEndpointHandlerReportsAccessToken(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{
		Issuer:     "https://auth.example.com",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := TokenEndpoint{
		Store: memorySessionStore{
			"sess_1": {
				ID:        "sess_1",
				Issuer:    "https://idp.example.com",
				Subject:   "upstream-1",
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
		Authorizer: auth.AuthorizerFunc(func(context.Context, auth.ExternalIdentity) (auth.Identity, error) {
			return auth.Identity{Subject: "user-1"}, nil
		}),
		Issuer: issuer,
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: "sess_1"})

	endpoint.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.AccessToken == "" {
		t.Fatal("access token is empty")
	}
}

type memorySessionStore map[string]Session

func (m memorySessionStore) Create(_ context.Context, session Session) (Session, error) {
	m[session.ID] = session
	return session, nil
}

func (m memorySessionStore) Get(_ context.Context, id string) (Session, error) {
	return m[id], nil
}

func (m memorySessionStore) Update(_ context.Context, session Session) error {
	m[session.ID] = session
	return nil
}

func (m memorySessionStore) Revoke(_ context.Context, id string) error {
	session := m[id]
	session.RevokedAt = time.Now()
	m[id] = session
	return nil
}

type refresherFunc func(context.Context, Session) (Session, error)

func (f refresherFunc) RefreshSession(ctx context.Context, session Session) (Session, error) {
	return f(ctx, session)
}
