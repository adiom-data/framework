package browserauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth/tokenissuer"
)

func TestLogoutHandlerRevokesAndClearsSession(t *testing.T) {
	t.Parallel()

	store := memorySessionStore{
		"sess_1": {
			ID:        "sess_1",
			Issuer:    "https://idp.example.com",
			Subject:   "user-1",
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
	handler := LogoutHandler{Store: store, Cookie: SessionCookie{}, Redirect: "/signed-out"}.Handler()
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: "sess_1"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Result().Header.Get("Location"); got != "/signed-out" {
		t.Fatalf("Location=%q want /signed-out", got)
	}
	if store["sess_1"].RevokedAt.IsZero() {
		t.Fatal("session was not revoked")
	}
	if cookies := rec.Result().Cookies(); len(cookies) == 0 || cookies[0].MaxAge != -1 {
		t.Fatalf("session cookie was not cleared: %#v", cookies)
	}
}

func TestHandlerDefaultsCookiePathToBasePath(t *testing.T) {
	t.Parallel()

	store := memorySessionStore{
		"sess_1": {
			ID:        "sess_1",
			Issuer:    "https://idp.example.com",
			Subject:   "user-1",
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
	auth := &BrowserAuth{}
	handler := auth.Handler(HandlerConfig{
		BasePath: "/auth",
		Store:    store,
	})
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: "sess_1"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Result().Header.Get("Set-Cookie"); !strings.Contains(got, "Path=/auth") {
		t.Fatalf("Set-Cookie=%q want Path=/auth", got)
	}
}

func TestHandlerServesIssuerEndpoints(t *testing.T) {
	t.Parallel()

	privateKey, err := tokenissuer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{
		Issuer:      "https://app.example.com/auth",
		ActiveKeyID: "test-key",
		Keys:        []tokenissuer.SigningKey{{KeyID: "test-key", PrivateKey: privateKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := (&BrowserAuth{}).Handler(HandlerConfig{Issuer: issuer})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	var metadata tokenissuer.Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.JWKSURI != "https://app.example.com/auth/.well-known/jwks.json" {
		t.Fatalf("jwks_uri=%q", metadata.JWKSURI)
	}
}

func TestSQLSessionStoreRequiresDB(t *testing.T) {
	t.Parallel()

	_, err := (SQLSessionStore{}).Create(context.Background(), Session{ExpiresAt: time.Now().Add(time.Hour)})
	if err == nil {
		t.Fatal("expected error")
	}
}
