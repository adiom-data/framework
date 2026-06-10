package browserauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestCookieStateStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state"}
	rec := httptest.NewRecorder()
	session, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	if session.CodeVerifier == "" {
		t.Fatal("CodeVerifier is empty")
	}
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))

	verifyRec := httptest.NewRecorder()
	got, err := store.VerifySession(verifyRec, req, session.State)
	if err != nil {
		t.Fatal(err)
	}
	if got.CodeVerifier != session.CodeVerifier {
		t.Fatalf("CodeVerifier=%q want original verifier", got.CodeVerifier)
	}
	if !strings.Contains(verifyRec.Result().Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("state cookie was not cleared: %q", verifyRec.Result().Header.Get("Set-Cookie"))
	}
	if !strings.Contains(rec.Result().Header.Get("Set-Cookie"), "Secure") {
		t.Fatalf("state cookie is not secure: %q", rec.Result().Header.Get("Set-Cookie"))
	}
}

func TestCookieStateStoreRejectsBadState(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state"}
	rec := httptest.NewRecorder()
	session, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))

	if _, err := store.VerifySession(httptest.NewRecorder(), req, "other"); err == nil {
		t.Fatal("expected invalid state")
	}
}

func TestCookieStateStoreRejectsTamperedCookie(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state"}
	rec := httptest.NewRecorder()
	session, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]
	cookie.Value += "tampered"
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.AddCookie(cookie)

	if _, err := store.VerifySession(httptest.NewRecorder(), req, session.State); err == nil {
		t.Fatal("expected tampered cookie to be rejected")
	}
}

func TestCookieStateStoreAllowsExplicitInsecureCookie(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state", Insecure: true}
	rec := httptest.NewRecorder()
	if _, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.Result().Header.Get("Set-Cookie"), "Secure") {
		t.Fatalf("state cookie is secure: %q", rec.Result().Header.Get("Set-Cookie"))
	}
}

func TestLoginHandlerUsesPKCE(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2: oauth2.Config{
			ClientID:    "client",
			RedirectURL: "https://app.example.com/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://keycloak.example.com/realms/app/protocol/openid-connect/auth",
			},
			Scopes: []string{"openid"},
		},
		stateStore: CookieStateStore{Name: "state"},
	}
	rec := httptest.NewRecorder()
	auth.LoginHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	location := rec.Result().Header.Get("Location")
	if location == "" {
		t.Fatal("missing redirect location")
	}
	redirect, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method=%q want S256", got)
	}
	if redirect.Query().Get("code_challenge") == "" {
		t.Fatal("missing code_challenge")
	}
	if redirect.Query().Get("state") == "" {
		t.Fatal("missing state")
	}
}

func TestLoginHandlerUsesAuthCodeOptions(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2: oauth2.Config{
			ClientID:    "client",
			RedirectURL: "https://app.example.com/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
			},
			Scopes: []string{"openid"},
		},
		stateStore: CookieStateStore{Name: "state"},
		authCodeOptions: []oauth2.AuthCodeOption{
			oauth2.AccessTypeOffline,
			oauth2.SetAuthURLParam("prompt", "consent"),
		},
	}
	rec := httptest.NewRecorder()
	auth.LoginHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	redirect, err := url.Parse(rec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Query().Get("access_type"); got != "offline" {
		t.Fatalf("access_type=%q want offline", got)
	}
	if got := redirect.Query().Get("prompt"); got != "consent" {
		t.Fatalf("prompt=%q want consent", got)
	}
	if redirect.Query().Get("code_challenge") == "" {
		t.Fatal("missing code_challenge")
	}
}
