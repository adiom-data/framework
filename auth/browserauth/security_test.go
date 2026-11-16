package browserauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
)

func securityTokenEndpoint(t *testing.T) TokenEndpoint {
	t.Helper()
	key, err := tokenissuer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{Issuer: "https://auth.example", ActiveKeyID: "key", Keys: []tokenissuer.SigningKey{{KeyID: "key", PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	return TokenEndpoint{
		Issuer: issuer,
		Store:  memorySessionStore{"session": {ID: "session", Issuer: "https://idp.example", Subject: "user", ExpiresAt: time.Now().Add(time.Hour)}},
		Authorizer: auth.AuthorizerFunc(func(context.Context, auth.ExternalIdentity) (auth.Identity, error) {
			return auth.Identity{Subject: "user"}, nil
		}),
	}
}

func securitySessionRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: "session"})
	return r
}

func TestTokenResponsesArePrivateAndClassified(t *testing.T) {
	t.Parallel()
	private := errors.New("private backend details")
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, tc := range []struct {
			name   string
			cause  error
			status int
		}{
			{"success", nil, http.StatusOK},
			{"denied", fmt.Errorf("%w: %w", auth.ErrPermissionDenied, private), http.StatusForbidden},
			{"unavailable", fmt.Errorf("%w: %w", auth.ErrUnavailable, private), http.StatusServiceUnavailable},
			{"internal", private, http.StatusInternalServerError},
			{"unauthenticated", errExpiredSession, http.StatusUnauthorized},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				e := securityTokenEndpoint(t)
				if tc.cause != nil {
					e.Authorizer = auth.AuthorizerFunc(func(context.Context, auth.ExternalIdentity) (auth.Identity, error) { return auth.Identity{}, tc.cause })
				}
				w := httptest.NewRecorder()
				e.Handler().ServeHTTP(w, securitySessionRequest(method, "/auth/token"))
				if w.Code != tc.status || strings.Contains(w.Body.String(), "private") {
					t.Fatalf("response=%d %s", w.Code, w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
					t.Fatalf("cacheable token response: %v", w.Header())
				}
				if tc.cause != nil {
					_, err := e.Mint(securitySessionRequest(method, "/auth/token"))
					if !errors.Is(err, tc.cause) {
						t.Fatal("Mint lost server-side error cause")
					}
				}
			})
		}
	}
}

type retryRevokeStore struct {
	memorySessionStore
	err error
}

func (s *retryRevokeStore) Revoke(ctx context.Context, id string) error {
	if s.err != nil {
		return s.err
	}
	return s.memorySessionStore.Revoke(ctx, id)
}

func TestLogoutFailureCanBeRetriedWithoutReportingSuccess(t *testing.T) {
	t.Parallel()
	e := securityTokenEndpoint(t)
	store := &retryRevokeStore{memorySessionStore: e.Store.(memorySessionStore), err: errors.New("private revocation details")}
	e.Store = store
	redirected := false
	handler := LogoutHandler{Store: store, RedirectFunc: func(*http.Request) (string, error) { redirected = true; return "/signed-out", nil }}.Handler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, securitySessionRequest(http.MethodPost, "/auth/logout"))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "private") || redirected || len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
		t.Fatalf("failed revocation reported success: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("logout response is cacheable")
	}
	// A retry with the retained cookie actually revokes the server session.
	store.err = nil
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, securitySessionRequest(http.MethodPost, "/auth/logout"))
	if w.Code != http.StatusFound || !redirected || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("successful logout did not clear cookie and redirect")
	}
	if _, err := e.Mint(securitySessionRequest(http.MethodPost, "/auth/token")); !errors.Is(err, errRevokedSession) {
		t.Fatalf("captured cookie survived logout: %v", err)
	}
	// A cookie without a configured revocation store must not succeed either.
	w = httptest.NewRecorder()
	LogoutHandler{}.Handler().ServeHTTP(w, securitySessionRequest(http.MethodPost, "/auth/logout"))
	if w.Code != http.StatusInternalServerError || len(w.Result().Cookies()) != 0 {
		t.Fatal("missing store falsely reported logout")
	}
}

func TestProxyRequiresExplicitDestinationPolicy(t *testing.T) {
	t.Parallel()
	state, err := encodeProxyState(proxyState{State: "forged", ReturnTo: "https://attacker.example/capture"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		validate func(string) bool
		status   int
	}{
		{"unconfigured", nil, http.StatusInternalServerError},
		{"untrusted", func(string) bool { return false }, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{"state": {state}, "code": {"private-code"}}.Encode(), nil)
			ProxyCallbackForwarder(ProxyCallbackForwarderConfig{ReturnToValidator: tc.validate}).ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "private-code") {
				t.Fatalf("unsafe redirect: %d %v %s", w.Code, w.Header(), w.Body.String())
			}
		})
	}
}

type failingSecurityStateStore struct {
	fixedStateStore
	newErr, verifyErr error
}

func (s failingSecurityStateStore) NewSession(w http.ResponseWriter, r *http.Request) (LoginSession, error) {
	if s.newErr != nil {
		return LoginSession{}, s.newErr
	}
	return s.fixedStateStore.NewSession(w, r)
}

func (s failingSecurityStateStore) VerifySession(w http.ResponseWriter, r *http.Request, state string) (LoginSession, error) {
	if s.verifyErr != nil {
		return LoginSession{}, s.verifyErr
	}
	return s.fixedStateStore.VerifySession(w, r, state)
}

func TestLoginSetupErrorsDoNotExposeDetails(t *testing.T) {
	t.Parallel()
	private := errors.New("private provider configuration details")
	for _, tc := range []struct {
		name                      string
		callback, resolver, state bool
		status                    int
	}{
		{"login_resolver", false, true, false, http.StatusInternalServerError},
		{"login_state", false, false, true, http.StatusInternalServerError},
		{"callback_resolver", true, true, false, http.StatusInternalServerError},
		{"callback_state", true, false, true, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := failingSecurityStateStore{}
			if tc.state {
				if tc.callback {
					state.verifyErr = private
				} else {
					state.newErr = private
				}
			}
			b := &BrowserAuth{stateStore: state}
			b.oauth2.RedirectURL = "https://app.example/callback"
			if tc.resolver {
				b.redirectURL = func(*http.Request) (string, error) { return "", private }
			}
			var handler http.Handler = b.LoginHandler()
			if tc.callback {
				handler = b.CallbackHandler(func(http.ResponseWriter, *http.Request, Tokens) error {
					t.Fatal("failed setup reached callback")
					return nil
				})
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?state=state", nil))
			if w.Code != tc.status || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("unsafe setup error: %d %s", w.Code, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	RedirectInvalidState("")(w, httptest.NewRequest(http.MethodGet, "/callback", nil), private)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "private") {
		t.Fatal("invalid-state fallback exposed details")
	}
}
