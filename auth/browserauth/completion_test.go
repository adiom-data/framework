package browserauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
)

type completionTestStore struct {
	memorySessionStore
	err     error
	creates int
}

func TestSessionCallbackHTTPFailureResponses(t *testing.T) {
	t.Parallel()
	key, err := tokenissuer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{
		Issuer: "https://idp.example", Audience: "client", ActiveKeyID: "key",
		Keys: []tokenissuer.SigningKey{{KeyID: "key", PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	idToken, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "user"})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: browserTestTransport(func(r *http.Request) (*http.Response, error) {
		var body any
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			body = map[string]any{
				"issuer": "https://idp.example", "authorization_endpoint": "https://idp.example/login",
				"token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/keys",
				"id_token_signing_alg_values_supported": []string{"EdDSA"},
			}
		case "/keys":
			body = issuer.JWKS()
		case "/token":
			body = map[string]any{"access_token": "upstream", "token_type": "Bearer", "id_token": idToken}
		default:
			return nil, fmt.Errorf("unexpected provider URL: %s", r.URL)
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(string(encoded))),
		}, nil
	})}
	b, err := New(context.Background(), Config{
		Issuer: "https://idp.example", ClientID: "client", RedirectURL: "https://app.example/auth/callback",
		HTTPClient: client, StateStore: fixedStateStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	privateFailure := errors.New("private application details")
	for _, tc := range []struct {
		name              string
		hookErr, storeErr error
		status, creates   int
		body              string
	}{
		{"denied", auth.ErrPermissionDenied, nil, http.StatusForbidden, 0, "Login is not permitted.\n"},
		{"wrapped_denied", fmt.Errorf("%w: %w", auth.ErrPermissionDenied, privateFailure), nil, http.StatusForbidden, 0, "Login is not permitted.\n"},
		{"hook_error", privateFailure, nil, http.StatusInternalServerError, 0, "Unable to complete login.\n"},
		{"store_error", nil, privateFailure, http.StatusInternalServerError, 1, "Unable to complete login.\n"},
	} {
		for _, composed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/composed=%t", tc.name, composed), func(t *testing.T) {
				store := &completionTestStore{memorySessionStore: memorySessionStore{}, err: tc.storeErr}
				hookCalled := false
				hook := func(_ *http.Request, tokens Tokens, session *Session) error {
					hookCalled = true
					if tokens.Claims["sub"] != "user" || session.Subject != "user" {
						t.Fatal("hook did not receive verified identity")
					}
					return tc.hookErr
				}
				var handler http.Handler
				if composed {
					handler = b.Handler(HandlerConfig{Store: store, BeforeCreate: hook})
				} else {
					handler = b.CallbackHandler(b.SessionCallback(SessionCallbackConfig{Store: store, BeforeCreate: hook}))
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?state=state&code=code", nil))
				if rec.Code != tc.status || rec.Body.String() != tc.body {
					t.Fatalf("response=%d %q, want=%d %q", rec.Code, rec.Body.String(), tc.status, tc.body)
				}
				if !hookCalled || store.creates != tc.creates || len(store.memorySessionStore) != 0 {
					t.Fatalf("hook=%v creates=%d stored=%d", hookCalled, store.creates, len(store.memorySessionStore))
				}
				if len(rec.Result().Cookies()) != 0 || rec.Header().Get("Location") != "" {
					t.Fatalf("failed completion set cookie or redirected: %v", rec.Header())
				}
			})
		}
	}
}

func (s *completionTestStore) Create(ctx context.Context, session Session) (Session, error) {
	s.creates++
	if s.err != nil {
		return Session{}, s.err
	}
	session.ID = "created-session"
	return s.memorySessionStore.Create(ctx, session)
}

func TestSessionCallbackCompletionAndFailures(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"success", "check_rejected", "store_failed"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			failure := errors.New("application failure")
			store := &completionTestStore{memorySessionStore: memorySessionStore{}}
			if mode == "store_failed" {
				store.err = failure
			}
			b := &BrowserAuth{issuer: "https://idp.example"}
			hookCalled := false
			complete := b.SessionCallback(SessionCallbackConfig{
				Store: store, BasePath: "/auth", SessionTTL: time.Hour, SuccessRedirect: "/welcome",
				Now: func() time.Time { return now },
				BeforeCreate: func(r *http.Request, tokens Tokens, s *Session) error {
					hookCalled = true
					if r.URL.Path != "/callback" || tokens.Claims["sub"] != "user" || s.Subject != "user" || !s.ExpiresAt.Equal(now.Add(time.Hour)) {
						t.Fatal("hook did not receive request, tokens, and initialized session")
					}
					if mode == "check_rejected" {
						return failure
					}
					s.Metadata = map[string]string{"connection_id": "connection-1"}
					return nil
				},
			})
			rec := httptest.NewRecorder()
			err := complete(rec, httptest.NewRequest(http.MethodGet, "/callback", nil), Tokens{Claims: map[string]any{"sub": "user"}})
			if !hookCalled {
				t.Fatal("hook not called")
			}
			if mode != "success" {
				if !errors.Is(err, failure) || len(rec.Result().Cookies()) != 0 || rec.Header().Get("Location") != "" || len(store.memorySessionStore) != 0 {
					t.Fatalf("failed completion had side effects: err=%v headers=%v", err, rec.Header())
				}
				if mode == "check_rejected" && store.creates != 0 {
					t.Fatal("rejected login reached store")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cookies := rec.Result().Cookies()
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/welcome" || len(cookies) != 1 {
				t.Fatalf("completion response: %d %v", rec.Code, rec.Header())
			}
			if cookies[0].Value != "created-session" || cookies[0].Path != "/auth" || !cookies[0].HttpOnly || !cookies[0].Secure || !cookies[0].Expires.Equal(now.Add(time.Hour)) {
				t.Fatalf("session cookie: %+v", cookies[0])
			}
			if store.memorySessionStore["created-session"].Metadata["connection_id"] != "connection-1" {
				t.Fatal("hook metadata was not saved")
			}
		})
	}
}
