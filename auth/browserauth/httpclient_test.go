package browserauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
	"golang.org/x/oauth2"
)

type browserTestTransport func(*http.Request) (*http.Response, error)

func (f browserTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPClientAcrossLoginAndRefresh(t *testing.T) {
	t.Parallel()
	for _, explicit := range []bool{false, true} {
		name := "context_client"
		if explicit {
			name = "configured_client"
		}
		t.Run(name, func(t *testing.T) {
			key, err := tokenissuer.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			issuer, err := tokenissuer.New(tokenissuer.Config{Issuer: "https://idp.example", Audience: "client", ActiveKeyID: "key",
				Keys: []tokenissuer.SigningKey{{KeyID: "key", PrivateKey: key}}})
			if err != nil {
				t.Fatal(err)
			}
			token, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "user", Claims: map[string]any{"metadata": map[string]any{"connection_id": "idp-value"}}})
			if err != nil {
				t.Fatal(err)
			}
			type operationKey struct{}
			grants := []string{}
			keysFetched := false
			client := &http.Client{Transport: browserTestTransport(func(r *http.Request) (*http.Response, error) {
				var body any
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					body = map[string]any{"issuer": "https://idp.example", "authorization_endpoint": "https://idp.example/login",
						"token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/keys", "id_token_signing_alg_values_supported": []string{"EdDSA"}}
				case "/keys":
					keysFetched = true
					body = issuer.JWKS()
				case "/token":
					if r.Context().Value(operationKey{}) != "preserved" {
						t.Fatal("operation context values lost")
					}
					if _, ok := r.Context().Deadline(); !ok {
						t.Fatal("operation deadline lost")
					}
					if err := r.Context().Err(); err != nil {
						return nil, err
					}
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					grant := r.Form.Get("grant_type")
					grants = append(grants, grant)
					if grant == "authorization_code" && r.Form.Get("code_verifier") != "verifier" {
						t.Fatal("PKCE verifier lost")
					}
					if grant == "refresh_token" && r.Form.Get("refresh_token") != "refresh" {
						t.Fatal("refresh token lost")
					}
					body = map[string]any{"access_token": "upstream", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh", "id_token": token}
				default:
					t.Fatalf("unexpected provider URL: %s", r.URL)
					return nil, errors.New("unexpected URL")
				}
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
			})}
			cfg := Config{Issuer: "https://idp.example", ClientID: "client", RedirectURL: "https://app.example/auth/callback", StateStore: fixedStateStore{}}
			constructorCtx := context.Background()
			operationCtx := context.WithValue(context.Background(), operationKey{}, "preserved")
			if explicit {
				cfg.HTTPClient = client
				other := &http.Client{Transport: browserTestTransport(func(*http.Request) (*http.Response, error) {
					t.Fatal("context client overrode configured client")
					return nil, errors.New("wrong client")
				})}
				operationCtx = context.WithValue(operationCtx, oauth2.HTTPClient, other)
			} else {
				constructorCtx = context.WithValue(constructorCtx, oauth2.HTTPClient, client)
				operationCtx = context.WithValue(operationCtx, oauth2.HTTPClient, client)
			}
			operationCtx, cancel := context.WithTimeout(operationCtx, time.Minute)
			defer cancel()
			b, err := New(constructorCtx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			store := &completionTestStore{memorySessionStore: memorySessionStore{}}
			handler := b.Handler(HandlerConfig{Store: store, BasePath: "/auth", BeforeCreate: func(_ *http.Request, _ Tokens, session *Session) error {
				session.Metadata = map[string]string{"connection_id": "trusted"}
				return nil
			}})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?state=state&code=code", nil).WithContext(operationCtx))
			if rec.Code != http.StatusFound {
				t.Fatalf("callback: %d %s", rec.Code, rec.Body.String())
			}
			session, err := b.RefreshSession(operationCtx, store.memorySessionStore["created-session"])
			if err != nil {
				t.Fatal(err)
			}
			if session.Subject != "user" || session.Metadata["connection_id"] != "trusted" || session.Claims["metadata"].(map[string]any)["connection_id"] != "idp-value" {
				t.Fatalf("refresh lost or confused metadata: %+v", session)
			}
			if len(grants) != 2 || grants[0] != "authorization_code" || grants[1] != "refresh_token" || !keysFetched {
				t.Fatalf("provider operations: %v keys=%v", grants, keysFetched)
			}
			cancel()
			if _, err := b.RefreshSession(operationCtx, session); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}
