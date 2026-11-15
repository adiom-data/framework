package browserauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
)

func TestCallbackRedactsProviderErrors(t *testing.T) {
	t.Parallel()
	key, err := tokenissuer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerConfig := tokenissuer.Config{
		Issuer: "https://idp.example", Audience: "client", ActiveKeyID: "key",
		Keys: []tokenissuer.SigningKey{{KeyID: "key", PrivateKey: key}},
	}
	issuer, err := tokenissuer.New(issuerConfig)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(issuer *tokenissuer.Issuer, audience string) string {
		t.Helper()
		token, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "user", Aud: []string{audience}})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	goodToken := mint(issuer, "client")
	badAudience := mint(issuer, "private-audience")
	issuerConfig.Issuer = "https://private-tenant.example"
	otherIssuer, err := tokenissuer.New(issuerConfig)
	if err != nil {
		t.Fatal(err)
	}
	badIssuer := mint(otherIssuer, "client")
	for _, tc := range []struct {
		name, exchangeBody, idToken, keysBody, providerError string
		exchangeStatus, keysStatus                           int
		transportErr                                         error
	}{
		{name: "exchange_oauth_error", exchangeStatus: 400, exchangeBody: `{"error":"invalid_grant","error_description":"private provider details","error_uri":"https://private-tenant.example/error"}`},
		{name: "exchange_response_body", exchangeStatus: 502, exchangeBody: "private provider response body"},
		{name: "exchange_transport", transportErr: errors.New("private provider transport details")},
		{name: "malformed_id_token", idToken: "private malformed token"},
		{name: "wrong_audience", idToken: badAudience},
		{name: "wrong_issuer", idToken: badIssuer},
		{name: "jwks_response_body", keysStatus: 503, keysBody: "private JWKS response body"},
		{name: "provider_callback", providerError: "private provider callback details"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: browserTestTransport(func(r *http.Request) (*http.Response, error) {
				status := http.StatusOK
				var body any
				rawBody := ""
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					body = map[string]any{
						"issuer": "https://idp.example", "authorization_endpoint": "https://idp.example/login",
						"token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/keys",
						"id_token_signing_alg_values_supported": []string{"EdDSA"},
					}
				case "/keys":
					body = issuer.JWKS()
					if tc.keysStatus != 0 {
						status, rawBody = tc.keysStatus, tc.keysBody
					}
				case "/token":
					if tc.providerError != "" {
						t.Fatal("provider rejection reached token exchange")
					}
					if tc.transportErr != nil {
						return nil, tc.transportErr
					}
					token := tc.idToken
					if token == "" {
						token = goodToken
					}
					body = map[string]any{"access_token": "upstream", "token_type": "Bearer", "id_token": token}
					if tc.exchangeStatus != 0 {
						status, rawBody = tc.exchangeStatus, tc.exchangeBody
					}
				default:
					return nil, fmt.Errorf("unexpected provider URL: %s", r.URL)
				}
				if rawBody == "" {
					encoded, err := json.Marshal(body)
					if err != nil {
						return nil, err
					}
					rawBody = string(encoded)
				}
				return &http.Response{
					StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(rawBody)),
				}, nil
			})}
			b, err := New(context.Background(), Config{
				Issuer: "https://idp.example", ClientID: "client", RedirectURL: "https://app.example/auth/callback",
				HTTPClient: client, StateStore: fixedStateStore{},
			})
			if err != nil {
				t.Fatal(err)
			}
			store := &completionTestStore{memorySessionStore: memorySessionStore{}}
			hookCalled := false
			handler := b.Handler(HandlerConfig{Store: store, BeforeCreate: func(*http.Request, Tokens, *Session) error {
				hookCalled = true
				return nil
			}})
			query := url.Values{"state": {"state"}, "code": {"private-code"}}
			wantStatus, wantBody := http.StatusBadGateway, "Unable to authenticate with identity provider.\n"
			if tc.providerError != "" {
				query.Set("error", tc.providerError)
				query.Set("error_description", "private error description")
				wantStatus, wantBody = http.StatusBadRequest, "Login was not completed.\n"
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?"+query.Encode(), nil))
			if rec.Code != wantStatus || rec.Body.String() != wantBody {
				t.Errorf("response=%d %q, want=%d %q", rec.Code, rec.Body.String(), wantStatus, wantBody)
			}
			if strings.Contains(rec.Body.String(), "private") {
				t.Error("callback exposed provider details")
			}
			if hookCalled || store.creates != 0 || len(store.memorySessionStore) != 0 || len(rec.Result().Cookies()) != 0 || rec.Header().Get("Location") != "" {
				t.Fatal("provider failure completed login or set a session cookie")
			}
		})
	}
}
