package authservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/credential"
	"github.com/adiom-data/framework/auth/tokenissuer"
	authv1 "github.com/adiom-data/framework/gen/go/adiom/auth/v1"
)

func newExchangeService(t *testing.T, scopes []string, authorizer auth.AuthorizerFunc) (*Service, string) {
	t.Helper()
	key, err := tokenissuer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{
		Issuer: "https://auth.example.com", Audience: "default-api", TTL: time.Minute,
		ActiveKeyID: "issuer-key", Keys: []tokenissuer.SigningKey{{KeyID: "issuer-key", PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := credential.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	token, err := credential.SignAssertion(pair.ID, pair.PrivateKey, scopes, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	exchanger := credential.APIKeyExchanger{Lookup: func(_ context.Context, id string) (credential.APIKeyRecord, error) {
		if id != pair.ID {
			return credential.APIKeyRecord{}, credential.ErrInvalid
		}
		return credential.APIKeyRecord{ID: id, PublicKey: pair.PublicKey}, nil
	}}
	return New(exchanger, authorizer, issuer), token
}

func exchangeForm(token string) url.Values {
	return url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {token}, "subject_token_type": {JWTTokenType},
	}
}

func performExchange(handler http.Handler, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestTokenExchangeSignedCredentialAndConnect(t *testing.T) {
	t.Parallel()
	svc, token := newExchangeService(t, []string{"read", "write"}, func(_ context.Context, external auth.ExternalIdentity) (auth.Identity, error) {
		if !reflect.DeepEqual(external.Claims["requested_scopes"], []string{"read", "write"}) {
			t.Fatalf("requested scopes: %#v", external.Claims)
		}
		// Policy belongs to the app; the HTTP adapter must report these actual
		// scopes rather than silently changing the author's decision.
		return auth.Identity{Subject: "user-1", Scopes: []string{"read", "tenant:abc"}}, nil
	})
	form := exchangeForm(token)
	form.Set("scope", "write read read")
	form.Set("requested_token_type", AccessTokenType)
	w := performExchange(svc.TokenExchangeHandler(), form)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers=%v", w.Header())
	}
	var body TokenExchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.IssuedTokenType != AccessTokenType || body.TokenType != "Bearer" || body.Scope != "read tenant:abc" || body.ExpiresIn < 59 || body.ExpiresIn > 60 {
		t.Fatalf("response=%+v", body)
	}
	claims, err := svc.Issuer.Verify(body.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" || claims.Scope != body.Scope || !reflect.DeepEqual([]string(claims.Audience), []string{"default-api"}) {
		t.Fatalf("claims=%+v", claims)
	}
	resp, err := svc.ExchangeCredential(context.Background(), connect.NewRequest(&authv1.ExchangeCredentialRequest{Credential: token}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Issuer.Verify(resp.Msg.AccessToken); err != nil {
		t.Fatal(err)
	}
}

func TestTokenExchangePassesScopesAndTargets(t *testing.T) {
	t.Parallel()
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			var scopes []string
			if signed {
				scopes = []string{"read"}
			}
			svc, token := newExchangeService(t, scopes, func(_ context.Context, external auth.ExternalIdentity) (auth.Identity, error) {
				if !reflect.DeepEqual(external.Claims["requested_scopes"], []string{"read"}) ||
					!reflect.DeepEqual(external.Audiences, []string{"api-one", "api-two"}) ||
					!reflect.DeepEqual(external.Resources, []string{"https://api.example.com/one", "urn:api:two"}) {
					t.Fatalf("external=%+v", external)
				}
				return auth.Identity{Subject: "user-1", Scopes: []string{"read"}, Aud: []string{"default-api", "api-one"}}, nil
			})
			form := exchangeForm(token)
			if !signed {
				form.Set("scope", "read")
			}
			form["audience"] = []string{"api-one", "api-two"}
			form["resource"] = []string{"https://api.example.com/one", "urn:api:two"}
			w := performExchange(svc.TokenExchangeHandler(), form)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var response TokenExchangeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			claims, err := svc.Issuer.Verify(response.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual([]string(claims.Audience), []string{"default-api", "api-one"}) {
				t.Fatalf("audience=%v", claims.Audience)
			}
		})
	}
}

func TestTokenExchangeRejectsBadRequestsBeforeAuthorization(t *testing.T) {
	t.Parallel()
	svc, token := newExchangeService(t, []string{"read"}, func(context.Context, auth.ExternalIdentity) (auth.Identity, error) {
		t.Fatal("invalid request reached authorizer")
		return auth.Identity{}, nil
	})
	cases := []struct {
		name, code string
		modify     func(url.Values)
	}{
		{"missing_grant", "invalid_request", func(v url.Values) { v.Del("grant_type") }},
		{"other_grant", "unsupported_grant_type", func(v url.Values) { v.Set("grant_type", "refresh_token"); v.Del("subject_token") }},
		{"missing_subject", "invalid_request", func(v url.Values) { v.Del("subject_token") }},
		{"missing_type", "invalid_request", func(v url.Values) { v.Del("subject_token_type") }},
		{"unsupported_subject_type", "invalid_request", func(v url.Values) { v.Set("subject_token_type", AccessTokenType) }},
		{"unsupported_output_type", "invalid_request", func(v url.Values) { v.Set("requested_token_type", JWTTokenType) }},
		{"actor", "invalid_request", func(v url.Values) { v.Set("actor_token", token) }},
		{"actor_type_alone", "invalid_request", func(v url.Values) { v.Set("actor_token_type", JWTTokenType) }},
		{"duplicate_scope", "invalid_request", func(v url.Values) { v["scope"] = []string{"read", "write"} }},
		{"duplicate_subject", "invalid_request", func(v url.Values) { v.Add("subject_token", token) }},
		{"bad_scope", "invalid_scope", func(v url.Values) { v.Set("scope", "read\twrite") }},
		{"empty_scope_token", "invalid_scope", func(v url.Values) { v.Set("scope", "read  write") }},
		{"scope_conflict", "invalid_request", func(v url.Values) { v.Set("scope", "write") }},
		{"relative_resource", "invalid_request", func(v url.Values) { v.Set("resource", "/api") }},
		{"fragment_resource", "invalid_request", func(v url.Values) { v.Set("resource", "https://api.example.com/#") }},
		{"invalid_subject", "invalid_request", func(v url.Values) { v.Set("subject_token", "not-a-jwt") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := exchangeForm(token)
			tc.modify(form)
			assertExchangeError(t, performExchange(svc.TokenExchangeHandler(), form), http.StatusBadRequest, tc.code)
		})
	}
	for _, tc := range []struct{ name, method, contentType, body, query string }{
		{"method", http.MethodGet, "application/x-www-form-urlencoded", "", ""},
		{"json", http.MethodPost, "application/json", `{}`, ""},
		{"charset", http.MethodPost, "application/x-www-form-urlencoded; charset=iso-8859-1", "", ""},
		{"malformed", http.MethodPost, "application/x-www-form-urlencoded", "scope=%zz", ""},
		{"oversized", http.MethodPost, "application/x-www-form-urlencoded", "subject_token=" + strings.Repeat("x", (1<<20)+1), ""},
		{"query_only", http.MethodPost, "application/x-www-form-urlencoded", "", "?" + exchangeForm(token).Encode()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/oauth/token"+tc.query, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			svc.TokenExchangeHandler().ServeHTTP(w, r)
			status := http.StatusBadRequest
			if tc.method == http.MethodGet {
				status = http.StatusMethodNotAllowed
				if w.Header().Get("Allow") != http.MethodPost {
					t.Fatalf("Allow=%q", w.Header().Get("Allow"))
				}
			}
			assertExchangeError(t, w, status, "invalid_request")
		})
	}
}

func TestTokenExchangeAuthorizationErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{
		{fmt.Errorf("policy: %w", ErrInvalidTarget), "invalid_target", http.StatusBadRequest},
		{ErrInvalidScope, "invalid_scope", http.StatusBadRequest},
		{errors.New("private database detail"), "server_error", http.StatusInternalServerError},
	} {
		t.Run(tc.code, func(t *testing.T) {
			svc, token := newExchangeService(t, nil, func(context.Context, auth.ExternalIdentity) (auth.Identity, error) {
				return auth.Identity{}, tc.err
			})
			w := performExchange(svc.TokenExchangeHandler(), exchangeForm(token))
			assertExchangeError(t, w, tc.status, tc.code)
			if strings.Contains(w.Body.String(), "private database detail") {
				t.Fatal("internal error leaked")
			}
		})
	}
	var svc *Service
	assertExchangeError(t, performExchange(svc.TokenExchangeHandler(), exchangeForm("jwt")), http.StatusInternalServerError, "server_error")
	svc, token := newExchangeService(t, nil, func(context.Context, auth.ExternalIdentity) (auth.Identity, error) {
		return auth.Identity{Subject: "user-1", Claims: map[string]any{"aud": "cannot-override-here"}}, nil
	})
	assertExchangeError(t, performExchange(svc.TokenExchangeHandler(), exchangeForm(token)), http.StatusInternalServerError, "server_error")
}

func TestTokenExchangePreservesVerifierClaims(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"requested_scopes": []any{"write", "read"}, "tenant": "abc"}
	svc, token := newExchangeService(t, nil, func(_ context.Context, external auth.ExternalIdentity) (auth.Identity, error) {
		if !reflect.DeepEqual(external.Claims["requested_scopes"], []string{"read", "write"}) {
			t.Fatalf("claims=%v", external.Claims)
		}
		return auth.Identity{Subject: "user-1"}, nil
	})
	svc.Exchanger = credential.ExchangerFunc(func(context.Context, string) (credential.Result, error) {
		return credential.Result{ExternalIdentity: auth.ExternalIdentity{Subject: "external", Claims: claims}}, nil
	})
	form := exchangeForm(token)
	form.Set("scope", "read write")
	w := performExchange(svc.TokenExchangeHandler(), form)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scope":""`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(claims["requested_scopes"], []any{"write", "read"}) {
		t.Fatalf("verifier-owned map mutated: %v", claims)
	}
	claims["requested_scopes"] = []any{123}
	assertExchangeError(t, performExchange(svc.TokenExchangeHandler(), form), http.StatusBadRequest, "invalid_request")
}

func assertExchangeError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body struct{ Error string }
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != status || body.Error != code {
		t.Fatalf("status=%d body=%s; want status=%d error=%s", w.Code, w.Body.String(), status, code)
	}
}
