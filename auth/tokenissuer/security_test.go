package tokenissuer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/httpapp/jwtauth"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestProtectedClaimsRejectDecoderAliases(t *testing.T) {
	t.Parallel()
	issuer, server := testRemoteTokenIssuer(t, "api")
	remote, err := NewRemoteVerifier(context.Background(), RemoteVerifierConfig{Issuer: server.URL, AllowedAudiences: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := jwtauth.NewVerifier(jwtauth.Config{Issuer: server.URL, AllowedAudiences: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"SUB", "ſub", "Scope", "ſcope", "ſcopes", "attributeſ", "AUD", "EXP"} {
		t.Run(alias, func(t *testing.T) {
			if _, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "ordinary-user", Scopes: []string{"read"}, Claims: map[string]any{alias: "administrator"}}); err == nil {
				t.Fatal("issuer accepted a protected claim alias")
			}
			// Also reject externally signed tokens; mint-time checks alone do
			// not protect receiving services against ambiguous claim names.
			claims := map[string]any{"iss": server.URL, "sub": "ordinary-user", "aud": "api", "exp": time.Now().Add(time.Minute).Unix(), "scope": "read", alias: "administrator"}
			opts := (&jose.SignerOptions{}).WithHeader("kid", issuer.activeKey.keyID)
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: issuer.activeKey.algorithm, Key: issuer.activeKey.privateKey}, opts)
			if err != nil {
				t.Fatal(err)
			}
			token, err := josejwt.Signed(signer).Claims(claims).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.Verify(token); err == nil {
				t.Fatal("local verifier accepted claim alias")
			}
			if _, err := remote.Verify(context.Background(), token); err == nil {
				t.Fatal("remote verifier accepted claim alias")
			}
			// Generic upstream JWT verification protects registered identity
			// fields; framework-specific custom scope fields are not its policy.
			if alias == "SUB" || alias == "ſub" || alias == "AUD" || alias == "EXP" {
				if _, err := upstream.Verify(context.Background(), token); err == nil {
					t.Fatal("OIDC JWT verifier accepted registered claim alias")
				}
			}
		})
	}
	token := mintTestToken(t, issuer, auth.Identity{
		Subject: "ordinary-user", Scopes: []string{"read"},
		Claims: map[string]any{"new_claim": "new-value", "project_ids": []string{"p1"}, "scope_label": "example", "ſtores": "unrelated"},
	})
	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "ordinary-user" || claims.Scope != "read" || claims.Custom["new_claim"] != "new-value" || claims.Custom["ſtores"] != "unrelated" {
		t.Fatalf("custom claims changed protected identity: %+v", claims)
	}
}

func TestConnectAuthRedactsFailuresAndRetainsCauses(t *testing.T) {
	t.Parallel()
	issuer := testTokenIssuer(t)
	token := mintTestToken(t, issuer, auth.Identity{Subject: "user"})
	private := errors.New("private backend details")
	typed := connect.NewError(connect.CodeUnavailable, private)
	typed.Meta().Set("Private-Header", "private metadata")
	detail, err := connect.NewErrorDetail(&emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	typed.AddDetail(detail)
	for _, tc := range []struct {
		name  string
		cause error
		code  connect.Code
	}{
		{"unknown", private, connect.CodeInternal},
		{"denied", fmt.Errorf("%w: %w", auth.ErrPermissionDenied, private), connect.CodePermissionDenied},
		{"typed", typed, connect.CodeUnavailable},
		{"unavailable", fmt.Errorf("%w: %w", auth.ErrUnavailable, private), connect.CodeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewBearerAuthenticator(issuer, WithPolicy(func(context.Context, *Claims) error { return tc.cause }))
			intercept := ConnectAuth(a)
			next := intercept.WrapUnary(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
				t.Fatal("auth failure reached handler")
				return nil, nil
			})
			req := connect.NewRequest(&emptypb.Empty{})
			req.Header().Set("Authorization", "Bearer "+token)
			_, err := next(context.Background(), req)
			if connect.CodeOf(err) != tc.code || !errors.Is(err, tc.cause) || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe or misclassified error: %v", err)
			}
			var public *connect.Error
			if !errors.As(err, &public) || len(public.Details()) != 0 || public.Meta().Get("Private-Header") != "" {
				t.Fatal("original Connect details or metadata copied")
			}
			handler := connect.NewUnaryHandler("/test.Service/Call", func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
				t.Fatal("auth failure reached handler")
				return nil, nil
			}, connect.WithInterceptors(intercept))
			r := httptest.NewRequest(http.MethodPost, "/test.Service/Call", strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Connect-Protocol-Version", "1")
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "private") || w.Header().Get("Private-Header") != "" {
				t.Fatalf("unsafe HTTP response: %d %s", w.Code, w.Body.String())
			}
		})
	}
	// Verifier causes survive Authenticate's invalid-token wrapper as well.
	_, err = NewBearerAuthenticatorFromVerifier(failingSecurityVerifier{private}).Authenticate(context.Background(), "Bearer jwt")
	if !errors.Is(err, private) {
		t.Fatal("authentication lost verifier cause")
	}
}

type failingSecurityVerifier struct{ err error }

func (v failingSecurityVerifier) Verify(context.Context, string) (*Claims, error) { return nil, v.err }
