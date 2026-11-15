package authservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/credential"
	authv1 "github.com/adiom-data/framework/gen/go/adiom/auth/v1"
)

func TestExchangeFailureClassificationAcrossTransports(t *testing.T) {
	t.Parallel()
	privateCause := errors.New("private dependency details")
	cases := []struct {
		name        string
		err         error
		httpStatus  int
		oauthCode   string
		connectCode connect.Code
	}{
		{"invalid", fmt.Errorf("%w: %w", credential.ErrInvalid, privateCause), 400, "invalid_request", connect.CodeUnauthenticated},
		{"unsupported", credential.ErrUnsupported, 400, "invalid_request", connect.CodeUnauthenticated},
		{"denied", fmt.Errorf("%w: %w", auth.ErrPermissionDenied, privateCause), 400, "invalid_request", connect.CodePermissionDenied},
		{"scope", ErrInvalidScope, 400, "invalid_scope", connect.CodeInvalidArgument},
		{"target", ErrInvalidTarget, 400, "invalid_target", connect.CodeInvalidArgument},
		{"unavailable", fmt.Errorf("%w: %w", auth.ErrUnavailable, privateCause), 503, "temporarily_unavailable", connect.CodeUnavailable},
		{"deadline", fmt.Errorf("dependency: %w", context.DeadlineExceeded), 503, "temporarily_unavailable", connect.CodeDeadlineExceeded},
		{"canceled", context.Canceled, 503, "temporarily_unavailable", connect.CodeCanceled},
		{"network", &net.DNSError{Err: "private dependency details", Name: "private-host", IsTimeout: true}, 503, "temporarily_unavailable", connect.CodeUnavailable},
		{"connect_unavailable", connect.NewError(connect.CodeUnavailable, privateCause), 503, "temporarily_unavailable", connect.CodeUnavailable},
		{"connect_internal", connect.NewError(connect.CodeInternal, privateCause), 500, "server_error", connect.CodeInternal},
		{"connect_denied", connect.NewError(connect.CodePermissionDenied, privateCause), 400, "invalid_request", connect.CodePermissionDenied},
		{"connect_unauthenticated", connect.NewError(connect.CodeUnauthenticated, privateCause), 400, "invalid_request", connect.CodeUnauthenticated},
		{"connect_busy", connect.NewError(connect.CodeResourceExhausted, privateCause), 503, "temporarily_unavailable", connect.CodeResourceExhausted},
		{"unclassified", privateCause, 500, "server_error", connect.CodeInternal},
	}
	for _, stage := range []string{"exchanger", "authorizer"} {
		for _, tc := range cases {
			t.Run(stage+"/"+tc.name, func(t *testing.T) {
				svc, token := newExchangeService(t, nil, func(context.Context, auth.ExternalIdentity) (auth.Identity, error) {
					if stage == "authorizer" {
						return auth.Identity{}, tc.err
					}
					t.Fatal("exchanger failure reached authorizer")
					return auth.Identity{}, nil
				})
				if stage == "exchanger" {
					svc.Exchanger = credential.ExchangerFunc(func(context.Context, string) (credential.Result, error) {
						return credential.Result{}, tc.err
					})
				}
				w := performExchange(svc.TokenExchangeHandler(), exchangeForm(token))
				assertExchangeError(t, w, tc.httpStatus, tc.oauthCode)
				if strings.Contains(w.Body.String(), "private") {
					t.Fatalf("HTTP exposed private cause: %s", w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("error response is cacheable")
				}
				_, err := svc.ExchangeCredential(context.Background(), connect.NewRequest(&authv1.ExchangeCredentialRequest{Credential: token}))
				if connect.CodeOf(err) != tc.connectCode {
					t.Fatalf("Connect error=%v want code=%v", err, tc.connectCode)
				}
				if !errors.Is(err, tc.err) {
					t.Fatalf("Connect lost original cause: %v", err)
				}
				if strings.Contains(err.Error(), "private") {
					t.Fatalf("Connect exposed private cause: %v", err)
				}
			})
		}
	}
}
