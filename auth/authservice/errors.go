package authservice

import (
	"context"
	"errors"
	"net"
	"net/http"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/credential"
	"github.com/adiom-data/framework/auth/tokenissuer"
)

var (
	// ErrInvalidTarget lets an authorizer reject requested audiences or resources.
	ErrInvalidTarget = errors.New("authservice: invalid exchange target")
	// ErrInvalidScope lets an authorizer reject requested scopes.
	ErrInvalidScope = errors.New("authservice: invalid exchange scope")
)

// exchangeErrorCode classifies shared exchanger/authorizer failures for both
// transports. An error without an explicit rejection category fails closed as
// an internal error rather than blaming the client for an operational failure.
func exchangeErrorCode(err error) connect.Code {
	switch {
	case errors.Is(err, auth.ErrUnavailable):
		return connect.CodeUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		return connect.CodeDeadlineExceeded
	case errors.Is(err, context.Canceled):
		return connect.CodeCanceled
	}
	var transportErr *connect.Error
	if errors.As(err, &transportErr) {
		return transportErr.Code()
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return connect.CodeUnavailable
	}
	switch {
	case errors.Is(err, credential.ErrInvalid), errors.Is(err, credential.ErrUnsupported):
		return connect.CodeUnauthenticated
	case errors.Is(err, auth.ErrPermissionDenied), errors.Is(err, tokenissuer.ErrPermissionDenied):
		return connect.CodePermissionDenied
	case errors.Is(err, ErrInvalidScope), errors.Is(err, ErrInvalidTarget):
		return connect.CodeInvalidArgument
	default:
		return connect.CodeInternal
	}
}

func writeExchangeFailure(w http.ResponseWriter, err error) {
	switch exchangeErrorCode(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled, connect.CodeResourceExhausted:
		writeExchangeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Token exchange is temporarily unavailable.")
	case connect.CodeUnauthenticated, connect.CodePermissionDenied:
		writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Subject token or exchange is not permitted.")
	case connect.CodeInvalidArgument:
		switch {
		case errors.Is(err, ErrInvalidTarget):
			writeExchangeError(w, http.StatusBadRequest, "invalid_target", "Requested target is not allowed.")
		case errors.Is(err, ErrInvalidScope):
			writeExchangeError(w, http.StatusBadRequest, "invalid_scope", "Requested scope is not allowed.")
		default:
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Exchange request is invalid.")
		}
	default:
		writeExchangeError(w, http.StatusInternalServerError, "server_error", "Unable to complete token exchange.")
	}
}

// exchangeFailure exposes a safe message while retaining the cause for
// errors.Is/errors.As and server-side logging.
type exchangeFailure struct {
	message string
	cause   error
}

func (e *exchangeFailure) Error() string { return e.message }
func (e *exchangeFailure) Unwrap() error { return e.cause }

func connectExchangeFailure(err error) error {
	code := exchangeErrorCode(err)
	message := "Unable to complete credential exchange."
	switch code {
	case connect.CodeUnauthenticated:
		message = "Credential is invalid or unsupported."
	case connect.CodePermissionDenied:
		message = "Credential exchange is not permitted."
	case connect.CodeInvalidArgument:
		message = "Credential exchange request is invalid."
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled, connect.CodeResourceExhausted:
		message = "Credential exchange is temporarily unavailable."
	}
	return connect.NewError(code, &exchangeFailure{message: message, cause: err})
}
