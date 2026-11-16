package tokenissuer

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
)

// ConnectAuth returns a Connect interceptor that runs authenticator and maps
// auth errors to Connect error codes.
func ConnectAuth(authenticator BearerAuthenticator) connect.Interceptor {
	return connectAuthInterceptor{authenticator: authenticator}
}

type connectAuthInterceptor struct {
	authenticator BearerAuthenticator
}

func (i connectAuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := i.authenticator.Authenticate(ctx, req.Header().Get("Authorization"))
		if err != nil {
			return nil, connectAuthError(err)
		}
		return next(ctx, req)
	}
}

func (i connectAuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i connectAuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := i.authenticator.Authenticate(ctx, conn.RequestHeader().Get("Authorization"))
		if err != nil {
			return connectAuthError(err)
		}
		return next(ctx, conn)
	}
}

func connectAuthError(err error) error {
	if err == nil {
		return nil
	}
	var connectErr *connect.Error
	code := connect.CodeInternal
	switch {
	case errors.Is(err, auth.ErrUnavailable):
		code = connect.CodeUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		code = connect.CodeDeadlineExceeded
	case errors.Is(err, context.Canceled):
		code = connect.CodeCanceled
	case errors.As(err, &connectErr):
		code = connectErr.Code()
	case errors.Is(err, ErrMissingBearerToken), errors.Is(err, ErrInvalidBearerToken):
		code = connect.CodeUnauthenticated
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, auth.ErrPermissionDenied):
		code = connect.CodePermissionDenied
	}
	message := "Unable to authenticate request."
	switch code {
	case connect.CodeUnauthenticated:
		message = "Authentication is required."
	case connect.CodePermissionDenied:
		message = "Request is not permitted."
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled, connect.CodeResourceExhausted:
		message = "Authentication is temporarily unavailable."
	}
	return connect.NewError(code, &safeAuthError{message: message, cause: err})
}

// Retain causes for server-side inspection without copying their messages,
// Connect metadata, or error details into client-facing responses.
type safeAuthError struct {
	message string
	cause   error
}

func (e *safeAuthError) Error() string { return e.message }
func (e *safeAuthError) Unwrap() error { return e.cause }
