package tokenissuer

import (
	"context"
	"errors"

	"connectrpc.com/connect"
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
	if errors.As(err, &connectErr) {
		return err
	}
	switch {
	case errors.Is(err, ErrMissingBearerToken), errors.Is(err, ErrInvalidBearerToken):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, ErrPermissionDenied):
		return connect.NewError(connect.CodePermissionDenied, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
