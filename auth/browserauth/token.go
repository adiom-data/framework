package browserauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
	"golang.org/x/oauth2"
)

// ErrInvalidSession marks a missing or unusable session, including rejected
// refresh credentials. Custom stores and refreshers may wrap this error to
// require a new login. Preserve operational errors instead, or wrap
// auth.ErrUnavailable when a dependency is temporarily unavailable.
var ErrInvalidSession = errors.New("browserauth: invalid session")

var (
	errMissingSession = fmt.Errorf("%w: missing session", ErrInvalidSession)
	errExpiredSession = fmt.Errorf("%w: expired session", ErrInvalidSession)
	errRevokedSession = fmt.Errorf("%w: revoked session", ErrInvalidSession)
	errNotConfigured  = errors.New("browserauth: not configured")
)

const DefaultRefreshLeeway = time.Minute

// SessionRefresher refreshes upstream browser auth state before token minting.
// Return or wrap ErrInvalidSession for rejected credentials. Preserve other
// failures, or wrap auth.ErrUnavailable to mark a temporary dependency failure.
type SessionRefresher interface {
	RefreshSession(context.Context, Session) (Session, error)
}

// TokenEndpoint mints final API tokens from browser auth sessions.
type TokenEndpoint struct {
	Store         SessionStore
	Cookie        SessionCookie
	Refresher     SessionRefresher
	RefreshLeeway time.Duration
	Authorizer    auth.Authorizer
	Issuer        *tokenissuer.Issuer
	Now           func() time.Time
}

// TokenResponse is returned by TokenEndpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

// Handler returns an HTTP handler suitable for /auth/token.
func (e TokenEndpoint) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		token, err := e.Mint(r)
		if err != nil {
			status := TokenErrorStatus(err)
			if status >= 500 {
				slog.ErrorContext(r.Context(), "browserauth: token issuance failed", "error", err)
			}
			http.Error(w, tokenErrorMessage(status), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: token})
	})
}

// Mint loads the browser session and mints a final API token. TokenErrorStatus
// classifies returned errors for custom HTTP handlers; causes remain available
// through errors.Is/errors.As. Do not return error text directly to clients.
func (e TokenEndpoint) Mint(r *http.Request) (string, error) {
	if e.Store == nil {
		return "", errors.Join(errNotConfigured, errors.New("session store is not configured"))
	}
	if e.Authorizer == nil {
		return "", errors.Join(errNotConfigured, errors.New("authorizer is not configured"))
	}
	if e.Issuer == nil {
		return "", errors.Join(errNotConfigured, errors.New("token issuer is not configured"))
	}
	sessionID, err := e.Cookie.Get(r)
	if err != nil {
		return "", errMissingSession
	}
	session, err := e.Store.Get(r.Context(), sessionID)
	if err != nil {
		return "", fmt.Errorf("browserauth: load session: %w", err)
	}
	now := e.now()
	if !session.RevokedAt.IsZero() {
		return "", errRevokedSession
	}
	if !session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt) {
		return "", errExpiredSession
	}
	if e.shouldRefresh(session, now) {
		session, err = e.refreshSession(r.Context(), session)
		if err != nil {
			return "", fmt.Errorf("browserauth: refresh session: %w", err)
		}
	}
	external, err := session.ExternalIdentity()
	if err != nil {
		return "", err
	}
	identity, err := e.Authorizer.Authorize(r.Context(), external)
	if err != nil {
		return "", err
	}
	token, _, err := e.Issuer.Mint(r.Context(), identity)
	return token, err
}

// TokenErrorStatus maps errors from TokenEndpoint.Mint to HTTP status codes.
// It returns 200 for nil, 401 for missing or invalid sessions, 403 for explicit
// permission denials, 503 for temporary dependency failures, and 500 for other
// errors. Temporary failures take precedence over session-rejection markers.
// The status does not expose error details or establish whether an arbitrary
// server error is safe to retry. Callers must use their own generic messages.
func TokenErrorStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, auth.ErrUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return http.StatusServiceUnavailable
	}
	var providerErr *oauth2.RetrieveError
	if errors.As(err, &providerErr) {
		if providerErr.Response != nil {
			status := providerErr.Response.StatusCode
			if status == http.StatusTooManyRequests || status >= 500 && status <= 599 {
				return http.StatusServiceUnavailable
			}
		}
		if providerErr.ErrorCode == "temporarily_unavailable" || providerErr.ErrorCode == "server_error" {
			return http.StatusServiceUnavailable
		}
	}
	switch {
	case errors.Is(err, errNotConfigured):
		return http.StatusInternalServerError
	case errors.Is(err, auth.ErrPermissionDenied), errors.Is(err, tokenissuer.ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, ErrInvalidSession):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func tokenErrorMessage(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "Authentication is required."
	case http.StatusForbidden:
		return "Token issuance is not permitted."
	case http.StatusServiceUnavailable:
		return "Authentication is temporarily unavailable."
	default:
		return "Unable to issue access token."
	}
}

func (e TokenEndpoint) refreshSession(ctx context.Context, session Session) (Session, error) {
	if store, ok := e.Store.(SessionUpdateStore); ok {
		return store.UpdateSession(ctx, session.ID, func(locked Session) (Session, error) {
			now := e.now()
			if !locked.RevokedAt.IsZero() {
				return Session{}, errRevokedSession
			}
			if !locked.ExpiresAt.IsZero() && !now.Before(locked.ExpiresAt) {
				return Session{}, errExpiredSession
			}
			if !e.shouldRefresh(locked, now) {
				return locked, nil
			}
			refreshed, err := e.Refresher.RefreshSession(ctx, locked)
			return refreshed, refreshCredentialError(err)
		})
	}
	session, err := e.Refresher.RefreshSession(ctx, session)
	if err != nil {
		return Session{}, refreshCredentialError(err)
	}
	if err := e.Store.Update(ctx, session); err != nil {
		return Session{}, err
	}
	return session, nil
}

// OAuth invalid_grant rejects the refresh credential, not the application's
// client configuration. Other provider failures retain their original category.
func refreshCredentialError(err error) error {
	if err == nil || errors.Is(err, ErrInvalidSession) {
		return err
	}
	var providerErr *oauth2.RetrieveError
	if errors.As(err, &providerErr) && providerErr.ErrorCode == "invalid_grant" {
		return fmt.Errorf("%w: %w", ErrInvalidSession, err)
	}
	return err
}

func (e TokenEndpoint) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e TokenEndpoint) shouldRefresh(session Session, now time.Time) bool {
	if e.Refresher == nil {
		return false
	}
	if session.UpstreamExpiresAt.IsZero() {
		return true
	}
	return !now.Add(e.refreshLeeway()).Before(session.UpstreamExpiresAt)
}

func (e TokenEndpoint) refreshLeeway() time.Duration {
	if e.RefreshLeeway < 0 {
		return 0
	}
	if e.RefreshLeeway > 0 {
		return e.RefreshLeeway
	}
	return DefaultRefreshLeeway
}
