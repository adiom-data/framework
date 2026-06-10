package browserauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
)

var (
	errMissingSession = errors.New("browserauth: missing session")
	errInvalidSession = errors.New("browserauth: invalid session")
	errExpiredSession = errors.New("browserauth: expired session")
	errRevokedSession = errors.New("browserauth: revoked session")
	errNotConfigured  = errors.New("browserauth: not configured")
)

const DefaultRefreshLeeway = time.Minute

// SessionRefresher refreshes upstream browser auth state before token minting.
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
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		token, err := e.Mint(r)
		if err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: token})
	})
}

// Mint loads the browser session and mints a final API token.
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
		return "", errInvalidSession
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
			return "", errInvalidSession
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

func statusCode(err error) int {
	if errors.Is(err, errNotConfigured) {
		return http.StatusInternalServerError
	}
	return http.StatusUnauthorized
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
			return e.Refresher.RefreshSession(ctx, locked)
		})
	}
	session, err := e.Refresher.RefreshSession(ctx, session)
	if err != nil {
		return Session{}, err
	}
	if err := e.Store.Update(ctx, session); err != nil {
		return Session{}, err
	}
	return session, nil
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
