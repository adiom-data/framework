package browserauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
)

const DefaultSessionTTL = 24 * time.Hour

// HandlerConfig configures a mounted browser auth handler.
type HandlerConfig struct {
	BasePath string

	Store         SessionStore
	Cookie        SessionCookie
	Authorizer    auth.Authorizer
	Issuer        *tokenissuer.Issuer
	Refresher     SessionRefresher
	RefreshLeeway time.Duration
	SessionTTL    time.Duration
	// BeforeCreate runs application checks and may attach trusted metadata.
	// An error prevents creation of the session and its cookie.
	// Return or wrap auth.ErrPermissionDenied for a safe HTTP 403 response.
	BeforeCreate func(*http.Request, Tokens, *Session) error

	SuccessRedirect     string
	LogoutRedirect      string
	LogoutRedirectFunc  LogoutRedirectFunc
	InvalidStateHandler InvalidStateHandler
	Now                 func() time.Time
}

// SessionCallbackConfig configures completion of a verified browser login.
type SessionCallbackConfig struct {
	Store           SessionStore
	Cookie          SessionCookie
	BasePath        string
	SessionTTL      time.Duration
	SuccessRedirect string
	Now             func() time.Time
	// BeforeCreate runs after session construction and lifetime defaults, but
	// before persistence, setting the session cookie, or redirecting. It may
	// reject login or attach application-owned metadata. It must not write a
	// response. Return or wrap auth.ErrPermissionDenied for HTTP 403; other
	// errors produce HTTP 500. CallbackHandler keeps error details private.
	BeforeCreate func(*http.Request, Tokens, *Session) error
}

// LogoutRedirectFunc resolves where logout should redirect after the local
// browser session has been revoked and its cookie has been cleared.
type LogoutRedirectFunc func(*http.Request) (string, error)

// Handler returns a composed browser auth handler with /login, /callback,
// /token, and /logout routes relative to its mount point.
func (b *BrowserAuth) Handler(cfg HandlerConfig) http.Handler {
	cfg.Cookie = cfg.Cookie.withDefaultPath(cfg.BasePath)
	mux := http.NewServeMux()
	mux.Handle("/login", b.loginHandler(PublicRedirectURL(callbackPath(cfg.BasePath))))
	mux.Handle("/callback", b.CallbackHandlerWithConfig(CallbackHandlerConfig{
		Callback: b.SessionCallback(SessionCallbackConfig{
			Store: cfg.Store, Cookie: cfg.Cookie, BasePath: cfg.BasePath,
			SessionTTL: cfg.SessionTTL, SuccessRedirect: cfg.SuccessRedirect,
			Now: cfg.Now, BeforeCreate: cfg.BeforeCreate,
		}),
		InvalidStateHandler: cfg.InvalidStateHandler,
	}))
	mux.Handle("/token", TokenEndpoint{
		Store:         cfg.Store,
		Cookie:        cfg.Cookie,
		Refresher:     cfg.Refresher,
		RefreshLeeway: cfg.RefreshLeeway,
		Authorizer:    cfg.Authorizer,
		Issuer:        cfg.Issuer,
		Now:           cfg.Now,
	}.Handler())
	mux.Handle("/logout", LogoutHandler{
		Store:        cfg.Store,
		Cookie:       cfg.Cookie,
		Redirect:     cfg.LogoutRedirect,
		RedirectFunc: cfg.LogoutRedirectFunc,
	}.Handler())
	if cfg.Issuer != nil {
		mux.Handle("/.well-known/openid-configuration", cfg.Issuer.MetadataHandler())
		mux.Handle("/.well-known/jwks.json", cfg.Issuer.JWKSHandler())
	}
	return mux
}

func callbackPath(basePath string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		return "/callback"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	basePath = strings.TrimRight(basePath, "/")
	if basePath == "" {
		return "/callback"
	}
	return basePath + "/callback"
}

// SessionCallback returns a reusable create-session, set-cookie, redirect
// callback. Pass it to CallbackHandler (which verifies OAuth state and tokens),
// or invoke it from a custom callback after its application checks. Tokens must
// come from a successful, verified OIDC callback.
func (b *BrowserAuth) SessionCallback(cfg SessionCallbackConfig) Callback {
	cfg.Cookie = cfg.Cookie.withDefaultPath(cfg.BasePath)
	return func(w http.ResponseWriter, r *http.Request, tokens Tokens) error {
		if cfg.Store == nil {
			return errors.New("browserauth: session store is not configured")
		}
		session, err := b.SessionFromTokens(tokens)
		if err != nil {
			return err
		}
		now := time.Now()
		if cfg.Now != nil {
			now = cfg.Now()
		}
		ttl := cfg.SessionTTL
		if ttl <= 0 {
			ttl = DefaultSessionTTL
		}
		session.ExpiresAt = now.Add(ttl)
		if cfg.BeforeCreate != nil {
			if err := cfg.BeforeCreate(r, tokens, &session); err != nil {
				return err
			}
		}
		session, err = cfg.Store.Create(r.Context(), session)
		if err != nil {
			return err
		}
		cfg.Cookie.Set(w, session.ID, session.ExpiresAt)
		redirect := strings.TrimSpace(cfg.SuccessRedirect)
		if redirect == "" {
			redirect = "/"
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return nil
	}
}

// LogoutHandler revokes the current browser session and clears the session cookie.
type LogoutHandler struct {
	Store        SessionStore
	Cookie       SessionCookie
	Redirect     string
	RedirectFunc LogoutRedirectFunc
}

// Handler returns an HTTP logout handler.
func (h LogoutHandler) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if h.Store != nil {
			if sessionID, err := h.Cookie.Get(r); err == nil {
				_ = h.Store.Revoke(r.Context(), sessionID)
			}
		}
		h.Cookie.Clear(w)
		if h.RedirectFunc != nil {
			redirect, err := h.RedirectFunc(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if strings.TrimSpace(redirect) != "" {
				http.Redirect(w, r, redirect, http.StatusFound)
				return
			}
		}
		if strings.TrimSpace(h.Redirect) != "" {
			http.Redirect(w, r, h.Redirect, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

var _ SessionRefresher = (*BrowserAuth)(nil)
