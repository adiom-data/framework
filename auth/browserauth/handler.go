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

	SuccessRedirect string
	LogoutRedirect  string
	Now             func() time.Time
}

// Handler returns a composed browser auth handler with /login, /callback,
// /token, and /logout routes relative to its mount point.
func (b *BrowserAuth) Handler(cfg HandlerConfig) http.Handler {
	cfg.Cookie = cfg.Cookie.withDefaultPath(cfg.BasePath)
	mux := http.NewServeMux()
	mux.Handle("/login", b.LoginHandler())
	mux.Handle("/callback", b.CallbackHandler(b.sessionCallback(cfg)))
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
		Store:    cfg.Store,
		Cookie:   cfg.Cookie,
		Redirect: cfg.LogoutRedirect,
	}.Handler())
	if cfg.Issuer != nil {
		mux.Handle("/.well-known/openid-configuration", cfg.Issuer.MetadataHandler())
		mux.Handle("/.well-known/jwks.json", cfg.Issuer.JWKSHandler())
	}
	return mux
}

func (b *BrowserAuth) sessionCallback(cfg HandlerConfig) Callback {
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
	Store    SessionStore
	Cookie   SessionCookie
	Redirect string
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
		if strings.TrimSpace(h.Redirect) != "" {
			http.Redirect(w, r, h.Redirect, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

var _ SessionRefresher = (*BrowserAuth)(nil)
