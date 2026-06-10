package browserauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/adiom-data/framework/auth"
)

const DefaultSessionCookieName = "auth_session"

// Session stores upstream browser auth state. App authorization is resolved
// when a token is minted, not stored here.
type Session struct {
	ID           string
	Issuer       string
	Subject      string
	RefreshToken string
	Claims       map[string]any
	ExpiresAt    time.Time
	// UpstreamExpiresAt is the expiration of the upstream OIDC token state.
	// It is separate from ExpiresAt, which is this browser session's lifetime.
	UpstreamExpiresAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	RevokedAt         time.Time
}

// SessionStore stores browser auth sessions behind an opaque cookie id.
type SessionStore interface {
	Create(context.Context, Session) (Session, error)
	Get(context.Context, string) (Session, error)
	Update(context.Context, Session) error
	Revoke(context.Context, string) error
}

// SessionUpdateStore updates a session while holding any store-specific lock.
// Stores that support refresh-token rotation should implement this to prevent
// concurrent refresh requests from overwriting each other.
type SessionUpdateStore interface {
	UpdateSession(context.Context, string, func(Session) (Session, error)) (Session, error)
}

// SessionCookie configures the browser auth session cookie.
type SessionCookie struct {
	Name     string
	Path     string
	Domain   string
	Insecure bool
	SameSite http.SameSite
}

// NewSessionID returns an opaque random browser session id.
func NewSessionID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ExternalIdentity returns the verified upstream identity represented by s.
func (s Session) ExternalIdentity() (auth.ExternalIdentity, error) {
	if strings.TrimSpace(s.Issuer) == "" {
		return auth.ExternalIdentity{}, errors.New("browserauth: session issuer is required")
	}
	if strings.TrimSpace(s.Subject) == "" {
		return auth.ExternalIdentity{}, errors.New("browserauth: session subject is required")
	}
	return auth.ExternalIdentity{
		Issuer:  s.Issuer,
		Subject: s.Subject,
		Claims:  s.Claims,
	}, nil
}

// Set writes sessionID to the response cookie.
func (c SessionCookie) Set(w http.ResponseWriter, sessionID string, expires time.Time) {
	http.SetCookie(w, c.cookie(sessionID, expires, 0))
}

// Clear removes the session cookie.
func (c SessionCookie) Clear(w http.ResponseWriter) {
	http.SetCookie(w, c.cookie("", time.Time{}, -1))
}

// Get reads the session id from the request cookie.
func (c SessionCookie) Get(r *http.Request) (string, error) {
	cookie, err := r.Cookie(c.name())
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(cookie.Value)
	if id == "" {
		return "", http.ErrNoCookie
	}
	return id, nil
}

func (c SessionCookie) cookie(value string, expires time.Time, maxAge int) *http.Cookie {
	sameSite := c.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	cookie := &http.Cookie{
		Name:     c.name(),
		Value:    value,
		Path:     c.path(),
		Domain:   c.Domain,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: sameSite,
		MaxAge:   maxAge,
	}
	if !expires.IsZero() {
		cookie.Expires = expires
	}
	return cookie
}

func (c SessionCookie) name() string {
	if c.Name != "" {
		return c.Name
	}
	return DefaultSessionCookieName
}

func (c SessionCookie) path() string {
	if c.Path != "" {
		return c.Path
	}
	return "/"
}

func (c SessionCookie) withDefaultPath(path string) SessionCookie {
	if c.Path != "" {
		return c
	}
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	c.Path = strings.TrimRight(path, "/")
	if c.Path == "" {
		c.Path = "/"
	}
	return c
}
