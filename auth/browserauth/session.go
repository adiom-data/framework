package browserauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/adiom-data/framework/auth"
)

const DefaultSessionCookieName = "adiom_auth_session"

// Session stores upstream browser auth state. App authorization is resolved
// when a token is minted, not stored here.
type Session struct {
	ID           string
	Issuer       string
	Subject      string
	RefreshToken string
	Claims       map[string]any
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	RevokedAt    time.Time
}

// SessionStore stores browser auth sessions behind an opaque cookie id.
type SessionStore interface {
	Create(context.Context, Session) (Session, error)
	Get(context.Context, string) (Session, error)
	Update(context.Context, Session) error
	Revoke(context.Context, string) error
}

// SessionCookie configures the browser auth session cookie.
type SessionCookie struct {
	Name     string
	Path     string
	Domain   string
	Secure   bool
	SameSite http.SameSite
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
		Secure:   c.Secure,
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
