package browserauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const DefaultStateCookieName = "adiom_auth_state"

// Config configures browser OIDC auth endpoints.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	HTTPClient   *http.Client
	StateStore   StateStore
}

// BrowserAuth manages OIDC browser login and callback flows.
type BrowserAuth struct {
	issuer     string
	provider   *oidc.Provider
	oauth2     oauth2.Config
	stateStore StateStore
}

// Tokens are returned after a successful callback exchange.
type Tokens struct {
	OAuth2Token *oauth2.Token
	IDToken     string
	Claims      map[string]any
}

// Callback handles tokens after a successful OIDC callback.
type Callback func(http.ResponseWriter, *http.Request, Tokens) error

// LoginSession is the browser OAuth state stored between login and callback.
type LoginSession struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
}

// StateStore creates and validates OAuth state and PKCE verifier data.
type StateStore interface {
	NewSession(http.ResponseWriter, *http.Request) (LoginSession, error)
	VerifySession(http.ResponseWriter, *http.Request, string) (LoginSession, error)
}

// CookieStateStore stores OAuth state in an HttpOnly cookie.
type CookieStateStore struct {
	Name     string
	Path     string
	Secure   bool
	SameSite http.SameSite
}

// New discovers an OIDC provider and returns browser auth helpers.
func New(ctx context.Context, cfg Config) (*BrowserAuth, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("browserauth: issuer is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("browserauth: client ID is required")
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, errors.New("browserauth: redirect URL is required")
	}
	providerCtx := ctx
	if providerCtx == nil {
		providerCtx = context.Background()
	}
	if cfg.HTTPClient != nil {
		providerCtx = oidc.ClientContext(providerCtx, cfg.HTTPClient)
	}
	provider, err := oidc.NewProvider(providerCtx, strings.TrimRight(cfg.Issuer, "/"))
	if err != nil {
		return nil, err
	}
	scopes := append([]string{oidc.ScopeOpenID}, cfg.Scopes...)
	if len(cfg.Scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	stateStore := cfg.StateStore
	if stateStore == nil {
		stateStore = CookieStateStore{}
	}
	return &BrowserAuth{
		issuer:   strings.TrimRight(cfg.Issuer, "/"),
		provider: provider,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		stateStore: stateStore,
	}, nil
}

// SessionFromTokens converts a successful callback token set into a browser session.
func (b *BrowserAuth) SessionFromTokens(tokens Tokens) (Session, error) {
	subject, _ := tokens.Claims["sub"].(string)
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return Session{}, errors.New("browserauth: token subject is required")
	}
	refreshToken := ""
	if tokens.OAuth2Token != nil {
		refreshToken = tokens.OAuth2Token.RefreshToken
	}
	return Session{
		Issuer:       b.issuer,
		Subject:      subject,
		RefreshToken: refreshToken,
		Claims:       tokens.Claims,
	}, nil
}

// RefreshSession refreshes upstream OIDC token state for session.
func (b *BrowserAuth) RefreshSession(ctx context.Context, session Session) (Session, error) {
	if strings.TrimSpace(session.RefreshToken) == "" {
		return session, nil
	}
	tokenSource := b.oauth2.TokenSource(ctx, &oauth2.Token{RefreshToken: session.RefreshToken})
	token, err := tokenSource.Token()
	if err != nil {
		return Session{}, err
	}
	if token.RefreshToken != "" {
		session.RefreshToken = token.RefreshToken
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return session, nil
	}
	claims, err := b.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return Session{}, err
	}
	subject, _ := claims["sub"].(string)
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(subject) != session.Subject {
		return Session{}, errors.New("browserauth: refreshed token subject changed")
	}
	session.Claims = claims
	return session, nil
}

// LoginHandler redirects the browser to the OIDC provider.
func (b *BrowserAuth) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := b.stateStore.NewSession(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, b.oauth2.AuthCodeURL(session.State, oauth2.S256ChallengeOption(session.CodeVerifier)), http.StatusFound)
	})
}

// CallbackHandler exchanges the authorization code and invokes callback.
func (b *BrowserAuth) CallbackHandler(callback Callback) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callback == nil {
			http.Error(w, "browserauth: callback is required", http.StatusInternalServerError)
			return
		}
		session, err := b.stateStore.VerifySession(w, r, r.URL.Query().Get("state"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if providerErr := r.URL.Query().Get("error"); providerErr != "" {
			http.Error(w, providerErr, http.StatusBadRequest)
			return
		}
		token, err := b.oauth2.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(session.CodeVerifier))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		rawIDToken, _ := token.Extra("id_token").(string)
		claims := map[string]any{}
		if rawIDToken != "" {
			claims, err = b.verifyIDToken(r.Context(), rawIDToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
		if err := callback(w, r, Tokens{OAuth2Token: token, IDToken: rawIDToken, Claims: claims}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

// OAuth2Config returns a copy of the underlying OAuth2 config.
func (b *BrowserAuth) OAuth2Config() oauth2.Config {
	return b.oauth2
}

func (b *BrowserAuth) verifyIDToken(ctx context.Context, rawIDToken string) (map[string]any, error) {
	verifier := b.provider.Verifier(&oidc.Config{ClientID: b.oauth2.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// NewSession implements StateStore.
func (s CookieStateStore) NewSession(w http.ResponseWriter, _ *http.Request) (LoginSession, error) {
	state, err := randomState()
	if err != nil {
		return LoginSession{}, err
	}
	session := LoginSession{
		State:        state,
		CodeVerifier: oauth2.GenerateVerifier(),
	}
	value, err := encodeSession(session)
	if err != nil {
		return LoginSession{}, err
	}
	http.SetCookie(w, s.cookie(value, 300))
	return session, nil
}

// VerifySession implements StateStore.
func (s CookieStateStore) VerifySession(w http.ResponseWriter, r *http.Request, state string) (LoginSession, error) {
	cookie, err := r.Cookie(s.name())
	if err != nil {
		return LoginSession{}, errors.New("browserauth: missing state")
	}
	http.SetCookie(w, s.cookie("", -1))
	session, err := decodeSession(cookie.Value)
	if err != nil {
		return LoginSession{}, err
	}
	if state == "" || subtle.ConstantTimeCompare([]byte(session.State), []byte(state)) != 1 {
		return LoginSession{}, errors.New("browserauth: invalid state")
	}
	return session, nil
}

func (s CookieStateStore) cookie(value string, maxAge int) *http.Cookie {
	sameSite := s.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	return &http.Cookie{
		Name:     s.name(),
		Value:    value,
		Path:     s.path(),
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: sameSite,
		MaxAge:   maxAge,
	}
}

func (s CookieStateStore) name() string {
	if s.Name != "" {
		return s.Name
	}
	return DefaultStateCookieName
}

func (s CookieStateStore) path() string {
	if s.Path != "" {
		return s.Path
	}
	return "/"
}

func randomState() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func encodeSession(session LoginSession) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeSession(value string) (LoginSession, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return LoginSession{}, errors.New("browserauth: invalid state")
	}
	var session LoginSession
	if err := json.Unmarshal(data, &session); err != nil {
		return LoginSession{}, errors.New("browserauth: invalid state")
	}
	if session.State == "" || session.CodeVerifier == "" {
		return LoginSession{}, errors.New("browserauth: invalid state")
	}
	return session, nil
}
