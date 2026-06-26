package browserauth

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/adiom-data/framework/httputil"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

const DefaultStateCookieName = "auth_state"

const (
	CookieStateSeedSize     = 32
	CookieStateHashKeySize  = 64
	CookieStateBlockKeySize = 32
)

var (
	ErrMissingState = errors.New("browserauth: missing state")
	ErrInvalidState = errors.New("browserauth: invalid state")
)

// Config configures browser OIDC auth endpoints.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is the OIDC callback URL for normal auth flows. When
	// ProxyRedirectURL is set, RedirectURL is instead the final app callback URL
	// that the proxy should forward back to.
	RedirectURL string
	// ProxyRedirectURL is the stable OIDC callback URL sent to the provider.
	// Use this for dynamic app hosts that receive callbacks through a simple
	// forwarding proxy.
	ProxyRedirectURL string
	// RedirectURLResolver resolves the OIDC callback URL for each request.
	// It overrides RedirectURL when set. When ProxyRedirectURL is set, it
	// resolves the final app callback URL encoded into state.
	RedirectURLResolver RedirectURLResolver
	Scopes              []string
	// AuthCodeOptions are added to the provider authorization redirect.
	// Use this for provider-specific parameters such as Google offline access.
	AuthCodeOptions []oauth2.AuthCodeOption
	HTTPClient      *http.Client
	StateStore      StateStore
	StateKeys       CookieStateKeys
}

// BrowserAuth manages OIDC browser login and callback flows.
type BrowserAuth struct {
	issuer           string
	provider         *oidc.Provider
	oauth2           oauth2.Config
	redirectURL      RedirectURLResolver
	appRedirectURL   string
	proxyRedirectURL string
	endSessionURL    string
	stateStore       StateStore
	authCodeOptions  []oauth2.AuthCodeOption
}

// Tokens are returned after a successful callback exchange.
type Tokens struct {
	OAuth2Token *oauth2.Token
	IDToken     string
	Claims      map[string]any
}

// Callback handles tokens after a successful OIDC callback.
type Callback func(http.ResponseWriter, *http.Request, Tokens) error

// RedirectURLResolver resolves the OIDC callback URL for a request.
type RedirectURLResolver func(*http.Request) (string, error)

// InvalidStateHandler handles rejected callback state.
type InvalidStateHandler func(http.ResponseWriter, *http.Request, error)

// CallbackHandlerConfig configures callback handling.
type CallbackHandlerConfig struct {
	Callback            Callback
	InvalidStateHandler InvalidStateHandler
}

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

// ReturnToStateStore creates OAuth state that carries a proxy return URL.
type ReturnToStateStore interface {
	StateStore
	NewSessionWithReturnTo(http.ResponseWriter, *http.Request, string) (LoginSession, error)
}

// CookieStateKeys configures stable keys for signed and encrypted OAuth state.
type CookieStateKeys struct {
	HashKey  []byte
	BlockKey []byte
}

// GenerateCookieStateSeed returns a new seed for deriving stable OAuth state keys.
func GenerateCookieStateSeed() ([]byte, error) {
	return randomBytes(CookieStateSeedSize)
}

// GenerateCookieStateSeedSecret returns a new base64 seed for secret/config storage.
func GenerateCookieStateSeedSecret() (string, error) {
	seed, err := GenerateCookieStateSeed()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(seed), nil
}

// CookieStateKeysFromSeed derives stable signed and encrypted OAuth state keys from seed.
func CookieStateKeysFromSeed(seed []byte) (CookieStateKeys, error) {
	if len(seed) < CookieStateSeedSize {
		return CookieStateKeys{}, errors.New("browserauth: state seed must be at least 32 bytes")
	}
	keyMaterial, err := hkdf.Key(sha256.New, seed, nil, "github.com/adiom-data/framework/auth/browserauth/cookie-state/v1", CookieStateHashKeySize+CookieStateBlockKeySize)
	if err != nil {
		return CookieStateKeys{}, err
	}
	keys := CookieStateKeys{
		HashKey:  append([]byte(nil), keyMaterial[:CookieStateHashKeySize]...),
		BlockKey: append([]byte(nil), keyMaterial[CookieStateHashKeySize:]...),
	}
	if err := keys.validate(); err != nil {
		return CookieStateKeys{}, err
	}
	return keys, nil
}

// CookieStateKeysFromSeedBase64 derives stable OAuth state keys from a base64 seed.
func CookieStateKeysFromSeedBase64(seed string) (CookieStateKeys, error) {
	decoded, err := decodeBase64Secret(seed, "state seed")
	if err != nil {
		return CookieStateKeys{}, err
	}
	return CookieStateKeysFromSeed(decoded)
}

// GenerateCookieStateKeys returns new stable keys for signed and encrypted OAuth state.
func GenerateCookieStateKeys() (CookieStateKeys, error) {
	hashKey, err := randomBytes(CookieStateHashKeySize)
	if err != nil {
		return CookieStateKeys{}, err
	}
	blockKey, err := randomBytes(CookieStateBlockKeySize)
	if err != nil {
		return CookieStateKeys{}, err
	}
	return CookieStateKeys{HashKey: hashKey, BlockKey: blockKey}, nil
}

// GenerateCookieStateKeySecrets returns new base64 secrets for state key config.
func GenerateCookieStateKeySecrets() (hashKeyBase64 string, blockKeyBase64 string, err error) {
	keys, err := GenerateCookieStateKeys()
	if err != nil {
		return "", "", err
	}
	hashKeyBase64, blockKeyBase64 = keys.EncodeBase64()
	return hashKeyBase64, blockKeyBase64, nil
}

// EncodeBase64 encodes stable state keys for secret/config storage.
func (k CookieStateKeys) EncodeBase64() (hashKeyBase64 string, blockKeyBase64 string) {
	return base64.StdEncoding.EncodeToString(k.HashKey), base64.StdEncoding.EncodeToString(k.BlockKey)
}

// CookieStateKeysFromBase64 decodes stable state keys from base64 strings.
func CookieStateKeysFromBase64(hashKey, blockKey string) (CookieStateKeys, error) {
	hash, err := decodeBase64Secret(hashKey, "state key")
	if err != nil {
		return CookieStateKeys{}, err
	}
	block, err := decodeBase64Secret(blockKey, "state key")
	if err != nil {
		return CookieStateKeys{}, err
	}
	keys := CookieStateKeys{HashKey: hash, BlockKey: block}
	if err := keys.validate(); err != nil {
		return CookieStateKeys{}, err
	}
	return keys, nil
}

// CookieStateStore stores OAuth state in an HttpOnly cookie.
type CookieStateStore struct {
	Name     string
	Path     string
	Insecure bool
	SameSite http.SameSite
	Keys     CookieStateKeys
	// Codecs overrides Keys for advanced callers that need custom securecookie codecs.
	Codecs []securecookie.Codec
}

// ProxyCallbackForwarderConfig configures a callback trampoline that forwards
// provider callbacks from a stable proxy URL back to the app callback URL
// encoded in OAuth state.
type ProxyCallbackForwarderConfig struct {
	ReturnToValidator func(string) bool
}

type proxyState struct {
	State    string `json:"state"`
	ReturnTo string `json:"return_to"`
}

// New discovers an OIDC provider and returns browser auth helpers.
func New(ctx context.Context, cfg Config) (*BrowserAuth, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("browserauth: issuer is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("browserauth: client ID is required")
	}
	redirectURL := strings.TrimSpace(cfg.RedirectURL)
	proxyRedirectURL := strings.TrimSpace(cfg.ProxyRedirectURL)
	if redirectURL == "" && cfg.RedirectURLResolver == nil && proxyRedirectURL == "" {
		return nil, errors.New("browserauth: redirect URL is required")
	}
	if redirectURL != "" {
		validRedirectURL, err := validateRedirectURL(redirectURL)
		if err != nil {
			return nil, err
		}
		redirectURL = validRedirectURL
	}
	if proxyRedirectURL != "" {
		validProxyRedirectURL, err := validateRedirectURL(proxyRedirectURL)
		if err != nil {
			return nil, err
		}
		proxyRedirectURL = validProxyRedirectURL
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
	var metadata struct {
		EndSessionURL string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, err
	}
	scopes := append([]string{oidc.ScopeOpenID}, cfg.Scopes...)
	if len(cfg.Scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	stateStore := cfg.StateStore
	if stateStore == nil {
		stateStore = CookieStateStore{Keys: cfg.StateKeys}
	}
	if proxyRedirectURL != "" {
		if _, ok := stateStore.(ReturnToStateStore); !ok {
			return nil, errors.New("browserauth: state store does not support proxy return URLs")
		}
	}
	providerRedirectURL := redirectURL
	if proxyRedirectURL != "" {
		providerRedirectURL = proxyRedirectURL
	}
	return &BrowserAuth{
		issuer:   strings.TrimRight(cfg.Issuer, "/"),
		provider: provider,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  providerRedirectURL,
			Scopes:       scopes,
		},
		endSessionURL:    strings.TrimSpace(metadata.EndSessionURL),
		redirectURL:      cfg.RedirectURLResolver,
		appRedirectURL:   redirectURL,
		proxyRedirectURL: proxyRedirectURL,
		stateStore:       stateStore,
		authCodeOptions:  append([]oauth2.AuthCodeOption(nil), cfg.AuthCodeOptions...),
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
	upstreamExpiresAt := time.Time{}
	if tokens.OAuth2Token != nil {
		refreshToken = tokens.OAuth2Token.RefreshToken
		upstreamExpiresAt = tokens.OAuth2Token.Expiry
	}
	return Session{
		Issuer:            b.issuer,
		Subject:           subject,
		RefreshToken:      refreshToken,
		Claims:            tokens.Claims,
		UpstreamExpiresAt: upstreamExpiresAt,
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
	session.UpstreamExpiresAt = token.Expiry
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
	return b.loginHandler(nil)
}

func (b *BrowserAuth) loginHandler(proxyReturnURL RedirectURLResolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauth2Config, err := b.oauth2Config(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session, err := b.newLoginSession(w, r, proxyReturnURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		options := append([]oauth2.AuthCodeOption{}, b.authCodeOptions...)
		options = append(options, oauth2.S256ChallengeOption(session.CodeVerifier))
		http.Redirect(w, r, oauth2Config.AuthCodeURL(session.State, options...), http.StatusFound)
	})
}

func (b *BrowserAuth) newLoginSession(w http.ResponseWriter, r *http.Request, proxyReturnURL RedirectURLResolver) (LoginSession, error) {
	if strings.TrimSpace(b.proxyRedirectURL) == "" {
		return b.stateStore.NewSession(w, r)
	}
	returnTo, err := b.proxyReturnURL(r, proxyReturnURL)
	if err != nil {
		return LoginSession{}, err
	}
	store, ok := b.stateStore.(ReturnToStateStore)
	if !ok {
		return LoginSession{}, errors.New("browserauth: state store does not support proxy return URLs")
	}
	return store.NewSessionWithReturnTo(w, r, returnTo)
}

func (b *BrowserAuth) proxyReturnURL(r *http.Request, override RedirectURLResolver) (string, error) {
	if b.redirectURL != nil {
		return b.redirectURL(r)
	}
	if strings.TrimSpace(b.appRedirectURL) != "" {
		return b.appRedirectURL, nil
	}
	if override != nil {
		return override(r)
	}
	return inferCallbackURL(r)
}

// CallbackHandler exchanges the authorization code and invokes callback.
func (b *BrowserAuth) CallbackHandler(callback Callback) http.Handler {
	return b.CallbackHandlerWithConfig(CallbackHandlerConfig{Callback: callback})
}

// CallbackHandlerWithConfig exchanges the authorization code and invokes callback.
func (b *BrowserAuth) CallbackHandlerWithConfig(cfg CallbackHandlerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback := cfg.Callback
		if callback == nil {
			http.Error(w, "browserauth: callback is required", http.StatusInternalServerError)
			return
		}
		session, err := b.stateStore.VerifySession(w, r, r.URL.Query().Get("state"))
		if err != nil {
			if cfg.InvalidStateHandler != nil {
				cfg.InvalidStateHandler(w, r, err)
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}
		if providerErr := r.URL.Query().Get("error"); providerErr != "" {
			http.Error(w, providerErr, http.StatusBadRequest)
			return
		}
		oauth2Config, err := b.oauth2Config(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(session.CodeVerifier))
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

// RedirectInvalidState redirects callbacks with missing, stale, or tampered state.
func RedirectInvalidState(location string) InvalidStateHandler {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		redirect := strings.TrimSpace(location)
		if redirect == "" {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

// PublicRedirectURL resolves callbackPath against the request's public base URL.
func PublicRedirectURL(callbackPath string) RedirectURLResolver {
	return func(r *http.Request) (string, error) {
		return publicURL(r, callbackPath, "callback path")
	}
}

// ProxyCallbackForwarder returns a handler for a stable callback proxy. It
// extracts the app callback URL from OAuth state and forwards the original
// provider callback query to that URL.
func ProxyCallbackForwarder(cfg ProxyCallbackForwarderConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		returnTo, err := ProxyStateReturnTo(r.URL.Query().Get("state"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if cfg.ReturnToValidator != nil && !cfg.ReturnToValidator(returnTo) {
			http.Error(w, "browserauth: proxy return URL is not allowed", http.StatusBadRequest)
			return
		}
		redirect, err := validateRedirectURL(returnTo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		redirect = appendRawQuery(redirect, r.URL.RawQuery)
		http.Redirect(w, r, redirect, http.StatusFound)
	})
}

// ProxyStateReturnTo extracts the app callback URL from proxy-mode OAuth state.
func ProxyStateReturnTo(state string) (string, error) {
	payload, err := decodeProxyState(state)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.ReturnTo) == "" {
		return "", errors.New("browserauth: proxy return URL is required")
	}
	return payload.ReturnTo, nil
}

// EndSessionLogoutRedirect redirects logout through the provider end-session endpoint.
func (b *BrowserAuth) EndSessionLogoutRedirect(postLogoutRedirectURI string) LogoutRedirectFunc {
	return func(*http.Request) (string, error) {
		return b.endSessionRedirect(strings.TrimSpace(postLogoutRedirectURI))
	}
}

// PublicEndSessionLogoutRedirect resolves postLogoutPath against the request's public base URL.
func (b *BrowserAuth) PublicEndSessionLogoutRedirect(postLogoutPath string) LogoutRedirectFunc {
	return func(r *http.Request) (string, error) {
		postLogoutRedirectURI, err := publicURL(r, postLogoutPath, "post logout path")
		if err != nil {
			return "", err
		}
		return b.endSessionRedirect(postLogoutRedirectURI)
	}
}

// OAuth2Config returns a copy of the underlying OAuth2 config.
func (b *BrowserAuth) OAuth2Config() oauth2.Config {
	return b.oauth2
}

func (b *BrowserAuth) oauth2Config(r *http.Request) (oauth2.Config, error) {
	cfg := b.oauth2
	if strings.TrimSpace(b.proxyRedirectURL) != "" {
		cfg.RedirectURL = b.proxyRedirectURL
		return cfg, nil
	}
	if b.redirectURL != nil {
		redirectURL, err := b.redirectURL(r)
		if err != nil {
			return oauth2.Config{}, err
		}
		redirectURL, err = validateRedirectURL(redirectURL)
		if err != nil {
			return oauth2.Config{}, err
		}
		cfg.RedirectURL = redirectURL
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return oauth2.Config{}, errors.New("browserauth: redirect URL is required")
	}
	return cfg, nil
}

func validateRedirectURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("browserauth: redirect URL is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("browserauth: redirect URL must be absolute")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("browserauth: redirect URL must use http or https")
	}
	if parsed.Fragment != "" {
		return "", errors.New("browserauth: redirect URL must not include a fragment")
	}
	return value, nil
}

func publicURL(r *http.Request, path string, label string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("browserauth: %s must start with /", label)
	}
	baseURL := httputil.PublicBaseURL(r)
	if baseURL == "" {
		return "", errors.New("browserauth: public base URL is required")
	}
	return validateRedirectURL(strings.TrimRight(baseURL, "/") + path)
}

func inferCallbackURL(r *http.Request) (string, error) {
	if r == nil {
		return "", errors.New("browserauth: request is required")
	}
	path := strings.TrimSpace(r.URL.Path)
	if path == "" || path == "/" {
		path = "/callback"
	} else if strings.HasSuffix(path, "/login") {
		path = strings.TrimSuffix(path, "/login") + "/callback"
	}
	return publicURL(r, path, "callback path")
}

func appendRawQuery(rawURL string, rawQuery string) string {
	if strings.TrimSpace(rawQuery) == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if parsed.RawQuery == "" {
		parsed.RawQuery = rawQuery
	} else {
		parsed.RawQuery += "&" + rawQuery
	}
	return parsed.String()
}

func (b *BrowserAuth) endSessionRedirect(postLogoutRedirectURI string) (string, error) {
	endSessionURL := strings.TrimSpace(b.endSessionURL)
	if endSessionURL == "" {
		return postLogoutRedirectURI, nil
	}
	parsed, err := url.Parse(endSessionURL)
	if err != nil {
		return "", err
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("browserauth: end session endpoint must be absolute")
	}
	query := parsed.Query()
	if strings.TrimSpace(b.oauth2.ClientID) != "" {
		query.Set("client_id", b.oauth2.ClientID)
	}
	if postLogoutRedirectURI != "" {
		postLogoutRedirectURI, err = validateRedirectURL(postLogoutRedirectURI)
		if err != nil {
			return "", err
		}
		query.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
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
	value, err := s.encodeSession(session)
	if err != nil {
		return LoginSession{}, err
	}
	http.SetCookie(w, s.cookie(value, 300))
	return session, nil
}

// NewSessionWithReturnTo implements ReturnToStateStore.
func (s CookieStateStore) NewSessionWithReturnTo(w http.ResponseWriter, _ *http.Request, returnTo string) (LoginSession, error) {
	state, err := randomState()
	if err != nil {
		return LoginSession{}, err
	}
	returnTo, err = validateRedirectURL(returnTo)
	if err != nil {
		return LoginSession{}, err
	}
	encodedState, err := encodeProxyState(proxyState{State: state, ReturnTo: returnTo})
	if err != nil {
		return LoginSession{}, err
	}
	session := LoginSession{
		State:        encodedState,
		CodeVerifier: oauth2.GenerateVerifier(),
	}
	value, err := s.encodeSession(session)
	if err != nil {
		return LoginSession{}, err
	}
	http.SetCookie(w, s.cookie(value, 300))
	return session, nil
}

// VerifySession implements StateStore.
func (s CookieStateStore) VerifySession(w http.ResponseWriter, r *http.Request, state string) (LoginSession, error) {
	http.SetCookie(w, s.cookie("", -1))
	cookie, err := r.Cookie(s.name())
	if err != nil {
		return LoginSession{}, ErrMissingState
	}
	session, err := s.decodeSession(cookie.Value)
	if err != nil {
		return LoginSession{}, err
	}
	if state == "" || subtle.ConstantTimeCompare([]byte(session.State), []byte(state)) != 1 {
		return LoginSession{}, ErrInvalidState
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
		Secure:   !s.Insecure,
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

func encodeProxyState(state proxyState) (string, error) {
	if strings.TrimSpace(state.State) == "" {
		return "", errors.New("browserauth: proxy state nonce is required")
	}
	if strings.TrimSpace(state.ReturnTo) == "" {
		return "", errors.New("browserauth: proxy return URL is required")
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeProxyState(state string) (proxyState, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return proxyState{}, ErrMissingState
	}
	payload, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return proxyState{}, ErrInvalidState
	}
	var decoded proxyState
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return proxyState{}, ErrInvalidState
	}
	if strings.TrimSpace(decoded.State) == "" {
		return proxyState{}, ErrInvalidState
	}
	return decoded, nil
}

func (s CookieStateStore) encodeSession(session LoginSession) (string, error) {
	codecs, err := s.codecs()
	if err != nil {
		return "", err
	}
	return securecookie.EncodeMulti(s.name(), session, codecs...)
}

func (s CookieStateStore) decodeSession(value string) (LoginSession, error) {
	codecs, err := s.codecs()
	if err != nil {
		return LoginSession{}, err
	}
	var session LoginSession
	if err := securecookie.DecodeMulti(s.name(), value, &session, codecs...); err != nil {
		return LoginSession{}, ErrInvalidState
	}
	if session.State == "" || session.CodeVerifier == "" {
		return LoginSession{}, ErrInvalidState
	}
	return session, nil
}

func (s CookieStateStore) codecs() ([]securecookie.Codec, error) {
	if len(s.Codecs) > 0 {
		return s.Codecs, nil
	}
	if s.Keys.configured() {
		if err := s.Keys.validate(); err != nil {
			return nil, err
		}
		return []securecookie.Codec{securecookie.New(s.Keys.HashKey, s.Keys.BlockKey)}, nil
	}
	return defaultStateCodecs(), nil
}

func (k CookieStateKeys) configured() bool {
	return len(k.HashKey) > 0 || len(k.BlockKey) > 0
}

func (k CookieStateKeys) validate() error {
	if len(k.HashKey) < 32 {
		return errors.New("browserauth: state hash key must be at least 32 bytes")
	}
	switch len(k.BlockKey) {
	case 16, 24, 32:
		return nil
	default:
		return errors.New("browserauth: state block key must be 16, 24, or 32 bytes")
	}
}

func decodeBase64Secret(value string, label string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("browserauth: " + label + " is required")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("browserauth: " + label + " is not valid base64")
}

var (
	defaultStateCodecsOnce  sync.Once
	defaultStateCodecsValue []securecookie.Codec
	defaultStateCodecsErr   error
)

func defaultStateCodecs() []securecookie.Codec {
	defaultStateCodecsOnce.Do(func() {
		hashKey, err := randomBytes(CookieStateHashKeySize)
		if err != nil {
			defaultStateCodecsErr = err
			return
		}
		blockKey, err := randomBytes(CookieStateBlockKeySize)
		if err != nil {
			defaultStateCodecsErr = err
			return
		}
		defaultStateCodecsValue = []securecookie.Codec{securecookie.New(hashKey, blockKey)}
	})
	if defaultStateCodecsErr != nil {
		panic(defaultStateCodecsErr)
	}
	return defaultStateCodecsValue
}

func randomBytes(size int) ([]byte, error) {
	raw := make([]byte, size)
	_, err := rand.Read(raw)
	return raw, err
}
