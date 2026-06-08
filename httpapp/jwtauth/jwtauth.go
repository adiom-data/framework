package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/adiom-data/framework/httpapp/middleware"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	defaultClockSkew = time.Minute
)

var (
	ErrMissingBearerToken = errors.New("missing bearer token")
	ErrInvalidBearerToken = errors.New("invalid bearer token")
)

// Config configures JWT verification against an OIDC issuer.
type Config struct {
	Issuer string
	// Audience is optional. When set, Verify requires the token aud claim to
	// contain this value. When empty, Verify skips audience validation.
	Audience   string
	HTTPClient *http.Client
	ClockSkew  time.Duration
}

// Claims are verified JWT claims.
type Claims struct {
	Raw map[string]any
	jwt.Claims
}

// UnmarshalJSON stores every claim in Raw while decoding registered claims.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type registeredClaims jwt.Claims
	if err := json.Unmarshal(data, (*registeredClaims)(&c.Claims)); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c.Raw); err != nil {
		return err
	}
	return nil
}

// MarshalJSON merges registered claims and Raw claims.
func (c Claims) MarshalJSON() ([]byte, error) {
	type registeredClaims jwt.Claims
	out := make(map[string]any, len(c.Raw)+8)
	for key, value := range c.Raw {
		out[key] = value
	}
	registered, err := json.Marshal(registeredClaims(c.Claims))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(registered, &out); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// Verifier verifies JWT bearer tokens against cached JWKS keys.
type Verifier struct {
	issuer    string
	audience  string
	clockSkew time.Duration
	keySet    *oidc.RemoteKeySet
	now       func() time.Time
}

// NewVerifier validates config and returns a JWT verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("jwtauth: issuer is required")
	}
	cfg.Issuer = normalizeIssuer(cfg.Issuer)
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	providerCtx := ctxWithHTTPClient(context.Background(), cfg.HTTPClient)
	provider, err := oidc.NewProvider(providerCtx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, err
	}
	if metadata.JWKSURI == "" {
		return nil, errors.New("jwtauth: issuer metadata missing jwks_uri")
	}
	return &Verifier{
		issuer:    cfg.Issuer,
		audience:  cfg.Audience,
		clockSkew: cfg.ClockSkew,
		keySet:    oidc.NewRemoteKeySet(providerCtx, metadata.JWKSURI),
		now:       time.Now,
	}, nil
}

// Verify validates tokenString and returns its claims.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	if v == nil {
		return nil, errors.New("jwtauth: nil verifier")
	}
	payload, err := v.keySet.VerifySignature(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBearerToken, err)
	}
	claims := &Claims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %v", ErrInvalidBearerToken, err)
	}
	if err := v.validateClaims(claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBearerToken, err)
	}
	return claims, nil
}

func (v *Verifier) validateClaims(claims *Claims) error {
	if normalizeIssuer(claims.Issuer) != normalizeIssuer(v.issuer) {
		return fmt.Errorf("issuer %q does not match %q", claims.Issuer, v.issuer)
	}
	if claims.Expiry == nil {
		return errors.New("token expiration is required")
	}
	now := v.now()
	if now.After(claims.Expiry.Time().Add(v.clockSkew)) {
		return errors.New("token is expired")
	}
	if claims.NotBefore != nil && now.Add(v.clockSkew).Before(claims.NotBefore.Time()) {
		return errors.New("token is not valid yet")
	}
	if v.audience != "" && !claims.Audience.Contains(v.audience) {
		return fmt.Errorf("audience %q not present", v.audience)
	}
	return nil
}

// Middleware requires a valid Bearer token and stores its claims on the request context.
func Middleware(verifier *Verifier) middleware.Middleware {
	if verifier == nil {
		panic("jwtauth: nil verifier")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := BearerToken(r.Header.Get("Authorization"))
			if token == "" {
				http.Error(w, ErrMissingBearerToken.Error(), http.StatusUnauthorized)
				return
			}
			claims, err := verifier.Verify(r.Context(), token)
			if err != nil {
				http.Error(w, ErrInvalidBearerToken.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
		})
	}
}

// BearerToken extracts a token from an Authorization header.
func BearerToken(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

type contextKey struct{}

// ContextWithClaims stores claims in ctx.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, contextKey{}, claims)
}

// ClaimsFromContext returns JWT claims stored by Middleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(contextKey{}).(*Claims)
	return claims, ok
}

// Claim returns a raw claim value.
func (c *Claims) Claim(name string) (any, bool) {
	if c == nil {
		return nil, false
	}
	value, ok := c.Raw[name]
	return value, ok
}

// String returns a raw string claim.
func (c *Claims) String(name string) string {
	value, ok := c.Claim(name)
	if !ok {
		return ""
	}
	stringValue, _ := value.(string)
	return stringValue
}

func normalizeIssuer(issuer string) string {
	return strings.TrimRight(issuer, "/")
}

func ctxWithHTTPClient(ctx context.Context, client *http.Client) context.Context {
	if client == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, client)
}
