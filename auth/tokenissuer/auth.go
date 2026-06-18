package tokenissuer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/adiom-data/framework/auth"
)

var (
	// ErrMissingBearerToken means an Authorization header did not contain a
	// bearer token.
	ErrMissingBearerToken = errors.New("tokenissuer: missing bearer token")
	// ErrInvalidBearerToken means a bearer token was present but failed
	// verification.
	ErrInvalidBearerToken = errors.New("tokenissuer: invalid bearer token")
	// ErrPermissionDenied means verified claims failed an auth policy.
	ErrPermissionDenied = errors.New("tokenissuer: permission denied")
)

// Policy validates verified token claims before a handler runs.
type Policy func(context.Context, *Claims) error

// BearerAuthOption customizes BearerAuthenticator.
type BearerAuthOption func(*bearerAuthConfig)

type bearerAuthConfig struct {
	allowMissing bool
	policies     []Policy
	mapAuthValue func(context.Context, *Claims) (any, error)
}

// TokenVerifier verifies a bearer token and returns tokenissuer claims.
type TokenVerifier interface {
	Verify(context.Context, string) (*Claims, error)
}

// BearerAuthenticator verifies Authorization bearer tokens, applies generic
// auth policy, and stores verified auth data on context.
type BearerAuthenticator struct {
	verifier TokenVerifier
	cfg      bearerAuthConfig
}

// NewBearerAuthenticator returns a protocol-neutral bearer-token authenticator.
func NewBearerAuthenticator(issuer *Issuer, opts ...BearerAuthOption) BearerAuthenticator {
	return NewBearerAuthenticatorFromVerifier(localTokenVerifier{issuer: issuer}, opts...)
}

// NewBearerAuthenticatorFromVerifier returns a bearer-token authenticator using verifier.
func NewBearerAuthenticatorFromVerifier(verifier TokenVerifier, opts ...BearerAuthOption) BearerAuthenticator {
	cfg := bearerAuthConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return BearerAuthenticator{verifier: verifier, cfg: cfg}
}

// AllowMissingBearerToken lets requests without an Authorization bearer token
// continue without auth context. Invalid bearer tokens are still rejected.
func AllowMissingBearerToken() BearerAuthOption {
	return func(cfg *bearerAuthConfig) {
		cfg.allowMissing = true
	}
}

// WithPolicy adds a policy check for verified token claims.
func WithPolicy(policy Policy) BearerAuthOption {
	return func(cfg *bearerAuthConfig) {
		if policy != nil {
			cfg.policies = append(cfg.policies, policy)
		}
	}
}

// RequireScopes requires verified token claims to contain all scopes.
func RequireScopes(scopes ...string) BearerAuthOption {
	required := auth.NormalizeScopes(scopes)
	return WithPolicy(func(_ context.Context, claims *Claims) error {
		if claims == nil {
			return ErrInvalidBearerToken
		}
		available := map[string]struct{}{}
		for _, scope := range claimScopes(claims) {
			available[scope] = struct{}{}
		}
		for _, scope := range required {
			if _, ok := available[scope]; !ok {
				return fmt.Errorf("%w: missing scope %q", ErrPermissionDenied, scope)
			}
		}
		return nil
	})
}

// WithAuthValue maps verified claims into an application-specific value stored
// on context for handlers to read with AuthValueFromContext.
func WithAuthValue[T any](mapper func(context.Context, *Claims) (T, error)) BearerAuthOption {
	return func(cfg *bearerAuthConfig) {
		if mapper == nil {
			return
		}
		cfg.mapAuthValue = func(ctx context.Context, claims *Claims) (any, error) {
			return mapper(ctx, claims)
		}
	}
}

// Authenticate verifies authorization and returns a context with verified auth
// data. The authorization value should be an HTTP Authorization header.
func (a BearerAuthenticator) Authenticate(ctx context.Context, authorization string) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	token := BearerToken(authorization)
	if token == "" {
		if a.cfg.allowMissing {
			return ctx, nil
		}
		return ctx, ErrMissingBearerToken
	}
	if a.verifier == nil {
		return ctx, fmt.Errorf("%w: verifier is not configured", ErrInvalidBearerToken)
	}
	claims, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return ctx, fmt.Errorf("%w: %v", ErrInvalidBearerToken, err)
	}
	for _, policy := range a.cfg.policies {
		if err := policy(ctx, claims); err != nil {
			return ctx, err
		}
	}
	ctx = ContextWithClaims(ctx, claims)
	ctx = ContextWithIdentity(ctx, IdentityFromClaims(claims))
	if a.cfg.mapAuthValue != nil {
		value, err := a.cfg.mapAuthValue(ctx, claims)
		if err != nil {
			return ctx, err
		}
		ctx = ContextWithAuthValue(ctx, value)
	}
	return ctx, nil
}

// BearerToken extracts a token from an Authorization header.
func BearerToken(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

type localTokenVerifier struct {
	issuer *Issuer
}

func (v localTokenVerifier) Verify(_ context.Context, token string) (*Claims, error) {
	return v.issuer.Verify(token)
}

type claimsContextKey struct{}
type identityContextKey struct{}
type authValueContextKey struct{}

// ContextWithClaims stores verified token claims in ctx.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext returns verified token claims stored by BearerAuthenticator.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return claims, ok
}

// IdentityFromClaims returns the generic framework identity represented by
// verified token claims.
func IdentityFromClaims(claims *Claims) auth.Identity {
	if claims == nil {
		return auth.Identity{}
	}
	return auth.Identity{
		Subject:    claims.Subject,
		Scopes:     claimScopes(claims),
		Attributes: copyStringMap(claims.Attributes),
	}
}

// ContextWithIdentity stores a generic framework identity in ctx.
func ContextWithIdentity(ctx context.Context, identity auth.Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

// IdentityFromContext returns the generic framework identity stored by
// BearerAuthenticator.
func IdentityFromContext(ctx context.Context) (auth.Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(auth.Identity)
	return identity, ok
}

// ContextWithAuthValue stores an application-specific auth value in ctx.
func ContextWithAuthValue(ctx context.Context, value any) context.Context {
	return context.WithValue(ctx, authValueContextKey{}, value)
}

// AuthValueFromContext returns an application-specific auth value stored by
// WithAuthValue.
func AuthValueFromContext[T any](ctx context.Context) (T, bool) {
	value, ok := ctx.Value(authValueContextKey{}).(T)
	return value, ok
}

func claimScopes(claims *Claims) []string {
	if claims == nil {
		return nil
	}
	scopes := append([]string(nil), claims.Scopes...)
	scopes = append(scopes, strings.Fields(claims.Scope)...)
	return auth.NormalizeScopes(scopes)
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	copy := make(map[string]string, len(values))
	for key, value := range values {
		if strings.TrimSpace(key) != "" {
			copy[key] = value
		}
	}
	return copy
}
