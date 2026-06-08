package auth

import (
	"context"
	"sort"
	"strings"
)

// ExternalIdentity is a verified upstream identity before app authorization.
type ExternalIdentity struct {
	Issuer  string
	Subject string
	Claims  map[string]any
}

// Identity is the final identity minted into Adiom access tokens.
type Identity struct {
	Subject    string
	Scopes     []string
	Attributes map[string]string
}

// Authorizer maps a verified upstream identity to a final token identity.
type Authorizer interface {
	Authorize(context.Context, ExternalIdentity) (Identity, error)
}

// AuthorizerFunc adapts a function into an Authorizer.
type AuthorizerFunc func(context.Context, ExternalIdentity) (Identity, error)

// Authorize implements Authorizer.
func (f AuthorizerFunc) Authorize(ctx context.Context, external ExternalIdentity) (Identity, error) {
	return f(ctx, external)
}

// NormalizeScopes trims, deduplicates, and sorts scopes for stable tokens.
func NormalizeScopes(scopes []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}
