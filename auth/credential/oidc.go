package credential

import (
	"context"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/httpapp/jwtauth"
)

// OIDCJWTExchanger verifies an OIDC JWT credential.
type OIDCJWTExchanger struct {
	Verifier *jwtauth.Verifier
	Map      func(*jwtauth.Claims) (auth.ExternalIdentity, error)
}

// ExchangeCredential implements Exchanger.
func (e OIDCJWTExchanger) ExchangeCredential(ctx context.Context, credential string) (Result, error) {
	token := tokenValue(credential)
	if token == "" {
		return Result{}, ErrUnsupported
	}
	if e.Verifier == nil {
		return Result{}, ErrUnsupported
	}
	claims, err := e.Verifier.Verify(ctx, token)
	if err != nil {
		return Result{}, err
	}
	mapper := e.Map
	if mapper == nil {
		mapper = DefaultJWTIdentity
	}
	external, err := mapper(claims)
	if err != nil {
		return Result{}, err
	}
	return Result{ExternalIdentity: external}, nil
}

// DefaultJWTIdentity maps verified JWT claims to an upstream identity.
func DefaultJWTIdentity(claims *jwtauth.Claims) (auth.ExternalIdentity, error) {
	return auth.ExternalIdentity{
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
		Claims:  claims.Raw,
	}, nil
}
