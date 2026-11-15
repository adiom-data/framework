package credential

import (
	"context"
	"errors"
	"strings"

	"github.com/adiom-data/framework/auth"
)

var (
	// ErrUnsupported means the exchanger does not handle this credential.
	// A chain tries the next exchanger, or rejects it if none supports it.
	ErrUnsupported = errors.New("credential: unsupported credential")
	// ErrInvalid marks a credential rejection, including unknown/revoked keys.
	// Custom exchangers and lookup functions should wrap it for such failures;
	// unclassified errors are treated as operational failures by authservice.
	ErrInvalid = errors.New("credential: invalid credential")
)

// Result is the verified upstream identity from a credential exchange.
type Result struct {
	ExternalIdentity auth.ExternalIdentity
	RequestedScopes  []string
}

func tokenValue(credential string) string {
	credential = strings.TrimSpace(credential)
	scheme, token, ok := strings.Cut(credential, " ")
	if ok && strings.EqualFold(scheme, "Bearer") {
		return strings.TrimSpace(token)
	}
	return credential
}

// Exchanger verifies a presented credential and returns its upstream identity.
type Exchanger interface {
	ExchangeCredential(context.Context, string) (Result, error)
}

// ExchangerFunc adapts a function into an Exchanger.
type ExchangerFunc func(context.Context, string) (Result, error)

// ExchangeCredential implements Exchanger.
func (f ExchangerFunc) ExchangeCredential(ctx context.Context, credential string) (Result, error) {
	return f(ctx, credential)
}

// Chain tries exchangers in order until one supports the credential.
type Chain []Exchanger

// ExchangeCredential implements Exchanger.
func (c Chain) ExchangeCredential(ctx context.Context, credential string) (Result, error) {
	for _, exchanger := range c {
		if exchanger == nil {
			continue
		}
		result, err := exchanger.ExchangeCredential(ctx, credential)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		return result, err
	}
	return Result{}, ErrUnsupported
}
