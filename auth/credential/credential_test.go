package credential

import (
	"context"
	"errors"
	"testing"

	"github.com/adiom-data/framework/auth"
)

func TestChainSkipsUnsupportedCredentials(t *testing.T) {
	t.Parallel()

	chain := Chain{
		ExchangerFunc(func(context.Context, string) (Result, error) {
			return Result{}, ErrUnsupported
		}),
		ExchangerFunc(func(context.Context, string) (Result, error) {
			return Result{ExternalIdentity: auth.ExternalIdentity{Subject: "user-1"}}, nil
		}),
	}
	result, err := chain.ExchangeCredential(context.Background(), "credential")
	if err != nil {
		t.Fatal(err)
	}
	if result.ExternalIdentity.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", result.ExternalIdentity.Subject)
	}
}

func TestChainReturnsNonUnsupportedError(t *testing.T) {
	t.Parallel()

	want := errors.New("boom")
	chain := Chain{
		ExchangerFunc(func(context.Context, string) (Result, error) {
			return Result{}, want
		}),
	}
	if _, err := chain.ExchangeCredential(context.Background(), "credential"); err != want {
		t.Fatalf("err=%v want %v", err, want)
	}
}
