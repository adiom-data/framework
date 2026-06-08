package authservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/credential"
	"github.com/adiom-data/framework/auth/tokenissuer"
	authv1 "github.com/adiom-data/framework/gen/go/adiom/auth/v1"
)

func TestExchangeCredentialAuthorizesAndMintsToken(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokenissuer.New(tokenissuer.Config{
		Issuer:     "https://auth.example.com",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := New(
		credential.ExchangerFunc(func(_ context.Context, got string) (credential.Result, error) {
			if got != "external" {
				t.Fatalf("credential=%q want external", got)
			}
			return credential.Result{
				ExternalIdentity: auth.ExternalIdentity{Issuer: "https://idp.example.com", Subject: "upstream-1"},
			}, nil
		}),
		auth.AuthorizerFunc(func(_ context.Context, external auth.ExternalIdentity) (auth.Identity, error) {
			if external.Subject != "upstream-1" {
				t.Fatalf("external subject=%q want upstream-1", external.Subject)
			}
			return auth.Identity{Subject: "user-1", Scopes: []string{"read"}}, nil
		}),
		issuer,
	)

	resp, err := service.ExchangeCredential(context.Background(), connect.NewRequest(&authv1.ExchangeCredentialRequest{
		Credential: "external",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetAccessToken() == "" {
		t.Fatal("access token is empty")
	}
	claims, err := issuer.Verify(resp.Msg.GetAccessToken())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject=%q want user-1", claims.Subject)
	}
}
