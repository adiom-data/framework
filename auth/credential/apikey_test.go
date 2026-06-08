package credential

import (
	"context"
	"testing"
	"time"
)

func TestAPIKeyExchanger(t *testing.T) {
	t.Parallel()

	keypair, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignAssertion(keypair.ID, keypair.PrivateKey, []string{"write", "read", "read"}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	exchanger := APIKeyExchanger{
		Lookup: func(ctx context.Context, id string) (APIKeyRecord, error) {
			if id != keypair.ID {
				t.Fatalf("id=%q want %q", id, keypair.ID)
			}
			return APIKeyRecord{
				ID:        id,
				PublicKey: keypair.PublicKey,
			}, nil
		},
	}

	result, err := exchanger.ExchangeCredential(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExternalIdentity.Issuer != DefaultAPIKeyIssuer {
		t.Fatalf("issuer=%q want %q", result.ExternalIdentity.Issuer, DefaultAPIKeyIssuer)
	}
	if result.ExternalIdentity.Subject != keypair.ID {
		t.Fatalf("subject=%q want %q", result.ExternalIdentity.Subject, keypair.ID)
	}
	if got, want := result.RequestedScopes, []string{"read", "write"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("requested scopes=%v want %v", got, want)
	}
}

func TestAPIKeyExchangerUnsupportedCredential(t *testing.T) {
	t.Parallel()

	_, err := (APIKeyExchanger{}).ExchangeCredential(context.Background(), "not-a-jwt")
	if err != ErrUnsupported {
		t.Fatalf("err=%v want ErrUnsupported", err)
	}
}

func TestAPIKeyExchangerRejectsMismatchedRecordID(t *testing.T) {
	t.Parallel()

	keypair, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignAPIKey(keypair.ID, keypair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	exchanger := APIKeyExchanger{
		Lookup: func(context.Context, string) (APIKeyRecord, error) {
			return APIKeyRecord{
				ID:        "apic_other",
				PublicKey: keypair.PublicKey,
			}, nil
		},
	}
	if _, err := exchanger.ExchangeCredential(context.Background(), token); err != ErrInvalid {
		t.Fatalf("err=%v want ErrInvalid", err)
	}
}
