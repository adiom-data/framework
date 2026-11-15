package credential

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
	"github.com/adiom-data/framework/httpapp/jwtauth"
)

type oidcTestTransport func(*http.Request) (*http.Response, error)

func (f oidcTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOIDCExchangerDistinguishesInvalidTokensFromKeyFailures(t *testing.T) {
	t.Parallel()
	key, err := tokenissuer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	config := tokenissuer.Config{
		Issuer: "https://idp.example.com", Audience: "login-client", ActiveKeyID: "key",
		Keys: []tokenissuer.SigningKey{{KeyID: "key", PrivateKey: key}},
	}
	issuer, err := tokenissuer.New(config)
	if err != nil {
		t.Fatal(err)
	}
	good, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := tokenissuer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherConfig := config
	otherConfig.Keys = []tokenissuer.SigningKey{{KeyID: "key", PrivateKey: otherKey}}
	otherIssuer, err := tokenissuer.New(otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	badSignature, _, err := otherIssuer.Mint(context.Background(), auth.Identity{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	badAudience, _, err := issuer.Mint(context.Background(), auth.Identity{Subject: "user-1", Aud: []string{"another-client"}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := json.Marshal(issuer.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, token, keyResponse string
		status                   int
		transportErr             error
		want                     error
	}{
		{"signature", badSignature, string(keys), 200, nil, ErrInvalid},
		{"claims", badAudience, string(keys), 200, nil, ErrInvalid},
		{"malformed", "not-a-jwt", string(keys), 200, nil, ErrInvalid},
		{"jwks_503", good, "issuer unavailable", 503, nil, auth.ErrUnavailable},
		{"jwks_invalid_json", good, "{", 200, nil, auth.ErrUnavailable},
		{"jwks_network", good, "", 0, &net.DNSError{Err: "lookup failed", Name: "idp.example.com"}, auth.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: oidcTestTransport(func(r *http.Request) (*http.Response, error) {
				status, body := tc.status, tc.keyResponse
				if r.URL.Path == "/.well-known/openid-configuration" {
					status = 200
					body = `{"issuer":"https://idp.example.com","jwks_uri":"https://idp.example.com/keys"}`
				} else if r.URL.Path != "/keys" {
					return nil, errors.New("unexpected OIDC request")
				} else if tc.transportErr != nil {
					return nil, tc.transportErr
				}
				return &http.Response{
					StatusCode: status, Status: http.StatusText(status),
					Header: http.Header{"Content-Type": {"application/json"}},
					Body:   io.NopCloser(strings.NewReader(body)),
				}, nil
			})}
			verifier, err := jwtauth.NewVerifier(jwtauth.Config{
				Issuer: config.Issuer, AllowedAudiences: []string{"login-client"}, HTTPClient: client,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = (OIDCJWTExchanger{Verifier: verifier}).ExchangeCredential(context.Background(), tc.token)
			if !errors.Is(err, tc.want) {
				t.Fatalf("exchange error=%v want category=%v", err, tc.want)
			}
			if tc.want == auth.ErrUnavailable && errors.Is(err, ErrInvalid) {
				t.Fatalf("key retrieval failure marked as invalid credential: %v", err)
			}
			if tc.transportErr != nil && !errors.Is(err, tc.transportErr) {
				t.Fatalf("lost original network cause: %v", err)
			}
		})
	}
}
