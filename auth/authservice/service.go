package authservice

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/credential"
	"github.com/adiom-data/framework/auth/tokenissuer"
	authv1 "github.com/adiom-data/framework/gen/go/adiom/auth/v1"
)

// Service implements adiom.auth.v1.AuthService.
type Service struct {
	Exchanger  credential.Exchanger
	Authorizer auth.Authorizer
	Issuer     *tokenissuer.Issuer
}

// New returns an AuthService implementation.
func New(exchanger credential.Exchanger, authorizer auth.Authorizer, issuer *tokenissuer.Issuer) *Service {
	return &Service{
		Exchanger:  exchanger,
		Authorizer: authorizer,
		Issuer:     issuer,
	}
}

// ExchangeCredential verifies a presented credential, authorizes it, and mints an access token.
func (s *Service) ExchangeCredential(ctx context.Context, req *connect.Request[authv1.ExchangeCredentialRequest]) (*connect.Response[authv1.ExchangeCredentialResponse], error) {
	if s == nil || s.Exchanger == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("authservice: credential exchanger is not configured"))
	}
	if s.Authorizer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("authservice: authorizer is not configured"))
	}
	if s.Issuer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("authservice: token issuer is not configured"))
	}
	result, err := s.Exchanger.ExchangeCredential(ctx, req.Msg.GetCredential())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	identity, err := s.Authorizer.Authorize(ctx, result.ExternalIdentity)
	if err != nil {
		return nil, err
	}
	token, _, err := s.Issuer.Mint(ctx, identity)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&authv1.ExchangeCredentialResponse{AccessToken: token}), nil
}
