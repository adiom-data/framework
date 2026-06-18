package tokenissuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

const defaultVerifierClockSkew = time.Minute

// RemoteVerifierConfig configures verification against an issuer's remote JWKS.
type RemoteVerifierConfig struct {
	Issuer string
	// AllowedAudiences is optional. When set, Verify requires the token aud
	// claim to contain at least one configured value.
	AllowedAudiences []string
	HTTPClient       *http.Client
	ClockSkew        time.Duration
}

// RemoteVerifier verifies tokenissuer access tokens against cached JWKS keys.
type RemoteVerifier struct {
	issuer    string
	audiences josejwt.Audience
	clockSkew time.Duration
	keySet    *oidc.RemoteKeySet
	now       func() time.Time
}

// LazyRemoteVerifier verifies with a remote JWKS verifier initialized on first use.
type LazyRemoteVerifier struct {
	cfg RemoteVerifierConfig

	mu       sync.Mutex
	verifier *RemoteVerifier
}

// NewRemoteVerifier discovers issuer metadata and returns a JWKS-backed verifier.
func NewRemoteVerifier(ctx context.Context, cfg RemoteVerifierConfig) (*RemoteVerifier, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("tokenissuer: issuer is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	clockSkew := cfg.ClockSkew
	if clockSkew <= 0 {
		clockSkew = defaultVerifierClockSkew
	}
	providerCtx := ctx
	if cfg.HTTPClient != nil {
		providerCtx = oidc.ClientContext(providerCtx, cfg.HTTPClient)
	}
	provider, err := oidc.NewProvider(providerCtx, issuer)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, err
	}
	if strings.TrimSpace(metadata.JWKSURI) == "" {
		return nil, errors.New("tokenissuer: issuer metadata missing jwks_uri")
	}
	return &RemoteVerifier{
		issuer:    issuer,
		audiences: verifierAudiences(cfg),
		clockSkew: clockSkew,
		keySet:    oidc.NewRemoteKeySet(providerCtx, metadata.JWKSURI),
		now:       time.Now,
	}, nil
}

// NewLazyRemoteVerifier returns a verifier that initializes remote discovery on demand.
func NewLazyRemoteVerifier(cfg RemoteVerifierConfig) *LazyRemoteVerifier {
	return &LazyRemoteVerifier{cfg: cfg}
}

// Verify validates tokenString and returns tokenissuer claims.
func (v *RemoteVerifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	if v == nil {
		return nil, errors.New("tokenissuer: verifier is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	payload, err := v.keySet.VerifySignature(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	claims := &Claims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	expected := josejwt.Expected{
		Issuer: v.issuer,
		Time:   v.now(),
	}
	if len(v.audiences) > 0 {
		expected.AnyAudience = v.audiences
	}
	if err := claims.Claims.ValidateWithLeeway(expected, v.clockSkew); err != nil {
		return nil, err
	}
	return claims, nil
}

// Verify validates tokenString, initializing the remote verifier if needed.
func (v *LazyRemoteVerifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	if v == nil {
		return nil, errors.New("tokenissuer: verifier is not configured")
	}
	verifier, err := v.remoteVerifier(ctx)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(ctx, tokenString)
}

func (v *LazyRemoteVerifier) remoteVerifier(ctx context.Context) (*RemoteVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	verifier, err := NewRemoteVerifier(ctx, v.cfg)
	if err != nil {
		return nil, err
	}
	v.verifier = verifier
	return verifier, nil
}

func verifierAudiences(cfg RemoteVerifierConfig) josejwt.Audience {
	seen := map[string]struct{}{}
	var audiences josejwt.Audience
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		audiences = append(audiences, value)
	}
	for _, audience := range cfg.AllowedAudiences {
		add(audience)
	}
	return audiences
}

var _ TokenVerifier = (*RemoteVerifier)(nil)
var _ TokenVerifier = (*LazyRemoteVerifier)(nil)
