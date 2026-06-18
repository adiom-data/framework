# auth

`auth` contains reusable building blocks for implementing an application auth service.

The standard service contract is generated from `proto/adiom/auth/v1/auth.proto`:

```proto
service AuthService {
  rpc ExchangeCredential(ExchangeCredentialRequest) returns (ExchangeCredentialResponse);
}
```

`ExchangeCredential` accepts a presented credential, such as an external OIDC
JWT or API key, and returns a short-lived access token minted by the auth
service.

## Packages

- `auth/tokenissuer` mints and verifies standard Ed25519/EdDSA access tokens.
- `auth/credential` verifies presented credentials and extracts upstream
  identities.
- `auth/authservice` wires credential verification, app authorization, and token
  minting into the generated Connect `AuthService`.
- `auth/browserauth` is experimental. It provides optional OIDC browser
  login/callback helpers with PKCE for future server-owned browser session
  flows.

## Exchange Flow

Applications provide one authorizer hook:

```go
authorizer := auth.AuthorizerFunc(func(ctx context.Context, external auth.ExternalIdentity) (auth.Identity, error) {
	// App code owns this lookup. Usually it finds/upserts a user by
	// external.Issuer + external.Subject, loads roles/orgs/scopes, and returns
	// the final token identity.
	return auth.Identity{
		Subject: "user_123",
		Scopes: []string{"tenant:abc"},
	}, nil
})
```

Credential exchange then becomes:

```go
exchanger := credential.Chain{
	credential.OIDCJWTExchanger{Verifier: externalVerifier},
	credential.APIKeyExchanger{Lookup: lookupAPIKey},
}

svc := authservice.New(exchanger, authorizer, issuer)
```

Internally the flow is:

```text
credential -> verified external identity -> app authorizer -> final identity -> final JWT
```

`auth.ExternalIdentity` is the upstream issuer/subject/claims. `auth.Identity`
is the final identity minted into application API bearer tokens.

## Issuer Endpoints

Services can verify tokens minted by `auth/tokenissuer` with `httpapp/jwtauth`
when the issuer serves:

```text
/.well-known/openid-configuration
/.well-known/jwks.json
```

`tokenissuer.Issuer` provides handlers for both endpoints:

```go
mux.Handle("/.well-known/openid-configuration", issuer.MetadataHandler())
mux.Handle("/.well-known/jwks.json", issuer.JWKSHandler())
```

The JWT itself is standard: `iss`, `sub`, `iat`, `exp`, optional `aud`, a `kid`
header, and an EdDSA signature. The default token also includes `scope`,
`scopes`, and `attributes` claims from `auth.Identity`.

For key rotation, configure multiple signing keys and choose the active key:

```go
issuer, err := tokenissuer.New(tokenissuer.Config{
	Issuer:      "https://app.example.com/auth",
	ActiveKeyID: "auth-2026-06",
	Keys: []tokenissuer.SigningKey{
		{KeyID: "auth-2026-05", PublicKey: oldPublicKey},
		{KeyID: "auth-2026-06", PrivateKey: newPrivateKey},
	},
})
```

The active key signs new tokens. JWKS publishes every configured public key, so
old tokens remain verifiable until they expire.

## Protected Connect APIs

Backend services can verify application bearer tokens with a protocol-neutral
authenticator and a thin Connect interceptor:

```go
verifier := tokenissuer.NewLazyRemoteVerifier(tokenissuer.RemoteVerifierConfig{
	Issuer:           "https://app.example.com/auth",
	AllowedAudiences: []string{"sample-service"},
})
authenticator := tokenissuer.NewBearerAuthenticatorFromVerifier(
	verifier,
	tokenissuer.RequireScopes("sample:read"),
	tokenissuer.WithAuthValue(func(_ context.Context, claims *tokenissuer.Claims) (*samplev1.User, error) {
		return &samplev1.User{
			Id:     claims.Subject,
			Email:  claims.Attributes["email"],
			Name:   claims.Attributes["name"],
			Scopes: claims.Scopes,
		}, nil
	}),
)

service := runtime.NewService(
	httpapp.WithServiceInterceptors(tokenissuer.ConnectAuth(authenticator)),
)
```

`NewLazyRemoteVerifier` starts without network I/O and initializes discovery/JWKS
on the first verification attempt. Requests fail closed until the issuer is
available. Use `NewRemoteVerifier(ctx, cfg)` when startup should block and fail
if issuer discovery is unavailable.

Both remote verifier paths cache keys through the OIDC remote key set.
`NewBearerAuthenticator(issuer, ...)` still verifies locally with an in-process
`tokenissuer.Issuer`, which is convenient for tests or same-process apps:

```go
authenticator := tokenissuer.NewBearerAuthenticator(
	issuer,
	tokenissuer.RequireScopes("sample:read"),
)
```

`BearerAuthenticator.Authenticate` owns extraction, verification, generic policy,
and context storage. `ConnectAuth` only adapts that result to Connect headers and
Connect error codes. Handlers can read the generic claims or identity:

```go
claims, ok := tokenissuer.ClaimsFromContext(ctx)
identity, ok := tokenissuer.IdentityFromContext(ctx)
```

Apps that need their own representation can read the mapped value:

```go
user, ok := tokenissuer.AuthValueFromContext[*samplev1.User](ctx)
```

## Browser Auth

Experimental: prefer direct SPA OIDC plus `AuthService.ExchangeCredential` until
we deliberately need server-owned browser sessions.

For customer-domain or shared-hostname auth, mount browser auth under a path
such as `/auth`:

```text
/auth/login
/auth/callback
/auth/token
/auth/logout
/auth/.well-known/openid-configuration
/auth/.well-known/jwks.json
```

The composed handler serves those routes relative to its mount point:

```go
handler := browserAuth.Handler(browserauth.HandlerConfig{
	BasePath:   "/auth",
	Store:      browserauth.SQLSessionStore{DB: db},
	Cookie:     browserauth.SessionCookie{},
	Authorizer: authorizer,
	Issuer:     issuer,
	Refresher:  browserAuth,
})

mux.Handle("/auth/", http.StripPrefix("/auth", handler))
```

Set `browserauth.Config.RedirectURL` when the public callback URL is fixed and
known at startup:

```go
browserauth.Config{
	// ...
	RedirectURL: "https://app.example.com/auth/callback",
}
```

If the callback URL depends on the request host, forwarded headers, or another
runtime policy, use `RedirectURLResolver`. The same resolved URL is used for
both the provider authorization redirect and callback token exchange:

```go
browserauth.Config{
	// ...
	RedirectURLResolver: browserauth.PublicRedirectURL("/auth/callback"),
}
```

`PublicRedirectURL` builds from `httputil.PublicBaseURL`, which honors
`Forwarded`, `X-Forwarded-Proto`, and `X-Forwarded-Host`. Only use those headers
behind trusted proxy/gateway configuration. Apps that support only certain
public hosts should wrap the resolver with their own allowlist check.

When `SessionCookie.Path` is empty, the composed handler defaults it to
`BasePath`, so the browser session cookie is scoped to the auth mount.
When `Issuer` is set, the composed handler also serves the matching discovery
and JWKS endpoints at the same mount point.

Some providers require extra authorization URL parameters to issue refresh
tokens. For example, Google commonly needs:

```go
browserauth.Config{
	// ...
	AuthCodeOptions: []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	},
}
```

The callback should save a `browserauth.Session` behind an opaque session cookie.
The token endpoint loads that session, turns it back into `auth.ExternalIdentity`,
runs the same app authorizer, and mints the final API JWT. The SPA uses that
final JWT as its `Authorization: Bearer ...` token for API calls.

The browser session stores upstream auth state, not final app scopes. Final
scopes should be resolved each time a new API token is minted. `SessionTTL` is
the maximum browser-auth session lifetime; once it expires, `/auth/token`
returns unauthorized and the user must log in again.

For silent refresh, configure `browserauth.TokenEndpoint.Refresher` with the
`BrowserAuth` instance. The endpoint refreshes upstream OIDC state from the
stored refresh token when `upstream_expires_at` is missing or within the
configured refresh leeway. The default leeway is one minute. Stores can
implement `browserauth.SessionUpdateStore` to coordinate concurrent refreshes;
`SQLSessionStore` does this with a row lock.

Browser auth cookies default to `HttpOnly`, `Secure`, and `SameSite=Lax`.
Local HTTP development can opt into insecure cookies explicitly. The temporary
OAuth state/PKCE cookie is signed and encrypted. For multiple replicas, provide
stable state keys so callbacks can be verified by any replica. The usual path
is to store one high-entropy seed and derive the cookie keys from it:

```go
stateKeys, err := browserauth.CookieStateKeysFromSeedBase64(
	os.Getenv("BROWSER_AUTH_STATE_SEED"),
)
if err != nil {
	return err
}
browserAuth, err := browserauth.New(ctx, browserauth.Config{
	// ...
	StateKeys: stateKeys,
})
```

Generate the seed once, then store it in your normal secret manager as a base64
string:

```go
seed, err := browserauth.GenerateCookieStateSeedSecret()
if err != nil {
	return err
}
fmt.Println("BROWSER_AUTH_STATE_SEED=" + seed)
```

The seed should be random secret material, not a predictable name or ID. Apps
that already manage separate key material can also use
`browserauth.CookieStateKeysFromBase64(hashKey, blockKey)`.

When no stable keys are configured, the framework uses process-local random
keys, which is fine for single-process development but not for multiple
replicas.
Apps that need to customize the state cookie name, path, or SameSite policy can
instead pass `StateStore: browserauth.CookieStateStore{Keys: stateKeys, ...}`.

Missing, stale, or tampered callback state is rejected before token exchange.
By default the callback returns `400` for compatibility. Apps that want a
friendlier recovery path can redirect those failures:

```go
handler := browserAuth.Handler(browserauth.HandlerConfig{
	// ...
	InvalidStateHandler: browserauth.RedirectInvalidState("/auth/login"),
})
```

CORS is intentionally not handled in `browserauth`. Prefer same-host `/auth`
mounts. If `/auth/token` is cross-origin, configure CORS at the gateway or
application HTTP layer.

## Browser Session Schema

The framework defines the `browserauth.SessionStore` interface and includes a
Postgres-compatible `browserauth.SQLSessionStore`. Run a migration like this:

```sql
create table auth_sessions (
  id text primary key,

  issuer text not null,
  subject text not null,

  refresh_token text not null,
  claims jsonb not null default '{}'::jsonb,

  expires_at timestamptz not null,
  upstream_expires_at timestamptz,
  revoked_at timestamptz,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index auth_sessions_identity_idx
  on auth_sessions (issuer, subject);

create index auth_sessions_expires_at_idx
  on auth_sessions (expires_at)
  where revoked_at is null;
```

`id` is the opaque value stored in the browser cookie. `expires_at` is the
browser session lifetime. `upstream_expires_at` is the upstream OIDC token-state
expiration used to decide when to refresh. `(issuer, subject)` should be indexed
for user/session lookup, but it should not be unique on the session table
because one upstream user can have multiple browser sessions. App-owned user
mapping tables may choose to enforce uniqueness on `(issuer, subject)`.

`SQLSessionStore` stores refresh tokens as provided. For production browser
sessions, encrypt them at the database/storage layer or wrap `SessionStore` with
application-managed encryption before writing refresh tokens.
