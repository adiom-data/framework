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
  minting into the generated Connect `AuthService` and an optional RFC 8693 HTTP
  token exchange handler.
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
	credential.APIKeyExchanger{Lookup: lookupAPIKey},
	credential.OIDCJWTExchanger{Verifier: externalVerifier},
}

svc := authservice.New(exchanger, authorizer, issuer)
```

Internally the flow is:

```text
credential -> verified external identity -> app authorizer -> final identity -> final JWT
```

`auth.ExternalIdentity` is the upstream issuer/subject/claims. `auth.Identity`
is the final identity minted into application API bearer tokens.

## RFC 8693 HTTP Token Exchange

Applications can expose the same credential exchange through an HTTP handler,
with or without mounting the Connect service:

```go
svc := authservice.New(exchanger, authorizer, issuer)
mux.Handle("/oauth/token", svc.TokenExchangeHandler())
```

The application chooses the URL and serves it over HTTPS. Clients configure
that URL directly; this handler does not add discovery endpoints. It accepts
form encoded POST requests using the RFC 8693 token exchange grant, with a JWT
subject and an access token output:

```sh
curl https://app.example.com/oauth/token \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  --data-urlencode "subject_token=$API_CREDENTIAL" \
  --data-urlencode 'scope=jobs:read' \
  --data-urlencode 'audience=jobs-api' \
  --data-urlencode 'resource=https://api.example.com/jobs'
```

`subject_token` is the signed upstream credential, not the issued API access
token. It is verified by the configured exchanger; declaring it a JWT does not
establish trust. Put the API key exchanger before a general OIDC JWT exchanger
in a chain so that API credentials are recognized before OIDC verification.

Optional `requested_token_type` must be
`urn:ietf:params:oauth:token-type:access_token`. Other input/output types and
actor tokens are rejected. The handler does not issue refresh tokens or perform
separate OAuth client authentication: `client_id`, client secrets, and the
Authorization header are not interpreted by this handler. Applications that
require client authentication must enforce it in middleware and may pass the
authenticated client to their authorizer through context.

The `auth.Authorizer` receives the verified external identity with:

- `Claims["requested_scopes"]` as normalized `[]string`, from the credential,
  the HTTP `scope` parameter, or both. If both sources request non-empty scopes,
  their normalized sets must match; differences reject the exchange before
  authorization. Claims returned by the exchanger are copied, not mutated.
- `Audiences` and `Resources` as requested targets, including repeated
  `audience` and `resource` parameters. These are caller-controlled requests,
  not verified permissions. The authorizer must validate them and map them to
  approved token audiences. Resources must be absolute URIs without fragments.

The authorizer returns the final `Identity.Scopes` and optionally `Identity.Aud`.
The handler does not impose a scope policy or automatically intersect scopes;
the application owns downscoping, defaults, and entitlement checks. Signed
`requested_scopes` are requests, not the API credential's permission ceiling;
load allowed permissions from application-owned credential/user records.
Return or wrap `authservice.ErrInvalidScope` or `authservice.ErrInvalidTarget`
to produce the corresponding OAuth error. Return or wrap
`auth.ErrPermissionDenied` for other policy rejections. Unclassified errors are
server failures, not authorization rejections. Internal error details are not
returned to the client.

Both the Connect and HTTP exchange interfaces classify wrapped errors:

| Error category | HTTP response | Connect code |
| --- | --- | --- |
| `credential.ErrInvalid` / `credential.ErrUnsupported` | 400 `invalid_request` | `Unauthenticated` |
| `auth.ErrPermissionDenied` | 400 `invalid_request` | `PermissionDenied` |
| `authservice.ErrInvalidScope` / `ErrInvalidTarget` | 400 `invalid_scope` / `invalid_target` | `InvalidArgument` |
| `auth.ErrUnavailable` or network failure | 503 `temporarily_unavailable` | `Unavailable` |
| Context deadline / cancellation | 503 `temporarily_unavailable` | `DeadlineExceeded` / `Canceled` |
| Unclassified failure | 500 `server_error` | `Internal` |

Existing typed Connect errors are recognized as well: for example,
`CodeUnavailable` produces HTTP 503 rather than an invalid-credential response.
Client-facing messages are generic; Connect errors retain the original cause
for server-side `errors.Is`/`errors.As` inspection.

Custom exchangers and `APIKeyLookup` functions must distinguish rejection from
infrastructure errors. An unknown, revoked, or disabled key should return
`credential.ErrInvalid`; a database outage should return its operational error
or wrap `auth.ErrUnavailable` to mark it retryable. For example:

```go
return auth.Identity{}, fmt.Errorf("%w: %w", auth.ErrUnavailable, databaseErr)
```

The built-in API credential exchanger marks signature/expiry failures as invalid
credentials and preserves lookup failures. The OIDC exchanger distinguishes JWT
rejection from JWKS retrieval failures, which are treated as unavailable.

For example, an approved identity could be:

```go
return auth.Identity{
	Subject: "user_123",
	Scopes:  []string{"jobs:read"},
	Aud:     []string{"jobs-api"},
}, nil
```

Non-empty `Identity.Aud` overrides `tokenissuer.Config.Audience`; nil or empty
uses the configured default. Requested targets are never automatically
copied into the output token. Consumers must configure their expected audience
independently (for example, `RemoteVerifierConfig.AllowedAudiences`). Local
`Issuer.Verify` continues to require the issuer's configured default audience.

A successful response contains our usual signed application JWT:

```json
{
  "access_token": "...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "jobs:read"
}
```

The response always reports the actual granted scope, even when the application
chooses scopes different from the request. Token responses and OAuth JSON error
responses include `Cache-Control: no-store` and `Pragma: no-cache`. The client
uses the access token in `Authorization: Bearer ...` for API requests.
This endpoint implements the token exchange grant, not MCP's interactive
authorization code/PKCE or enterprise ID-JAG flows.

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

The JWT itself is standard: `iss`, `sub`, `iat`, `exp`, optional `aud`, and a
`kid` header. Tokens are signed with EdDSA by default. The issuer can also be
configured for RS256:

```go
rsaKey, err := tokenissuer.GenerateRSAPrivateKey()
issuer, err := tokenissuer.New(tokenissuer.Config{
	Issuer:      "https://app.example.com/auth",
	Algorithm:   jose.RS256,
	ActiveKeyID: "auth-rsa-2026-06",
	Keys: []tokenissuer.SigningKey{{
		KeyID:         "auth-rsa-2026-06",
		RSAPrivateKey: rsaKey,
	}},
})
```

The default token also includes `scope`, `scopes`, and `attributes` claims from
`auth.Identity`. Apps can also set `auth.Identity.Claims` to mint custom
top-level claims. Custom claims cannot use registered or framework-reserved
names such as `iss`, `sub`, `aud`, `exp`, `scope`, `scopes`, or `attributes`.

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

`/auth/logout` always revokes the local browser session and clears the local
session cookie. If the user should also be signed out of the upstream OIDC
provider, configure a provider logout redirect. For request-hosted apps, this
uses the provider `end_session_endpoint` when it is advertised and sends the
browser back to the public app URL afterward:

```go
handler := browserAuth.Handler(browserauth.HandlerConfig{
	// ...
	LogoutRedirectFunc: browserAuth.PublicEndSessionLogoutRedirect("/"),
})
```

For fixed public URLs, use `browserAuth.EndSessionLogoutRedirect("https://app.example.com/")`.
Providers such as Keycloak must be configured to allow the resulting
`post_logout_redirect_uri`.

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

For preview or development environments with dynamic public hosts, set a stable
provider callback with `ProxyRedirectURL`. The browser auth handler still owns
login, PKCE, callback exchange, and the local browser session. The proxy only
forwards the provider callback back to the app callback URL encoded in OAuth
state:

```go
browserauth.Config{
	// ...
	ProxyRedirectURL: "https://auth-preview.example.com/callback",
}
```

Configure the provider, such as Google, with only the stable proxy callback URL.
Run the proxy callback with the framework forwarder:

```go
mux.Handle("/callback", browserauth.ProxyCallbackForwarder(
	browserauth.ProxyCallbackForwarderConfig{
		ReturnToValidator: regexp.MustCompile(
			`^https://[a-z0-9-]+\.preview\.example\.com/auth/callback$`,
		).MatchString,
	},
))
```

The forwarder does not exchange codes or verify user identity. It extracts the
app callback URL from state, optionally applies the configured return URL
constraint, and redirects with the original provider callback query.

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

`browserauth.Config.HTTPClient` applies to discovery, JWKS retrieval, authorization
code exchange, and refresh. An explicitly configured client takes precedence
over one in the operation context. When unset, operations use the client in
their context or Go's default HTTP client. Operation cancellation and deadlines
are retained.

### Application-owned session metadata and custom callbacks

Advanced integrations can attach provider/connection provenance to
`Session.Metadata` (`map[string]string`). It is separate from IdP `Claims` and
is preserved when upstream tokens and claims refresh. The refresher receives
it on `Session`; the authorizer receives a copy as `ExternalIdentity.Metadata`.
The framework does not automatically put it in the final API JWT. Populate it
from validated application configuration, not IdP claims or unvalidated callback
parameters. Resolve current permissions through the authorizer as usual.

Metadata persistence is **opt-in** for `SQLSessionStore`. Set `MetadataColumn`
to the name of a JSONB column in the [session table](#browser-session-schema):

```go
store := browserauth.SQLSessionStore{DB: db, MetadataColumn: "metadata"}
```

With `MetadataColumn` unset, the SQL store returns
`browserauth.ErrSessionMetadataDisabled` if asked to write non-empty metadata.
Custom session stores must persist metadata on creation and updates, including
transactional refresh updates. Session metadata may be empty; applications
decide whether their checks require it. Applications with multiple provider
connections still select the appropriate refresher using their connection ID.

Use the public `SessionCallback` helper when a custom callback needs the standard
session creation, cookie, and redirect sequence:

```go
complete := browserAuth.SessionCallback(browserauth.SessionCallbackConfig{
	Store:           store,
	BasePath:        "/auth", // defaults the session cookie path
	SuccessRedirect: "/",
	BeforeCreate: func(r *http.Request, tokens browserauth.Tokens, session *browserauth.Session) error {
		if err := checkLogin(r.Context(), tokens); err != nil {
			return err
		}
		session.Metadata = map[string]string{"connection_id": configuredConnectionID}
		return nil
	},
})
mux.Handle("/auth/callback", browserAuth.CallbackHandler(complete))
```

`CallbackHandler` validates state and verifies tokens before invoking completion.
`BeforeCreate` runs after session construction and lifetime defaults, before
persisting the session, setting its cookie, or redirecting. An error prevents
those completion steps. Return or wrap `auth.ErrPermissionDenied` for a generic
HTTP 403 response; other callback errors produce a generic HTTP 500. Original
error details are not sent to the browser. The hook must not write a response.
A custom callback can also call
`complete(w, r, tokens)` after its own checks. Only pass tokens from a verified
OIDC callback. Configure the same cookie path/name on separately mounted token
and logout handlers.

The composed `browserAuth.Handler` uses the same helper and exposes the optional
hook as `HandlerConfig.BeforeCreate`. Configure `SessionTTL`, `Cookie`, and
`SuccessRedirect` to control session completion.

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
Postgres-compatible `browserauth.SQLSessionStore`. Create the session table with
the following schema:

```sql
create table auth_sessions (
  id text primary key,

  issuer text not null,
  subject text not null,

  refresh_token text not null,
  claims jsonb not null default '{}'::jsonb,

  -- Optional: enable with SQLSessionStore.MetadataColumn = "metadata".
  -- metadata jsonb not null default '{}'::jsonb,

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
