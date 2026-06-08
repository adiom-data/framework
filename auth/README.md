# auth

`auth` contains reusable building blocks for implementing an Adiom auth service.

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
is the final identity minted into Adiom API bearer tokens.

## Browser Auth

Experimental: prefer direct SPA OIDC plus `AuthService.ExchangeCredential` until
we deliberately need server-owned browser sessions.

For customer-domain or shared-hostname auth, mount browser auth routes under a
path such as `/auth`:

```text
/auth/login
/auth/callback
/auth/token
/auth/logout
```

The callback should save a `browserauth.Session` behind an opaque session cookie.
The token endpoint loads that session, turns it back into `auth.ExternalIdentity`,
runs the same app authorizer, and mints the final API JWT. The SPA uses that
final JWT as its `Authorization: Bearer ...` token for API calls.

The browser session stores upstream auth state, not final app scopes. Final
scopes should be resolved each time a new API token is minted.

For silent refresh, configure `browserauth.TokenEndpoint.Refresher` with the
`BrowserAuth` instance. The endpoint can refresh upstream OIDC state from the
stored refresh token before minting a new final API JWT.

## Browser Session Schema

The framework defines the `browserauth.SessionStore` interface. A production
Postgres-backed store can use a minimal table like this:

```sql
create table auth_sessions (
  id text primary key,

  issuer text not null,
  subject text not null,

  refresh_token text not null,
  claims jsonb not null default '{}'::jsonb,

  expires_at timestamptz not null,
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
browser session lifetime, not the upstream access-token expiration. `(issuer,
subject)` should be indexed for user/session lookup, but it should not be unique
on the session table because one upstream user can have multiple browser
sessions. App-owned user mapping tables may choose to enforce uniqueness on
`(issuer, subject)`.

Refresh tokens should be encrypted at rest by the concrete store or the
database/storage layer.
