# jwtauth

`jwtauth` verifies JWT Bearer tokens for an OIDC issuer and stores the decoded
claims on the request context.

Use it as ordinary HTTP middleware:

```go
verifier, err := jwtauth.NewVerifier(jwtauth.Config{
	Issuer:   "https://auth.example.com/realms/adiom",
	Audience: "service",
})
if err != nil {
	return err
}

route := httpapp.Handle(
	"/admin/",
	adminHandler,
	httpapp.WithMiddleware(jwtauth.Middleware(verifier)),
)
```

The verifier discovers signing keys from the issuer's
`/.well-known/openid-configuration` document and caches the discovered
`jwks_uri` keys.

When `Config.Audience` is set, the standard `aud` claim is checked against it.
When `Config.Audience` is empty, audience validation is skipped.
Application-specific middleware can inspect provider-specific claims such as
`client_id` or `azp` through `Claims.Raw`.

Read claims in downstream handlers:

```go
claims, ok := jwtauth.ClaimsFromContext(r.Context())
```

`Claims` contains standard registered JWT claims and `Raw` for provider or
application-specific claims:

```go
claims, _ := jwtauth.ClaimsFromContext(r.Context())
orgID := claims.String("org_id")
rawPermissions, _ := claims.Claim("permissions")
```
