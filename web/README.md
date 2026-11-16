# framework web

Small browser helpers for applications using the framework auth endpoints.

## Installing Without A Registry

The package builds to `dist` and exports JavaScript plus TypeScript
declarations, so consumers do not need to compile files from `src`.

For local development, use a file dependency:

```json
{
  "dependencies": {
    "@adiom-data/framework-web": "file:../framework/web"
  }
}
```

For a pnpm project that depends on this package from the framework repo, use a
git dependency with the package path:

```json
{
  "dependencies": {
    "@adiom-data/framework-web": "git+ssh://git@github.com/adiom-data/framework.git#path:web"
  }
}
```

For package managers that do not support git subdirectory dependencies, create a
tarball and depend on that artifact:

```sh
cd web && npm pack
```

```json
{
  "dependencies": {
    "@adiom-data/framework-web": "file:../adiom-data-framework-web-0.0.3.tgz"
  }
}
```

## Browser Auth

`AuthTokenManager` fetches short-lived app JWTs from `/auth/token`, caches them
until they are close to expiration, and clears local state on unauthorized
responses. `clear()` also invalidates pending token results. A response from an
older authentication state cannot replace or clear a newer token.
Forced refreshes bypass the cached token and share any pending token fetch.
`authStateVersion` changes when authentication is cleared, allowing request
retries to stay within the authentication state in which they started.

```ts
import { AuthTokenManager, createAuthInterceptor } from "@adiom-data/framework-web/auth";

const tokenManager = new AuthTokenManager({
  tokenUrl: "/auth/token",
  logoutUrl: "/auth/logout",
});

const authInterceptor = createAuthInterceptor(tokenManager);
```

Use the interceptor with Connect clients that should send the app bearer token.
Concurrent authentication retries share a refresh. If another request already
refreshed the rejected token, the interceptor reuses it. Requests are not retried
across a `clear()` or logout.

```ts
const transport = createConnectTransport({
  baseUrl: "/api",
  interceptors: [authInterceptor],
});
```

The default `credentials` mode is `same-origin`, matching the recommended
same-host `/auth` mount. For cross-origin auth hosts, pass `credentials:
"include"` and configure CORS at the gateway or HTTP layer.

For local-only logout, call `await tokenManager.logout()` and handle rejection
when the server cannot complete logout. Token retrieval is suspended while
logout is in progress, and pending token responses are discarded. Requests to
the token and logout endpoints use `cache: "no-store"`. If `/auth/logout`
redirects through the upstream OIDC provider, use a top-level browser
navigation instead:

```ts
tokenManager.logoutWithRedirect();
```
