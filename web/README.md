# framework web

Small browser helpers for applications using the framework auth endpoints.

## Browser Auth

`AuthTokenManager` fetches short-lived app JWTs from `/auth/token`, caches them
until they are close to expiration, and clears local state on unauthorized
responses.

```ts
import { AuthTokenManager, createAuthInterceptor } from "@adiom-data/framework-web/auth";

const tokenManager = new AuthTokenManager({
  tokenUrl: "/auth/token",
  logoutUrl: "/auth/logout",
});

const authInterceptor = createAuthInterceptor(tokenManager);
```

Use the interceptor with Connect clients that should send the app bearer token.

```ts
const transport = createConnectTransport({
  baseUrl: "/api",
  interceptors: [authInterceptor],
});
```

The default `credentials` mode is `same-origin`, matching the recommended
same-host `/auth` mount. For cross-origin auth hosts, pass `credentials:
"include"` and configure CORS at the gateway or HTTP layer.
