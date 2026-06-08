# httpapp

`httpapp` assembles normal Adiom HTTP services with framework defaults.

Use `httpapp.Service` for internal Connect services. Use `httpapp.App` directly
when a service needs a custom mix of Connect services and regular HTTP routes.

## Service

```go
ctx, stop := httpapp.SignalContext(context.Background())
defer stop()

return httpapp.NewService(
	httpapp.WithServices(
		httpapp.Connect(
			appv1connect.AppServiceName,
			func(opts ...connect.HandlerOption) (string, http.Handler) {
				return appv1connect.NewAppServiceHandler(api, opts...)
			},
			httpapp.WithInterceptors(authInterceptor),
		),
	),
	httpapp.WithServiceRoutes(
		httpapp.Handle("/admin/", http.StripPrefix("/admin/", spa.DirHandler(webDir))),
	),
	httpapp.WithServiceReadinessChecks(
		httpapp.ReadinessCheck(db.Ping),
	),
	httpapp.WithReflection(),
).Run(ctx)
```

## Routes

Regular HTTP routes are explicit handlers:

```go
httpapp.Handle("/oauth/callback", callbackHandler)
```

## Defaults

`Service` and `App` automatically:

- enable HTTP/1 and unencrypted HTTP/2
- install standard gRPC health
- register `liveness` and `readiness` health labels for Kubernetes probes
- recover panics and log requests
- gracefully shut down when the context is canceled

Reflection is explicit and disabled by default.

If `Addr` is empty, the app listens on `:8080`.

## Kubernetes Health

Use Kubernetes gRPC probes against the same service port:

```yaml
livenessProbe:
  grpc:
    port: 8080
    service: liveness
readinessProbe:
  grpc:
    port: 8080
    service: readiness
```

`ReadinessChecks` back the `readiness` health label. Kubernetes does not need to
know the individual dependency names.

`LivenessChecks` are also available, but leave them empty unless the service has
a concrete stuck-process condition that should restart the pod. With no checks,
both liveness and readiness return serving.

## Customization

Common Connect interceptors apply to every Connect service:

```go
httpapp.NewService(
	httpapp.WithServiceInterceptors(traceInterceptor),
)
```

Service-specific interceptors apply after common interceptors:

```go
httpapp.Connect(
	userv1connect.UserServiceName,
	func(opts ...connect.HandlerOption) (string, http.Handler) {
		return userv1connect.NewUserServiceHandler(userSvc, opts...)
	},
	httpapp.WithInterceptors(authInterceptor),
)
```

Use HTTP middleware for regular HTTP concerns:

```go
stack := append(middleware.Default(logger), cors, addRequestID)

httpapp.NewService(
	httpapp.WithServiceMiddleware(stack...),
)
```

Tune server timeouts when a service needs to override defaults:

```go
httpapp.NewService(
	httpapp.WithServiceIdleTimeout(75 * time.Second),
)
```

Per-route and per-service middleware wraps only that route or service. Standard
gRPC health bypasses HTTP middleware so Kubernetes probes do not need
application credentials.
