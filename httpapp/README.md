# httpapp

`httpapp` assembles normal Adiom HTTP services with framework defaults.

Use `httpapp.Service` for internal Connect services. Use `httpapp.App` directly
when a service needs a custom mix of Connect services and regular HTTP routes.

## Service

```go
ctx, stop := httpapp.SignalContext(context.Background())
defer stop()

runtime, err := httpapp.Init(ctx)
if err != nil {
	return err
}
defer runtime.Shutdown(context.Background())

return runtime.NewService(
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

## Wiring

Initialize the framework before constructing outbound clients. That lets client
interceptors capture the real telemetry providers instead of the default noop
providers.

```go
ctx, stop := httpapp.SignalContext(context.Background())
defer stop()

runtime, err := httpapp.Init(ctx)
if err != nil {
	return err
}
defer runtime.Shutdown(context.Background())

clientOpts, err := runtime.ConnectClientOptions()
if err != nil {
	return err
}
upstream := appv1connect.NewAppServiceClient(
	runtime.HTTPClient(nil),
	"http://upstream-service",
	clientOpts...,
)

api := NewAPI(upstream)

return runtime.NewService(
	httpapp.WithServices(
		httpapp.Connect(
			appv1connect.AppServiceName,
			func(opts ...connect.HandlerOption) (string, http.Handler) {
				return appv1connect.NewAppServiceHandler(api, opts...)
			},
		),
	),
	httpapp.WithServiceRoutes(
		httpapp.Handle("/admin/", http.StripPrefix("/admin/", spa.DirHandler(webDir))),
	),
).Run(ctx)
```

Use `runtime.ConnectClientOptions()` for generated Connect clients and
`runtime.HTTPClient(nil)` for raw outbound HTTP. Use `runtime.NewService` so the
service shares the runtime telemetry configuration.

## Defaults

`Service` and `App` automatically:

- enable HTTP/1 and unencrypted HTTP/2
- install standard gRPC health
- register `liveness` and `readiness` health labels for Kubernetes probes
- recover panics and log requests
- install OpenTelemetry HTTP server instrumentation
- gracefully shut down when the context is canceled

Reflection is explicit and disabled by default.

If `Addr` is empty, the app listens on `:8080`.

## Telemetry

`httpapp.Init` sets up OpenTelemetry traces and metrics by default. `Service.Run`
and `App.Run` also set up telemetry when `Init` was not called, so simple
services still get telemetry automatically.
The default OTLP/HTTP collector endpoint is `http://otel-collector:4318`, which
matches the tenant namespace collector service. Exporters send traces to
`/v1/traces` and metrics to `/v1/metrics`.

Connect services get `connectrpc.com/otelconnect` instrumentation automatically,
including RPC spans, trace context propagation, and RPC metrics such as
`rpc.server.duration`, request size, response size, and messages per RPC.
Regular HTTP routes get `otelhttp` instrumentation. Connect routes are filtered
out of the generic HTTP middleware so they do not emit duplicate HTTP and RPC
server spans.

The framework propagator is W3C Trace Context plus Baggage. Incoming Connect
trace contexts are trusted so gateway and service spans stay in one trace.
For outbound generated Connect clients, pass `telemetry.ConnectClientOptions`
into the client constructor, or use `runtime.ConnectClientOptions()` after
`httpapp.Init`. For raw outbound HTTP, use `runtime.HTTPClient(nil)` or
`telemetry.HTTPClient`.

The service name defaults to `OTEL_SERVICE_NAME`, then the executable name. Set
it explicitly when constructing services:

```go
httpapp.NewService(
	httpapp.WithServiceTelemetry(telemetry.DefaultConfig("platform-manager")),
)
```

Useful environment overrides:

- `OTEL_SDK_DISABLED=true` disables framework telemetry.
- `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318` overrides the base endpoint.
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` override individual signal endpoints.
- `OTEL_TRACES_EXPORTER=none` or `OTEL_METRICS_EXPORTER=none` disables one signal.

For local tests or tools that should stay quiet:

```go
httpapp.NewService(
	httpapp.WithServiceTelemetry(telemetry.DisabledConfig()),
)
```

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
