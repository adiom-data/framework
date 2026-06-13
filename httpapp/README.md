# httpapp

`httpapp` assembles normal Adiom HTTP services with framework defaults.

Use `httpapp.Service` for internal Connect services. Use `httpapp.App` directly
when a service needs a custom mix of Connect services and regular HTTP routes.

## Service

```go
runtime, err := httpapp.Init(
	context.Background(),
	httpapp.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
)
if err != nil {
	return err
}
defer runtime.Shutdown(context.Background())

return runtime.NewService(
	httpapp.WithServices(
		httpapp.ConnectHandler(
			appv1connect.AppServiceName,
			appv1connect.NewAppServiceHandler,
			api,
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
).Run(runtime.Context())
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
runtime, err := httpapp.Init(context.Background())
if err != nil {
	return err
}
defer runtime.Shutdown(context.Background())

clientOpts, err := runtime.ConnectClientOptions()
if err != nil {
	return err
}
upstream := appv1connect.NewAppServiceClient(
	runtime.ConnectHTTPClient(),
	"http://upstream-service",
	clientOpts...,
)

api := NewAPI(upstream)

return runtime.NewService(
	httpapp.WithServices(
		httpapp.ConnectHandler(
			appv1connect.AppServiceName,
			appv1connect.NewAppServiceHandler,
			api,
		),
	),
	httpapp.WithServiceRoutes(
		httpapp.Handle("/admin/", http.StripPrefix("/admin/", spa.DirHandler(webDir))),
	),
).Run(runtime.Context())
```

Use `runtime.Context()` for server lifetime, `runtime.ConnectClientOptions()`
with `runtime.ConnectHTTPClient()` for generated Connect clients, and
`runtime.HTTPClient()` for raw outbound HTTP. Configure shared outbound HTTP
settings once with `httpapp.WithHTTPClient(...)`. Use `runtime.NewService` so
the service shares the runtime telemetry configuration.

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

`httpapp.Init` sets up signal handling, OpenTelemetry traces, metrics, and the
default logger. `Service.Run` and `App.Run` also set up telemetry when `Init`
was not called, so simple services still get telemetry automatically.
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
`httpapp.Init`. Pass `runtime.ConnectHTTPClient()` to generated Connect clients;
the Connect interceptor emits RPC client telemetry and propagates trace context.
For raw outbound HTTP, use `runtime.HTTPClient()` or `telemetry.HTTPClient`.

Root trace sampling is parent-based and defaults to sampling all new root
traces. Downstream services honor the upstream sampled bit. Configure root
sampling with `SampleRatioValue`, including explicit 0% sampling:

```go
runtime, err := httpapp.Init(
	context.Background(),
	httpapp.WithTelemetry(telemetry.Config{
		ServiceName: "platform-manager",
		SampleRatio: telemetry.SampleRatioValue(0.10),
	}),
)
```

Use `telemetry.SampleRatioValue(0)` for 0% root sampling while still honoring
sampled upstream parents.

Add custom spans around application operations with a stable span name:

```go
ctx, span := telemetry.StartSpan(ctx, "CreateNamespace")
defer span.End()
```

The framework derives the instrumentation scope from the caller package. Span
names should be bounded operation names, not user input, IDs, or raw paths.

`httpapp.Init` installs a structured default logger wrapped with
`telemetry.TraceLogHandler`, so package-level `slog.InfoContext(ctx, ...)`
includes framework log fields and trace correlation. To customize the logger,
pass one to `Init`:

```go
logger := telemetry.NewLogger(slog.NewJSONHandler(os.Stdout, nil))

runtime, err := httpapp.Init(context.Background(), httpapp.WithLogger(logger))
if err != nil {
	return err
}
defer runtime.Shutdown(context.Background())

return runtime.NewService(
	// ...
).Run(runtime.Context())
```

To suppress low-severity application logs when the current trace is not sampled,
wrap the output handler with `telemetry.SampledLogHandler`:

```go
logger := telemetry.NewLogger(
	telemetry.SampledLogHandler(slog.NewJSONHandler(os.Stdout, nil)),
)
```

By default, unsampled traces suppress logs below `Warn`; warnings, errors,
sampled traces, and logs without trace context still emit.

Request-specific log fields live in `ctx`. Use `ContextWithLogAttrs` as
middleware and handlers learn more scope, then log normally with any wrapped
logger:

```go
ctx = telemetry.ContextWithLogAttrs(ctx, "tenant_id", tenantID)

logger.InfoContext(ctx, "loaded workspace", "workspace_id", workspaceID)
```

If the framework logger is the default logger, package-level slog calls work
too:

```go
slog.InfoContext(ctx, "loaded workspace", "workspace_id", workspaceID)
```

Components with their own logger should use a logger built from
`telemetry.TraceLogHandler` or derived from the service logger with
`logger.With(...)`, then call `InfoContext`, `ErrorContext`, and the other
context-aware slog methods. Static component fields can live on the logger;
request fields and trace/span IDs come from `ctx`.

For APIs that accept a logger but do not pass `ctx` to each log call, snapshot
the current context into a child logger:

```go
scopedLogger := telemetry.LoggerWithContext(ctx, logger)
component := NewComponent(scopedLogger)
```

Use that form only at boundaries with context-less logging APIs. In normal
request code, prefer `InfoContext(ctx, ...)` so child spans and added context
fields are read at the moment of the log call.

When `ctx` contains an active span, the logger adds `trace_id`, `span_id`, and
`trace_sampled` fields at log-call time. The log collector should parse JSON
logs and preserve those fields so the log backend can link or query logs by
trace ID.

Framework telemetry keeps built-in metric dimensions low-cardinality. HTTP
server metrics keep method, status, and route pattern. HTTP client metrics keep
method and status. RPC metrics keep system, service, method, and status/error
code. Connect trace events and peer address attributes are omitted by default.

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
httpapp.ConnectHandler(
	userv1connect.UserServiceName,
	userv1connect.NewUserServiceHandler,
	userSvc,
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
