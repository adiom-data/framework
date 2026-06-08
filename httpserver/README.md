# httpserver

`httpserver` runs composable `net/http` servers with common lifecycle defaults
and small helpers for Connect services.

For ordinary Adiom services, prefer `httpapp`. Use `httpserver` directly when a
service needs custom mux assembly or lifecycle behavior.

The package does not own routing. Build a normal `http.ServeMux`, mount regular
HTTP handlers, Connect handlers, SPA handlers, redirects, and middleware in the
application, then pass the final handler to `Server.Run`.

## Usage

```go
ctx, stop := httpserver.SignalContext(context.Background())
defer stop()

mux := http.NewServeMux()

httpserver.RegisterHealth(mux, httpserver.Health{
	Enabled: true,
})

path, handler := appv1connect.NewAppServiceHandler(api)
services := []httpserver.ConnectService{
	httpserver.Connect(appv1connect.AppServiceName, path, auth.HTTPMiddleware(handler)),
}
httpserver.RegisterConnect(mux, services...)

if cfg.Reflection {
	httpserver.RegisterReflection(mux, httpserver.ServiceNames(services...)...)
}

mux.Handle("/admin/", http.StripPrefix("/admin/", spa.DirHandler(cfg.WebDistDir)))

return httpserver.Server{
	Handler: cors(cfg.CORSOrigin, mux),
}.Run(ctx)
```

## Lifecycle

`Server.Run`:

- listens on `Addr`, or `:8080` when `Addr` is empty
- serves `Handler`
- enables HTTP/1 and unencrypted HTTP/2 by default
- enables HTTP/1 and TLS HTTP/2 when `TLSConfig` is set
- shuts down gracefully when the context is canceled
- treats `http.ErrServerClosed` as a clean stop

Defaults:

- `Addr`: `:8080`
- `ReadHeaderTimeout`: `5s`
- `IdleTimeout`: `75s`
- `ShutdownTimeout`: `10s`

Use `SignalContext` when a process should stop on `SIGINT` or `SIGTERM`.

## Health

Health uses the standard gRPC health service only. No `/healthz` HTTP mirror is
registered by this package.

The simplest Kubernetes setup uses the standard gRPC health service labels:

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

`liveness` and `readiness` report serving unless checks are configured and one
fails. With no checks, both are noop-ish and return serving. The empty service
name reports readiness.

Add dependency checks only when readiness should depend on something external:

```go
httpserver.RegisterHealth(mux, httpserver.Health{
	Enabled: true,
	ReadinessChecks: []httpserver.Check{
		httpserver.ReadinessCheck(db.Ping),
	},
})
```

Kubernetes still probes `service: readiness`; it does not know or care that
Postgres is one of the checks behind that readiness result.

Prefer readiness checks for dependencies. Add liveness checks only for concrete
stuck-process conditions that should restart the pod.

Register health directly on the mux before applying application auth middleware
to service handlers, so kubelet probes do not need app credentials.

## Reflection

Connect reflection is explicit:

```go
httpserver.RegisterReflection(mux, httpserver.ServiceNames(services...)...)
```

Do not enable reflection by default for public surfaces.
