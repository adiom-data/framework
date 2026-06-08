package httpapp

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	httpmiddleware "github.com/adiom-data/framework/httpapp/middleware"
	"github.com/adiom-data/framework/httpserver"
)

// Middleware wraps an HTTP handler. The first middleware in a list is outermost.
type Middleware = httpmiddleware.Middleware

// Check is a health dependency check.
type Check = httpserver.Check

const (
	// DefaultAddr is the default listen address for HTTP apps.
	DefaultAddr = httpserver.DefaultAddr

	// LivenessService is the Kubernetes gRPC health service label for liveness.
	LivenessService = httpserver.LivenessService
	// ReadinessService is the Kubernetes gRPC health service label for readiness.
	ReadinessService = httpserver.ReadinessService
)

// App is the shared assembly base used by Service.
// Prefer NewService for normal internal services.
type App struct {
	Addr              string
	Routes            []Route
	Connect           []ConnectService
	Reflection        bool
	LivenessChecks    []Check
	ReadinessChecks   []Check
	Interceptors      []connect.Interceptor
	ConnectOptions    []connect.HandlerOption
	Middleware        []Middleware
	Logger            *slog.Logger
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// Route is a regular HTTP route.
type Route struct {
	Pattern    string
	Handler    http.Handler
	Middleware []Middleware
}

// ConnectService is a generated Connect service handler factory plus service
// specific options.
type ConnectService struct {
	Name           string
	NewHandler     func(...connect.HandlerOption) (string, http.Handler)
	Interceptors   []connect.Interceptor
	ConnectOptions []connect.HandlerOption
	Middleware     []Middleware
}

// SignalContext returns a context canceled on SIGINT or SIGTERM.
func SignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return httpserver.SignalContext(parent)
}

// ReadinessCheck adapts fn into a readiness check.
func ReadinessCheck(fn func(context.Context) error) Check {
	return httpserver.ReadinessCheck(fn)
}

// LivenessCheck adapts fn into a liveness check.
func LivenessCheck(fn func(context.Context) error) Check {
	return httpserver.LivenessCheck(fn)
}

// RouteOption customizes a route.
type RouteOption func(*Route)

// ConnectOption customizes a Connect service.
type ConnectOption func(*ConnectService)

// Handle builds a regular HTTP route.
func Handle(pattern string, handler http.Handler, opts ...RouteOption) Route {
	route := Route{
		Pattern: pattern,
		Handler: handler,
	}
	for _, opt := range opts {
		opt(&route)
	}
	return route
}

// Connect builds a Connect service registration.
func Connect(name string, newHandler func(...connect.HandlerOption) (string, http.Handler), opts ...ConnectOption) ConnectService {
	service := ConnectService{
		Name:       name,
		NewHandler: newHandler,
	}
	for _, opt := range opts {
		opt(&service)
	}
	return service
}

// WithMiddleware adds HTTP middleware to a route.
func WithMiddleware(middleware ...Middleware) RouteOption {
	return func(route *Route) {
		route.Middleware = append(route.Middleware, middleware...)
	}
}

// WithConnectMiddleware adds HTTP middleware to a Connect service.
func WithConnectMiddleware(middleware ...Middleware) ConnectOption {
	return func(service *ConnectService) {
		service.Middleware = append(service.Middleware, middleware...)
	}
}

// WithInterceptors adds Connect interceptors to a Connect service.
func WithInterceptors(interceptors ...connect.Interceptor) ConnectOption {
	return func(service *ConnectService) {
		service.Interceptors = append(service.Interceptors, interceptors...)
	}
}

// WithConnectOptions adds Connect handler options to a Connect service.
func WithConnectOptions(options ...connect.HandlerOption) ConnectOption {
	return func(service *ConnectService) {
		service.ConnectOptions = append(service.ConnectOptions, options...)
	}
}

// Handler assembles the application handler.
func (a App) Handler() http.Handler {
	mux := http.NewServeMux()

	for _, route := range a.Routes {
		mux.Handle(route.Pattern, applyMiddleware(route.Handler, route.Middleware...))
	}

	services := make([]httpserver.ConnectService, 0, len(a.Connect))
	for _, service := range a.Connect {
		path, handler := service.NewHandler(a.connectOptions(service)...)
		services = append(services, httpserver.Connect(
			service.Name,
			path,
			applyMiddleware(handler, service.Middleware...),
		))
	}
	httpserver.RegisterConnect(mux, services...)

	serviceNames := httpserver.ServiceNames(services...)
	if a.Reflection {
		httpserver.RegisterReflection(mux, serviceNames...)
	}
	appHandler := applyMiddleware(mux, a.middleware()...)

	root := http.NewServeMux()
	httpserver.RegisterHealth(root, httpserver.Health{
		Enabled:         true,
		LivenessChecks:  a.LivenessChecks,
		ReadinessChecks: a.ReadinessChecks,
		ServiceNames:    serviceNames,
	})
	root.Handle("/", appHandler)
	return root
}

// Run assembles and runs the app server.
func (a App) Run(ctx context.Context) error {
	return httpserver.Server{
		Addr:              a.Addr,
		Handler:           a.Handler(),
		Logger:            a.logger(),
		ReadHeaderTimeout: a.ReadHeaderTimeout,
		IdleTimeout:       a.IdleTimeout,
		ShutdownTimeout:   a.ShutdownTimeout,
	}.Run(ctx)
}

func (a App) connectOptions(service ConnectService) []connect.HandlerOption {
	options := make([]connect.HandlerOption, 0, len(a.ConnectOptions)+len(service.ConnectOptions)+1)
	options = append(options, a.ConnectOptions...)
	interceptors := make([]connect.Interceptor, 0, len(a.Interceptors)+len(service.Interceptors))
	interceptors = append(interceptors, a.Interceptors...)
	interceptors = append(interceptors, service.Interceptors...)
	if len(interceptors) > 0 {
		options = append(options, connect.WithInterceptors(interceptors...))
	}
	options = append(options, service.ConnectOptions...)
	return options
}

func (a App) middleware() []Middleware {
	if a.Middleware != nil {
		return a.Middleware
	}
	return httpmiddleware.Default(a.logger())
}

func (a App) logger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}

func applyMiddleware(handler http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		if middleware[i] != nil {
			handler = middleware[i](handler)
		}
	}
	return handler
}
