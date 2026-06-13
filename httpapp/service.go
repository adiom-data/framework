package httpapp

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/telemetry"
)

// ServiceOption customizes a Service.
type ServiceOption func(*Service)

// Service is the normal shape for an internal Connect service.
type Service struct {
	Addr              string
	Connect           []ConnectService
	Routes            []Route
	Reflection        bool
	LivenessChecks    []Check
	ReadinessChecks   []Check
	Interceptors      []connect.Interceptor
	ConnectOptions    []connect.HandlerOption
	Middleware        []Middleware
	Logger            *slog.Logger
	Telemetry         telemetry.Config
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// NewService builds an internal Connect service with framework defaults.
func NewService(opts ...ServiceOption) Service {
	var service Service
	for _, opt := range opts {
		opt(&service)
	}
	return service
}

// WithServices adds Connect services.
func WithServices(services ...ConnectService) ServiceOption {
	return func(service *Service) {
		service.Connect = append(service.Connect, services...)
	}
}

// WithServiceRoutes adds regular HTTP routes.
func WithServiceRoutes(routes ...Route) ServiceOption {
	return func(service *Service) {
		service.Routes = append(service.Routes, routes...)
	}
}

// WithReflection enables explicit Connect reflection.
func WithReflection() ServiceOption {
	return func(service *Service) {
		service.Reflection = true
	}
}

// WithServiceLivenessChecks adds liveness checks.
func WithServiceLivenessChecks(checks ...Check) ServiceOption {
	return func(service *Service) {
		service.LivenessChecks = append(service.LivenessChecks, checks...)
	}
}

// WithServiceReadinessChecks adds readiness checks.
func WithServiceReadinessChecks(checks ...Check) ServiceOption {
	return func(service *Service) {
		service.ReadinessChecks = append(service.ReadinessChecks, checks...)
	}
}

// WithServiceInterceptors adds common Connect interceptors.
func WithServiceInterceptors(interceptors ...connect.Interceptor) ServiceOption {
	return func(service *Service) {
		service.Interceptors = append(service.Interceptors, interceptors...)
	}
}

// WithServiceConnectOptions adds common Connect handler options.
func WithServiceConnectOptions(options ...connect.HandlerOption) ServiceOption {
	return func(service *Service) {
		service.ConnectOptions = append(service.ConnectOptions, options...)
	}
}

// WithServiceMiddleware replaces the service HTTP middleware stack.
func WithServiceMiddleware(middleware ...Middleware) ServiceOption {
	return func(service *Service) {
		service.Middleware = middleware
	}
}

// WithServiceAddr overrides the default listen address.
func WithServiceAddr(addr string) ServiceOption {
	return func(service *Service) {
		service.Addr = addr
	}
}

// WithServiceLogger sets the service logger.
func WithServiceLogger(logger *slog.Logger) ServiceOption {
	return func(service *Service) {
		service.Logger = logger
	}
}

// WithServiceTelemetry overrides the service OpenTelemetry configuration.
func WithServiceTelemetry(cfg telemetry.Config) ServiceOption {
	return func(service *Service) {
		service.Telemetry = cfg
	}
}

// WithServiceTimeouts overrides server timeouts.
func WithServiceTimeouts(readHeaderTimeout, shutdownTimeout time.Duration) ServiceOption {
	return func(service *Service) {
		service.ReadHeaderTimeout = readHeaderTimeout
		service.ShutdownTimeout = shutdownTimeout
	}
}

// WithServiceIdleTimeout overrides the server idle timeout.
func WithServiceIdleTimeout(timeout time.Duration) ServiceOption {
	return func(service *Service) {
		service.IdleTimeout = timeout
	}
}

// Handler assembles the service handler.
func (s Service) Handler() http.Handler {
	return s.app().Handler()
}

// Run assembles and runs the service.
func (s Service) Run(ctx context.Context) error {
	return s.app().Run(ctx)
}

func (s Service) app() App {
	return App{
		Addr:              s.Addr,
		Routes:            s.Routes,
		Connect:           s.Connect,
		Reflection:        s.Reflection,
		LivenessChecks:    s.LivenessChecks,
		ReadinessChecks:   s.ReadinessChecks,
		Interceptors:      s.Interceptors,
		ConnectOptions:    s.ConnectOptions,
		Middleware:        s.Middleware,
		Logger:            s.Logger,
		Telemetry:         s.Telemetry,
		ReadHeaderTimeout: s.ReadHeaderTimeout,
		IdleTimeout:       s.IdleTimeout,
		ShutdownTimeout:   s.ShutdownTimeout,
	}
}
