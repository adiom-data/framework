package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	// DefaultEndpoint is the in-namespace OTLP/HTTP collector endpoint.
	DefaultEndpoint = "http://otel-collector:4318"

	// DefaultMetricInterval is how often metrics are exported.
	DefaultMetricInterval = 30 * time.Second
	// DefaultExportTimeout bounds one telemetry export attempt.
	DefaultExportTimeout = 5 * time.Second
	// DefaultShutdownTimeout bounds provider shutdown.
	DefaultShutdownTimeout = 5 * time.Second
)

// Config controls framework OpenTelemetry setup.
type Config struct {
	// Enabled controls whether telemetry is installed. If nil, telemetry is
	// enabled unless OTEL_SDK_DISABLED is true.
	Enabled *bool

	// ServiceName becomes the service.name resource attribute. If empty, the
	// value comes from OTEL_SERVICE_NAME or the executable name.
	ServiceName string

	// Endpoint is the OTLP/HTTP base endpoint. If empty, OTEL_EXPORTER_OTLP_ENDPOINT
	// is used, then DefaultEndpoint.
	Endpoint string

	// TracesEnabled and MetricsEnabled can disable individual signals. If nil,
	// the signal is enabled unless the matching OTEL_*_EXPORTER env var is none.
	TracesEnabled  *bool
	MetricsEnabled *bool

	// Headers are sent with OTLP exporter requests.
	Headers map[string]string

	// ResourceAttributes are added to every exported metric and span.
	ResourceAttributes map[string]string

	MetricInterval  time.Duration
	ExportTimeout   time.Duration
	ShutdownTimeout time.Duration

	// SampleRatio sets parent-based root trace sampling. Nil samples all root
	// traces. Use SampleRatioValue to allow an explicit 0% sample ratio.
	SampleRatio *float64
}

// Shutdown flushes and stops telemetry providers.
type Shutdown func(context.Context) error

var setupState globalSetup

type globalSetup struct {
	mu     sync.Mutex
	active bool
}

// DefaultConfig returns the default framework telemetry configuration for a service.
func DefaultConfig(serviceName string) Config {
	return Config{ServiceName: serviceName}
}

// DisabledConfig returns a configuration that disables telemetry.
func DisabledConfig() Config {
	enabled := false
	return Config{Enabled: &enabled}
}

// SampleRatioValue returns a SampleRatio pointer for Config literals.
func SampleRatioValue(ratio float64) *float64 {
	return &ratio
}

// Setup installs OpenTelemetry providers and returns a shutdown function.
func Setup(ctx context.Context, cfg Config) (Shutdown, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg = cfg.defaults()
	if !cfg.enabled() || !cfg.signalsEnabled() {
		return func(context.Context) error { return nil }, nil
	}

	setupState.mu.Lock()
	if setupState.active {
		setupState.mu.Unlock()
		return func(context.Context) error { return nil }, nil
	}

	res := cfg.resource()
	var shutdowns []Shutdown
	var tp *sdktrace.TracerProvider
	var mp *metric.MeterProvider

	if cfg.tracesEnabled() {
		exporter, err := otlptracehttp.New(ctx, cfg.traceExporterOptions()...)
		if err != nil {
			setupState.mu.Unlock()
			return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
		}
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(cfg.sampler()),
		)
		shutdowns = append(shutdowns, tp.Shutdown)
	}

	if cfg.metricsEnabled() {
		exporter, err := otlpmetrichttp.New(ctx, cfg.metricExporterOptions()...)
		if err != nil {
			_ = shutdownAll(ctx, shutdowns)
			setupState.mu.Unlock()
			return nil, fmt.Errorf("create OTLP metric exporter: %w", err)
		}
		reader := metric.NewPeriodicReader(
			exporter,
			metric.WithInterval(cfg.metricInterval()),
			metric.WithTimeout(cfg.exportTimeout()),
		)
		mp = metric.NewMeterProvider(
			metric.WithReader(reader),
			metric.WithResource(res),
			metric.WithView(lowCardinalityMetricViews()...),
		)
		shutdowns = append(shutdowns, mp.Shutdown)
	}

	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()
	previousPropagator := otel.GetTextMapPropagator()
	if tp != nil {
		otel.SetTracerProvider(tp)
	}
	if mp != nil {
		otel.SetMeterProvider(mp)
	}
	otel.SetTextMapPropagator(Propagator())

	shutdown := func(ctx context.Context) error {
		setupState.mu.Lock()
		if !setupState.active {
			setupState.mu.Unlock()
			return nil
		}
		setupState.active = false
		setupState.mu.Unlock()
		if tp != nil {
			otel.SetTracerProvider(previousTracerProvider)
		}
		if mp != nil {
			otel.SetMeterProvider(previousMeterProvider)
		}
		otel.SetTextMapPropagator(previousPropagator)
		return shutdownAll(ctx, shutdowns)
	}
	setupState.active = true
	setupState.mu.Unlock()

	return func(ctx context.Context) error {
		return shutdown(ctx)
	}, nil
}

// Propagator returns the framework trace context propagator.
func Propagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

// StartSpan starts a child span using the caller package as the instrumentation
// scope. The span name should be a stable operation name, not user input.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "operation"
	}
	return tracerForCaller(1).Start(ctx, name, opts...)
}

// Middleware returns HTTP server instrumentation middleware. Filters can be
// used to skip requests that are instrumented at a richer protocol layer.
func Middleware(cfg Config, filters ...func(*http.Request) bool) func(http.Handler) http.Handler {
	cfg = cfg.defaults()
	if !cfg.enabled() || !cfg.signalsEnabled() {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		options := []otelhttp.Option{
			otelhttp.WithPropagators(Propagator()),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return httpSpanName(r)
			}),
		}
		for _, filter := range filters {
			if filter != nil {
				options = append(options, otelhttp.WithFilter(filter))
			}
		}
		return otelhttp.NewHandler(
			next,
			cfg.serviceName(),
			options...,
		)
	}
}

// ConnectInterceptor returns Connect RPC tracing and metrics instrumentation.
func ConnectInterceptor(cfg Config) (connect.Interceptor, error) {
	cfg = cfg.defaults()
	if !cfg.enabled() || !cfg.signalsEnabled() {
		return nil, nil
	}
	options := []otelconnect.Option{
		otelconnect.WithPropagator(Propagator()),
		otelconnect.WithTrustRemote(),
		otelconnect.WithoutTraceEvents(),
		otelconnect.WithoutServerPeerAttributes(),
	}
	if !cfg.tracesEnabled() {
		options = append(options, otelconnect.WithoutTracing())
	}
	if !cfg.metricsEnabled() {
		options = append(options, otelconnect.WithoutMetrics())
	}
	return otelconnect.NewInterceptor(options...)
}

// ConnectClientOptions returns Connect client options for RPC tracing, metrics,
// and trace context injection.
func ConnectClientOptions(cfg Config) ([]connect.ClientOption, error) {
	interceptor, err := ConnectInterceptor(cfg)
	if err != nil || interceptor == nil {
		return nil, err
	}
	return []connect.ClientOption{connect.WithInterceptors(interceptor)}, nil
}

// HTTPClient returns a client whose transport emits outbound HTTP telemetry.
func HTTPClient(cfg Config, client *http.Client) *http.Client {
	cfg = cfg.defaults()
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	if cfg.enabled() && cfg.signalsEnabled() {
		copy.Transport = otelhttp.NewTransport(copy.Transport, otelhttp.WithPropagators(Propagator()))
	}
	return &copy
}

func tracerForCaller(skip int) trace.Tracer {
	scope := callerScope(skip + 1)
	return otel.Tracer(scope)
}

func callerScope(skip int) string {
	pc, _, _, ok := runtime.Caller(skip + 1)
	if !ok {
		return "github.com/adiom-data/framework/telemetry"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "github.com/adiom-data/framework/telemetry"
	}
	return packagePath(fn.Name())
}

func packagePath(function string) string {
	if function == "" {
		return "github.com/adiom-data/framework/telemetry"
	}
	start := strings.LastIndex(function, "/") + 1
	if dot := strings.Index(function[start:], "."); dot >= 0 {
		return function[:start+dot]
	}
	return function
}

func httpSpanName(r *http.Request) string {
	route := ""
	if r != nil {
		route = r.Pattern
	}
	if strings.TrimSpace(route) == "" {
		route = "unknown_route"
	}
	method := "HTTP"
	if r != nil && strings.TrimSpace(r.Method) != "" {
		method = r.Method
	}
	return method + " " + route
}

func lowCardinalityMetricViews() []metric.View {
	return []metric.View{
		metric.NewView(
			metric.Instrument{
				Name:  "http.server.*",
				Scope: instrumentation.Scope{Name: otelhttp.ScopeName},
			},
			metric.Stream{AttributeFilter: attribute.NewAllowKeysFilter(
				"http.request.method",
				"http.response.status_code",
				"http.route",
			)},
		),
		metric.NewView(
			metric.Instrument{
				Name:  "http.client.*",
				Scope: instrumentation.Scope{Name: otelhttp.ScopeName},
			},
			metric.Stream{AttributeFilter: attribute.NewAllowKeysFilter(
				"http.request.method",
				"http.response.status_code",
			)},
		),
		metric.NewView(
			metric.Instrument{
				Name:  "rpc.*.*",
				Scope: instrumentation.Scope{Name: "connectrpc.com/otelconnect"},
			},
			metric.Stream{AttributeFilter: attribute.NewAllowKeysFilter(
				"rpc.system",
				"rpc.service",
				"rpc.method",
				"rpc.grpc.status_code",
				"rpc.connect_rpc.error_code",
				"http.response.status_code",
			)},
		),
	}
}

func (c Config) defaults() Config {
	if c.ServiceName == "" {
		c.ServiceName = os.Getenv("OTEL_SERVICE_NAME")
	}
	if c.Endpoint == "" {
		c.Endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if c.Endpoint == "" {
		c.Endpoint = DefaultEndpoint
	}
	if len(c.Headers) == 0 {
		c.Headers = parseHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
	}
	if c.SampleRatio == nil {
		if ratio, ok := parseFloat(os.Getenv("OTEL_TRACES_SAMPLER_ARG")); ok {
			c.SampleRatio = &ratio
		}
	}
	return c
}

func (c Config) enabled() bool {
	if c.Enabled != nil {
		return *c.Enabled
	}
	return !envBool("OTEL_SDK_DISABLED")
}

func (c Config) tracesEnabled() bool {
	if c.TracesEnabled != nil {
		return *c.TracesEnabled
	}
	return strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER"))) != "none"
}

func (c Config) metricsEnabled() bool {
	if c.MetricsEnabled != nil {
		return *c.MetricsEnabled
	}
	return strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_METRICS_EXPORTER"))) != "none"
}

func (c Config) signalsEnabled() bool {
	return c.tracesEnabled() || c.metricsEnabled()
}

func (c Config) serviceName() string {
	if strings.TrimSpace(c.ServiceName) != "" {
		return strings.TrimSpace(c.ServiceName)
	}
	name := filepath.Base(os.Args[0])
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "adiom-service"
	}
	return name
}

func (c Config) metricInterval() time.Duration {
	if c.MetricInterval > 0 {
		return c.MetricInterval
	}
	return DefaultMetricInterval
}

func (c Config) exportTimeout() time.Duration {
	if c.ExportTimeout > 0 {
		return c.ExportTimeout
	}
	return DefaultExportTimeout
}

func (c Config) resource() *resource.Resource {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", c.serviceName()),
	}
	for key, value := range c.ResourceAttributes {
		if strings.TrimSpace(key) != "" {
			attrs = append(attrs, attribute.String(key, value))
		}
	}
	return resource.NewSchemaless(attrs...)
}

func (c Config) sampler() sdktrace.Sampler {
	if c.SampleRatio == nil {
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
	ratio := *c.SampleRatio
	if ratio <= 0 {
		return sdktrace.ParentBased(sdktrace.NeverSample())
	}
	if ratio >= 1 {
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
}

func (c Config) traceExporterOptions() []otlptracehttp.Option {
	options := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(c.signalEndpoint("traces")),
		otlptracehttp.WithTimeout(c.exportTimeout()),
	}
	if len(c.Headers) > 0 {
		options = append(options, otlptracehttp.WithHeaders(c.Headers))
	}
	return options
}

func (c Config) metricExporterOptions() []otlpmetrichttp.Option {
	options := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpointURL(c.signalEndpoint("metrics")),
		otlpmetrichttp.WithTimeout(c.exportTimeout()),
	}
	if len(c.Headers) > 0 {
		options = append(options, otlpmetrichttp.WithHeaders(c.Headers))
	}
	return options
}

func (c Config) signalEndpoint(signal string) string {
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_" + strings.ToUpper(signal) + "_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	base := strings.TrimRight(c.Endpoint, "/")
	if strings.HasSuffix(base, "/v1/"+signal) {
		return base
	}
	return base + "/v1/" + signal
}

func parseHeaders(value string) map[string]string {
	if value == "" {
		return nil
	}
	headers := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		if key != "" {
			headers[key] = value
		}
	}
	return headers
}

func shutdownAll(ctx context.Context, shutdowns []Shutdown) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var err error
	for i := len(shutdowns) - 1; i >= 0; i-- {
		err = errors.Join(err, shutdowns[i](ctx))
	}
	return err
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "t", "true", "y", "yes":
		return true
	default:
		return false
	}
}

func parseFloat(value string) (float64, bool) {
	if strings.TrimSpace(value) == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	return parsed, err == nil
}
