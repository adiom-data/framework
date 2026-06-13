package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestDefaultsUseNamespaceCollector(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_SERVICE_NAME", "")

	cfg := Config{}.defaults()

	if got := cfg.Endpoint; got != DefaultEndpoint {
		t.Fatalf("Endpoint=%q want %q", got, DefaultEndpoint)
	}
	if got := cfg.signalEndpoint("traces"); got != DefaultEndpoint+"/v1/traces" {
		t.Fatalf("trace endpoint=%q", got)
	}
	if got := cfg.signalEndpoint("metrics"); got != DefaultEndpoint+"/v1/metrics" {
		t.Fatalf("metric endpoint=%q", got)
	}
}

func TestEnvironmentCanDisableTelemetry(t *testing.T) {
	t.Setenv("OTEL_SDK_DISABLED", "true")

	if (Config{}).defaults().enabled() {
		t.Fatal("telemetry should be disabled by OTEL_SDK_DISABLED")
	}
}

func TestSetupShutdownRestoresGlobals(t *testing.T) {
	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()
	previousPropagator := otel.GetTextMapPropagator()
	restored := false
	t.Cleanup(func() {
		if !restored {
			otel.SetTracerProvider(previousTracerProvider)
			otel.SetMeterProvider(previousMeterProvider)
			otel.SetTextMapPropagator(previousPropagator)
			setupState.mu.Lock()
			setupState.active = false
			setupState.mu.Unlock()
		}
	})

	metricsEnabled := false
	shutdown, err := Setup(context.Background(), Config{
		ServiceName:    "test",
		MetricsEnabled: &metricsEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := otel.GetTracerProvider(); got == previousTracerProvider {
		t.Fatal("tracer provider was not installed")
	}

	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored = true
	if got := otel.GetTracerProvider(); got != previousTracerProvider {
		t.Fatalf("tracer provider was not restored after shutdown: %T", got)
	}
	if got := otel.GetMeterProvider(); got != previousMeterProvider {
		t.Fatalf("meter provider changed after shutdown: %T", got)
	}
	setupState.mu.Lock()
	active := setupState.active
	setupState.mu.Unlock()
	if active {
		t.Fatal("setup state remained active after shutdown")
	}
}

func TestDisabledMiddlewareReturnsHandler(t *testing.T) {
	handler := handlerStub{}
	wrapped := Middleware(DisabledConfig())(handler)

	if wrapped != handler {
		t.Fatal("disabled middleware should return the original handler")
	}
}

func TestMiddlewareReturnsHandlerWhenSignalsDisabled(t *testing.T) {
	handler := handlerStub{}
	tracesEnabled := false
	metricsEnabled := false
	wrapped := Middleware(Config{
		TracesEnabled:  &tracesEnabled,
		MetricsEnabled: &metricsEnabled,
	})(handler)

	if wrapped != handler {
		t.Fatal("middleware should return the original handler when both signals are disabled")
	}
}

func TestConnectInterceptorFollowsTelemetryEnabled(t *testing.T) {
	interceptor, err := ConnectInterceptor(DefaultConfig("api"))
	if err != nil {
		t.Fatal(err)
	}
	if interceptor == nil {
		t.Fatal("ConnectInterceptor returned nil")
	}

	interceptor, err = ConnectInterceptor(DisabledConfig())
	if err != nil {
		t.Fatal(err)
	}
	if interceptor != nil {
		t.Fatal("disabled ConnectInterceptor should return nil")
	}
}

func TestConnectClientOptionsFollowTelemetryEnabled(t *testing.T) {
	options, err := ConnectClientOptions(DefaultConfig("api"))
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 1 {
		t.Fatalf("ConnectClientOptions len=%d want 1", len(options))
	}

	options, err = ConnectClientOptions(DisabledConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 0 {
		t.Fatalf("disabled ConnectClientOptions len=%d want 0", len(options))
	}
}

func TestPropagatorInjectsTraceContextAndBaggage(t *testing.T) {
	fields := Propagator().Fields()
	if !contains(fields, "traceparent") {
		t.Fatalf("propagator fields=%v missing traceparent", fields)
	}
	if !contains(fields, "baggage") {
		t.Fatalf("propagator fields=%v missing baggage", fields)
	}

	var _ propagation.TextMapPropagator = Propagator()
}

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig("api").defaults()

	if got := cfg.serviceName(); got != "api" {
		t.Fatalf("serviceName=%q want api", got)
	}
	if got := cfg.metricInterval(); got != DefaultMetricInterval {
		t.Fatalf("metricInterval=%s want %s", got, DefaultMetricInterval)
	}
	cfg.MetricInterval = time.Second
	if got := cfg.metricInterval(); got != time.Second {
		t.Fatalf("metricInterval override=%s want 1s", got)
	}
}

func TestSamplerAllowsExplicitZeroPercentRootSampling(t *testing.T) {
	sampler := Config{SampleRatio: SampleRatioValue(0)}.sampler()
	decision := sampler.ShouldSample(sdktrace.SamplingParameters{
		ParentContext: context.Background(),
		TraceID:       trace.TraceID{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		Name:          "root",
	}).Decision

	if decision != sdktrace.Drop {
		t.Fatalf("root sampling decision=%v want drop", decision)
	}
}

func TestSamplerHonorsSampledParentWithZeroPercentRootSampling(t *testing.T) {
	parent := trace.ContextWithRemoteSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		SpanID:     trace.SpanID{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	}))
	sampler := Config{SampleRatio: SampleRatioValue(0)}.sampler()
	decision := sampler.ShouldSample(sdktrace.SamplingParameters{
		ParentContext: parent,
		TraceID:       trace.TraceID{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
		Name:          "child",
	}).Decision

	if decision != sdktrace.RecordAndSample {
		t.Fatalf("child sampling decision=%v want record and sample", decision)
	}
}

func TestStartSpanUsesCallerScope(t *testing.T) {
	previous := otel.GetTracerProvider()
	defer otel.SetTracerProvider(previous)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(provider)

	_, span := StartSpan(context.Background(), "CreateNamespace")
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d want 1", len(spans))
	}
	if got := spans[0].Name(); got != "CreateNamespace" {
		t.Fatalf("span name=%q want CreateNamespace", got)
	}
	if got := spans[0].InstrumentationScope().Name; got != "github.com/adiom-data/framework/telemetry" {
		t.Fatalf("instrumentation scope=%q", got)
	}
}

func TestPackagePath(t *testing.T) {
	tests := map[string]string{
		"main.main": "main",
		"github.com/adiom-data/platform/manager.CreateNamespace":  "github.com/adiom-data/platform/manager",
		"github.com/adiom-data/platform/manager.(*API).Create":    "github.com/adiom-data/platform/manager",
		"github.com/adiom-data/platform/manager/internal/api.run": "github.com/adiom-data/platform/manager/internal/api",
	}
	for input, want := range tests {
		if got := packagePath(input); got != want {
			t.Fatalf("packagePath(%q)=%q want %q", input, got, want)
		}
	}
}

func TestHTTPSpanNameUsesRoutePattern(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "/workspaces/123", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Pattern = "/workspaces/{workspaceID}"

	if got := httpSpanName(request); got != "GET /workspaces/{workspaceID}" {
		t.Fatalf("httpSpanName=%q", got)
	}

	request.Pattern = ""
	if got := httpSpanName(request); got != "GET unknown_route" {
		t.Fatalf("fallback httpSpanName=%q", got)
	}
}

func TestMiddlewareNamesHTTPSpanWithRoutePattern(t *testing.T) {
	previous := otel.GetTracerProvider()
	defer otel.SetTracerProvider(previous)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(provider)

	metricsEnabled := false
	mux := http.NewServeMux()
	mux.Handle("/workspaces/{workspaceID}", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := Middleware(Config{MetricsEnabled: &metricsEnabled})(mux)

	handler.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/workspaces/123", nil),
	)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d want 1", len(spans))
	}
	if got := spans[0].Name(); got != "GET /workspaces/{workspaceID}" {
		t.Fatalf("span name=%q want route pattern", got)
	}
}

func TestLowCardinalityMetricViews(t *testing.T) {
	views := lowCardinalityMetricViews()
	serverStream, ok := views[0](sdkmetric.Instrument{
		Name:  "http.server.request.duration",
		Scope: instrumentation.Scope{Name: otelhttp.ScopeName},
	})
	if !ok {
		t.Fatal("http server metric view did not match")
	}
	if _, ok := views[0](sdkmetric.Instrument{Name: "http.server.request.duration"}); ok {
		t.Fatal("http server metric view should only match otelhttp scope")
	}
	if !serverStream.AttributeFilter(attribute.String("http.route", "/workspaces/{workspaceID}")) {
		t.Fatal("http.route should be kept")
	}
	if serverStream.AttributeFilter(attribute.String("server.address", "tenant.example.com")) {
		t.Fatal("server.address should be dropped")
	}

	rpcStream, ok := views[2](sdkmetric.Instrument{
		Name:  "rpc.server.duration",
		Scope: instrumentation.Scope{Name: "connectrpc.com/otelconnect"},
	})
	if !ok {
		t.Fatal("rpc metric view did not match")
	}
	if _, ok := views[2](sdkmetric.Instrument{Name: "rpc.server.duration"}); ok {
		t.Fatal("rpc metric view should only match otelconnect scope")
	}
	if !rpcStream.AttributeFilter(attribute.String("rpc.service", "adiom.app.v1.AppService")) {
		t.Fatal("rpc.service should be kept")
	}
	if rpcStream.AttributeFilter(attribute.String("net.peer.name", "10.0.0.1")) {
		t.Fatal("net.peer.name should be dropped")
	}
}

type handlerStub struct{}

func (handlerStub) ServeHTTP(http.ResponseWriter, *http.Request) {}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
