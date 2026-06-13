package telemetry

import (
	"net/http"
	"testing"
	"time"

	"go.opentelemetry.io/otel/propagation"
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
