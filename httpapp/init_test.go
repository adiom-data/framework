package httpapp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/adiom-data/framework/telemetry"
)

func TestInitRuntimeUsesTelemetryConfig(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)

	runtime, err := Init(context.Background(), WithTelemetry(telemetry.DisabledConfig()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()

	if runtime.TelemetryConfig().Enabled == nil || *runtime.TelemetryConfig().Enabled {
		t.Fatal("runtime telemetry config was not disabled")
	}

	service := runtime.NewService()
	app := service.app()
	if app.Telemetry.Enabled == nil || *app.Telemetry.Enabled {
		t.Fatal("runtime.NewService did not apply runtime telemetry config")
	}

	clientOptions, err := runtime.ConnectClientOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(clientOptions) != 0 {
		t.Fatalf("ConnectClientOptions len=%d want 0 for disabled telemetry", len(clientOptions))
	}
}

func TestInitSetsDefaultLogger(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)

	runtime, err := Init(context.Background(), WithTelemetry(telemetry.DisabledConfig()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()

	if slog.Default() != runtime.Logger() {
		t.Fatal("Init did not install runtime logger as slog default")
	}
	if runtime.NewService().Logger != runtime.Logger() {
		t.Fatal("runtime.NewService did not apply runtime logger")
	}
}

func TestInitWithLoggerSetsProvidedDefaultLogger(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime, err := Init(
		context.Background(),
		WithTelemetry(telemetry.DisabledConfig()),
		WithLogger(logger),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()

	if slog.Default() != logger {
		t.Fatal("Init did not install provided logger as slog default")
	}
	if runtime.Logger() != logger {
		t.Fatal("runtime did not keep provided logger")
	}
}

func TestRuntimeContextFollowsParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	runtime, err := Init(parent, WithTelemetry(telemetry.DisabledConfig()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()

	cancel()

	select {
	case <-runtime.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("runtime context was not canceled")
	}
}

func TestRuntimeShutdownCancelsContext(t *testing.T) {
	runtime, err := Init(context.Background(), WithTelemetry(telemetry.DisabledConfig()))
	if err != nil {
		t.Fatal(err)
	}

	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case <-runtime.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("runtime context was not canceled by shutdown")
	}
}

func TestRuntimeHTTPClientsUseRuntimeBaseClient(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)

	transport := http.DefaultTransport
	custom := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
	runtime, err := Init(
		context.Background(),
		WithTelemetry(telemetry.DisabledConfig()),
		WithHTTPClient(custom),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()

	connectClient := runtime.ConnectHTTPClient()
	if connectClient == custom {
		t.Fatal("ConnectHTTPClient returned the runtime base client directly")
	}
	if connectClient.Transport != transport {
		t.Fatal("ConnectHTTPClient did not preserve runtime transport")
	}
	if connectClient.Timeout != custom.Timeout {
		t.Fatal("ConnectHTTPClient did not preserve runtime timeout")
	}

	httpClient := runtime.HTTPClient()
	if httpClient == custom {
		t.Fatal("HTTPClient returned the runtime base client directly")
	}
	if httpClient.Transport != transport {
		t.Fatal("HTTPClient did not preserve runtime transport")
	}
	if httpClient.Timeout != custom.Timeout {
		t.Fatal("HTTPClient did not preserve runtime timeout")
	}
}

func TestRuntimeConnectHTTPClientCanUseDefaultsAndOverrides(t *testing.T) {
	runtime := Runtime{}

	defaultClient := runtime.ConnectHTTPClient()
	if defaultClient == nil {
		t.Fatal("ConnectHTTPClient returned nil")
	}
	if defaultClient == http.DefaultClient {
		t.Fatal("ConnectHTTPClient returned http.DefaultClient directly")
	}
	if defaultClient.Transport != http.DefaultClient.Transport {
		t.Fatal("ConnectHTTPClient changed the default transport")
	}

	transport := http.DefaultTransport
	custom := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
	connectClient := runtime.ConnectHTTPClient(custom)
	if connectClient == custom {
		t.Fatal("ConnectHTTPClient returned the input client directly")
	}
	if connectClient.Transport != transport {
		t.Fatal("ConnectHTTPClient did not preserve custom transport")
	}
	if connectClient.Timeout != custom.Timeout {
		t.Fatal("ConnectHTTPClient did not preserve custom timeout")
	}
}
