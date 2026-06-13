package httpapp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/telemetry"
)

func TestServiceAssemblesConnectHealthAndRoutes(t *testing.T) {
	service := NewService(
		WithServiceLogger(testLogger()),
		WithServiceRoutes(
			Handle("/extra", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("extra"))
			})),
		),
		WithServices(
			Connect("example.v1.ExampleService", func(...connect.HandlerOption) (string, http.Handler) {
				return "/example.v1.ExampleService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("connect"))
				})
			}),
		),
	)
	handler := service.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/extra", nil))
	if got := rec.Body.String(); got != "extra" {
		t.Fatalf("route body=%q want extra", got)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/example.v1.ExampleService/Method", nil))
	if got := rec.Body.String(); got != "connect" {
		t.Fatalf("connect body=%q want connect", got)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("health was not mounted")
	}
}

func TestServiceIdleTimeoutOption(t *testing.T) {
	t.Parallel()

	service := NewService(WithServiceIdleTimeout(45 * time.Second))
	app := service.app()

	if app.IdleTimeout != 45*time.Second {
		t.Fatalf("IdleTimeout=%s want 45s", app.IdleTimeout)
	}
}

func TestServiceTelemetryOption(t *testing.T) {
	service := NewService(WithServiceTelemetry(telemetry.DefaultConfig("example")))
	app := service.app()

	if got := app.Telemetry.ServiceName; got != "example" {
		t.Fatalf("Telemetry.ServiceName=%q want example", got)
	}
}
