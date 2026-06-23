package httpapp

import (
	"crypto/tls"
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

func TestServiceTLSFilesOption(t *testing.T) {
	t.Parallel()

	service := NewService(WithServiceTLSFiles("/certs/tls.crt", "/certs/tls.key"))
	app := service.app()

	if app.TLSCertFile != "/certs/tls.crt" {
		t.Fatalf("TLSCertFile=%q want /certs/tls.crt", app.TLSCertFile)
	}
	if app.TLSKeyFile != "/certs/tls.key" {
		t.Fatalf("TLSKeyFile=%q want /certs/tls.key", app.TLSKeyFile)
	}
}

func TestServiceTLSConfigOption(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	service := NewService(WithServiceTLSConfig(tlsConfig))
	app := service.app()

	if app.TLSConfig != tlsConfig {
		t.Fatal("TLSConfig was not propagated")
	}
}

func TestAppAddrUsesExplicitAddr(t *testing.T) {
	t.Setenv("PORT", "9090")
	app := App{Addr: ":7070"}

	if got := app.addr(); got != ":7070" {
		t.Fatalf("addr=%q want explicit addr", got)
	}
}

func TestAppAddrUsesPortEnv(t *testing.T) {
	t.Setenv("PORT", "9090")

	if got := (App{}).addr(); got != ":9090" {
		t.Fatalf("addr=%q want :9090", got)
	}
}

func TestAppAddrUsesDefault(t *testing.T) {
	t.Setenv("PORT", "")

	if got := (App{}).addr(); got != DefaultAddr {
		t.Fatalf("addr=%q want %q", got, DefaultAddr)
	}
}

func TestAppTLSFilesUseExplicitValues(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/env/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/env/tls.key")
	app := App{
		TLSCertFile: "/explicit/tls.crt",
		TLSKeyFile:  "/explicit/tls.key",
	}

	if got := app.tlsCertFile(); got != "/explicit/tls.crt" {
		t.Fatalf("TLS cert file=%q want explicit value", got)
	}
	if got := app.tlsKeyFile(); got != "/explicit/tls.key" {
		t.Fatalf("TLS key file=%q want explicit value", got)
	}
}

func TestAppTLSFilesUseEnv(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/env/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/env/tls.key")
	app := App{}

	if got := app.tlsCertFile(); got != "/env/tls.crt" {
		t.Fatalf("TLS cert file=%q want env value", got)
	}
	if got := app.tlsKeyFile(); got != "/env/tls.key" {
		t.Fatalf("TLS key file=%q want env value", got)
	}
}
