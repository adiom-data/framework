package httpapp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	httpmiddleware "github.com/adiom-data/framework/httpapp/middleware"
)

func TestAppRegistersRoutesConnectAndHealth(t *testing.T) {
	connectMiddlewareCalled := false
	app := App{
		Logger: testLogger(),
		Routes: []Route{
			Handle("/static", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("static"))
			})),
		},
		Connect: []ConnectService{
			Connect("example.v1.ExampleService", func(options ...connect.HandlerOption) (string, http.Handler) {
				if len(options) != 0 {
					t.Fatalf("options len=%d want 0", len(options))
				}
				return "/example.v1.ExampleService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("connect"))
				})
			}, WithConnectMiddleware(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					connectMiddlewareCalled = true
					next.ServeHTTP(w, r)
				})
			})),
		},
	}
	handler := app.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static", nil))
	if got := rec.Body.String(); got != "static" {
		t.Fatalf("route body=%q want static", got)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/example.v1.ExampleService/Call", nil))
	if got := rec.Body.String(); got != "connect" {
		t.Fatalf("connect body=%q want connect", got)
	}
	if !connectMiddlewareCalled {
		t.Fatal("connect middleware was not called")
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("default health was not mounted")
	}
}

func TestAppPassesCommonAndServiceConnectOptions(t *testing.T) {
	called := false
	app := App{
		Logger:         testLogger(),
		Interceptors:   []connect.Interceptor{noopInterceptor{}},
		ConnectOptions: []connect.HandlerOption{connect.WithRequireConnectProtocolHeader()},
		Connect: []ConnectService{
			Connect("example.v1.ExampleService", func(options ...connect.HandlerOption) (string, http.Handler) {
				called = true
				if len(options) != 3 {
					t.Fatalf("options len=%d want 3", len(options))
				}
				return "/example.v1.ExampleService/", http.NotFoundHandler()
			},
				WithInterceptors(noopInterceptor{}),
				WithConnectOptions(connect.WithRequireConnectProtocolHeader()),
			),
		},
	}

	_ = app.Handler()
	if !called {
		t.Fatal("connect factory was not called")
	}
}

func TestAppCanEnableReflection(t *testing.T) {
	app := App{
		Logger:     testLogger(),
		Reflection: true,
		Connect: []ConnectService{
			Connect("example.v1.ExampleService", func(...connect.HandlerOption) (string, http.Handler) {
				return "/example.v1.ExampleService/", http.NotFoundHandler()
			}),
		},
	}
	handler := app.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("health was not mounted")
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("reflection was not mounted")
	}
}

func TestAppReadinessChecksBackDefaultHealth(t *testing.T) {
	app := App{
		Logger: testLogger(),
		ReadinessChecks: []Check{
			func(context.Context) error { return context.Canceled },
		},
	}
	handler := app.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("health was not mounted")
	}
}

func TestAppLivenessChecksBackDefaultHealth(t *testing.T) {
	app := App{
		Logger: testLogger(),
		LivenessChecks: []Check{
			func(context.Context) error { return context.Canceled },
		},
	}
	handler := app.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("health was not mounted")
	}
}

func TestHealthServiceLabelsAreExposed(t *testing.T) {
	if LivenessService != "liveness" {
		t.Fatalf("LivenessService=%q want liveness", LivenessService)
	}
	if ReadinessService != "readiness" {
		t.Fatalf("ReadinessService=%q want readiness", ReadinessService)
	}
}

func TestAppHealthBypassesGlobalMiddleware(t *testing.T) {
	calls := 0
	app := App{
		Logger: testLogger(),
		Middleware: []Middleware{
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					next.ServeHTTP(w, r)
				})
			},
		},
		Routes: []Route{
			Handle("/route", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})),
		},
	}
	handler := app.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if calls != 0 {
		t.Fatalf("global middleware calls=%d want 0 for health", calls)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/route", nil))
	if calls != 1 {
		t.Fatalf("global middleware calls=%d want 1 after app route", calls)
	}
}

func TestDefaultMiddlewareIsComposable(t *testing.T) {
	var calls []string
	middleware := append(httpmiddleware.Default(testLogger()), recordMiddleware(&calls, "custom"))
	app := NewService(
		WithServiceMiddleware(middleware...),
		WithServiceRoutes(
			Handle("/route", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls = append(calls, "handler")
				w.WriteHeader(http.StatusNoContent)
			})),
		),
	)

	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/route", nil))

	want := []string{
		"custom before",
		"handler",
		"custom after",
	}
	if !equalStrings(calls, want) {
		t.Fatalf("calls=%v want %v", calls, want)
	}
}

func TestAppMiddlewareOrder(t *testing.T) {
	var calls []string
	app := App{
		Logger: testLogger(),
		Middleware: []Middleware{
			recordMiddleware(&calls, "global-a"),
			recordMiddleware(&calls, "global-b"),
		},
		Routes: []Route{
			Handle("/route", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls = append(calls, "handler")
				w.WriteHeader(http.StatusNoContent)
			}),
				WithMiddleware(
					recordMiddleware(&calls, "route-a"),
					recordMiddleware(&calls, "route-b"),
				),
			),
		},
	}

	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/route", nil))

	want := []string{
		"global-a before",
		"global-b before",
		"route-a before",
		"route-b before",
		"handler",
		"route-b after",
		"route-a after",
		"global-b after",
		"global-a after",
	}
	if !equalStrings(calls, want) {
		t.Fatalf("calls=%v want %v", calls, want)
	}
}

func TestAppConnectMiddlewareOrder(t *testing.T) {
	var calls []string
	app := App{
		Logger: testLogger(),
		Middleware: []Middleware{
			recordMiddleware(&calls, "global"),
		},
		Connect: []ConnectService{
			Connect("example.v1.ExampleService", func(...connect.HandlerOption) (string, http.Handler) {
				return "/example.v1.ExampleService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls = append(calls, "handler")
					w.WriteHeader(http.StatusNoContent)
				})
			},
				WithConnectMiddleware(recordMiddleware(&calls, "connect")),
			),
		},
	}

	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/example.v1.ExampleService/Call", nil))

	want := []string{
		"global before",
		"connect before",
		"handler",
		"connect after",
		"global after",
	}
	if !equalStrings(calls, want) {
		t.Fatalf("calls=%v want %v", calls, want)
	}
}

func TestAppDefaultRecovery(t *testing.T) {
	app := App{
		Logger: testLogger(),
		Routes: []Route{
			Handle("/panic", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				panic("boom")
			})),
		},
	}
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusInternalServerError)
	}
}

type noopInterceptor struct{}

func (noopInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return next
}

func (noopInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (noopInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func recordMiddleware(calls *[]string, name string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*calls = append(*calls, name+" before")
			next.ServeHTTP(w, r)
			*calls = append(*calls, name+" after")
		})
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
