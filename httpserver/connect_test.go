package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterConnectAndServiceNames(t *testing.T) {
	mux := http.NewServeMux()
	service := Connect("example.v1.ExampleService", "/example.v1.ExampleService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	RegisterConnect(mux, service)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/example.v1.ExampleService/Method", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusNoContent)
	}

	names := ServiceNames(service, Connect("", "/ignored/", http.NotFoundHandler()))
	if len(names) != 1 || names[0] != "example.v1.ExampleService" {
		t.Fatalf("ServiceNames=%v want [example.v1.ExampleService]", names)
	}
}

func TestRegisterReflection(t *testing.T) {
	mux := http.NewServeMux()
	RegisterReflection(mux, "example.v1.ExampleService")

	for _, target := range []string{
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, nil))
		if rec.Code == http.StatusNotFound {
			t.Fatalf("%s returned 404, reflection handler was not mounted", target)
		}
	}
}
