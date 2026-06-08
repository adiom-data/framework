package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
)

func TestHealthCheckerReportsLivenessAndReadiness(t *testing.T) {
	checker := newHealthChecker(Health{
		Enabled: true,
		ReadinessChecks: []Check{
			ReadinessCheck(func(context.Context) error { return nil }),
		},
		ServiceNames: []string{"example.v1.ExampleService"},
	})

	for _, service := range []string{"", LivenessService, ReadinessService, "example.v1.ExampleService"} {
		resp, err := checker.Check(context.Background(), &grpchealth.CheckRequest{Service: service})
		if err != nil {
			t.Fatalf("%q: %v", service, err)
		}
		if resp.Status != grpchealth.StatusServing {
			t.Fatalf("%q status=%s want serving", service, resp.Status)
		}
	}
}

func TestHealthCheckerReportsReadinessFailure(t *testing.T) {
	checker := newHealthChecker(Health{
		Enabled: true,
		ReadinessChecks: []Check{
			ReadinessCheck(func(context.Context) error { return errors.New("down") }),
		},
	})

	resp, err := checker.Check(context.Background(), &grpchealth.CheckRequest{Service: ReadinessService})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != grpchealth.StatusNotServing {
		t.Fatalf("status=%s want not_serving", resp.Status)
	}
}

func TestHealthCheckerReportsLivenessFailure(t *testing.T) {
	checker := newHealthChecker(Health{
		Enabled: true,
		LivenessChecks: []Check{
			LivenessCheck(func(context.Context) error { return errors.New("wedged") }),
		},
	})

	resp, err := checker.Check(context.Background(), &grpchealth.CheckRequest{Service: LivenessService})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != grpchealth.StatusNotServing {
		t.Fatalf("status=%s want not_serving", resp.Status)
	}
}

func TestHealthCheckerDefaultsToServingWithNoChecks(t *testing.T) {
	checker := newHealthChecker(Health{Enabled: true})

	for _, service := range []string{"", LivenessService, ReadinessService} {
		resp, err := checker.Check(context.Background(), &grpchealth.CheckRequest{Service: service})
		if err != nil {
			t.Fatalf("%q: %v", service, err)
		}
		if resp.Status != grpchealth.StatusServing {
			t.Fatalf("%q status=%s want serving", service, resp.Status)
		}
	}
}

func TestHealthCheckerReturnsNotFoundForUnknownService(t *testing.T) {
	checker := newHealthChecker(Health{Enabled: true})

	_, err := checker.Check(context.Background(), &grpchealth.CheckRequest{Service: "missing.v1.Service"})
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("code=%s want %s err=%v", connect.CodeOf(err), connect.CodeNotFound, err)
	}
}

func TestRegisterHealth(t *testing.T) {
	mux := http.NewServeMux()
	RegisterHealth(mux, Health{Enabled: true})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("health handler was not mounted")
	}
}

func TestRegisterHealthDisabled(t *testing.T) {
	mux := http.NewServeMux()
	RegisterHealth(mux, Health{})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/grpc.health.v1.Health/Check", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusNotFound)
	}
}
