package httpserver

import (
	"context"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
)

const (
	// LivenessService is the Kubernetes gRPC health service label for liveness.
	LivenessService = "liveness"
	// ReadinessService is the Kubernetes gRPC health service label for readiness.
	ReadinessService = "readiness"
)

// Health configures the standard gRPC health service.
type Health struct {
	Enabled         bool
	LivenessChecks  []Check
	ReadinessChecks []Check
	ServiceNames    []string
}

// Check is a health dependency check.
type Check func(context.Context) error

// LivenessCheck adapts fn into a liveness check.
func LivenessCheck(fn func(context.Context) error) Check {
	return Check(fn)
}

// ReadinessCheck adapts fn into a readiness check.
func ReadinessCheck(fn func(context.Context) error) Check {
	return Check(fn)
}

// RegisterHealth mounts the standard gRPC health service on mux.
func RegisterHealth(mux *http.ServeMux, health Health) {
	if !health.Enabled {
		return
	}
	path, handler := grpchealth.NewHandler(newHealthChecker(health))
	mux.Handle(path, handler)
}

func newHealthChecker(health Health) grpchealth.Checker {
	return healthChecker{
		livenessChecks:  health.LivenessChecks,
		readinessChecks: health.ReadinessChecks,
		serviceNames:    health.ServiceNames,
	}
}

type healthChecker struct {
	livenessChecks  []Check
	readinessChecks []Check
	serviceNames    []string
}

func (c healthChecker) Check(ctx context.Context, req *grpchealth.CheckRequest) (*grpchealth.CheckResponse, error) {
	switch req.Service {
	case LivenessService:
		if err := runChecks(ctx, c.livenessChecks); err != nil {
			return notServing(), nil
		}
		return serving(), nil
	case ReadinessService, "":
		if err := runChecks(ctx, c.readinessChecks); err != nil {
			return notServing(), nil
		}
		return serving(), nil
	default:
		if hasServiceName(req.Service, c.serviceNames) {
			return serving(), nil
		}
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("unknown health service %s", req.Service))
	}
}

func runChecks(ctx context.Context, checks []Check) error {
	for _, check := range checks {
		if check == nil {
			continue
		}
		if err := check(ctx); err != nil {
			return err
		}
	}
	return nil
}

func serving() *grpchealth.CheckResponse {
	return &grpchealth.CheckResponse{Status: grpchealth.StatusServing}
}

func notServing() *grpchealth.CheckResponse {
	return &grpchealth.CheckResponse{Status: grpchealth.StatusNotServing}
}

func hasServiceName(name string, serviceNames []string) bool {
	for _, serviceName := range serviceNames {
		if name == serviceName {
			return true
		}
	}
	return false
}
