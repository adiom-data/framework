package httpserver

import (
	"net/http"

	"connectrpc.com/grpcreflect"
)

// ConnectService describes a generated Connect handler mounted on an HTTP mux.
type ConnectService struct {
	Name    string
	Path    string
	Handler http.Handler
}

// Connect builds a ConnectService from a generated service name, path, and handler.
func Connect(name, path string, handler http.Handler) ConnectService {
	return ConnectService{
		Name:    name,
		Path:    path,
		Handler: handler,
	}
}

// RegisterConnect mounts Connect services on mux.
func RegisterConnect(mux *http.ServeMux, services ...ConnectService) {
	for _, service := range services {
		mux.Handle(service.Path, service.Handler)
	}
}

// ServiceNames returns the service names for registration with reflection or health.
func ServiceNames(services ...ConnectService) []string {
	names := make([]string, 0, len(services))
	for _, service := range services {
		if service.Name != "" {
			names = append(names, service.Name)
		}
	}
	return names
}

// RegisterReflection mounts explicit Connect reflection handlers on mux.
func RegisterReflection(mux *http.ServeMux, serviceNames ...string) {
	reflector := grpcreflect.NewStaticReflector(serviceNames...)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
}
