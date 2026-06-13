package httpapp

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/telemetry"
)

// Runtime holds process-level framework initialization.
type Runtime struct {
	telemetry telemetry.Config
	shutdown  telemetry.Shutdown
}

// InitOption customizes process-level framework initialization.
type InitOption func(*initConfig)

type initConfig struct {
	telemetry telemetry.Config
}

// Init performs process-level framework initialization.
func Init(ctx context.Context, opts ...InitOption) (Runtime, error) {
	var cfg initConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	shutdown, err := telemetry.Setup(ctx, cfg.telemetry)
	if err != nil {
		return Runtime{}, err
	}
	return Runtime{
		telemetry: cfg.telemetry,
		shutdown:  shutdown,
	}, nil
}

// WithTelemetry overrides the default telemetry configuration for Init.
func WithTelemetry(cfg telemetry.Config) InitOption {
	return func(init *initConfig) {
		init.telemetry = cfg
	}
}

// Shutdown flushes and stops initialized framework resources.
func (r Runtime) Shutdown(ctx context.Context) error {
	if r.shutdown == nil {
		return nil
	}
	return r.shutdown(ctx)
}

// TelemetryConfig returns the runtime telemetry configuration.
func (r Runtime) TelemetryConfig() telemetry.Config {
	return r.telemetry
}

// NewService builds a Service using the runtime telemetry configuration.
func (r Runtime) NewService(opts ...ServiceOption) Service {
	options := make([]ServiceOption, 0, len(opts)+1)
	options = append(options, WithServiceTelemetry(r.telemetry))
	options = append(options, opts...)
	return NewService(options...)
}

// HTTPClient returns a client whose transport emits outbound HTTP telemetry.
func (r Runtime) HTTPClient(client *http.Client) *http.Client {
	return telemetry.HTTPClient(r.telemetry, client)
}

// ConnectClientOptions returns Connect client options for RPC telemetry.
func (r Runtime) ConnectClientOptions() ([]connect.ClientOption, error) {
	return telemetry.ConnectClientOptions(r.telemetry)
}
