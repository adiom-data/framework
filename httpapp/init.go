package httpapp

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/adiom-data/framework/telemetry"
)

// Runtime holds process-level framework initialization.
type Runtime struct {
	ctx        context.Context
	stop       context.CancelFunc
	telemetry  telemetry.Config
	logger     *slog.Logger
	httpClient *http.Client
	shutdown   telemetry.Shutdown
}

// InitOption customizes process-level framework initialization.
type InitOption func(*initConfig)

type initConfig struct {
	telemetry  telemetry.Config
	logger     *slog.Logger
	httpClient *http.Client
}

// Init performs process-level framework initialization.
func Init(ctx context.Context, opts ...InitOption) (Runtime, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, stop := SignalContext(ctx)
	var cfg initConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	shutdown, err := telemetry.Setup(runCtx, cfg.telemetry)
	if err != nil {
		stop()
		return Runtime{}, err
	}
	logger := cfg.logger
	if logger == nil {
		logger = telemetry.DefaultLogger()
	}
	slog.SetDefault(logger)
	return Runtime{
		ctx:        runCtx,
		stop:       stop,
		telemetry:  cfg.telemetry,
		logger:     logger,
		httpClient: cfg.httpClient,
		shutdown:   shutdown,
	}, nil
}

// WithTelemetry overrides the default telemetry configuration for Init.
func WithTelemetry(cfg telemetry.Config) InitOption {
	return func(init *initConfig) {
		init.telemetry = cfg
	}
}

// WithLogger overrides the process default logger installed by Init.
func WithLogger(logger *slog.Logger) InitOption {
	return func(init *initConfig) {
		init.logger = logger
	}
}

// WithHTTPClient sets the runtime's base outbound HTTP client.
func WithHTTPClient(client *http.Client) InitOption {
	return func(init *initConfig) {
		init.httpClient = client
	}
}

// Shutdown flushes and stops initialized framework resources.
func (r Runtime) Shutdown(ctx context.Context) error {
	if r.stop != nil {
		r.stop()
	}
	if r.shutdown == nil {
		return nil
	}
	return r.shutdown(ctx)
}

// Context returns the runtime context canceled on SIGINT, SIGTERM, parent
// cancellation, or Shutdown.
func (r Runtime) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// TelemetryConfig returns the runtime telemetry configuration.
func (r Runtime) TelemetryConfig() telemetry.Config {
	return r.telemetry
}

// Logger returns the runtime logger.
func (r Runtime) Logger() *slog.Logger {
	if r.logger != nil {
		return r.logger
	}
	return slog.Default()
}

// NewService builds a Service using the runtime telemetry configuration.
func (r Runtime) NewService(opts ...ServiceOption) Service {
	options := make([]ServiceOption, 0, len(opts)+2)
	options = append(options, WithServiceTelemetry(r.telemetry))
	options = append(options, WithServiceLogger(r.Logger()))
	options = append(options, opts...)
	return NewService(options...)
}

// HTTPClient returns a runtime outbound client whose transport emits HTTP
// telemetry. Passing a client overrides the runtime base client for this call.
func (r Runtime) HTTPClient(client ...*http.Client) *http.Client {
	return telemetry.HTTPClient(r.telemetry, r.baseHTTPClient(client...))
}

// ConnectHTTPClient returns a runtime outbound client for generated Connect
// clients. Passing a client overrides the runtime base client for this call.
// Connect telemetry comes from ConnectClientOptions, so this does not wrap the
// transport with HTTP telemetry.
func (r Runtime) ConnectHTTPClient(client ...*http.Client) *http.Client {
	return cloneHTTPClient(r.baseHTTPClient(client...))
}

func (r Runtime) baseHTTPClient(overrides ...*http.Client) *http.Client {
	if len(overrides) > 0 && overrides[0] != nil {
		return overrides[0]
	}
	if r.httpClient != nil {
		return r.httpClient
	}
	return http.DefaultClient
}

func cloneHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	return &copy
}

// ConnectClientOptions returns Connect client options for RPC telemetry.
func (r Runtime) ConnectClientOptions() ([]connect.ClientOption, error) {
	return telemetry.ConnectClientOptions(r.telemetry)
}
