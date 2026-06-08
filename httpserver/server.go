package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	// DefaultAddr is the default listen address for internal services.
	DefaultAddr = ":8080"

	defaultReadHeaderTimeout = 5 * time.Second
	defaultIdleTimeout       = 75 * time.Second
	defaultShutdownTimeout   = 10 * time.Second
)

// Protocols selects the HTTP protocols accepted by a server.
type Protocols int

const (
	// ProtocolsInternalCleartext serves HTTP/1 and unencrypted HTTP/2.
	ProtocolsInternalCleartext Protocols = iota
	// ProtocolsTLS serves HTTP/1 and HTTP/2 over TLS.
	ProtocolsTLS
	// ProtocolsHTTP1Only serves only HTTP/1.
	ProtocolsHTTP1Only
)

// Server runs an http.Handler with common lifecycle defaults.
type Server struct {
	Addr              string
	Handler           http.Handler
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	Protocols         Protocols
	TLSConfig         *tls.Config
	Logger            *slog.Logger
	OnShutdown        func()
}

// SignalContext returns a context canceled on SIGINT or SIGTERM.
func SignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// Run starts the server and gracefully shuts it down when ctx is canceled.
func (s Server) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	srv, err := s.httpServer()
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	errc := make(chan error, 1)
	go func() {
		s.log().Info("http server listening", "addr", listener.Addr().String())
		if s.usesTLS() {
			errc <- srv.ServeTLS(listener, "", "")
			return
		}
		errc <- srv.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout())
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errc
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s Server) httpServer() (*http.Server, error) {
	if s.Handler == nil {
		return nil, errors.New("httpserver: Handler is required")
	}
	srv := &http.Server{
		Addr:              s.addr(),
		Handler:           s.Handler,
		ReadHeaderTimeout: s.readHeaderTimeout(),
		IdleTimeout:       s.idleTimeout(),
		Protocols:         s.httpProtocols(),
		TLSConfig:         s.TLSConfig,
	}
	if s.OnShutdown != nil {
		srv.RegisterOnShutdown(s.OnShutdown)
	}
	return srv, nil
}

func (s Server) addr() string {
	if s.Addr != "" {
		return s.Addr
	}
	return DefaultAddr
}

func (s Server) httpProtocols() *http.Protocols {
	protocols := new(http.Protocols)
	switch s.Protocols {
	case ProtocolsHTTP1Only:
		protocols.SetHTTP1(true)
	case ProtocolsTLS:
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
	case ProtocolsInternalCleartext:
		if s.TLSConfig != nil {
			protocols.SetHTTP1(true)
			protocols.SetHTTP2(true)
			return protocols
		}
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
	default:
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
	}
	return protocols
}

func (s Server) usesTLS() bool {
	return s.Protocols == ProtocolsTLS || s.TLSConfig != nil
}

func (s Server) readHeaderTimeout() time.Duration {
	if s.ReadHeaderTimeout > 0 {
		return s.ReadHeaderTimeout
	}
	return defaultReadHeaderTimeout
}

func (s Server) idleTimeout() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return defaultIdleTimeout
}

func (s Server) shutdownTimeout() time.Duration {
	if s.ShutdownTimeout > 0 {
		return s.ShutdownTimeout
	}
	return defaultShutdownTimeout
}

func (s Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
