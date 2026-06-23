package httpserver

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestHTTPServerDefaults(t *testing.T) {
	server := Server{
		Handler: http.NewServeMux(),
	}

	got, err := server.httpServer()
	if err != nil {
		t.Fatal(err)
	}
	if got.ReadHeaderTimeout != defaultReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout=%s want %s", got.ReadHeaderTimeout, defaultReadHeaderTimeout)
	}
	if got.IdleTimeout != defaultIdleTimeout {
		t.Fatalf("IdleTimeout=%s want %s", got.IdleTimeout, defaultIdleTimeout)
	}
	if got.Addr != DefaultAddr {
		t.Fatalf("Addr=%q want %q", got.Addr, DefaultAddr)
	}
	if got.Protocols == nil || !got.Protocols.HTTP1() || !got.Protocols.UnencryptedHTTP2() || got.Protocols.HTTP2() {
		t.Fatalf("protocols=%v want HTTP/1 and unencrypted HTTP/2", got.Protocols)
	}
}

func TestHTTPServerTimeoutOverrides(t *testing.T) {
	server := Server{
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       30 * time.Second,
		ShutdownTimeout:   4 * time.Second,
	}

	got, err := server.httpServer()
	if err != nil {
		t.Fatal(err)
	}
	if got.ReadHeaderTimeout != 3*time.Second {
		t.Fatalf("ReadHeaderTimeout=%s want 3s", got.ReadHeaderTimeout)
	}
	if got.IdleTimeout != 30*time.Second {
		t.Fatalf("IdleTimeout=%s want 30s", got.IdleTimeout)
	}
	if server.shutdownTimeout() != 4*time.Second {
		t.Fatalf("shutdownTimeout=%s want 4s", server.shutdownTimeout())
	}
}

func TestHTTPServerRequiresHandler(t *testing.T) {
	if _, err := (Server{Addr: "127.0.0.1:0"}).httpServer(); err == nil {
		t.Fatal("expected missing Handler error")
	}
}

func TestHTTPServerTLSConfigSelectsTLSProtocols(t *testing.T) {
	got, err := (Server{
		Handler:   http.NewServeMux(),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}).httpServer()
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocols == nil || !got.Protocols.HTTP1() || !got.Protocols.HTTP2() || got.Protocols.UnencryptedHTTP2() {
		t.Fatalf("protocols=%v want HTTP/1 and TLS HTTP/2", got.Protocols)
	}
}

func TestHTTPServerTLSFilesSelectTLSProtocols(t *testing.T) {
	got, err := (Server{
		Handler:     http.NewServeMux(),
		TLSCertFile: "/certs/tls.crt",
		TLSKeyFile:  "/certs/tls.key",
	}).httpServer()
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocols == nil || !got.Protocols.HTTP1() || !got.Protocols.HTTP2() || got.Protocols.UnencryptedHTTP2() {
		t.Fatalf("protocols=%v want HTTP/1 and TLS HTTP/2", got.Protocols)
	}
}

func TestHTTPServerRejectsPartialTLSFiles(t *testing.T) {
	_, _, err := (Server{TLSCertFile: "/certs/tls.crt"}).tlsCertFiles()
	if err == nil {
		t.Fatal("expected partial TLS file config error")
	}
}

func TestRunReturnsAfterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := (Server{
		Addr:            "127.0.0.1:0",
		Handler:         http.NewServeMux(),
		ShutdownTimeout: time.Second,
	}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
}
