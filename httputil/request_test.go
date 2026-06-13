package httputil

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicBaseURLUsesForwardedHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://internal.local/path", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")

	if got := PublicBaseURL(req); got != "https://app.example.com" {
		t.Fatalf("PublicBaseURL() = %q, want https://app.example.com", got)
	}
}

func TestPublicBaseURLUsesFirstForwardedHeaderValue(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://internal.local/path", nil)
	req.Header.Set("X-Forwarded-Proto", "https,http")
	req.Header.Set("X-Forwarded-Host", "app.example.com,internal.local")

	if got := PublicBaseURL(req); got != "https://app.example.com" {
		t.Fatalf("PublicBaseURL() = %q, want https://app.example.com", got)
	}
}

func TestPublicBaseURLUsesRFCForwardedHeader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://internal.local/path", nil)
	req.Header.Set("Forwarded", `for=192.0.2.1; proto=https; host="app.example.com"`)

	if got := PublicBaseURL(req); got != "https://app.example.com" {
		t.Fatalf("PublicBaseURL() = %q, want https://app.example.com", got)
	}
}

func TestPublicBaseURLFallsBackToRequest(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/path", nil)

	if got := PublicBaseURL(req); got != "http://app.example.com" {
		t.Fatalf("PublicBaseURL() = %q, want http://app.example.com", got)
	}
}

func TestPublicBaseURLFallsBackToTLS(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	req.Host = "app.example.com"
	req.URL.Scheme = ""
	req.TLS = &tls.ConnectionState{}

	if got := PublicBaseURL(req); got != "https://app.example.com" {
		t.Fatalf("PublicBaseURL() = %q, want https://app.example.com", got)
	}
}

func TestPublicBaseURLNilRequest(t *testing.T) {
	t.Parallel()

	if got := PublicBaseURL(nil); got != "" {
		t.Fatalf("PublicBaseURL(nil) = %q, want empty string", got)
	}
}
