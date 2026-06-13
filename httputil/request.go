package httputil

import (
	"net/http"
	"strings"
)

// PublicBaseURL returns the externally visible scheme and host for r.
//
// It honors X-Forwarded-Proto, X-Forwarded-Host, and Forwarded headers before
// falling back to the request scheme and Host.
func PublicBaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))
	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if forwarded := parseForwarded(r.Header.Get("Forwarded")); forwarded != nil {
		if scheme == "" {
			scheme = forwarded["proto"]
		}
		if host == "" {
			host = forwarded["host"]
		}
	}
	if scheme == "" {
		scheme = r.URL.Scheme
	}
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func firstHeaderValue(value string) string {
	value, _, _ = strings.Cut(value, ",")
	return strings.TrimSpace(value)
}

func parseForwarded(value string) map[string]string {
	value = firstHeaderValue(value)
	if value == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		raw = strings.Trim(strings.TrimSpace(raw), `"`)
		if key != "" && raw != "" {
			out[key] = raw
		}
	}
	return out
}
