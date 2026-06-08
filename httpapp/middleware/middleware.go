package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// Middleware wraps an HTTP handler. The first middleware in a list is outermost.
type Middleware func(http.Handler) http.Handler

// Default returns the default HTTP middleware stack.
func Default(logger *slog.Logger) []Middleware {
	return []Middleware{
		LogRequests(logger),
		RecoverPanics(logger),
	}
}

// LogRequests logs completed HTTP requests.
func LogRequests(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(recorder, r)
			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", recorder.status,
				"duration", time.Since(start),
			)
		})
	}
}

// RecoverPanics recovers HTTP panics and writes a 500 response.
func RecoverPanics(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if value := recover(); value != nil {
					logger.Error("http panic",
						"method", r.Method,
						"path", r.URL.Path,
						"panic", value,
						"stack", string(debug.Stack()),
					)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
