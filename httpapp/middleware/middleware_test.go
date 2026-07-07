package middleware

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestLogRequestsUsesRoutePattern(t *testing.T) {
	handler := &recordHandler{}
	mux := http.NewServeMux()
	mux.Handle("/workspaces/{workspaceID}", LogRequests(slog.New(handler))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})))

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/workspaces/abc123", nil))

	record := handler.onlyRecord(t)
	if got := record.stringAttr("method"); got != http.MethodPost {
		t.Fatalf("method=%q want %q", got, http.MethodPost)
	}
	if got := record.stringAttr("route"); got != "/workspaces/{workspaceID}" {
		t.Fatalf("route=%q want route pattern", got)
	}
	if record.hasAttr("path") {
		t.Fatal("request log included raw path")
	}
	if got := record.intAttr("status"); got != http.StatusAccepted {
		t.Fatalf("status=%d want %d", got, http.StatusAccepted)
	}
}

func TestLogRequestsPreservesFlusher(t *testing.T) {
	handler := &recordHandler{}
	mux := http.NewServeMux()
	mux.Handle("/stream", LogRequests(slog.New(handler))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatalf("%T does not implement http.Flusher", w)
		}
		flusher.Flush()
	})))

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/stream", nil))

	if !recorder.Flushed {
		t.Fatal("response was not flushed")
	}
	record := handler.onlyRecord(t)
	if got := record.intAttr("status"); got != http.StatusOK {
		t.Fatalf("status=%d want %d", got, http.StatusOK)
	}
}

func TestLogRequestsPreservesHijackerAndPusher(t *testing.T) {
	handler := &recordHandler{}
	mux := http.NewServeMux()
	mux.Handle("/upgrade", LogRequests(slog.New(handler))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatalf("%T does not implement http.Hijacker", w)
		}
		if _, _, err := hijacker.Hijack(); !errors.Is(err, errHijacked) {
			t.Fatalf("hijack err=%v want %v", err, errHijacked)
		}

		pusher, ok := w.(http.Pusher)
		if !ok {
			t.Fatalf("%T does not implement http.Pusher", w)
		}
		if err := pusher.Push("/asset.js", nil); !errors.Is(err, errPushed) {
			t.Fatalf("push err=%v want %v", err, errPushed)
		}

		readerFrom, ok := w.(io.ReaderFrom)
		if !ok {
			t.Fatalf("%T does not implement io.ReaderFrom", w)
		}
		n, err := readerFrom.ReadFrom(strings.NewReader("response body"))
		if err != nil {
			t.Fatal(err)
		}
		if n != int64(len("response body")) {
			t.Fatalf("read bytes=%d want %d", n, len("response body"))
		}
	})))

	recorder := &optionalResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/upgrade", nil))

	if !recorder.hijacked {
		t.Fatal("response was not hijacked")
	}
	if recorder.pushed != "/asset.js" {
		t.Fatalf("pushed=%q want /asset.js", recorder.pushed)
	}
	if recorder.readFrom != "response body" {
		t.Fatalf("readFrom=%q want response body", recorder.readFrom)
	}
	handler.onlyRecord(t)
}

func TestLogRequestsDoesNotAddUnsupportedOptionalInterfaces(t *testing.T) {
	handler := &recordHandler{}
	mux := http.NewServeMux()
	mux.Handle("/plain", LogRequests(slog.New(handler))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := w.(http.Flusher); ok {
			t.Fatalf("%T unexpectedly implements http.Flusher", w)
		}
		if _, ok := w.(http.Hijacker); ok {
			t.Fatalf("%T unexpectedly implements http.Hijacker", w)
		}
		if _, ok := w.(http.Pusher); ok {
			t.Fatalf("%T unexpectedly implements http.Pusher", w)
		}
		if _, ok := w.(io.ReaderFrom); ok {
			t.Fatalf("%T unexpectedly implements io.ReaderFrom", w)
		}
	})))

	mux.ServeHTTP(&plainResponseWriter{header: http.Header{}}, httptest.NewRequest(http.MethodGet, "/plain", nil))

	handler.onlyRecord(t)
}

func TestRecoverPanicsLogsRouteAndPath(t *testing.T) {
	handler := &recordHandler{}
	mux := http.NewServeMux()
	mux.Handle("/workspaces/{workspaceID}", RecoverPanics(slog.New(handler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/workspaces/abc123", nil))

	record := handler.onlyRecord(t)
	if got := record.stringAttr("route"); got != "/workspaces/{workspaceID}" {
		t.Fatalf("route=%q want route pattern", got)
	}
	if got := record.stringAttr("path"); got != "/workspaces/abc123" {
		t.Fatalf("path=%q want raw path", got)
	}
}

type recordHandler struct {
	records []recordedLog
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *recordHandler) Handle(_ context.Context, record slog.Record) error {
	log := recordedLog{message: record.Message, attrs: map[string]slog.Value{}}
	record.Attrs(func(attr slog.Attr) bool {
		log.attrs[attr.Key] = attr.Value
		return true
	})
	h.records = append(h.records, log)
	return nil
}

func (h *recordHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copy := &recordHandler{records: slices.Clone(h.records)}
	if len(attrs) > 0 {
		copy.records = append(copy.records, recordedLog{attrs: map[string]slog.Value{}})
		for _, attr := range attrs {
			copy.records[len(copy.records)-1].attrs[attr.Key] = attr.Value
		}
	}
	return copy
}

func (h *recordHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *recordHandler) onlyRecord(t *testing.T) recordedLog {
	t.Helper()
	if len(h.records) != 1 {
		t.Fatalf("records len=%d want 1", len(h.records))
	}
	return h.records[0]
}

var (
	errHijacked = errors.New("hijacked")
	errPushed   = errors.New("pushed")
)

type optionalResponseWriter struct {
	*httptest.ResponseRecorder
	hijacked bool
	pushed   string
	readFrom string
}

func (w *optionalResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, errHijacked
}

func (w *optionalResponseWriter) Push(target string, _ *http.PushOptions) error {
	w.pushed = target
	return errPushed
}

func (w *optionalResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	var builder strings.Builder
	n, err := io.Copy(&builder, src)
	w.readFrom = builder.String()
	return n, err
}

type plainResponseWriter struct {
	header http.Header
	status int
}

func (w *plainResponseWriter) Header() http.Header {
	return w.header
}

func (w *plainResponseWriter) Write(body []byte) (int, error) {
	return len(body), nil
}

func (w *plainResponseWriter) WriteHeader(status int) {
	w.status = status
}

type recordedLog struct {
	message string
	attrs   map[string]slog.Value
}

func (r recordedLog) hasAttr(key string) bool {
	_, ok := r.attrs[key]
	return ok
}

func (r recordedLog) stringAttr(key string) string {
	return r.attrs[key].String()
}

func (r recordedLog) intAttr(key string) int64 {
	return r.attrs[key].Int64()
}
