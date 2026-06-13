package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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
