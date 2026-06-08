package spa

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestHandlerServesIndexForRootAndSPARoutes(t *testing.T) {
	handler := Handler(testFS())

	for _, target := range []string{"/", "/orgs/123/settings"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, htmlRequest(http.MethodGet, target))

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d want %d", target, rec.Code, http.StatusOK)
		}
		if got := rec.Body.String(); got != "index" {
			t.Fatalf("%s body=%q want index", target, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != defaultIndexCacheControl {
			t.Fatalf("%s Cache-Control=%q want %q", target, got, defaultIndexCacheControl)
		}
	}
}

func TestHandlerServesStaticFileWithImmutableCache(t *testing.T) {
	handler := Handler(testFS())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "js" {
		t.Fatalf("body=%q want js", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != defaultFileCacheControl {
		t.Fatalf("Cache-Control=%q want %q", got, defaultFileCacheControl)
	}
}

func TestHandlerDoesNotServeIndexForMissingAssets(t *testing.T) {
	handler := Handler(testFS())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandlerDoesNotServeIndexForFileLikeMissingPaths(t *testing.T) {
	handler := Handler(testFS())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandlerOnlyFallsBackForHTMLNavigationRequests(t *testing.T) {
	handler := Handler(testFS())

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/infrapad.v1.TenantService/ListNamespaces", nil),
		httptest.NewRequest(http.MethodGet, "/infrapad.v1.TenantService/ListNamespaces", nil),
		httptest.NewRequest(http.MethodGet, "/api/users", nil),
	} {
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s status=%d want %d", req.Method, req.URL.Path, rec.Code, http.StatusNotFound)
		}
	}
}

func TestHandlerCleansPathsWithinFSRoot(t *testing.T) {
	handler := Handler(testFS())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, htmlRequest(http.MethodGet, "/assets/../index.html"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusOK)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "index" {
		t.Fatalf("body=%q want index", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != defaultIndexCacheControl {
		t.Fatalf("Cache-Control=%q want %q", got, defaultIndexCacheControl)
	}
}

func TestHandlerOptions(t *testing.T) {
	handler := Handler(
		fstest.MapFS{
			"shell.html":         {Data: []byte("shell")},
			"static/missing.txt": {Data: []byte("present")},
		},
		WithIndexPath("shell.html"),
		WithAssetPrefixes("/static/"),
		WithIndexCacheControl("no-cache"),
		WithFileCacheControl("max-age=60"),
	)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, htmlRequest(http.MethodGet, "/dashboard"))
	if got := rec.Body.String(); got != "shell" {
		t.Fatalf("index body=%q want shell", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("index Cache-Control=%q want no-cache", got)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/missing.txt", nil))
	if got := rec.Header().Get("Cache-Control"); got != "max-age=60" {
		t.Fatalf("file Cache-Control=%q want max-age=60", got)
	}
}

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    {Data: []byte("index")},
		"assets/app.js": {Data: []byte("js")},
	}
}

func htmlRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	return req
}
