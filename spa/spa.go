package spa

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

const (
	defaultIndexCacheControl = "no-cache, no-store, must-revalidate"
	defaultFileCacheControl  = "public, max-age=31536000, immutable"
)

type config struct {
	indexPath         string
	assetPrefixes     []string
	indexCacheControl string
	fileCacheControl  string
}

// Option configures an SPA static file handler.
type Option func(*config)

// WithIndexPath changes the file served for client-side routes.
func WithIndexPath(indexPath string) Option {
	return func(cfg *config) {
		cfg.indexPath = cleanName(indexPath)
	}
}

// WithAssetPrefixes marks URL prefixes that should 404 when the requested file
// does not exist. This prevents missing versioned assets from serving index.html.
func WithAssetPrefixes(prefixes ...string) Option {
	return func(cfg *config) {
		cfg.assetPrefixes = append(cfg.assetPrefixes[:0], cleanPrefixes(prefixes)...)
	}
}

// WithIndexCacheControl changes the Cache-Control value for the SPA index.
func WithIndexCacheControl(value string) Option {
	return func(cfg *config) {
		cfg.indexCacheControl = value
	}
}

// WithFileCacheControl changes the Cache-Control value for static files other
// than index.html.
func WithFileCacheControl(value string) Option {
	return func(cfg *config) {
		cfg.fileCacheControl = value
	}
}

// DirHandler serves an SPA from an operating-system directory.
func DirHandler(root string, opts ...Option) http.Handler {
	return Handler(os.DirFS(root), opts...)
}

// Handler serves static files from root and falls back to index.html for
// client-side SPA routes.
func Handler(root fs.FS, opts ...Option) http.Handler {
	return handler(root, newConfig(opts...))
}

func newConfig(opts ...Option) config {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

func handler(root fs.FS, cfg config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := cleanURLPath(r.URL.Path)
		if requestPath == "" {
			if !acceptsHTML(r) {
				http.NotFound(w, r)
				return
			}
			serveIndex(w, r, root, cfg)
			return
		}
		if info, err := fs.Stat(root, requestPath); err == nil && !info.IsDir() {
			setFileCacheHeaders(w, requestPath, cfg)
			serveFile(w, r, root, requestPath)
			return
		}
		if hasPrefix(r.URL.Path, cfg.assetPrefixes) || path.Ext(requestPath) != "" {
			http.NotFound(w, r)
			return
		}
		if !acceptsHTML(r) {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r, root, cfg)
	})
}

func defaultConfig() config {
	return config{
		indexPath:         "index.html",
		assetPrefixes:     []string{"/assets/"},
		indexCacheControl: defaultIndexCacheControl,
		fileCacheControl:  defaultFileCacheControl,
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request, root fs.FS, cfg config) {
	setIndexCacheHeaders(w, cfg)
	serveFile(w, r, root, cfg.indexPath)
}

func serveFile(w http.ResponseWriter, r *http.Request, root fs.FS, name string) {
	file, err := root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	if seeker, ok := file.(io.ReadSeeker); ok {
		http.ServeContent(w, r, name, info.ModTime(), seeker)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), bytes.NewReader(data))
}

func setFileCacheHeaders(w http.ResponseWriter, name string, cfg config) {
	if name == cfg.indexPath {
		setIndexCacheHeaders(w, cfg)
		return
	}
	if cfg.fileCacheControl != "" {
		w.Header().Set("Cache-Control", cfg.fileCacheControl)
	}
}

func setIndexCacheHeaders(w http.ResponseWriter, cfg config) {
	if cfg.indexCacheControl != "" {
		w.Header().Set("Cache-Control", cfg.indexCacheControl)
	}
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func cleanURLPath(value string) string {
	return cleanName(value)
}

func cleanName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		return ""
	}
	return strings.TrimPrefix(path.Clean("/"+value), "/")
}

func cleanPrefixes(values []string) []string {
	prefixes := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "/") {
			value = "/" + value
		}
		prefixes = append(prefixes, value)
	}
	return prefixes
}

func acceptsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		mediaType := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if mediaType == "text/html" || mediaType == "application/xhtml+xml" {
			return true
		}
	}
	return false
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
