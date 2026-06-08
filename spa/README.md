# spa

`spa` serves built single-page app assets from Go HTTP servers.

It is intended for Vite-style bundles packaged with an `index.html` and hashed
assets under `/assets/`.

## Usage

Serve one known directory:

```go
mux.Handle("/", spa.DirHandler(os.Getenv("WEB_DIST_DIR")))
```

Serve an embedded filesystem:

```go
//go:embed web/*
var embeddedWeb embed.FS

sub, err := fs.Sub(embeddedWeb, "web")
if err != nil {
	panic(err)
}
mux.Handle("/", spa.Handler(sub))
```

Mount an SPA under a path prefix:

```go
mux.Handle("/admin/", http.StripPrefix("/admin/", spa.DirHandler(adminWebDir)))
mux.Handle("/console/", http.StripPrefix("/console/", spa.DirHandler(consoleWebDir)))
```

Configure the frontend build to use the same base path so generated asset URLs
include the prefix. For Vite, that is the `base` option.

## Routing

- Existing files are served directly.
- `/` and extensionless missing paths fall back to `index.html` only for
  `GET` or `HEAD` requests whose `Accept` header includes `text/html`.
- Missing paths under `/assets/` return `404`.
- Missing file-like paths such as `/favicon.ico` return `404`.

Connect, gRPC, and JSON API requests do not need route whitelists. They do not
look like browser HTML navigations, so missing API routes return `404` instead
of serving the SPA shell.

## Cache Headers

By default, `index.html` is served with:

```text
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

Other existing files are served with:

```text
Cache-Control: public, max-age=31536000, immutable
```

Override these with `WithIndexCacheControl` and `WithFileCacheControl`.

## Options

- `WithIndexPath(path)` changes the SPA shell file from `index.html`.
- `WithAssetPrefixes(prefixes...)` changes prefixes that return `404` when a
  requested file is missing.
- `WithIndexCacheControl(value)` changes the `Cache-Control` value for the SPA
  shell.
- `WithFileCacheControl(value)` changes the `Cache-Control` value for other
  static files.
