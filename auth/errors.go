package auth

import "errors"

var (
	// ErrPermissionDenied marks an explicit application authorization rejection.
	// Other unclassified errors are treated as internal failures by authservice.
	ErrPermissionDenied = errors.New("auth: permission denied")
	// ErrUnavailable marks a temporary failure of an authentication or
	// authorization dependency. Wrap it together with the underlying cause.
	ErrUnavailable = errors.New("auth: service unavailable")
)
