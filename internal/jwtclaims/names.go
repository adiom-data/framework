// Package jwtclaims protects registered claim names from encoding/json's
// case-insensitive field matching, including Unicode case-fold equivalents.
package jwtclaims

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Registered contains the case-sensitive registered JWT claim names.
var Registered = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

// Reserved reports whether name would match any protected field in the decoder.
func Reserved(name string, protected []string) bool {
	for _, field := range protected {
		if strings.EqualFold(name, field) {
			return true
		}
	}
	return false
}

// ValidateNames rejects non-canonical aliases before decoding into a struct.
// Unrelated custom claims remain unrestricted.
func ValidateNames(data []byte, protected []string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		for _, field := range protected {
			if name != field && strings.EqualFold(name, field) {
				return fmt.Errorf("JWT claim name %q aliases protected claim %q", name, field)
			}
		}
	}
	return nil
}
