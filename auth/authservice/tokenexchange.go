package authservice

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/credential"
)

const (
	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	JWTTokenType           = "urn:ietf:params:oauth:token-type:jwt"
	AccessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
)

// TokenExchangeResponse is an RFC 8693 bearer access token response.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

// TokenExchangeHandler returns an optional RFC 8693 HTTP interface to this
// service. Mount it at the application's chosen token URL and serve over HTTPS.
// It accepts JWT subjects and issues bearer access tokens using the existing
// exchanger, authorizer, and issuer. Client authentication, if required, is the
// application's responsibility (for example, in middleware).
//
// Requested scopes are passed in ExternalIdentity.Claims["requested_scopes"];
// conflicting credential and HTTP scope requests are rejected. Audiences and
// resources are passed as request metadata on ExternalIdentity. The authorizer
// owns target validation and the final identity, including its scopes and Aud.
// This handler does not provide discovery, actor tokens, or refresh tokens.
func (s *Service) TokenExchangeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeExchangeError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST.")
			return
		}
		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" ||
			(params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Use a UTF-8 form encoded request body.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
			return
		}
		form := r.PostForm // Exchange parameters must come from the body, not the URL.
		for name, values := range form {
			if len(values) > 1 && name != "resource" && name != "audience" {
				writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Repeated request parameter.")
				return
			}
		}
		if form.Get("grant_type") == "" {
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Missing required exchange parameter.")
			return
		}
		if form.Get("grant_type") != TokenExchangeGrantType {
			writeExchangeError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type.")
			return
		}
		if form.Get("subject_token") == "" || form.Get("subject_token_type") == "" {
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Missing required exchange parameter.")
			return
		}
		if form.Get("subject_token_type") != JWTTokenType ||
			(form.Get("requested_token_type") != "" && form.Get("requested_token_type") != AccessTokenType) {
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Only JWT subjects and access token outputs are supported.")
			return
		}
		if form.Get("actor_token") != "" || form.Get("actor_token_type") != "" {
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Actor tokens are not supported.")
			return
		}
		var requestedScopes []string
		if scope := form.Get("scope"); scope != "" {
			requestedScopes = strings.Split(scope, " ")
			if !validScopeTokens(requestedScopes) {
				writeExchangeError(w, http.StatusBadRequest, "invalid_scope", "Invalid scope syntax.")
				return
			}
			requestedScopes = auth.NormalizeScopes(requestedScopes)
		}
		resources := nonEmptyValues(form["resource"])
		for _, resource := range resources {
			u, err := url.Parse(resource)
			if err != nil || !u.IsAbs() || strings.Contains(resource, "#") || strings.ContainsAny(resource, " \t\r\n") {
				writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Resources must be absolute URIs without fragments.")
				return
			}
		}
		if s == nil || s.Exchanger == nil || s.Authorizer == nil || s.Issuer == nil {
			writeExchangeError(w, http.StatusInternalServerError, "server_error", "Token exchange is not configured.")
			return
		}
		result, err := s.Exchanger.ExchangeCredential(r.Context(), form.Get("subject_token"))
		if err != nil {
			writeExchangeFailure(w, err)
			return
		}
		external := result.ExternalIdentity
		external.Claims, err = exchangeClaims(result, requestedScopes)
		if err != nil {
			writeExchangeError(w, http.StatusBadRequest, "invalid_request", "Conflicting or invalid credential scope requests.")
			return
		}
		external.Audiences = nonEmptyValues(form["audience"])
		external.Resources = resources
		identity, err := s.Authorizer.Authorize(r.Context(), external)
		if err != nil {
			writeExchangeFailure(w, err)
			return
		}
		identity.Scopes = auth.NormalizeScopes(identity.Scopes)
		if !validScopeTokens(identity.Scopes) {
			writeExchangeError(w, http.StatusInternalServerError, "server_error", "Invalid authorized scope syntax.")
			return
		}
		token, expiresAt, err := s.Issuer.Mint(r.Context(), identity)
		if err != nil {
			writeExchangeError(w, http.StatusInternalServerError, "server_error", "Unable to issue access token.")
			return
		}
		_ = json.NewEncoder(w).Encode(TokenExchangeResponse{
			AccessToken:     token,
			IssuedTokenType: AccessTokenType,
			TokenType:       "Bearer",
			ExpiresIn:       max(int64(0), expiresAt.Unix()-time.Now().Unix()),
			Scope:           strings.Join(identity.Scopes, " "),
		})
	})
}

func writeExchangeError(w http.ResponseWriter, status int, code, description string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{code, description})
}

// exchangeClaims preserves verifier-owned claims and normalizes both scope
// request representations without mutating maps returned by the exchanger.
func exchangeClaims(result credential.Result, requested []string) (map[string]any, error) {
	claims := make(map[string]any, len(result.ExternalIdentity.Claims)+1)
	for key, value := range result.ExternalIdentity.Claims {
		claims[key] = value
	}
	credentialScopes := auth.NormalizeScopes(result.RequestedScopes)
	if value, ok := claims["requested_scopes"]; ok {
		var claimScopes []string
		switch value := value.(type) {
		case []string:
			claimScopes = value
		case []any:
			for _, item := range value {
				scope, ok := item.(string)
				if !ok {
					return nil, credential.ErrInvalid
				}
				claimScopes = append(claimScopes, scope)
			}
		default:
			return nil, credential.ErrInvalid
		}
		claimScopes = auth.NormalizeScopes(claimScopes)
		if len(credentialScopes) > 0 && !slices.Equal(credentialScopes, claimScopes) {
			return nil, credential.ErrInvalid
		}
		credentialScopes = claimScopes
	}
	if !validScopeTokens(credentialScopes) ||
		(len(credentialScopes) > 0 && len(requested) > 0 && !slices.Equal(credentialScopes, requested)) {
		return nil, credential.ErrInvalid
	}
	if len(requested) > 0 {
		claims["requested_scopes"] = requested
	} else if len(credentialScopes) > 0 {
		claims["requested_scopes"] = credentialScopes
	}
	return claims, nil
}

// RFC 6749 scope-token = %x21 / %x23-5B / %x5D-7E.
func validScopeTokens(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "" {
			return false
		}
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return false
			}
		}
	}
	return true
}

func nonEmptyValues(values []string) []string {
	var out []string
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
