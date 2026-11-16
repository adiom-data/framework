package browserauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adiom-data/framework/auth"
	"github.com/adiom-data/framework/auth/tokenissuer"
	"golang.org/x/oauth2"
)

func TestTokenErrorStatus(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, 200},
		{"missing", errMissingSession, 401},
		{"invalid", ErrInvalidSession, 401},
		{"expired", errExpiredSession, 401},
		{"revoked", errRevokedSession, 401},
		{"permission", auth.ErrPermissionDenied, 403},
		{"token_permission", tokenissuer.ErrPermissionDenied, 403},
		{"unavailable", auth.ErrUnavailable, 503},
		{"deadline", context.DeadlineExceeded, 503},
		{"canceled", context.Canceled, 503},
		{"network", &net.DNSError{Err: "private resolver error", Name: "idp.example"}, 503},
		{"provider_unavailable", &oauth2.RetrieveError{Response: &http.Response{StatusCode: 503}}, 503},
		{"provider_rate_limit", &oauth2.RetrieveError{Response: &http.Response{StatusCode: 429}}, 503},
		{"provider_temporary_code", &oauth2.RetrieveError{ErrorCode: "temporarily_unavailable"}, 503},
		{"provider_server_code", &oauth2.RetrieveError{ErrorCode: "server_error"}, 503},
		{"provider_client_error", &oauth2.RetrieveError{ErrorCode: "invalid_client"}, 500},
		{"configuration", errNotConfigured, 500},
		{"unknown", errors.New("private failure"), 500},
		{"unavailable_over_invalid", errors.Join(ErrInvalidSession, auth.ErrUnavailable), 503},
		{"deadline_over_invalid", errors.Join(ErrInvalidSession, context.DeadlineExceeded), 503},
		{"network_over_invalid", errors.Join(ErrInvalidSession, &net.DNSError{Err: "private error"}), 503},
		{"provider_over_invalid", errors.Join(ErrInvalidSession, &oauth2.RetrieveError{Response: &http.Response{StatusCode: 503}}), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TokenErrorStatus(tc.err); got != tc.want {
				t.Fatalf("status=%d want %d", got, tc.want)
			}
			if tc.want == http.StatusUnauthorized && !errors.Is(tc.err, ErrInvalidSession) {
				t.Fatal("session rejection does not match public marker")
			}
			if tc.err != nil && TokenErrorStatus(fmt.Errorf("application wrapper: %w", tc.err)) != tc.want {
				t.Fatal("wrapping changed classification")
			}
		})
	}
}

func TestMintSessionRejectionsMatchPublicMarker(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"missing", "expired", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			e := securityTokenEndpoint(t)
			r := securitySessionRequest(http.MethodPost, "/auth/token")
			store := e.Store.(memorySessionStore)
			session := store["session"]
			switch kind {
			case "missing":
				r.Header.Del("Cookie")
			case "expired":
				session.ExpiresAt = time.Now().Add(-time.Minute)
			case "revoked":
				session.RevokedAt = time.Now()
			}
			store["session"] = session
			_, err := e.Mint(r)
			if !errors.Is(err, ErrInvalidSession) || TokenErrorStatus(err) != http.StatusUnauthorized {
				t.Fatalf("session error=%v status=%d", err, TokenErrorStatus(err))
			}
		})
	}
}

func TestTokenEndpointPreservesFailureCategories(t *testing.T) {
	t.Parallel()
	for _, transactional := range []bool{false, true} {
		for _, tc := range []struct {
			name, stage string
			cause       error
			status      int
		}{
			{"unknown_session", "get", ErrInvalidSession, 401},
			{"database_failure", "get", errors.New("private database failure"), 500},
			{"database_unavailable", "get", errors.Join(auth.ErrUnavailable, errors.New("private database outage")), 503},
			{"database_network", "get", &net.DNSError{Err: "private database network failure"}, 503},
			{"refresh_rejected", "refresh", ErrInvalidSession, 401},
			{"refresh_invalid_grant", "refresh", &oauth2.RetrieveError{ErrorCode: "invalid_grant", Response: &http.Response{StatusCode: 400}}, 401},
			{"refresh_unknown", "refresh", errors.New("private refresh failure"), 500},
			{"refresh_unavailable", "refresh", auth.ErrUnavailable, 503},
			{"persist_unknown", "update", errors.New("private persistence failure"), 500},
			{"persist_timeout", "update", context.DeadlineExceeded, 503},
		} {
			t.Run(fmt.Sprintf("transactional=%t/%s", transactional, tc.name), func(t *testing.T) {
				e := securityTokenEndpoint(t)
				store := &tokenErrorStore{memorySessionStore: e.Store.(memorySessionStore)}
				e.Store = store
				if transactional {
					e.Store = tokenErrorUpdateStore{store}
				}
				e.Refresher = refresherFunc(func(_ context.Context, session Session) (Session, error) {
					if tc.stage == "refresh" {
						return Session{}, tc.cause
					}
					return session, nil
				})
				if tc.stage == "get" {
					store.getErr = tc.cause
				}
				if tc.stage == "update" {
					store.updateErr = tc.cause
				}
				_, err := e.Mint(securitySessionRequest(http.MethodPost, "/auth/token"))
				if !errors.Is(err, tc.cause) || TokenErrorStatus(err) != tc.status {
					t.Fatalf("Mint error=%v status=%d want cause=%v status=%d", err, TokenErrorStatus(err), tc.cause, tc.status)
				}
				// A custom handler using the public helper and the built-in
				// handler must make the same decision without exposing causes.
				custom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := e.Mint(r)
					w.WriteHeader(TokenErrorStatus(err))
				})
				for _, handler := range []http.Handler{custom, e.Handler()} {
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, securitySessionRequest(http.MethodPost, "/auth/token"))
					if w.Code != tc.status || strings.Contains(w.Body.String(), "private") || len(w.Result().Cookies()) != 0 {
						t.Fatalf("response=%d cookies=%v body=%s", w.Code, w.Result().Cookies(), w.Body.String())
					}
				}
			})
		}
	}
}

func TestBrowserRefreshProviderFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, code     string
		upstream, want int
	}{
		{"invalid_grant", "invalid_grant", 400, 401},
		{"invalid_client", "invalid_client", 401, 500},
		{"unavailable", "server_error", 503, 503},
		{"rate_limit", "rate_limited", 429, 503},
		{"temporary_code", "temporarily_unavailable", 400, 503},
		{"unavailable_over_rejection", "invalid_grant", 503, 503},
		{"unknown", "unknown_error", 400, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.upstream)
				fmt.Fprintf(w, `{"error":%q,"error_description":"private provider detail"}`, tc.code)
			}))
			defer server.Close()
			b := &BrowserAuth{oauth2: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL, AuthStyle: oauth2.AuthStyleInParams}}}
			e := securityTokenEndpoint(t)
			store := e.Store.(memorySessionStore)
			session := store["session"]
			session.RefreshToken = "refresh"
			store["session"] = session
			e.Refresher = b
			_, err := b.RefreshSession(context.Background(), session)
			var providerErr *oauth2.RetrieveError
			if !errors.As(err, &providerErr) || providerErr.ErrorCode != tc.code || TokenErrorStatus(err) != tc.want {
				t.Fatalf("provider error=%v status=%d want %d", err, TokenErrorStatus(err), tc.want)
			}
			w := httptest.NewRecorder()
			e.Handler().ServeHTTP(w, securitySessionRequest(http.MethodPost, "/auth/token"))
			if w.Code != tc.want || strings.Contains(w.Body.String(), "private") || len(w.Result().Cookies()) != 0 {
				t.Fatalf("response=%d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable error response")
			}
			if store["session"].RefreshToken != "refresh" || !store["session"].RevokedAt.IsZero() {
				t.Fatal("failed refresh changed the stored session")
			}
		})
	}
}

func TestSQLMissingSessionRetainsNoRows(t *testing.T) {
	t.Parallel()
	_, err := (SQLSessionStore{}).scanSession(noSessionRow{})
	if !errors.Is(err, sql.ErrNoRows) || !errors.Is(err, ErrInvalidSession) || TokenErrorStatus(err) != http.StatusUnauthorized {
		t.Fatalf("missing session error=%v status=%d", err, TokenErrorStatus(err))
	}
}

type noSessionRow struct{}

func (noSessionRow) Scan(...any) error { return sql.ErrNoRows }

type tokenErrorStore struct {
	memorySessionStore
	getErr, updateErr error
}

func (s *tokenErrorStore) Get(ctx context.Context, id string) (Session, error) {
	if s.getErr != nil {
		return Session{}, s.getErr
	}
	return s.memorySessionStore.Get(ctx, id)
}
func (s *tokenErrorStore) Update(ctx context.Context, session Session) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	return s.memorySessionStore.Update(ctx, session)
}

type tokenErrorUpdateStore struct{ *tokenErrorStore }

func (s tokenErrorUpdateStore) UpdateSession(ctx context.Context, id string, update func(Session) (Session, error)) (Session, error) {
	session, err := s.Get(ctx, id)
	if err != nil {
		return Session{}, err
	}
	session, err = update(session)
	if err != nil {
		return Session{}, err
	}
	return session, s.Update(ctx, session)
}
