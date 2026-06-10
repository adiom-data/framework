package browserauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const DefaultSessionTable = "auth_sessions"

var tableNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type sessionScanner interface {
	Scan(...any) error
}

type sessionExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// SQLSessionStore stores sessions in a PostgreSQL-compatible database/sql DB.
type SQLSessionStore struct {
	DB    *sql.DB
	Table string
	Now   func() time.Time
}

// Create implements SessionStore.
func (s SQLSessionStore) Create(ctx context.Context, session Session) (Session, error) {
	if s.DB == nil {
		return Session{}, errors.New("browserauth: sql session store DB is required")
	}
	if session.ID == "" {
		id, err := NewSessionID()
		if err != nil {
			return Session{}, err
		}
		session.ID = id
	}
	if session.ExpiresAt.IsZero() {
		return Session{}, errors.New("browserauth: session expiration is required")
	}
	now := s.now()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	session.UpdatedAt = now
	claims, err := json.Marshal(nonNilClaims(session.Claims))
	if err != nil {
		return Session{}, err
	}
	_, err = s.DB.ExecContext(ctx, fmt.Sprintf(`
insert into %s (
  id, issuer, subject, refresh_token, claims, expires_at, upstream_expires_at, revoked_at, created_at, updated_at
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
`, s.table()),
		session.ID,
		session.Issuer,
		session.Subject,
		session.RefreshToken,
		claims,
		nullTime(session.ExpiresAt),
		nullTime(session.UpstreamExpiresAt),
		nullTime(session.RevokedAt),
		session.CreatedAt,
		session.UpdatedAt,
	)
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

// Get implements SessionStore.
func (s SQLSessionStore) Get(ctx context.Context, id string) (Session, error) {
	if s.DB == nil {
		return Session{}, errors.New("browserauth: sql session store DB is required")
	}
	return scanSession(s.DB.QueryRowContext(ctx, fmt.Sprintf(`
	select id, issuer, subject, refresh_token, claims, expires_at, upstream_expires_at, revoked_at, created_at, updated_at
	from %s
	where id = $1
	`, s.table()), id))
}

// Update implements SessionStore.
func (s SQLSessionStore) Update(ctx context.Context, session Session) error {
	if s.DB == nil {
		return errors.New("browserauth: sql session store DB is required")
	}
	return s.update(ctx, s.DB, session)
}

// UpdateSession implements SessionUpdateStore.
func (s SQLSessionStore) UpdateSession(ctx context.Context, id string, update func(Session) (Session, error)) (Session, error) {
	if s.DB == nil {
		return Session{}, errors.New("browserauth: sql session store DB is required")
	}
	if update == nil {
		return Session{}, errors.New("browserauth: session update function is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	session, err := scanSession(tx.QueryRowContext(ctx, fmt.Sprintf(`
	select id, issuer, subject, refresh_token, claims, expires_at, upstream_expires_at, revoked_at, created_at, updated_at
	from %s
	where id = $1
	for update
	`, s.table()), id))
	if err != nil {
		return Session{}, err
	}
	session, err = update(session)
	if err != nil {
		return Session{}, err
	}
	if err := s.update(ctx, tx, session); err != nil {
		return Session{}, err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, err
	}
	committed = true
	return session, nil
}

func scanSession(row sessionScanner) (Session, error) {
	var session Session
	var claims []byte
	var refreshToken sql.NullString
	var expiresAt, upstreamExpiresAt, revokedAt sql.NullTime
	err := row.Scan(
		&session.ID,
		&session.Issuer,
		&session.Subject,
		&refreshToken,
		&claims,
		&expiresAt,
		&upstreamExpiresAt,
		&revokedAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		return Session{}, err
	}
	session.RefreshToken = refreshToken.String
	session.ExpiresAt = expiresAt.Time
	session.UpstreamExpiresAt = upstreamExpiresAt.Time
	session.RevokedAt = revokedAt.Time
	if len(claims) > 0 {
		if err := json.Unmarshal(claims, &session.Claims); err != nil {
			return Session{}, err
		}
	}
	if session.Claims == nil {
		session.Claims = map[string]any{}
	}
	return session, nil
}

func (s SQLSessionStore) update(ctx context.Context, execer sessionExecer, session Session) error {
	session.UpdatedAt = s.now()
	claims, err := json.Marshal(nonNilClaims(session.Claims))
	if err != nil {
		return err
	}
	_, err = execer.ExecContext(ctx, fmt.Sprintf(`
	update %s
	set issuer = $2,
	    subject = $3,
    refresh_token = $4,
    claims = $5,
    expires_at = $6,
    upstream_expires_at = $7,
    revoked_at = $8,
    updated_at = $9
where id = $1
`, s.table()),
		session.ID,
		session.Issuer,
		session.Subject,
		session.RefreshToken,
		claims,
		nullTime(session.ExpiresAt),
		nullTime(session.UpstreamExpiresAt),
		nullTime(session.RevokedAt),
		session.UpdatedAt,
	)
	return err
}

// Revoke implements SessionStore.
func (s SQLSessionStore) Revoke(ctx context.Context, id string) error {
	if s.DB == nil {
		return errors.New("browserauth: sql session store DB is required")
	}
	now := s.now()
	_, err := s.DB.ExecContext(ctx, fmt.Sprintf(`
update %s
set revoked_at = $2, updated_at = $2
where id = $1
`, s.table()), id, now)
	return err
}

func (s SQLSessionStore) table() string {
	table := s.Table
	if table == "" {
		table = DefaultSessionTable
	}
	if !tableNamePattern.MatchString(table) {
		panic("browserauth: invalid SQL session table name")
	}
	return table
}

func (s SQLSessionStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func nonNilClaims(claims map[string]any) map[string]any {
	if claims == nil {
		return map[string]any{}
	}
	return claims
}

func nullTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: !value.IsZero()}
}

var _ SessionStore = SQLSessionStore{}
var _ SessionUpdateStore = SQLSessionStore{}
