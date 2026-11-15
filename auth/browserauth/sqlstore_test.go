package browserauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Exercise database/sql's parameter conversion and scanning without requiring a
// running Postgres server. The scripted rows use the documented session schema.
type sessionTestConn struct {
	exec      func(string, []driver.NamedValue) error
	query     func(string) []driver.Value
	committed bool
}
type sessionTestConnector struct{ conn *sessionTestConn }

func (c sessionTestConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (c sessionTestConnector) Driver() driver.Driver                        { return sessionTestDriver{} }

type sessionTestDriver struct{}

func (sessionTestDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }
func (*sessionTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*sessionTestConn) Close() error                { return nil }
func (c *sessionTestConn) Begin() (driver.Tx, error) { return sessionTestTx{c}, nil }
func (c *sessionTestConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.exec(q, args); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}
func (c *sessionTestConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	return &sessionTestRows{values: c.query(q)}, nil
}

type sessionTestTx struct{ conn *sessionTestConn }

func (tx sessionTestTx) Commit() error { tx.conn.committed = true; return nil }
func (sessionTestTx) Rollback() error  { return nil }

type sessionTestRows struct {
	values []driver.Value
	done   bool
}

func (r *sessionTestRows) Columns() []string { return make([]string, len(r.values)) }
func (*sessionTestRows) Close() error        { return nil }
func (r *sessionTestRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

func TestSQLSessionStoreMetadataOptIn(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		name := "legacy"
		if enabled {
			name = "metadata"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			session := Session{ID: "sess", Issuer: "https://idp.example", Subject: "user", RefreshToken: "refresh",
				Claims: map[string]any{"connection_id": "idp-value"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
			if enabled {
				session.Metadata = map[string]string{"connection_id": "trusted"}
			}
			claims, _ := json.Marshal(session.Claims)
			row := []driver.Value{session.ID, session.Issuer, session.Subject, session.RefreshToken, claims,
				session.ExpiresAt, nil, nil, now, now}
			if enabled {
				row = append(row, []byte(`{"connection_id":"trusted"}`))
			}
			conn := &sessionTestConn{}
			db := sql.OpenDB(sessionTestConnector{conn})
			t.Cleanup(func() { _ = db.Close() })
			store := SQLSessionStore{DB: db, Now: func() time.Time { return now }}
			if enabled {
				store.MetadataColumn = "app_metadata"
			}
			writes := 0
			conn.exec = func(q string, args []driver.NamedValue) error {
				writes++
				wantArgs := 9
				if strings.HasPrefix(strings.TrimSpace(q), "insert") {
					wantArgs = 10
				}
				if enabled {
					wantArgs++
				}
				if len(args) != wantArgs {
					t.Fatalf("query %q has %d arguments, want %d", q, len(args), wantArgs)
				}
				if strings.Contains(q, "app_metadata") != enabled {
					t.Fatalf("metadata column selection: %q", q)
				}
				if enabled {
					var got map[string]string
					if err := json.Unmarshal(args[len(args)-1].Value.([]byte), &got); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, session.Metadata) {
						t.Fatalf("metadata=%v want=%v", got, session.Metadata)
					}
				}
				return nil
			}
			locked := false
			conn.query = func(q string) []driver.Value {
				if strings.Contains(q, "app_metadata") != enabled {
					t.Fatalf("metadata select: %q", q)
				}
				locked = strings.Contains(q, "for update")
				return row
			}
			if _, err := store.Create(context.Background(), session); err != nil {
				t.Fatal(err)
			}
			got, err := store.Get(context.Background(), session.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Metadata, session.Metadata) || !reflect.DeepEqual(got.Claims, session.Claims) {
				t.Fatalf("round trip: %+v", got)
			}
			if enabled {
				session.Metadata["connection_id"] = "updated"
			}
			if err := store.Update(context.Background(), session); err != nil {
				t.Fatal(err)
			}
			updated, err := store.UpdateSession(context.Background(), session.ID, func(s Session) (Session, error) {
				if enabled && s.Metadata["connection_id"] != "trusted" {
					t.Fatal("locked read lost metadata")
				}
				s.Metadata = session.Metadata
				s.RefreshToken = "rotated"
				return s, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !locked || !conn.committed || writes != 3 || updated.RefreshToken != "rotated" {
				t.Fatal("transactional update did not complete")
			}
			if !enabled {
				session.Metadata = map[string]string{"connection_id": "must-not-drop"}
				if _, err := store.Create(context.Background(), session); !errors.Is(err, ErrSessionMetadataDisabled) {
					t.Fatalf("create error=%v", err)
				}
				if err := store.Update(context.Background(), session); !errors.Is(err, ErrSessionMetadataDisabled) {
					t.Fatalf("update error=%v", err)
				}
				if writes != 3 {
					t.Fatal("disabled metadata reached database")
				}
			}
		})
	}
}
