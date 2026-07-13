package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

var postgresTestDriverID atomic.Uint64

type postgresExecDriver struct {
	exec func() error
}

func (d *postgresExecDriver) Open(string) (driver.Conn, error) {
	return &postgresExecConn{exec: d.exec}, nil
}

type postgresExecConn struct {
	exec func() error
}

func (c *postgresExecConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}

func (c *postgresExecConn) Close() error { return nil }

func (c *postgresExecConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}

func (c *postgresExecConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	if errExec := c.exec(); errExec != nil {
		return nil, errExec
	}
	return driver.RowsAffected(1), nil
}

func openPostgresTestDB(t *testing.T, exec func() error) *sql.DB {
	t.Helper()
	driverName := fmt.Sprintf("postgres-store-test-%d", postgresTestDriverID.Add(1))
	sql.Register(driverName, &postgresExecDriver{exec: exec})
	db, errOpen := sql.Open(driverName, "")
	if errOpen != nil {
		t.Fatalf("open test database: %v", errOpen)
	}
	t.Cleanup(func() {
		if errClose := db.Close(); errClose != nil {
			t.Errorf("close test database: %v", errClose)
		}
	})
	return db
}

func TestPostgresStoreSaveCommitsDatabaseBeforeReplacingLocalMirror(t *testing.T) {
	authDir := t.TempDir()
	path := filepath.Join(authDir, "codex.json")
	original := []byte(`{"type":"codex","access_token":"old"}`)
	if errWrite := os.WriteFile(path, original, 0o600); errWrite != nil {
		t.Fatalf("write original auth file: %v", errWrite)
	}

	var observedDuringExec []byte
	db := openPostgresTestDB(t, func() error {
		var errRead error
		observedDuringExec, errRead = os.ReadFile(path)
		return errRead
	})
	store := &PostgresStore{
		db:      db,
		cfg:     PostgresStoreConfig{AuthTable: defaultAuthTable},
		authDir: authDir,
	}
	auth := &cliproxyauth.Auth{
		ID:       "codex.json",
		FileName: "codex.json",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "new"},
	}

	if _, errSave := store.Save(context.Background(), auth); errSave != nil {
		t.Fatalf("Save() error = %v", errSave)
	}
	if string(observedDuringExec) != string(original) {
		t.Fatalf("local mirror during database commit = %s, want original %s", observedDuringExec, original)
	}
	updated, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read updated auth file: %v", errRead)
	}
	if string(updated) == string(original) || !jsonEqual(updated, []byte(`{"type":"codex","access_token":"new","disabled":false}`)) {
		t.Fatalf("updated local mirror = %s, want new persisted metadata", updated)
	}
}

func TestPostgresStoreSaveDatabaseFailureLeavesLocalMirrorUnchanged(t *testing.T) {
	authDir := t.TempDir()
	path := filepath.Join(authDir, "codex.json")
	original := []byte(`{"type":"codex","access_token":"old"}`)
	if errWrite := os.WriteFile(path, original, 0o600); errWrite != nil {
		t.Fatalf("write original auth file: %v", errWrite)
	}

	errDatabase := errors.New("database unavailable")
	db := openPostgresTestDB(t, func() error { return errDatabase })
	store := &PostgresStore{
		db:      db,
		cfg:     PostgresStoreConfig{AuthTable: defaultAuthTable},
		authDir: authDir,
	}
	auth := &cliproxyauth.Auth{
		ID:       "codex.json",
		FileName: "codex.json",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "new"},
	}

	_, errSave := store.Save(context.Background(), auth)
	if !errors.Is(errSave, errDatabase) {
		t.Fatalf("Save() error = %v, want database error", errSave)
	}
	unchanged, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read auth file after failed save: %v", errRead)
	}
	if string(unchanged) != string(original) {
		t.Fatalf("local mirror after database failure = %s, want original %s", unchanged, original)
	}
}

func TestPostgresStoreSaveReportsCommittedDatabaseWhenLocalMirrorFails(t *testing.T) {
	authDir := t.TempDir()
	path := filepath.Join(authDir, "codex.json")
	if errMkdir := os.Mkdir(path, 0o700); errMkdir != nil {
		t.Fatalf("create conflicting local directory: %v", errMkdir)
	}

	databaseWrites := 0
	db := openPostgresTestDB(t, func() error {
		databaseWrites++
		return nil
	})
	store := &PostgresStore{
		db:      db,
		cfg:     PostgresStoreConfig{AuthTable: defaultAuthTable},
		authDir: authDir,
	}
	auth := &cliproxyauth.Auth{
		ID:       "codex.json",
		FileName: "codex.json",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "new"},
	}

	_, errSave := store.Save(context.Background(), auth)
	if errSave == nil {
		t.Fatal("Save() error = nil, want local mirror error")
	}
	if databaseWrites != 1 {
		t.Fatalf("database writes = %d, want 1", databaseWrites)
	}
	var committed interface{ PersistenceCommitted() bool }
	if !errors.As(errSave, &committed) || !committed.PersistenceCommitted() {
		t.Fatalf("Save() error = %T %v, want committed persistence error", errSave, errSave)
	}
	if got := auth.Attributes[cliproxyauth.AttributePath]; got != path {
		t.Fatalf("auth path = %q, want %q after committed database write", got, path)
	}
	if got := auth.Attributes[cliproxyauth.AttributeSourceBackend]; got != cliproxyauth.AuthSourcePostgres {
		t.Fatalf("auth source backend = %q, want %q", got, cliproxyauth.AuthSourcePostgres)
	}
}
