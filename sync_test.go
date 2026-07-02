package quackjwt

import (
	"database/sql"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"
)

// quackPermissionsSchema mirrors the table created by Server.Start so that
// SyncPermissions can be exercised without spinning up the full control plane.
const quackPermissionsSchema = `
CREATE TABLE IF NOT EXISTS quack_permissions (
	sub VARCHAR,
	allowed_table VARCHAR,
	UNIQUE(sub, allowed_table)
);`

func TestSyncPermissions_ReplacesAllGrants(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(quackPermissionsSchema); err != nil {
		t.Fatalf("create table: %v", err)
	}

	srv := &Server{db: db}

	// Seed an existing grant that should disappear after sync.
	if _, err := db.Exec(`INSERT INTO quack_permissions (sub, allowed_table) VALUES ('stale', 'old_table');`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	grants := map[string][]string{
		"alice": {"sales", "ops_logs"},
		"bob":   {"sales_redacted"},
	}
	if err := srv.SyncPermissions(grants); err != nil {
		t.Fatalf("SyncPermissions: %v", err)
	}

	countRows := func() int {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM quack_permissions;`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if got := countRows(); got != 3 {
		t.Fatalf("row count after sync = %d, want 3", got)
	}

	// The stale grant must be gone.
	var c int
	if err := db.QueryRow(`SELECT count(*) FROM quack_permissions WHERE sub = 'stale';`).Scan(&c); err != nil {
		t.Fatalf("query stale: %v", err)
	}
	if c != 0 {
		t.Errorf("stale grant still present after sync: %d rows", c)
	}

	// Alice's grants are exactly the new set.
	rows, err := db.Query(`SELECT allowed_table FROM quack_permissions WHERE sub = 'alice' ORDER BY allowed_table;`)
	if err != nil {
		t.Fatalf("query alice: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, s)
	}
	if len(got) != 2 || got[0] != "ops_logs" || got[1] != "sales" {
		t.Errorf("alice grants = %v, want [ops_logs sales]", got)
	}
}

func TestSyncPermissions_EmptyMapClears(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(quackPermissionsSchema); err != nil {
		t.Fatalf("create table: %v", err)
	}
	srv := &Server{db: db}

	if _, err := db.Exec(`INSERT INTO quack_permissions VALUES ('alice', 'sales');`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := srv.SyncPermissions(map[string][]string{}); err != nil {
		t.Fatalf("SyncPermissions: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM quack_permissions;`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("row count after empty sync = %d, want 0", n)
	}
}

func TestSyncPermissions_DedupesConflicts(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(quackPermissionsSchema); err != nil {
		t.Fatalf("create table: %v", err)
	}
	srv := &Server{db: db}

	// Duplicate table entries for the same subject must not error (UNIQUE + ON
	// CONFLICT DO NOTHING) and must produce a single row.
	grants := map[string][]string{
		"alice": {"sales", "sales"},
	}
	if err := srv.SyncPermissions(grants); err != nil {
		t.Fatalf("SyncPermissions with dupes: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM quack_permissions WHERE sub = 'alice';`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("alice rows after duped sync = %d, want 1", n)
	}
}
