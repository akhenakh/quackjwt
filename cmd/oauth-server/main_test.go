package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"
)

func TestReaderArgs(t *testing.T) {
	for reader, want := range map[string]string{
		"read_parquet":   ", hive_partitioning = true",
		"read_csv_auto":  ", hive_partitioning = true",
		"read_json_auto": ", hive_partitioning = true",
		"read_vortex":    "",
	} {
		if got := readerArgs(reader, nil); got != want {
			t.Errorf("readerArgs(%q, nil) = %q, want %q", reader, got, want)
		}
	}

	// A declared schema replaces hive_partitioning rather than joining it:
	// DuckDB refuses the two together.
	got := readerArgs("read_parquet", []viewColumn{{Name: "in_tfr", Type: "BOOLEAN"}})
	if strings.Contains(got, "hive_partitioning") {
		t.Errorf("readerArgs with a declared schema still sets hive_partitioning: %q", got)
	}
	if !strings.Contains(got, "'in_tfr'") || !strings.Contains(got, "'BOOLEAN'") {
		t.Errorf("readerArgs = %q, want the declared column and type", got)
	}

	// union_by_name must never be the default: it makes CREATE VIEW read every
	// footer in the glob, which is one S3 request per object at startup.
	for _, args := range []string{
		readerArgs("read_parquet", nil),
		readerArgs("read_parquet", []viewColumn{{Name: "a", Type: "VARCHAR"}}),
	} {
		if strings.Contains(args, "union_by_name") {
			t.Errorf("readerArgs sets union_by_name: %q", args)
		}
	}
}

// twoGenerationArchive writes a hive-partitioned archive holding two shapes of
// file: an older one written before in_tfr existed, and a current one. The old
// partition sorts first, so it is what a glob binds to by default.
func twoGenerationArchive(t *testing.T, db *sql.DB) string {
	t.Helper()
	dir := t.TempDir()
	for q, rel := range map[string]string{
		"SELECT 'a' AS flight_id, 1 AS point_count":                 "year=2026/month=08/old.parquet",
		"SELECT 'b' AS flight_id, 2 AS point_count, true AS in_tfr": "year=2026/month=09/new.parquet",
	} {
		f := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(f), err)
		}
		if _, err := db.Exec(fmt.Sprintf("COPY (%s) TO '%s' (FORMAT parquet)", q, f)); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	return filepath.Join(dir, "**", "*.parquet")
}

func openDuckDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestBootstrapViewsBindsFromOneFile pins the property that broke production:
// creating a view must not depend on reading the whole glob. An unreadable
// file that the view's schema does not come from must not prevent creation —
// with union_by_name it would, because every footer is read up front.
func TestBootstrapViewsBindsFromOneFile(t *testing.T) {
	db := openDuckDB(t)

	dir := t.TempDir()
	good := filepath.Join(dir, "year=2026/month=08/aaa.parquet")
	if err := os.MkdirAll(filepath.Dir(good), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf("COPY (SELECT 'a' AS flight_id) TO '%s' (FORMAT parquet)", good)); err != nil {
		t.Fatalf("write good file: %v", err)
	}
	// Stands in for the thousandth object in an archive: never read at CREATE
	// time unless the reader is forced to walk every file.
	unread := filepath.Join(dir, "year=2026/month=09/zzz.parquet")
	if err := os.MkdirAll(filepath.Dir(unread), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(unread, []byte("not parquet"), 0o644); err != nil {
		t.Fatalf("write unreadable file: %v", err)
	}

	cfg := Config{S3Views: fmt.Sprintf("flights=%s", filepath.Join(dir, "**", "*.parquet"))}
	if err := bootstrapViews(db, cfg); err != nil {
		t.Fatalf("bootstrapViews read more than one file to create the view: %v", err)
	}
}

// TestBootstrapViewsDeclaredSchema covers VIEW_SCHEMA_PATH: the declared
// columns bind without walking the glob, and a file written before a column
// existed reads it back as NULL rather than making it unselectable.
func TestBootstrapViewsDeclaredSchema(t *testing.T) {
	db := openDuckDB(t)
	glob := twoGenerationArchive(t, db)

	schemaFile := filepath.Join(t.TempDir(), "schemas.yaml")
	if err := os.WriteFile(schemaFile, []byte(`views:
  flights:
    - {name: flight_id, type: VARCHAR}
    - {name: in_tfr, type: BOOLEAN}
`), 0o644); err != nil {
		t.Fatalf("write schema file: %v", err)
	}

	cfg := Config{
		S3Views:        fmt.Sprintf("flights=%s", glob),
		ViewSchemaPath: schemaFile,
	}
	if err := bootstrapViews(db, cfg); err != nil {
		t.Fatalf("bootstrapViews: %v", err)
	}

	rows, err := db.Query(`SELECT flight_id, in_tfr FROM flights ORDER BY flight_id`)
	if err != nil {
		t.Fatalf("select declared column across generations: %v", err)
	}
	defer rows.Close()

	got := map[string]any{}
	for rows.Next() {
		var id string
		var inTFR *bool
		if err := rows.Scan(&id, &inTFR); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if inTFR == nil {
			got[id] = nil
		} else {
			got[id] = *inTFR
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if v, ok := got["a"]; !ok || v != nil {
		t.Errorf("row from before the column existed: in_tfr = %v, want NULL", v)
	}
	if v, ok := got["b"]; !ok || v != true {
		t.Errorf("row written after the column existed: in_tfr = %v, want true", v)
	}

	// The trade-off: a declared schema exposes no hive partition columns, so
	// pruning predicates cannot be written against this view.
	if _, err := db.Query(`SELECT month FROM flights`); err == nil {
		t.Error("expected partition columns to be absent from a view with a declared schema")
	}
}

// Without a declared schema the view binds to the first file, so a column
// added later is not selectable. This is the documented trade-off, not a bug;
// pin it so the default is not changed back by accident.
func TestBootstrapViewsWithoutSchemaBindsFirstFile(t *testing.T) {
	db := openDuckDB(t)
	glob := twoGenerationArchive(t, db)

	cfg := Config{S3Views: fmt.Sprintf("flights=%s", glob)}
	if err := bootstrapViews(db, cfg); err != nil {
		t.Fatalf("bootstrapViews: %v", err)
	}
	if _, err := db.Query(`SELECT in_tfr FROM flights`); err == nil {
		t.Fatal("expected in_tfr to be unselectable without a declared schema")
	}
	// The partition columns must still be there.
	var month string
	if err := db.QueryRow(`SELECT month FROM flights WHERE flight_id = 'b'`).Scan(&month); err != nil {
		t.Fatalf("select hive partition column: %v", err)
	}
	if month != "09" {
		t.Errorf("month = %q, want %q", month, "09")
	}
}

func TestLoadViewSchemas(t *testing.T) {
	dir := t.TempDir()
	write := func(t *testing.T, body string) string {
		t.Helper()
		f := filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")+".yaml")
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return f
	}

	t.Run("unset path yields no schemas", func(t *testing.T) {
		got, err := loadViewSchemas("")
		if err != nil || got != nil {
			t.Fatalf("loadViewSchemas(\"\") = %v, %v; want nil, nil", got, err)
		}
	})

	t.Run("column order is file order", func(t *testing.T) {
		f := write(t, "views:\n  flights:\n    - {name: z, type: VARCHAR}\n    - {name: a, type: BOOLEAN}\n")
		got, err := loadViewSchemas(f)
		if err != nil {
			t.Fatalf("loadViewSchemas: %v", err)
		}
		if len(got["flights"]) != 2 || got["flights"][0].Name != "z" || got["flights"][1].Name != "a" {
			t.Errorf("columns = %+v, want declared order z, a", got["flights"])
		}
	})

	for name, body := range map[string]string{
		"no columns":     "views:\n  flights: []\n",
		"missing name":   "views:\n  flights:\n    - {type: VARCHAR}\n",
		"missing type":   "views:\n  flights:\n    - {name: a}\n",
		"duplicate name": "views:\n  flights:\n    - {name: a, type: VARCHAR}\n    - {name: a, type: BOOLEAN}\n",
		"not yaml":       "\tthis: [is: not\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadViewSchemas(write(t, body)); err == nil {
				t.Errorf("loadViewSchemas accepted %s", name)
			}
		})
	}
}

// A schema declared for a view that is not served, or for one read by a
// function that cannot take it, is a config error rather than a silent no-op.
func TestBootstrapViewsRejectsUnusableSchema(t *testing.T) {
	db := openDuckDB(t)
	dir := t.TempDir()
	schemaFile := filepath.Join(dir, "schemas.yaml")
	if err := os.WriteFile(schemaFile, []byte("views:\n  flights:\n    - {name: a, type: VARCHAR}\n"), 0o644); err != nil {
		t.Fatalf("write schema file: %v", err)
	}

	t.Run("view not in S3_VIEWS", func(t *testing.T) {
		cfg := Config{S3Views: "other=" + filepath.Join(dir, "*.parquet"), ViewSchemaPath: schemaFile}
		if err := bootstrapViews(db, cfg); err == nil {
			t.Error("expected an error for a schema naming an unserved view")
		}
	})

	t.Run("reader cannot take a schema", func(t *testing.T) {
		cfg := Config{S3Views: "flights=" + filepath.Join(dir, "*.csv"), ViewSchemaPath: schemaFile}
		if err := bootstrapViews(db, cfg); err == nil {
			t.Error("expected an error for a declared schema on read_csv_auto")
		}
	})
}
