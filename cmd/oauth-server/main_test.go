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

func TestViewQuery(t *testing.T) {
	const path = "s3://b/**/*.parquet"
	cols := []viewColumn{{Name: "in_tfr", Type: "BOOLEAN"}}

	t.Run("no schema gets hive partitioning", func(t *testing.T) {
		got := viewQuery("read_parquet", path, viewSchema{})
		if !strings.Contains(got, "hive_partitioning = true") {
			t.Errorf("viewQuery = %q, want hive_partitioning", got)
		}
	})

	t.Run("read_vortex takes no options", func(t *testing.T) {
		got := viewQuery("read_vortex", path, viewSchema{})
		if strings.Contains(got, "hive_partitioning") || strings.Contains(got, "schema") {
			t.Errorf("viewQuery = %q, want a bare call", got)
		}
	})

	// DuckDB refuses a declared schema together with hive partitioning.
	t.Run("declared schema replaces hive partitioning", func(t *testing.T) {
		got := viewQuery("read_parquet", path, viewSchema{Columns: cols})
		if strings.Contains(got, "hive_partitioning") {
			t.Errorf("viewQuery = %q, still sets hive_partitioning", got)
		}
		if !strings.Contains(got, "'in_tfr'") {
			t.Errorf("viewQuery = %q, want the declared column", got)
		}
	})

	t.Run("partitions are derived and filename dropped", func(t *testing.T) {
		got := viewQuery("read_parquet", path, viewSchema{
			Columns:    cols,
			Partitions: []partitionColumn{{Name: "org_id"}, {Name: "year", Type: "BIGINT"}},
		})
		for _, want := range []string{
			"filename = true",
			"EXCLUDE (filename)",
			`regexp_extract(filename, 'org_id=([^/]+)', 1) AS "org_id"`,
			`CAST(regexp_extract(filename, 'year=([^/]+)', 1) AS BIGINT) AS "year"`,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("viewQuery = %q, want it to contain %q", got, want)
			}
		}
	})

	// union_by_name must never appear: it makes CREATE VIEW read every footer
	// in the glob, i.e. one S3 request per object at startup.
	for _, v := range []viewSchema{
		{},
		{Columns: cols},
		{Columns: cols, Partitions: []partitionColumn{{Name: "org_id"}}},
	} {
		if q := viewQuery("read_parquet", path, v); strings.Contains(q, "union_by_name") {
			t.Errorf("viewQuery sets union_by_name: %q", q)
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

	// A declared schema on its own exposes no partition columns: DuckDB will
	// not combine `schema` with hive partitioning. Declaring partitions is
	// what brings them back — see TestBootstrapViewsDerivedPartitions.
	if _, err := db.Query(`SELECT month FROM flights`); err == nil {
		t.Error("expected partition columns to be absent without declared partitions")
	}
}

// TestBootstrapViewsDerivedPartitions covers the form that has both: columns
// pinned from the schema file, and partition columns rebuilt out of each
// object's path, so a view can expose a late-added column without giving up
// the predicates that prune.
func TestBootstrapViewsDerivedPartitions(t *testing.T) {
	db := openDuckDB(t)
	glob := twoGenerationArchive(t, db)

	schemaFile := filepath.Join(t.TempDir(), "schemas.yaml")
	if err := os.WriteFile(schemaFile, []byte(`views:
  flights:
    columns:
      - {name: flight_id, type: VARCHAR}
      - {name: in_tfr, type: BOOLEAN}
    partitions:
      - {name: year, type: BIGINT}
      - {name: month}
`), 0o644); err != nil {
		t.Fatalf("write schema file: %v", err)
	}

	cfg := Config{S3Views: fmt.Sprintf("flights=%s", glob), ViewSchemaPath: schemaFile}
	if err := bootstrapViews(db, cfg); err != nil {
		t.Fatalf("bootstrapViews: %v", err)
	}

	// The late-added column and the partition columns, in one query.
	var month string
	var inTFR *bool
	err := db.QueryRow(`SELECT month, in_tfr FROM flights WHERE year = 2026 AND month = '09'`).
		Scan(&month, &inTFR)
	if err != nil {
		t.Fatalf("select declared column beside derived partitions: %v", err)
	}
	if month != "09" {
		t.Errorf("month = %q, want %q", month, "09")
	}
	if inTFR == nil || !*inTFR {
		t.Errorf("in_tfr = %v, want true", inTFR)
	}

	// The row from before the column existed still reads NULL, and its
	// partition still resolves.
	var oldMonth string
	var oldTFR *bool
	if err := db.QueryRow(`SELECT month, in_tfr FROM flights WHERE flight_id = 'a'`).
		Scan(&oldMonth, &oldTFR); err != nil {
		t.Fatalf("select pre-column row: %v", err)
	}
	if oldMonth != "08" || oldTFR != nil {
		t.Errorf("pre-column row: month = %q, in_tfr = %v; want \"08\", NULL", oldMonth, oldTFR)
	}

	// filename is plumbing for the partition values, not a column of the view.
	if _, err := db.Query(`SELECT filename FROM flights`); err == nil {
		t.Error("filename should not be exposed by the view")
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

	// The bare-list spelling is the original form and must keep working.
	t.Run("bare list is columns, in file order", func(t *testing.T) {
		f := write(t, "views:\n  flights:\n    - {name: z, type: VARCHAR}\n    - {name: a, type: BOOLEAN}\n")
		got, err := loadViewSchemas(f)
		if err != nil {
			t.Fatalf("loadViewSchemas: %v", err)
		}
		cols := got["flights"].Columns
		if len(cols) != 2 || cols[0].Name != "z" || cols[1].Name != "a" {
			t.Errorf("columns = %+v, want declared order z, a", cols)
		}
		if len(got["flights"].Partitions) != 0 {
			t.Errorf("partitions = %+v, want none", got["flights"].Partitions)
		}
	})

	t.Run("mapping form carries partitions", func(t *testing.T) {
		f := write(t, "views:\n  flights:\n    columns:\n      - {name: a, type: VARCHAR}\n    partitions:\n      - {name: org_id}\n      - {name: year, type: BIGINT}\n")
		got, err := loadViewSchemas(f)
		if err != nil {
			t.Fatalf("loadViewSchemas: %v", err)
		}
		parts := got["flights"].Partitions
		if len(parts) != 2 || parts[0].Name != "org_id" || parts[1].Type != "BIGINT" {
			t.Errorf("partitions = %+v, want org_id and year BIGINT", parts)
		}
	})

	for name, body := range map[string]string{
		"no columns":                    "views:\n  flights: []\n",
		"missing name":                  "views:\n  flights:\n    - {type: VARCHAR}\n",
		"missing type":                  "views:\n  flights:\n    - {name: a}\n",
		"duplicate name":                "views:\n  flights:\n    - {name: a, type: VARCHAR}\n    - {name: a, type: BOOLEAN}\n",
		"not yaml":                      "\tthis: [is: not\n",
		"partitions without columns":    "views:\n  flights:\n    partitions:\n      - {name: org_id}\n",
		"partition with no name":        "views:\n  flights:\n    columns:\n      - {name: a, type: VARCHAR}\n    partitions:\n      - {type: VARCHAR}\n",
		"partition clashes with column": "views:\n  flights:\n    columns:\n      - {name: a, type: VARCHAR}\n    partitions:\n      - {name: a}\n",
		"partition name not a path key": "views:\n  flights:\n    columns:\n      - {name: a, type: VARCHAR}\n    partitions:\n      - {name: \"or/g\"}\n",
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
		cfg := Config{S3Views: "flights=" + filepath.Join(dir, "*.vortex"), ViewSchemaPath: schemaFile}
		if err := bootstrapViews(db, cfg); err == nil {
			t.Error("expected an error for a declared schema on read_vortex")
		}
	})

	t.Run("csv reader accepts a schema", func(t *testing.T) {
		csv := filepath.Join(dir, "flights.csv")
		if err := os.WriteFile(csv, []byte("a\n1\n"), 0o644); err != nil {
			t.Fatalf("write csv: %v", err)
		}
		cfg := Config{S3Views: "flights=" + csv, ViewSchemaPath: schemaFile}
		if err := bootstrapViews(db, cfg); err != nil {
			t.Fatalf("bootstrapViews with a csv schema: %v", err)
		}
		var typ string
		if err := db.QueryRow(`SELECT data_type FROM duckdb_columns() WHERE table_name = 'flights' AND column_name = 'a'`).Scan(&typ); err != nil {
			t.Fatalf("describe views: %v", err)
		}
		if typ != "VARCHAR" {
			t.Fatalf("column a type = %q, want VARCHAR from the declared schema", typ)
		}
	})
}
