package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"
)

func TestReaderOptions(t *testing.T) {
	for reader, want := range map[string]string{
		"read_parquet":   ", union_by_name = true, hive_partitioning = true",
		"read_csv_auto":  ", union_by_name = true, hive_partitioning = true",
		"read_json_auto": ", union_by_name = true, hive_partitioning = true",
		"read_vortex":    "",
	} {
		if got := readerOptions(reader); got != want {
			t.Errorf("readerOptions(%q) = %q, want %q", reader, got, want)
		}
	}
}

// TestBootstrapViewsSpansSchemaGenerations pins the reason readerOptions
// exists. An archive whose producer gained a column partway through holds two
// shapes of file at once; a view over the glob must expose the union, reading
// the column back as NULL on the files written before it existed. Without
// union_by_name the view binds against whichever file the glob opens first and
// the newer columns cannot be selected at all.
func TestBootstrapViewsSpansSchemaGenerations(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	dir := t.TempDir()
	// Written by the old producer: no in_tfr column. Sorts first in the glob.
	oldFile := filepath.Join(dir, "year=2026", "month=08", "old.parquet")
	// Written by the current producer, after the rollup columns were added.
	newFile := filepath.Join(dir, "year=2026", "month=09", "new.parquet")
	for q, f := range map[string]string{
		"SELECT 'a' AS flight_id, 1 AS point_count":                 oldFile,
		"SELECT 'b' AS flight_id, 2 AS point_count, true AS in_tfr": newFile,
	} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(f), err)
		}
		if _, err := db.Exec(fmt.Sprintf("COPY (%s) TO '%s' (FORMAT parquet)", q, f)); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	cfg := Config{S3Views: fmt.Sprintf("flights=%s", filepath.Join(dir, "**", "*.parquet"))}
	if err := bootstrapViews(db, cfg); err != nil {
		t.Fatalf("bootstrapViews: %v", err)
	}

	rows := map[string]any{}
	r, err := db.Query(`SELECT flight_id, in_tfr FROM flights ORDER BY flight_id`)
	if err != nil {
		t.Fatalf("select across generations: %v", err)
	}
	defer r.Close()
	for r.Next() {
		var id string
		var inTFR *bool
		if err := r.Scan(&id, &inTFR); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if inTFR == nil {
			rows[id] = nil
		} else {
			rows[id] = *inTFR
		}
	}
	if err := r.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if got, ok := rows["a"]; !ok || got != nil {
		t.Errorf("pre-column row: in_tfr = %v, want NULL (the check never ran for it)", got)
	}
	if got, ok := rows["b"]; !ok || got != true {
		t.Errorf("post-column row: in_tfr = %v, want true", got)
	}

	// The partition columns must survive too.
	var month string
	if err := db.QueryRow(`SELECT month FROM flights WHERE flight_id = 'b'`).Scan(&month); err != nil {
		t.Fatalf("select hive column: %v", err)
	}
	if month != "09" {
		t.Errorf("month = %q, want \"09\"", month)
	}
}
