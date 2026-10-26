package quackjwt

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
)

// TokenVerifier takes a raw token (e.g., JWT) and returns the subject (sub).
// Return an error if the token is invalid or expired.
type TokenVerifier func(token string) (sub string, err error)

// Server wraps a DuckDB Quack instance with JWT-based access control.
type Server struct {
	db            *sql.DB
	verify        TokenVerifier
	quackURI      string
	serverSecret  string
	controlServer *http.Server
	sessionTTL    time.Duration
	sweepCancel   context.CancelFunc
}

// Authorization patterns. A query is denied if it calls a file/system function
// (arbitrary file/network read or internal-state leakage) or begins with a
// non-SELECT statement. Matched as function-call / statement-start forms to
// avoid false positives on string literals.
const (
	dangerousFnPattern = `(?i)\b(read_csv|read_csv_auto|read_json|read_json_auto|read_json_objects|read_json_objects_auto|read_parquet|read_parquet_metadata|read_vortex|read_blob|read_blob_auto|read_text|read_text_auto|read_sql|read_ndjson|read_arrow|read_ipc|read_feather|read_avro|read_sqlite|read_postgres|read_mysql|read_duckdb|read_wkb|read_wkt|read_spatial|read_iceberg|st_read|glob|glob_each|list_glob|query_table|query_table_function|duckdb_settings|duckdb_functions|duckdb_secrets|duckdb_persistent_secrets|duckdb_variables|duckdb_memory|duckdb_extensions|duckdb_databases|duckdb_schemas|duckdb_views|duckdb_columns|duckdb_indexes|duckdb_constraints|duckdb_dependencies|duckdb_keywords|duckdb_types|duckdb_partition_info|duckdb_partitions|duckdb_table_info|quack_server_list|quack_identify|quack_clear_cache|quack_query|quack_query_by_name)\s*\(`

	ddlPattern = `(?i)(^|;)\s*(create|insert|update|delete|drop|alter|attach|detach|copy|checkpoint|force_checkpoint|pragma|install|load|set|call|vacuum|summarize)\b`

	// pathStringPattern blocks DuckDB's `FROM '<path>'` / `JOIN '<path>'` /
	// `, '<path>'` string-source shorthand, which reads files/S3/HTTP without
	// invoking a read_*() function (and thus bypasses dangerousFnPattern). It
	// targets the FROM/JOIN position or a comma-join with a path-like literal
	// (s3://, https://, /abs, *.parquet, …) so that legitimate WHERE-clause
	// string filters such as WHERE url = 'https://…' are not affected.
	pathStringPattern = `(?i)\bfrom\s+\x27[^\x27]*\x27|\bjoin\s+\x27[^\x27]*\x27|,\s*\x27(?:/[^\x27]*|[^\x27]*://[^\x27]*|[^\x27]*\.(?:parquet|csv|json|avro|arrow|feather|ndjson|tsv|orc|txt|sqlite|vortex)[^\x27]*)\x27`
)

// The statements Quack's client sends outside the user's SQL, which bypass
// table grants:
//
//   - the catalog-loading queries issued during ATTACH. They are matched
//     exactly (after whitespace normalization) rather than by function name: a
//     pattern that admits duckdb_views() also admits `SELECT sql FROM
//     duckdb_views()`, which would expose view definitions and the S3 paths in
//     them. Pinned to Quack protocol 3 (DuckDB 2.0); an upstream change to
//     either query makes ATTACH fail closed until these are updated.
//   - the transaction control statements that wrap a remote scan. They touch no
//     data on their own, and every data query inside the transaction is still
//     authorized separately.
const (
	quackSchemaLoadQuery = `
WITH RECURSIVE schema_tree AS (
	SELECT oid, database_name, [schema_name] AS schema_path
	FROM duckdb_schemas()
	WHERE parent_schema_oid IS NULL
	UNION ALL
	SELECT nested.oid, nested.database_name, list_append(parent.schema_path, nested.schema_name)
	FROM duckdb_schemas() nested
	JOIN schema_tree parent ON nested.parent_schema_oid = parent.oid
)
SELECT oid, database_name, schema_path, current_database()
FROM schema_tree
WHERE database_name NOT IN ('system', 'temp')
ORDER BY (database_name = current_database()) DESC, database_name, length(schema_path), schema_path
	`

	quackTablesLoadQuery = `
SELECT schema_oid, sql, 'table'
FROM duckdb_tables()
UNION ALL
SELECT schema_oid, view_name, 'view'
FROM duckdb_views()
	`
)

// quackControlQueries are sent verbatim by Quack's client.
var quackControlQueries = []string{"BEGIN TRANSACTION", "COMMIT", "ROLLBACK"}

const (
	defaultSessionTTL    = time.Hour
	defaultSweepInterval = 10 * time.Minute
)

// normalizeQuery collapses whitespace runs the same way the authz macro does.
func normalizeQuery(q string) string { return strings.Join(strings.Fields(q), " ") }

// ungatedQueriesList renders the control statements and catalog-load queries
// as a SQL literal list, for exact comparison against the normalized req_query.
func ungatedQueriesList() string {
	queries := append([]string{quackSchemaLoadQuery, quackTablesLoadQuery}, quackControlQueries...)
	parts := make([]string, len(queries))
	for i, q := range queries {
		parts[i] = "'" + strings.ReplaceAll(normalizeQuery(q), "'", "''") + "'"
	}
	return strings.Join(parts, ", ")
}

// NewServer initializes the wrapper.
func NewServer(db *sql.DB, quackURI string, verify TokenVerifier) *Server {
	return &Server{
		db:         db,
		verify:     verify,
		quackURI:   quackURI,
		sessionTTL: defaultSessionTTL,
	}
}

// SetSessionTTL configures the lifetime after which idle quack_sessions rows
// are reaped. Must be called before Start. Defaults to one hour.
func (s *Server) SetSessionTTL(ttl time.Duration) { s.sessionTTL = ttl }

func generateSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Start sets up the tables, macros, hidden control plane, and the Quack server.
func (s *Server) Start() error {
	s.serverSecret = generateSecret()

	// Install & load necessary extensions
	setupQueries := []string{
		"SET autoinstall_known_extensions=1;",
		"SET autoload_known_extensions=1;",
		"INSTALL httpfs;",
		"LOAD httpfs;",
		"INSTALL quack;",
		"LOAD quack;",
		// Create tables for tracking active sessions and permissions.
		// created_at supports reaping stale sessions (see sweepSessions).
		`CREATE TABLE IF NOT EXISTS quack_sessions (
			sid VARCHAR PRIMARY KEY,
			sub VARCHAR,
			created_at TIMESTAMP
		);`,
		// Migrate persistent DBs that predate the created_at column.
		`ALTER TABLE quack_sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP;`,
		`CREATE TABLE IF NOT EXISTS quack_permissions (
			sub VARCHAR,
			allowed_table VARCHAR,
			UNIQUE(sub, allowed_table)
		);`,
	}

	for _, q := range setupQueries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("failed to execute setup query %q: %w", q, err)
		}
	}

	// Start local control plane HTTP server on a random loopback port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start control plane: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", s.handleAuth)
	s.controlServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB
	}
	go s.controlServer.Serve(listener)

	// Background reaper for stale sessions so quack_sessions does not grow
	// without bound and stale sid->sub mappings cannot linger.
	sweepCtx, cancel := context.WithCancel(context.Background())
	s.sweepCancel = cancel
	go s.sweepSessions(sweepCtx)

	// Authentication macro: bridges DuckDB's auth hook to the Go control plane.
	// req_server_token is the secret passed to quack_serve; the macro forwards
	// it (url-encoded) so handleAuth can verify the call originated from Quack,
	// not from a client invoking the macro directly via SQL. The macro body is
	// readable by clients via duckdb_functions(), so it must not embed secrets;
	// the only secret travels through req_server_token, which clients cannot
	// supply.
	authMacro := fmt.Sprintf(`
		CREATE OR REPLACE MACRO quack_jwt_auth(req_sid, req_client_token, req_server_token) AS (
			SELECT allowed FROM read_json_auto('http://127.0.0.1:%d/auth?sid=' || url_encode(req_sid) || '&token=' || url_encode(req_client_token) || '&srv=' || url_encode(req_server_token))
		);
	`, port)
	if _, err := s.db.Exec(authMacro); err != nil {
		return fmt.Errorf("failed to create auth macro: %w", err)
	}

	// Authorization macro. The previous design authorized any query whose text
	// merely mentioned a granted table name, which let a granted user read any
	// table by referencing the granted name in a comment, CTE, or alias
	// (e.g. `WITH public_metrics AS (SELECT * FROM secret) SELECT * FROM public_metrics`).
	//
	// The new logic is default-deny: a query is authorized only if it references
	// at least one granted table, references NO non-granted table (reading a
	// table always requires naming it), and invokes no file/system function that
	// could bypass table-level grants (e.g. read_csv_auto, duckdb_settings).
	// Quack's own ATTACH-time catalog queries and transaction control
	// statements are matched exactly and allowed; everything else referencing
	// data is gated by the grants below.
	authzMacro := fmt.Sprintf(`
		CREATE OR REPLACE MACRO quack_jwt_authz(req_sid, req_query) AS (
			trim(regexp_replace(req_query, '\s+', ' ', 'g')) IN (%s) OR
			(
				EXISTS (
					SELECT 1
					FROM quack_sessions s
					JOIN quack_permissions p ON p.sub = s.sub
					WHERE s.sid = req_sid
					  AND regexp_matches(req_query, '(?i)\b' || regexp_escape(p.allowed_table) || '\b')
				)
				AND NOT EXISTS (
					SELECT 1
					FROM information_schema.tables t
					JOIN quack_sessions s ON s.sid = req_sid
					WHERE NOT EXISTS (
						SELECT 1 FROM quack_permissions p
						WHERE p.sub = s.sub AND p.allowed_table = t.table_name
					)
					AND regexp_matches(req_query, '(?i)\b' || regexp_escape(t.table_name) || '\b')
				)
				AND NOT regexp_matches(req_query, '%s')
				AND NOT regexp_matches(req_query, '%s')
				AND NOT regexp_matches(req_query, '%s')
			)
		);
	`, ungatedQueriesList(), dangerousFnPattern, ddlPattern, pathStringPattern)
	if _, err := s.db.Exec(authzMacro); err != nil {
		return fmt.Errorf("failed to create authz macro: %w", err)
	}

	// Hook up settings and start Quack. The server secret is passed as the
	// quack_serve `token` argument; Quack hands it to the auth function as
	// req_server_token, which handleAuth checks against s.serverSecret.
	quackStartQueries := []string{
		"SET GLOBAL quack_authentication_function = 'quack_jwt_auth';",
		"SET GLOBAL quack_authorization_function = 'quack_jwt_authz';",
		fmt.Sprintf("CALL quack_serve('%s', token => '%s', allow_other_hostname => true, disable_ssl => true);", s.quackURI, s.serverSecret),
	}

	for _, q := range quackStartQueries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("failed to start quack server: %w", err)
		}
	}

	return nil
}

// Stop shuts down the local control plane and the Quack server.
func (s *Server) Stop() error {
	var errs []error
	if s.sweepCancel != nil {
		s.sweepCancel()
	}
	if s.controlServer != nil {
		if err := s.controlServer.Shutdown(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}

	if _, err := s.db.Exec(fmt.Sprintf("CALL quack_stop('%s');", s.quackURI)); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping server: %v", errs)
	}
	return nil
}

// sweepSessions periodically deletes quack_sessions rows older than sessionTTL
// so the table does not grow without bound and stale sid->sub mappings cannot
// outlive the connection they belong to.
func (s *Server) sweepSessions(ctx context.Context) {
	ticker := time.NewTicker(defaultSweepInterval)
	defer ticker.Stop()
	cutoff := func() any { return time.Now().UTC().Add(-s.sessionTTL) }
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.db.Exec(`DELETE FROM quack_sessions WHERE created_at < ?;`, cutoff())
		}
	}
}

// GrantAccess gives a JWT subject permission to query a specific table/view.
func (s *Server) GrantAccess(sub, table string) error {
	_, err := s.db.Exec(`
		INSERT INTO quack_permissions (sub, allowed_table) 
		VALUES (?, ?) 
		ON CONFLICT DO NOTHING;
	`, sub, table)
	return err
}

// SyncPermissions atomically replaces the entire quack_permissions table with
// the provided grants (sub -> allowed tables). It is intended for reloading
// permissions from an external source such as a YAML ConfigMap: callers hand
// the freshly parsed mapping here and the swap is applied inside a single
// transaction so concurrent authz-macro reads never observe a half-applied
// state. Existing sessions (sid->sub) are left untouched.
func (s *Server) SyncPermissions(grants map[string][]string) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin sync transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM quack_permissions;`); err != nil {
		return fmt.Errorf("clear permissions: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO quack_permissions (sub, allowed_table)
		VALUES (?, ?)
		ON CONFLICT DO NOTHING;
	`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for sub, tables := range grants {
		for _, t := range tables {
			if _, err := stmt.Exec(sub, t); err != nil {
				return fmt.Errorf("insert grant (%s, %s): %w", sub, t, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sync: %w", err)
	}
	return nil
}

// handleAuth validates the JWT via Go, recording the sid->sub session in DuckDB.
// It first verifies req_server_token (srv) against the server secret so that
// only Quack — not a client invoking the macro directly, nor a stray local
// process — can establish a session.
//
// Every denial answers HTTP 200 with {"allowed": false}. DuckDB 2.0 raises on
// a non-2xx response from read_json_auto and Quack forwards the callback error
// to the client verbatim, URL included — which would leak the control-plane
// port and the srv token in it. An in-body false keeps the client message a
// plain "Authentication failed".
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sid := r.URL.Query().Get("sid")
	token := r.URL.Query().Get("token")
	srv := r.URL.Query().Get("srv")

	switch {
	case sid == "", token == "", srv == "":
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
		return
	case len(sid) > 256, len(token) > 1<<15, len(srv) > 256:
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
		return
	case subtle.ConstantTimeCompare([]byte(srv), []byte(s.serverSecret)) != 1:
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
		return
	}

	sub, err := s.verify(token)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
		return
	}

	// Insert sid -> sub mapping into DuckDB so the Authz macro can read it.
	if _, err := s.db.Exec(`
		INSERT INTO quack_sessions (sid, sub, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT (sid) DO UPDATE SET sub = excluded.sub, created_at = excluded.created_at;
	`, sid, sub, time.Now().UTC()); err != nil {
		log.Printf("quackjwt: recording session %q failed: %v", sid, err)
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
}
