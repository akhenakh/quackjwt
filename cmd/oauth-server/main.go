// Command oauth-server runs a quackjwt.Server whose authentication is backed
// by JWT verification (PEM public key, inline JWKS, or refreshable JWKS URL —
// the same option set as github.com/akhenakh/csi-secret-age) and whose
// table-level grants are loaded from a YAML file. The YAML file is watched
// with fsnotify and re-applied atomically on change, including the atomic
// symlink swap kubelet performs when updating a ConfigMap volume.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/akhenakh/quackjwt"
	"github.com/akhenakh/quackjwt/permissions"
)

// slogLevel parses a log-level string into a slog.Level.
func slogLevel(level string) (slog.Level, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN", "WARNING":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q", level)
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	level, err := slogLevel(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid LOG_LEVEL: %v\n", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	db, err := sql.Open("duckdb", cfg.DuckDBPath)
	if err != nil {
		logger.Error("Failed to open DuckDB", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if cfg.DuckDBPath == "" {
		logger.Warn("DuckDB is in-memory — views, grants, and session state will be lost on restart. Set DUCKDB_PATH to a persistent file for production.")
	}

	// DuckDB extensions required by quackjwt (httpfs for the control plane,
	// quack for the remote protocol). autoinstall/autoload make first run
	// self-sufficient; they are idempotent on subsequent runs.
	for _, q := range []string{
		"SET autoinstall_known_extensions=1;",
		"SET autoload_known_extensions=1;",
	} {
		if _, err := db.Exec(q); err != nil {
			logger.Error("Failed to set DuckDB extension option", "query", q, "error", err)
			os.Exit(1)
		}
	}

	// Validated eagerly, unlike the S3 work below: it is a local file, and a
	// malformed one is a config error that should stop the process now rather
	// than after the listener is up.
	if _, err := loadViewSchemas(cfg.ViewSchemaPath); err != nil {
		logger.Error("Failed to load view schemas", "path", cfg.ViewSchemaPath, "error", err)
		os.Exit(1)
	}

	permMgr, err := permissions.New(permissions.Config{
		ConfigPath: cfg.PermConfigPath,
		JWT: permissions.JWTKeyConfig{
			PublicKeyPEM:    cfg.JWTPublicKey,
			JWKSURL:         cfg.JWTJWKSURL,
			JWKSJSON:        cfg.JWTJWKS,
			RefreshInterval: cfg.JWTJWKSRefreshInterval,
			Audience:        cfg.JWTAudience,
			Issuer:          cfg.JWTIssuer,
		},
		UserClaim: cfg.JWTUserClaim,
	})
	if err != nil {
		logger.Error("Failed to load permissions", "error", err)
		os.Exit(1)
	}
	logger.Info("Permissions loaded", "path", cfg.PermConfigPath, "user_claim", cfg.JWTUserClaim)

	// The quack server validates the JWT via the permission manager's
	// verifier and consults quack_permissions for table-level grants.
	srv := quackjwt.NewServer(db, cfg.QuackURI, permMgr.VerifyToken)
	srv.SetSessionTTL(cfg.SessionTTL)

	// syncPermissions replaces the DuckDB grants table with the current YAML
	// snapshot. Admins (from admin_users) are granted every table currently
	// present in the catalog; everyone else gets only their listed tables.
	syncPermissions := func() error {
		snap := permMgr.Snapshot()
		grants := make(map[string][]string, len(snap.Grants)+len(snap.Admins))
		for sub, tables := range snap.Grants {
			grants[sub] = append(grants[sub], tables...)
		}
		if len(snap.Admins) > 0 {
			names, err := tableNames(db)
			if err != nil {
				return fmt.Errorf("list tables for admin grant: %w", err)
			}
			for _, admin := range snap.Admins {
				grants[admin] = append(grants[admin], names...)
			}
		}
		return srv.SyncPermissions(grants)
	}

	// Start the server first: Server.Start creates the quack_permissions table
	// that syncPermissions writes into. There is a brief window before the
	// initial sync completes where the server accepts connections but no grants
	// exist; the authz macro is default-deny, so this fails safe (denied).
	if err := srv.Start(); err != nil {
		logger.Error("Failed to start quack server", "error", err)
		os.Exit(1)
	}

	if err := syncPermissions(); err != nil {
		logger.Error("Failed to sync permissions", "error", err)
		os.Exit(1)
	}
	logger.Info("Quack server listening", "uri", cfg.QuackURI)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// S3 views are bootstrapped after the listener is up, not before it.
	// Creating them talks to S3 — listing a glob, reading footers, resolving
	// credentials — and how long that takes scales with the archive, not with
	// anything this process controls. Held in front of srv.Start() it delays
	// the port opening, and a liveness probe kills the container before the
	// first log line is written, which reads as a crash with no output.
	//
	// Consequence: there is a window after startup where the views do not
	// exist yet and a query naming one fails to bind. That is the honest
	// failure and it is visible in the logs, unlike the silent restart loop.
	if cfg.S3Views != "" {
		g.Go(func() error {
			for _, q := range []string{"INSTALL httpfs;", "LOAD httpfs;"} {
				if _, err := db.Exec(q); err != nil {
					return fmt.Errorf("load httpfs extension: %w", err)
				}
			}
			if cfg.S3Region != "" {
				if err := createS3Secret(db, cfg); err != nil {
					logger.Error("Failed to create S3 secret", "error", err)
					return err
				}
			}
			if err := bootstrapViews(db, cfg); err != nil {
				// Logged here as well as returned: g.Wait() reports every
				// group error under one generic message, and this is the one
				// an operator sees when the archive or its credentials are
				// wrong.
				logger.Error("Failed to bootstrap S3 views", "error", err)
				return err
			}
			logger.Info("Views bootstrapped", "count", len(strings.Split(cfg.S3Views, ",")))

			// Admins are granted every table present in the catalog at sync
			// time, so the initial sync above — which ran before these views
			// existed — missed them. Re-sync now that they do.
			if err := syncPermissions(); err != nil {
				return fmt.Errorf("re-sync permissions after view bootstrap: %w", err)
			}
			return nil
		})
	}

	// Permissions file watcher: reload on change and re-apply grants
	// atomically so the DuckDB authz macro never observes a partial state.
	g.Go(func() error {
		return permMgr.Watch(ctx, logger, func() {
			if err := syncPermissions(); err != nil {
				logger.Error("Failed to re-sync permissions after reload", "error", err)
			}
		})
	})

	// Periodically recreate the DuckDB S3 SECRET so that credential-chain
	// providers (e.g. IRSA/sts on EKS) resolve fresh temporary credentials.
	// Without this, DuckDB caches the initial credentials indefinitely and
	// S3 queries fail with ExpiredToken after the temporary session expires.
	if cfg.S3Region != "" && cfg.S3CredentialRefreshInterval > 0 && cfg.S3Views != "" {
		g.Go(func() error {
			ticker := time.NewTicker(cfg.S3CredentialRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					if err := refreshS3Secret(db, cfg); err != nil {
						logger.Error("Failed to refresh S3 secret", "error", err)
					} else {
						logger.Debug("S3 secret refreshed")
					}
				}
			}
		})
	}

	// Landing page — a tiny HTTP server that validates the Authorization
	// header and shows connection instructions. Disabled when HTTPPort is 0.
	var landingSrv *http.Server
	if cfg.HTTPPort > 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/", landingHandler(permMgr, cfg.IDTokenCookie, cfg.ExternalDuckPort))
		landingSrv = &http.Server{Addr: fmt.Sprintf(":%d", cfg.HTTPPort), Handler: mux}
		g.Go(func() error {
			logger.Info("Landing page listening", "port", cfg.HTTPPort)
			if err := landingSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		})
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-interrupt:
		logger.Info("Shutting down")
		cancel()
	case <-ctx.Done():
	}

	if landingSrv != nil {
		_ = landingSrv.Shutdown(context.Background())
	}
	if err := srv.Stop(); err != nil {
		logger.Error("Error stopping quack server", "error", err)
	}

	if err := g.Wait(); err != nil {
		logger.Error("Watcher error", "error", err)
		os.Exit(1)
	}
}

// parseS3Views parses a comma-separated list of view-name=s3-path pairs.
func parseS3Views(raw string) (map[string]string, error) {
	views := make(map[string]string)
	if raw == "" {
		return views, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := strings.Index(pair, "=")
		if idx < 0 {
			return nil, fmt.Errorf("invalid S3_VIEWS entry %q: expected name=s3://path", pair)
		}
		name := strings.TrimSpace(pair[:idx])
		path := strings.TrimSpace(pair[idx+1:])
		if name == "" || path == "" {
			return nil, fmt.Errorf("invalid S3_VIEWS entry %q: both name and path are required", pair)
		}
		views[name] = path
	}
	return views, nil
}

func s3SecretSQL(cfg Config, orReplace bool) string {
	q := "CREATE "
	if orReplace {
		q += "OR REPLACE "
	}
	q += "SECRET "
	if !orReplace {
		q += "IF NOT EXISTS "
	}
	q += fmt.Sprintf("quackjwt_s3 (TYPE S3, PROVIDER CREDENTIAL_CHAIN, REGION %s", sqlString(cfg.S3Region))
	if cfg.S3CredentialChain != "" {
		q += fmt.Sprintf(", CHAIN %s", sqlString(cfg.S3CredentialChain))
	}
	if cfg.S3Endpoint != "" {
		q += fmt.Sprintf(", ENDPOINT %s", sqlString(cfg.S3Endpoint))
	}
	if !cfg.S3UseSSL {
		q += ", USE_SSL false"
	}
	q += ");"
	return q
}

// createS3Secret creates a DuckDB S3 secret using the ambient credential
// chain. Idempotent across restarts (IF NOT EXISTS).
func createS3Secret(db *sql.DB, cfg Config) error {
	q := s3SecretSQL(cfg, false)
	if _, err := db.Exec(q); err != nil {
		return fmt.Errorf("create S3 secret: %w", err)
	}
	return nil
}

// refreshS3Secret atomically replaces the DuckDB S3 secret with fresh
// credentials from the credential chain. Intended for periodic refresh
// to handle temporary credential expiry (e.g. IRSA/sts on EKS).
func refreshS3Secret(db *sql.DB, cfg Config) error {
	q := s3SecretSQL(cfg, true)
	if _, err := db.Exec(q); err != nil {
		return fmt.Errorf("refresh S3 secret: %w", err)
	}
	return nil
}

// bootstrapViews parses S3_VIEWS, auto-installs any needed extensions, and
// creates a VIEW IF NOT EXISTS for each entry. The reader function is chosen
// from the file extension (e.g. .parquet → read_parquet, .vortex →
// read_vortex).
func bootstrapViews(db *sql.DB, cfg Config) error {
	views, err := parseS3Views(cfg.S3Views)
	if err != nil {
		return err
	}

	needed := map[string]bool{}
	for _, path := range views {
		if readerForPath(path) == "read_vortex" {
			needed["vortex"] = true
		}
	}
	for ext := range needed {
		for _, q := range []string{
			fmt.Sprintf("INSTALL %s;", ext),
			fmt.Sprintf("LOAD %s;", ext),
		} {
			if _, err := db.Exec(q); err != nil {
				return fmt.Errorf("load %s extension: %w", ext, err)
			}
		}
	}

	schemas, err := loadViewSchemas(cfg.ViewSchemaPath)
	if err != nil {
		return err
	}
	for name := range schemas {
		if _, ok := views[name]; !ok {
			return fmt.Errorf("view schema declared for %q, which is not in S3_VIEWS", name)
		}
	}

	for name, path := range views {
		reader := readerForPath(path)
		if len(schemas[name]) > 0 && reader != "read_parquet" {
			return fmt.Errorf("view %q declares a schema but reads with %s, which does not accept one", name, reader)
		}
		q := fmt.Sprintf(
			"CREATE VIEW IF NOT EXISTS %s AS SELECT * FROM %s(%s%s);",
			sqlIdent(name), reader, sqlString(path), readerArgs(reader, schemas[name]),
		)
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("create view %s: %w", name, err)
		}
	}
	return nil
}

// viewColumn is one declared column of a view, in the order it should appear.
type viewColumn struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
}

// loadViewSchemas reads the VIEW_SCHEMA_PATH file, mapping view name to its
// declared columns. An empty path means no view has a declared schema.
//
// The file is a list per view rather than a mapping so that column order is
// the order written, which is the order SELECT * returns:
//
//	views:
//	  flights:
//	    - {name: flight_id, type: VARCHAR}
//	    - {name: in_tfr,    type: BOOLEAN}
//	    - {name: tfr_incursions, type: "VARCHAR[]"}
func loadViewSchemas(path string) (map[string][]viewColumn, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read view schema file: %w", err)
	}
	var raw struct {
		Views map[string][]viewColumn `yaml:"views"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse view schema file: %w", err)
	}
	for name, cols := range raw.Views {
		if len(cols) == 0 {
			return nil, fmt.Errorf("view schema %q declares no columns", name)
		}
		seen := make(map[string]bool, len(cols))
		for _, c := range cols {
			switch {
			case c.Name == "":
				return nil, fmt.Errorf("view schema %q has a column with no name", name)
			case c.Type == "":
				return nil, fmt.Errorf("view schema %q column %q has no type", name, c.Name)
			case seen[c.Name]:
				return nil, fmt.Errorf("view schema %q declares column %q twice", name, c.Name)
			}
			seen[c.Name] = true
		}
	}
	return raw.Views, nil
}

// readerArgs returns the named parameters appended to the reader call, for a
// view read by reader and optionally declaring cols.
//
// With no declared schema the view binds from a single file's footer and gets
// hive_partitioning, stated rather than left to auto-detection so a path that
// stops looking hive-shaped does not silently drop the partition columns. The
// cost of this form is that a column the producer added partway through the
// archive's life is not selectable through the view: whichever file the glob
// opens first defines the schema. Pass union_by_name on the query that needs
// to span generations, or declare the columns below.
//
// union_by_name is deliberately never set here. It answers that exact problem
// but makes CREATE VIEW eager — DuckDB reads every footer in the glob to
// compute the union, which on an archive of any size is one S3 request per
// object before the process can serve anything.
//
// With a declared schema the columns are pinned from the file, so they bind
// without reading the glob at all and a file predating one of them reads it
// back as NULL. DuckDB refuses `schema` together with hive partitioning and
// exposes no partition columns alongside it, so a declared schema trades them
// away: partition-pruning predicates are no longer expressible against the
// view. Only worth it for a glob that is not partitioned, or one small enough
// that a full scan is acceptable.
//
// read_vortex takes none of these, and only read_parquet accepts `schema`
// (verified against DuckDB 1.5.5; read_csv_auto and read_json_auto reject it),
// which bootstrapViews enforces rather than silently ignoring.
func readerArgs(reader string, cols []viewColumn) string {
	if reader == "read_vortex" {
		return ""
	}
	if len(cols) == 0 {
		return ", hive_partitioning = true"
	}
	entries := make([]string, 0, len(cols))
	for _, c := range cols {
		entries = append(entries, fmt.Sprintf(
			"%s: {'name': %s, 'type': %s, 'default_value': NULL}",
			sqlString(c.Name), sqlString(c.Name), sqlString(c.Type),
		))
	}
	return ", schema = map { " + strings.Join(entries, ", ") + " }"
}

// readerForPath returns the DuckDB read function for the given file path,
// chosen from the file extension.
func readerForPath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".vortex", ".vx":
		return "read_vortex"
	case ".csv", ".tsv":
		return "read_csv_auto"
	case ".json", ".ndjson":
		return "read_json_auto"
	default:
		return "read_parquet"
	}
}

// sqlIdent double-quotes an identifier, escaping embedded double quotes.
func sqlIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// sqlString single-quotes a string literal, escaping embedded single quotes.
func sqlString(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}

// tableNames returns all base table and view names in the catalog. Admins are
// granted each of these so they bypass the per-table grant check in the authz
// macro. Tables created after a reload only become visible to admins after the
// next reload.
func tableNames(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
		ORDER BY table_name;
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		// The internal quack_sessions / quack_permissions tables must never be
		// granted: doing so would let an admin's sid read the trust backbone.
		if n == "quack_sessions" || n == "quack_permissions" {
			continue
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
