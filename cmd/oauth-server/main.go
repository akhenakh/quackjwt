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

	_ "github.com/duckdb/duckdb-go/v2"
	"golang.org/x/sync/errgroup"

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

	// S3/bootstrap views: when S3_VIEWS is set, create views with the reader
	// function auto-detected from each path's file extension. If S3_REGION is
	// also set, a DuckDB S3 SECRET (credential chain) is created first.
	if cfg.S3Views != "" {
		for _, q := range []string{"INSTALL httpfs;", "LOAD httpfs;"} {
			if _, err := db.Exec(q); err != nil {
				logger.Error("Failed to load httpfs extension", "error", err)
				os.Exit(1)
			}
		}
		if cfg.S3Region != "" {
			if err := createS3Secret(db, cfg); err != nil {
				logger.Error("Failed to create S3 secret", "error", err)
				os.Exit(1)
			}
		}
		if err := bootstrapViews(db, cfg); err != nil {
			logger.Error("Failed to bootstrap views", "error", err)
			os.Exit(1)
		}
		logger.Info("Views bootstrapped", "count", len(strings.Split(cfg.S3Views, ",")))
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

	// Permissions file watcher: reload on change and re-apply grants
	// atomically so the DuckDB authz macro never observes a partial state.
	g.Go(func() error {
		return permMgr.Watch(ctx, logger, func() {
			if err := syncPermissions(); err != nil {
				logger.Error("Failed to re-sync permissions after reload", "error", err)
			}
		})
	})

	// Landing page — a tiny HTTP server that validates the Authorization
	// header and shows connection instructions. Disabled when HTTPPort is 0.
	var landingSrv *http.Server
	if cfg.HTTPPort > 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/", landingHandler(permMgr))
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

// createS3Secret creates a DuckDB S3 secret using the ambient credential
// chain. Idempotent across restarts (IF NOT EXISTS).
func createS3Secret(db *sql.DB, cfg Config) error {
	q := fmt.Sprintf(
		"CREATE SECRET IF NOT EXISTS quackjwt_s3 (TYPE S3, PROVIDER CREDENTIAL_CHAIN, REGION %s",
		sqlString(cfg.S3Region),
	)
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
	if _, err := db.Exec(q); err != nil {
		return fmt.Errorf("create S3 secret: %w", err)
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

	for name, path := range views {
		q := fmt.Sprintf(
			"CREATE VIEW IF NOT EXISTS %s AS SELECT * FROM %s(%s);",
			sqlIdent(name), readerForPath(path), sqlString(path),
		)
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("create view %s: %w", name, err)
		}
	}
	return nil
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
		FROM duckdb_tables()
		WHERE schema_name NOT IN ('information_schema', 'pg_catalog')
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
