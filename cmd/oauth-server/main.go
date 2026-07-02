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
	"os"
	"os/signal"
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

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-interrupt:
		logger.Info("Shutting down")
		cancel()
	case <-ctx.Done():
	}

	if err := srv.Stop(); err != nil {
		logger.Error("Error stopping quack server", "error", err)
	}

	if err := g.Wait(); err != nil {
		logger.Error("Watcher error", "error", err)
		os.Exit(1)
	}
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
