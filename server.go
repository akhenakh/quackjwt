package quackjwt

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	// Import the DuckDB driver
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
	controlServer *http.Server
}

// NewServer initializes the wrapper.
func NewServer(db *sql.DB, quackURI string, verify TokenVerifier) *Server {
	return &Server{
		db:       db,
		verify:   verify,
		quackURI: quackURI,
	}
}

// Start sets up the tables, macros, hidden control plane, and the Quack server.
func (s *Server) Start() error {
	// 1. Install & load necessary extensions
	setupQueries := []string{
		"SET autoinstall_known_extensions=1;",
		"SET autoload_known_extensions=1;",
		"INSTALL httpfs;",
		"LOAD httpfs;",
		"INSTALL quack;",
		"LOAD quack;",
		// 2. Create tables for tracking active sessions and permissions
		`CREATE TABLE IF NOT EXISTS quack_sessions (
			sid VARCHAR PRIMARY KEY,
			sub VARCHAR
		);`,
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

	// 3. Start local control plane HTTP server on a random available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start control plane: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", s.handleAuth)
	s.controlServer = &http.Server{Handler: mux}
	go s.controlServer.Serve(listener)

	// 4. Create Authentication Macro bridging to the Go control plane
	authMacro := fmt.Sprintf(`
		CREATE OR REPLACE MACRO quack_jwt_auth(req_sid, req_client_token, req_server_token) AS (
			SELECT allowed FROM read_json_auto('http://127.0.0.1:%d/auth?sid=' || req_sid || '&token=' || req_client_token)
		);
	`, port)
	if _, err := s.db.Exec(authMacro); err != nil {
		return fmt.Errorf("failed to create auth macro: %w", err)
	}

	// 5. Create Authorization Macro checking the tracked session against permissions
	// Fix: Use standard LIKE for the internal multi-line C++ ATTACH queries
	authzMacro := `
		CREATE OR REPLACE MACRO quack_jwt_authz(req_sid, req_query) AS (
			req_query LIKE '%information_schema.schemata%' OR
			req_query LIKE '%duckdb_tables()%' OR
			EXISTS (
				SELECT 1
				FROM quack_sessions s
				JOIN quack_permissions p ON p.sub = s.sub
				WHERE s.sid = req_sid
				  AND regexp_matches(req_query, '(?i)\b' || p.allowed_table || '\b')
			)
		);
	`
	if _, err := s.db.Exec(authzMacro); err != nil {
		return fmt.Errorf("failed to create authz macro: %w", err)
	}

	// 6. Hook up settings and start Quack
	quackStartQueries := []string{
		"SET GLOBAL quack_authentication_function = 'quack_jwt_auth';",
		"SET GLOBAL quack_authorization_function = 'quack_jwt_authz';",
		fmt.Sprintf("CALL quack_serve('%s', allow_other_hostname => true);", s.quackURI),
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

// GrantAccess gives a JWT subject permission to query a specific table/view.
func (s *Server) GrantAccess(sub, table string) error {
	_, err := s.db.Exec(`
		INSERT INTO quack_permissions (sub, allowed_table) 
		VALUES (?, ?) 
		ON CONFLICT DO NOTHING;
	`, sub, table)
	return err
}

// handleAuth validates the JWT via Go, recording the sid->sub session in DuckDB.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	token := r.URL.Query().Get("token")
	w.Header().Set("Content-Type", "application/json")

	// 1. Verify JWT via the user-provided function
	sub, err := s.verify(token)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
		return
	}

	// 2. Insert sid -> sub mapping into DuckDB so the Authz macro can read it
	_, err = s.db.Exec(`
		INSERT INTO quack_sessions (sid, sub) 
		VALUES (?, ?) 
		ON CONFLICT (sid) DO UPDATE SET sub = excluded.sub;
	`, sid, sub)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
}
