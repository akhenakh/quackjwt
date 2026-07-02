package quackjwt

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
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
