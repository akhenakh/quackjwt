package main

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/akhenakh/quackjwt"
	_ "github.com/duckdb/duckdb-go/v2"
)

func main() {
	// 1. Open a persistent DuckDB connection
	db, err := sql.Open("duckdb", "my_data.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 2. Create some sample data
	db.Exec("CREATE TABLE IF NOT EXISTS public_metrics (id INT, val VARCHAR);")
	db.Exec("CREATE TABLE IF NOT EXISTS financial_data (id INT, amount DECIMAL);")

	// 3. Define your JWT verifier logic (e.g. using github.com/golang-jwt/jwt/v5)
	verifyJWT := func(token string) (string, error) {
		// In a real app, parse and verify the JWT signature cryptographically here.
		// For the demo, we'll pretend any token starting with "ey" is user "alice"
		if token == "ey.fake.jwt.alice" {
			return "user_alice", nil
		}
		return "", fmt.Errorf("invalid token")
	}

	// 4. Initialize and start the Quack server
	// We bind to 0.0.0.0 to allow external connections (you should front this with Nginx/Caddy for TLS)
	srv := quackjwt.NewServer(db, "quack:0.0.0.0:9494", verifyJWT)
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start Quack server: %v", err)
	}

	// 5. Grant Permissions based on the JWT `sub`
	// Alice gets access to public_metrics, but not financial_data
	if err := srv.GrantAccess("user_alice", "public_metrics"); err != nil {
		log.Fatalf("Failed to grant access: %v", err)
	}

	fmt.Println("🚀 Quack server is running on port 9494...")

	// Keep the main thread alive
	select {}
}
