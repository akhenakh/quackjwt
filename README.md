# QuackJWT

**QuackJWT** is a Go library that seamlessly adds JSON Web Token (JWT) authentication and table-level authorization to [DuckDB's Quack Remote Protocol](https://duckdb.org/2026/05/12/quack.html). 

DuckDB's Quack extension allows you to query remote DuckDB instances over HTTP. QuackJWT wraps this capability in a Go server, giving you fine-grained, identity-based access control using JWTs.

## Features

* **JWT Authentication**: Authenticate Quack clients using standard JWTs.
* **Table-Level Authorization**: Grant specific users (based on the JWT `sub` claim) access to specific tables or views.
* **Automated Control Plane**: Automatically bridges DuckDB's macro-based authentication hooks to your Go application via a hidden, loopback HTTP control plane.
* **Seamless Client Experience**: Clients use standard DuckDB `ATTACH` statements, passing their JWT as the Quack token.

## Installation

```bash
go get github.com/akhenakh/quackjwt
```
*(Requires `github.com/duckdb/duckdb-go/v2` and DuckDB v1.5.3+)*

## Server Setup (Go)

Embed the Quack server in your Go application and configure your JWT verification logic.

```go
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

	// Create some sample data
	db.Exec("CREATE TABLE public_metrics (id INT, val VARCHAR);")
	db.Exec("CREATE TABLE secret_financials (id INT, amount DECIMAL);")

	// 2. Define your JWT verifier logic
	// In production, parse and cryptographically verify the JWT here.
	verifyJWT := func(token string) (sub string, err error) {
		if token == "ey.fake.jwt.alice" {
			return "user_alice", nil // The subject (sub)
		}
		return "", fmt.Errorf("invalid token")
	}

	// 3. Initialize and start the Quack server
	// Binding to 0.0.0.0 allows external connections.
	srv := quackjwt.NewServer(db, "quack:0.0.0.0:9494", verifyJWT)
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start Quack server: %v", err)
	}
	defer srv.Stop()

	// 4. Grant Permissions based on the JWT `sub`
	// Alice gets access to public_metrics, but not secret_financials
	srv.GrantAccess("user_alice", "public_metrics")

	fmt.Println("🚀 Quack server is running on port 9494...")
	select {} // Block forever
}
```

## How to Attach (Client Side)

Clients do not need any special Go binaries or plugins to connect. They just need standard DuckDB (v1.5.3 or newer) with the `quack` extension installed.

To connect, the client uses the DuckDB `ATTACH` command and passes their JWT as the `TOKEN`.

```sql
-- 1. Install and load the Quack extension on the client
INSTALL quack;
LOAD quack;

-- 2. Attach to the remote QuackJWT server using the JWT
ATTACH 'quack:your_host.com:9494' AS remote_db (
    TOKEN 'ey.fake.jwt.alice',
    DISABLE_SSL true  -- Note: Set to `false` if your server is behind a TLS reverse proxy like Nginx/Caddy!
);

-- 3. Run Authorized Queries
SELECT * FROM remote_db.public_metrics;
-- Returns your data securely over the network.

-- 4. Unauthorized Queries are rejected
SELECT * FROM remote_db.secret_financials;
-- Fails with: Catalog Error: Authorization failed
```

### Stateless Queries (Without Attaching)

Clients can also execute one-off stateless queries using the `quack_query` macro, passing the JWT dynamically:

```sql
FROM quack_query(
    'quack:your_host.com:9494',
    'SELECT * FROM public_metrics',
    token = 'ey.fake.jwt.alice',
    disable_ssl => true
);
```

## Security Considerations

### 1. Reverse Proxies & TLS
The Quack protocol speaks **plain HTTP**. By default, `DISABLE_SSL true` is used in the local examples above. **Do not expose Quack directly to the public internet.** 

Instead, front your Go application with a TLS-terminating reverse proxy (like Nginx, Caddy, or an AWS Application Load Balancer). Clients should then connect without the `DISABLE_SSL true` flag so that their DuckDB client uses HTTPS automatically.

### 2. How the Authorization Macro Works
Because DuckDB's authentication hooks execute in transient, read-only SQL contexts, `QuackJWT` uses an internal architecture trick:
1. When a client connects, the DuckDB `quack_jwt_auth` macro calls out to a hidden HTTP control plane managed by Go (via DuckDB's `httpfs` extension).
2. Go validates the JWT and inserts the Session-ID (`sid`) to Subject (`sub`) mapping into a hidden table (`quack_sessions`).
3. During queries, the `quack_jwt_authz` macro checks the SQL string for authorized table names using regex boundary matching (`\b`). 

> **Note:** The boundary matching is strict, but theoretically susceptible to SQL comments (e.g., `SELECT 1; -- public_metrics`). Always ensure your analytical clients are treating this as an analytical boundary, and combine this with TLS proxies to prevent unauthorized query sniffing.
