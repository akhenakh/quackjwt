# QuackJWT

Add JWT authentication and table-level authorization to [DuckDB's Quack Remote Protocol](https://duckdb.org/2026/05/12/quack.html). Clients connect with a standard DuckDB `ATTACH` and pass their JWT as the token; the server verifies it against your IdP's JWKS and enforces per-subject, per-table grants.

The primary production use case is **exposing S3/Parquet data as per-user views** — sharing specific buckets with specific users (by JWT `sub`) while denying everyone else, including access to raw files.

## Quickstart — oauth-server

The `cmd/oauth-server` binary is a batteries-included deployment: give it a JWT key source (PEM, inline JWKS, or a JWKS URL) and a YAML permissions file, and it runs the Quack server. The permissions file is watched and re-applied on change — including the atomic symlink swap kubelet performs when updating a ConfigMap.

### Build & run

```bash
go build -o oauth-server ./cmd/oauth-server
```

Create `perm.yaml`:

```yaml
user_permissions:
  alice:
    - sales
    - ops_logs
  bob:
    - sales_redacted
```

Point to your IdP's JWKS endpoint (Auth0, Keycloak, Google, …) and run:

```bash
export PERM_CONFIG_PATH=/etc/quackjwt/perm.yaml
export JWT_JWKS_URL=https://auth.example.com/.well-known/jwks.json
export JWT_AUDIENCE=my-client-id
export JWT_ISSUER=https://auth.example.com
export QUACK_URI=quack:0.0.0.0:9494

oauth-server
```

> For local dev without an IdP, generate an RSA keypair (`openssl genpkey …`) and use `JWT_PUBLIC_KEY_FILE` instead. See the [Configuration](#configuration) table for all options.

### Configuration

All environment variables follow the same naming and `_FILE` convention as [csi-secret-age](https://github.com/akhenakh/csi-secret-age). File variants take precedence over inline values.

| Variable | File variant | Default | Description |
|---|---|---|---|
| `PERM_CONFIG_PATH` | — | *required* | Path to the YAML permissions file |
| `JWT_PUBLIC_KEY` | `JWT_PUBLIC_KEY_FILE` | — | PEM-encoded RSA public key |
| `JWT_JWKS_URL` | — | — | URL returning a JWKS document |
| `JWT_JWKS` | `JWT_JWKS_FILE` | — | Inline JWKS JSON |
| `JWT_JWKS_REFRESH_INTERVAL` | — | `15m` | JWKS URL cache TTL |
| `JWT_AUDIENCE` | — | — | Required `aud` claim |
| `JWT_ISSUER` | — | — | Required `iss` claim |
| `JWT_USER_CLAIM` | — | `sub` | JWT claim to use as the subject |
| `QUACK_URI` | — | `quack:0.0.0.0:9494` | Quack listen address |
| `DUCKDB_PATH` | — | `""` | DuckDB database path (empty = in-memory) |
| `SESSION_TTL` | — | `1h` | Idle session reap interval |
| `LOG_LEVEL` | — | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `S3_REGION` | — | — | AWS region; setting this triggers S3 bootstrap |
| `S3_ENDPOINT` | — | — | Custom S3-compatible endpoint (MinIO, R2, …) |
| `S3_USE_SSL` | — | `true` | Use HTTPS for S3 endpoint |
| `S3_VIEWS` | — | — | Comma-separated `name=path` pairs; views are auto-created with the reader matched to the file extension (`.parquet` → `read_parquet`, `.vortex`/`.vx` → `read_vortex`, `.csv` → `read_csv_auto`, etc.) |

Exactly one JWT key source must be set (`JWT_PUBLIC_KEY`, `JWT_JWKS_URL`, or `JWT_JWKS`).

### Permissions file format

The server reads a YAML file mapping JWT subjects to the DuckDB table/view names they may query:

```yaml
# Optional: subjects that bypass table-level grants — they are granted every
# table present in the catalog at sync time.
admin_users:
  - admin@acme.com

user_permissions:
  alice:
    - sales
    - ops_logs
  bob:
    - sales_redacted
```

The file is loaded at startup and watched for changes. Whenever it is updated (either by a direct `write` or by a Kubernetes ConfigMap atomic swap) the server re-parses it and transactionally replaces the grant table — no restart, no disruption.

### Getting a JWT

Clients obtain JWTs from your identity provider (the same `JWT_JWKS_URL` issuer). The `sub` claim (or `JWT_USER_CLAIM`) maps to an entry in `perm.yaml`. For local testing with a static PEM key, see `keygen` in [csi-secret-age](https://github.com/akhenakh/csi-secret-age) for a Go signer.

### Kubernetes deployment

Point the server at your IdP's JWKS endpoint. Mount the permissions file as a ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: quackjwt-perms
data:
  perm.yaml: |
    user_permissions:
      alice:
        - sales
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: quackjwt
spec:
  template:
    spec:
      containers:
        - name: oauth-server
          image: ghcr.io/akhenakh/quackjwt:latest
          env:
            - name: PERM_CONFIG_PATH
              value: /etc/quackjwt/perm.yaml
            - name: JWT_JWKS_URL
              value: https://auth.example.com/.well-known/jwks.json
            - name: JWT_AUDIENCE
              value: my-client-id
            - name: JWT_ISSUER
              value: https://auth.example.com
            - name: QUACK_URI
              value: "quack:0.0.0.0:9494"
          volumeMounts:
            - name: perms
              mountPath: /etc/quackjwt/perm.yaml
              subPath: perm.yaml
      volumes:
        - name: perms
          configMap:
            name: quackjwt-perms
```

When kubelet updates the ConfigMap it atomically swaps the symlink behind `perm.yaml`. The server detects the `Remove` event, re-establishes the watch on the new inode, and reloads. Grant updates are transactional — a concurrent query never observes a half-applied state.

## Client usage

Clients need standard DuckDB (v1.5.3+) with the `quack` extension installed:

```sql
INSTALL quack;
LOAD quack;

-- Attach with a JWT
ATTACH 'quack:host.example:9494' AS remote (
    TOKEN '<your_jwt>',
    DISABLE_SSL false   -- set to true only for local/dev without TLS
);

-- Authorized
SELECT * FROM remote.sales;

-- Denied
SELECT * FROM remote.secret_financials;
-- Catalog Error: Authorization failed
```

Stateless queries without attaching:

```sql
FROM quack_query(
    'quack:host.example:9494',
    'SELECT * FROM sales',
    token = '<your_jwt>'
);
```

## S3 / Parquet use case

Set `S3_REGION` and `S3_VIEWS` to let the server auto-create the DuckDB secret and views on startup — no manual SQL needed. The reader function is chosen from the file extension automatically:

```bash
export S3_REGION=us-east-1
export S3_VIEWS='sales=s3://acme-sales/**/*.parquet,ops_logs=s3://acme-ops-logs/*.parquet,events=s3://acme-events/**/*.vortex'
```

The server creates `CREATE SECRET IF NOT EXISTS quackjwt_s3` (using the ambient AWS credential chain) and a `CREATE VIEW IF NOT EXISTS` for each entry, using `read_parquet` for `.parquet` files and `read_vortex` for `.vortex`/`.vx` files. Required DuckDB extensions (including `vortex`) are installed and loaded automatically. Views are idempotent across restarts.

On Kubernetes, pair this with an IAM-annotated service account (IRSA) to scope the pod to the exact buckets:

```yaml
env:
  - name: S3_REGION
    value: "us-east-1"
  - name: S3_VIEWS
    value: "sales=s3://acme-sales/**/*.parquet,ops_logs=s3://acme-ops-logs/*.parquet,events=s3://acme-events/**/*.vortex"
  # Non-AWS endpoints:
  # - name: S3_ENDPOINT
  #   value: "https://minio.example.com"
  # - name: S3_USE_SSL
  #   value: "false"
```

The view name becomes the grant token in `perm.yaml`:

```yaml
user_permissions:
  alice:
    - sales
    - ops_logs
  bob:
    - sales_redacted
```

Clients never see bucket paths, never hold S3 credentials, and cannot call `read_parquet` directly.

```
┌──────────┐  JWT (sub=user)   ┌───────────────┐  read_parquet(s3://)  ┌──────────┐
│  Client  │ ─────────────────▶│  oauth-server  │ ─────────────────────▶│  S3/IAM  │
│  DuckDB  │◀─ results (HTTPS)─│  behind TLS    │◀── Parquet chunks ────│  buckets  │
└──────────┘                   └───────────────┘                       └──────────┘
     │ issued by
  ┌──┴──────────┐
  │  IdP (JWKS) │
  └─────────────┘
```

> If you need custom view definitions (e.g. column-level redaction) or additional secrets beyond the credential chain, use `DUCKDB_PATH` with a pre-seeded database file and omit `S3_REGION`.

## Library usage

If you need custom grant logic or want to embed the Quack server in an existing Go binary, use the `quackjwt` package directly:

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
    db, _ := sql.Open("duckdb", "my_data.db")
    defer db.Close()

    db.Exec("CREATE TABLE public_metrics (id INT, val VARCHAR);")
    db.Exec("CREATE TABLE secret_financials (id INT, amount DECIMAL);")

    verifyJWT := func(token string) (string, error) {
        // Verify with golang-jwt/jwt v5 + your JWKS, IdP, et cetera.
        if token == "ey.fake.jwt.alice" {
            return "user_alice", nil
        }
        return "", fmt.Errorf("invalid token")
    }

    srv := quackjwt.NewServer(db, "quack:0.0.0.0:9494", verifyJWT)
    srv.Start()
    defer srv.Stop()

    srv.GrantAccess("user_alice", "public_metrics")
    select {}
}
```

The `permissions` subpackage provides the JWT key-source options (static PEM, inline JWKS, refreshable JWKS URL plus `aud`/`iss` validation), YAML loading, and the fsnotify-based ConfigMap-aware file watcher — the same stack the oauth-server binary uses. See `permissions/permissions.go` for the public API.

For a lighter starting point that skips JWKS/YAML and uses a hard-coded (fake) verifier, see `cmd/example/main.go`.

## Security considerations

### TLS
The Quack protocol speaks plain HTTP. Always front the oauth-server with a TLS-terminating reverse proxy (Caddy, Nginx, ALB). Clients should connect without `DISABLE_SSL`.

### Authorization model
The authz macro enforces a **default-deny** policy: a query is authorized only if it references at least one granted table, references no non-granted table, invokes no file/system function (`read_parquet`, `duckdb_settings`, …), and uses no `FROM '<path>'` / `JOIN '<path>'` string-source shorthand. The classic bypasses — commenting a granted name, naming a CTE/alias after a granted table, smuggling `read_csv_auto` — are all blocked because the prohibited token still appears in the query text.

Regex-based authorization can never be as rigorous as a real SQL parser; treat it as an analytical boundary and always combine it with defense-in-depth measures.

### Internal tables
The `quack_sessions` and `quack_permissions` tables (the trust backbone) are never grantable. A client cannot read, write, or exfiltrate them.

### Session reaping
`quack_sessions` rows are timestamped and a background goroutine deletes idle rows past the `SESSION_TTL` (default 1h). This prevents unbounded growth and stale `sid`→`sub` mappings.

### Defense-in-depth

- IAM role scoped to only the buckets this server exposes.
- Short-lived S3 credentials (instance profile / IRSA / STS), not static access keys.
- JWT verified against IdP JWKS, `exp` enforced, short token lifetimes + refresh.
- Views redact sensitive columns (column-level security lives in the view `SELECT` list).
- One QuackJWT instance per sensitivity tier for hard isolation.
- TLS reverse proxy in front; never expose the plain-HTTP Quack listener directly.
- Rotate the S3 secret and IdP signing keys periodically.
