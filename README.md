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
| `HTTP_PORT` | — | `0` | Optional landing page port (set to a port number to enable) |
| `ID_TOKEN_COOKIE` | — | `quackjwt-id-token` | Cookie name for the JWT ID token set by Envoy OAuth2 proxy |
| `EXTERNAL_DUCK_PORT` | — | — | Port shown in the landing page ATTACH command (set when API gateway exposes Quack on a different port, e.g. `443`) |
| `DUCKDB_PATH` | — | `""` | DuckDB database path (empty = in-memory) |
| `SESSION_TTL` | — | `1h` | Idle session reap interval |
| `LOG_LEVEL` | — | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `S3_REGION` | — | — | AWS region; setting this triggers S3 bootstrap |
| `S3_CREDENTIAL_CHAIN` | — | — | AWS SDK credential chain to try (semicolon-separated: `env`, `sts`, `instance`, `config`). For IRSA/EKS, set to `sts` or `env;sts;instance`. See [DuckDB httpfs docs](https://duckdb.org/docs/current/core_extensions/httpfs/s3api#credential_chain-provider). |
| `S3_ENDPOINT` | — | — | Custom S3-compatible endpoint (MinIO, R2, …) |
| `S3_USE_SSL` | — | `true` | Use HTTPS for S3 endpoint |
| `S3_VIEWS` | — | — | Comma-separated `name=path` pairs; views are auto-created with the reader matched to the file extension (`.parquet` → `read_parquet`, `.vortex`/`.vx` → `read_vortex`, `.csv` → `read_csv_auto`, etc.) |
| `VIEW_SCHEMA_PATH` | — | — | YAML file declaring the columns of named views, pinning their schema without reading the whole glob. Trades away the hive partition columns — see below |

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

### Landing page

Set `HTTP_PORT` to enable a simple landing page that shows the authenticated user and a copy-pasteable DuckDB `ATTACH` command. When running behind Envoy's OAuth2 proxy, the JWT ID token is delivered in the cookie named by `ID_TOKEN_COOKIE` (default `quackjwt-id-token` — this must match `cookieNames.idToken` in your Envoy SecurityPolicy). The handler falls back to the `Authorization: Bearer` header for direct API callers.

The ATTACH command uses the request's `Host` header. Set `EXTERNAL_DUCK_PORT` when your API gateway exposes the Quack protocol on a port that differs from the internal listen port (e.g. `443` when terminating TLS at the gateway).

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

Views are bootstrapped **after** the Quack listener is up, not before it. Creating them talks to S3, and how long that takes scales with the archive; held in front of the listener it delays the port opening and a liveness probe kills the container before the first log line is written. The cost is a window after startup where a query naming a view fails to bind — visible in the logs, unlike a silent restart loop.

Views are created with `hive_partitioning = true` (except `read_vortex`, which does not take it). `union_by_name` is deliberately **not** set: it would let one view span an archive written by several versions of a producer, but it makes `CREATE VIEW` eager — DuckDB reads every footer in the glob to compute the union, i.e. one S3 request per object at startup. So a view binds from whichever file the glob opens first, and a column the producer added partway through the archive's life is not selectable through it.

Two ways to read across that boundary:

- **Per query** — pass `union_by_name` inline, and the cost is paid by the query that wants it rather than by every startup:
  ```sql
  SELECT * FROM remote.query($$
    SELECT flight_id, in_tfr FROM read_parquet('s3://bucket/flights/**/*.parquet',
             hive_partitioning = true, union_by_name = true)
    WHERE year = '2026' AND month = '09'
  $$);
  ```
- **Per view** — declare the columns in `VIEW_SCHEMA_PATH` (below), which pins them without reading the glob.

### `VIEW_SCHEMA_PATH`

A YAML file declaring the columns of one or more views by name. A view listed there is created with `read_parquet`'s `schema` argument: the columns bind from the file rather than from the data, and a file written before one of them existed reads it back as NULL.

```yaml
views:
  flights:
    - {name: flight_id, type: VARCHAR}
    - {name: in_tfr, type: BOOLEAN}
    - {name: tfr_incursions, type: "VARCHAR[]"}
```

Columns are a list, not a mapping, so the declared order is the order `SELECT *` returns them.

#### Generating the file

Derive the columns from the archive rather than typing them. Point `DESCRIBE` at **one recent object** — not the glob, and not an old one, or you will pin the schema you are trying to get away from:

```bash
FILE=$(aws s3 ls --recursive s3://acme-archive/flights/ \
       | sort | tail -1 | awk '{print $4}')

{ echo "views:"; echo "  flights:"
  duckdb -noheader -list -c "
    SELECT '    - {name: ' || column_name || ', type: \"' || column_type || '\"}'
    FROM (DESCRIBE SELECT * FROM read_parquet('s3://acme-archive/$FILE'));"
} > view-schemas.yaml
```

giving:

```yaml
views:
  flights:
    - {name: flight_id, type: "VARCHAR"}
    - {name: organization_id, type: "VARCHAR"}
    - {name: tenant_ids, type: "VARCHAR[]"}
    - {name: in_tfr, type: "BOOLEAN"}
    - {name: tfr_incursions, type: "VARCHAR[]"}
```

Types are quoted because some of them (`VARCHAR[]`, `STRUCT(...)`) are not bare YAML scalars. Mount the file and point `VIEW_SCHEMA_PATH` at it:

```yaml
- name: VIEW_SCHEMA_PATH
  value: /etc/quackjwt/view-schemas.yaml
```

The file is read once at startup, so regenerate and restart when the producer adds a column. Columns it doesn't list are not visible through the view at all — the declaration is the whole schema, not an addition to what the files hold.

**A declared schema trades away the partition columns.** DuckDB refuses `schema` together with hive partitioning and exposes no partition columns alongside it, so `org_id`, `year`, `month`, … are not selectable through such a view and partition-pruning predicates cannot be written against it. Declaring a partition column by hand does not help — it lives in the path, not in the files, and reads back all-NULL. Worth it for a glob that is not partitioned, or one small enough that a full scan is fine; for a large partitioned archive, prefer the inline `union_by_name` form above.

Only `read_parquet` accepts `schema`. A schema declared for a view read by `read_csv_auto`, `read_json_auto` or `read_vortex`, or naming a view absent from `S3_VIEWS`, is refused at startup rather than silently ignored.

On Kubernetes, pair this with an IAM-annotated service account (IRSA) to scope the pod to the exact buckets:

```yaml
env:
  - name: S3_REGION
    value: "us-east-1"
  - name: S3_CREDENTIAL_CHAIN
    value: "sts"             # use "env;sts;instance" for a fallback chain
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
│  Client  │ ─────────────────▶│  oauth-serve  │ ────────────────────▶ │  S3/IAM  │
│  DuckDB  │◀─ results (HTTPS)─│  behind TLS   │◀── Parquet chunks ─── │  buckets │
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
