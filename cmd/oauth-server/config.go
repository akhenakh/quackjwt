package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds the runtime configuration for the oauth-server. JWT option
// names mirror github.com/akhenakh/csi-secret-age so the same deployment
// vocabulary (and the same ConfigMap/Secret layout) applies.
//
// Secret fields support a _FILE suffix (e.g. JWT_JWKS_FILE) to read the value
// from a file instead of an environment variable. When both the inline and
// file variants are set, the file takes precedence.
type Config struct {
	// DuckDBPath is the DuckDB database file (or "" for in-memory). Views and
	// tables exposed to clients live here.
	DuckDBPath string `env:"DUCKDB_PATH" envDefault:""`
	// QuackURI is the address Quack binds, e.g. "quack:0.0.0.0:9494".
	QuackURI string `env:"QUACK_URI" envDefault:"quack:0.0.0.0:9494"`
	// HTTPPort is the port for the optional landing page. Set to 0 to disable.
	HTTPPort int `env:"HTTP_PORT" envDefault:"0"`
	// SessionTTL controls how long idle sid->sub mappings live before being
	// reaped.
	SessionTTL time.Duration `env:"SESSION_TTL" envDefault:"1h"`

	LogLevel string `env:"LOG_LEVEL" envDefault:"INFO"`

	// PermConfigPath is the path to the YAML permissions file. In Kubernetes
	// mount a ConfigMap here; it is watched and reloaded on change.
	PermConfigPath string `env:"PERM_CONFIG_PATH"`

	// JWTPublicKey is the PEM-encoded RSA public key used to validate JWT
	// tokens. Use JWTPublicKeyFile to read from a file instead. Mutually
	// exclusive with JWT_JWKS_URL / JWT_JWKS / JWT_JWKS_FILE.
	JWTPublicKey     string `env:"JWT_PUBLIC_KEY"`
	JWTPublicKeyFile string `env:"JWT_PUBLIC_KEY_FILE"`
	JWTUserClaim     string `env:"JWT_USER_CLAIM" envDefault:"sub"`
	// JWTAudience is the expected audience (aud) claim of incoming JWTs.
	JWTAudience string `env:"JWT_AUDIENCE"`
	// JWTIssuer is the expected issuer (iss) claim of incoming JWTs.
	JWTIssuer string `env:"JWT_ISSUER"`
	// IDTokenCookie is the name of the cookie that Envoy OAuth2 proxy
	// stores the ID token (JWT) in. Matches cookieNames.idToken in the
	// Envoy SecurityPolicy.
	IDTokenCookie string `env:"ID_TOKEN_COOKIE" envDefault:"quackjwt-id-token"`
	// ExternalDuckPort is the port shown in the landing page ATTACH
	// command. Set this when your API gateway exposes Quack on a port
	// that differs from the internal listen port (e.g. 443 behind TLS).
	ExternalDuckPort int `env:"EXTERNAL_DUCK_PORT"`

	// JWT_JWKS_URL fetches a JSON Web Key Set from an HTTPS (or HTTP) URL.
	// The key identified by the token's `kid` header is used for RS256
	// validation. Mutually exclusive with JWT_PUBLIC_KEY / JWT_JWKS / JWT_JWKS_FILE.
	JWTJWKSURL string `env:"JWT_JWKS_URL"`
	// JWTJWKS is an inline JSON Web Key Set. Use JWTJWKSFile to read from a file.
	JWTJWKS     string `env:"JWT_JWKS"`
	JWTJWKSFile string `env:"JWT_JWKS_FILE"`
	// JWTJWKSRefreshInterval controls how often the JWKS URL cache is refreshed.
	JWTJWKSRefreshInterval time.Duration `env:"JWT_JWKS_REFRESH_INTERVAL" envDefault:"15m"`

	// S3Region is the AWS region for S3 access. When set, a DuckDB SECRET
	// (using the ambient credential chain) is auto-created on startup.
	S3Region string `env:"S3_REGION"`
	// S3Endpoint sets a custom S3-compatible endpoint (MinIO, R2, …).
	S3Endpoint string `env:"S3_ENDPOINT"`
	// S3CredentialChain is the AWS SDK credential chain to use
	// (semicolon-separated). Defaults to DuckDB's built-in default chain.
	// For IRSA (EKS) set "web_identity"; for EKS Pod Identity or ECS task
	// roles set "container"; for an EC2 instance profile set "instance".
	// "sts" assumes a role and requires an ASSUME_ROLE_ARN, which this config
	// does not expose, so it is not used here. See the DuckDB aws extension
	// docs for the full list.
	S3CredentialChain string `env:"S3_CREDENTIAL_CHAIN"`
	// S3UseSSL controls whether HTTPS is used for the S3 endpoint.
	S3UseSSL bool `env:"S3_USE_SSL" envDefault:"true"`
	// S3CredentialRefreshInterval controls how often the DuckDB S3 SECRET is
	// recreated to pick up fresh credentials from the credential chain. Set
	// to 0 to disable periodic refresh (credentials are only loaded at startup).
	S3CredentialRefreshInterval time.Duration `env:"S3_CREDENTIAL_REFRESH_INTERVAL" envDefault:"30m"`
	// S3Views is a comma-separated list of view-name=file-path pairs. Each
	// entry creates a DuckDB view IF NOT EXISTS. The reader function is
	// auto-detected from the file extension (.parquet → read_parquet,
	// .vortex → read_vortex, etc.).
	// Example: sales=s3://acme-sales/**/*.parquet,ops_logs=s3://acme-ops-logs/*.parquet
	S3Views string `env:"S3_VIEWS"`

	// ViewSchemaPath is a YAML file declaring the column schema of one or more
	// views by name. A view listed there is created with read_parquet's
	// `schema` argument, which pins its columns without reading the whole
	// glob: files missing a declared column read it back as NULL. Views absent
	// from the file (or all views, when this is unset) bind to whichever file
	// the glob opens first, so a column the producer added later is not
	// selectable through them.
	ViewSchemaPath string `env:"VIEW_SCHEMA_PATH"`

	// QuackTargetBatchBytes is the target size in bytes of one FETCH wire
	// payload (one rebalanced batch). Zero leaves quack's own default alone
	// (32 MiB in DuckDB 2.0).
	//
	// DuckDB cuts a batch when it reaches this many bytes, so many small
	// DataChunks — an archive of many small Parquet files emits at least one
	// chunk per file — are packed together rather than shipped one response
	// each. Raising it reduces round trips at the cost of buffering a larger
	// response per FETCH; lowering it does the reverse. The server also holds
	// each response under `quack_server_stream_buffer_bytes` (256 MiB, capped
	// at a quarter of memory_limit), so size this against the container.
	QuackTargetBatchBytes uint64 `env:"QUACK_TARGET_BATCH_BYTES" envDefault:"0"`

	// QuackServerMaxConnections caps concurrent Quack clients. Zero leaves
	// quack's default (1024). Each live client holds a DuckDB connection and a
	// result buffer, so this is the first bound on memory under load.
	QuackServerMaxConnections uint64 `env:"QUACK_SERVER_MAX_CONNECTIONS" envDefault:"0"`

	// QuackServerStreamBufferBytes is the per-stream server buffer budget in
	// bytes. Zero leaves quack's default (256 MiB, further capped at a quarter
	// of memory_limit). Lower it to bound the worst-case memory an authenticated
	// client can hold with a large result or insert stream.
	QuackServerStreamBufferBytes uint64 `env:"QUACK_SERVER_STREAM_BUFFER_BYTES" envDefault:"0"`
}

// resolveSecretValue reads a secret from a file if filePath is set, otherwise
// falls back to the inline value. File content is trimmed of leading/trailing
// whitespace. File takes precedence over the inline value when both are set.
func resolveSecretValue(inline, filePath string) (string, error) {
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read secret file %q: %w", filePath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return inline, nil
}

// ResolveSecrets resolves file-backed secret values, preferring files over
// inline environment values. Call this after env.Parse.
func (c *Config) ResolveSecrets() error {
	resolvers := []struct {
		name     string
		inline   *string
		filePath string
	}{
		{"JWT_PUBLIC_KEY", &c.JWTPublicKey, c.JWTPublicKeyFile},
		{"JWT_JWKS", &c.JWTJWKS, c.JWTJWKSFile},
	}
	for _, r := range resolvers {
		val, err := resolveSecretValue(*r.inline, r.filePath)
		if err != nil {
			return fmt.Errorf("%s: %w", r.name, err)
		}
		*r.inline = val
	}
	return nil
}

// loadConfig parses the environment, resolves file-backed secrets, and
// validates that exactly one JWT key source is configured.
func loadConfig() (Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := cfg.ResolveSecrets(); err != nil {
		return cfg, err
	}
	if cfg.PermConfigPath == "" {
		return cfg, fmt.Errorf("PERM_CONFIG_PATH is required (path to the YAML permissions file)")
	}
	sources := 0
	for _, s := range []string{cfg.JWTPublicKey, cfg.JWTJWKSURL, cfg.JWTJWKS} {
		if s != "" {
			sources++
		}
	}
	if sources == 0 {
		return cfg, fmt.Errorf("no JWT key source configured: set one of JWT_PUBLIC_KEY(_FILE), JWT_JWKS_URL, or JWT_JWKS(_FILE)")
	}
	if sources > 1 {
		return cfg, fmt.Errorf("only one JWT key source may be configured: JWT_PUBLIC_KEY, JWT_JWKS_URL, or JWT_JWKS")
	}
	return cfg, nil
}
