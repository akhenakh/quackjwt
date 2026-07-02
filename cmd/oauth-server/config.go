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
	DuckDBPath string `env:"DUCKDB_PATH" envDefault:"quackjwt.db"`
	// QuackURI is the address Quack binds, e.g. "quack:0.0.0.0:9494".
	QuackURI string `env:"QUACK_URI" envDefault:"quack:0.0.0.0:9494"`
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
	// S3UseSSL controls whether HTTPS is used for the S3 endpoint.
	S3UseSSL bool `env:"S3_USE_SSL" envDefault:"true"`
	// S3Views is a comma-separated list of view-name=file-path pairs. Each
	// entry creates a DuckDB view IF NOT EXISTS. The reader function is
	// auto-detected from the file extension (.parquet → read_parquet,
	// .vortex → read_vortex, etc.).
	// Example: sales=s3://acme-sales/**/*.parquet,ops_logs=s3://acme-ops-logs/*.parquet
	S3Views string `env:"S3_VIEWS"`
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
