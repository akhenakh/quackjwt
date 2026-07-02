// Package permissions wires JWT verification and a YAML permission file to a
// quackjwt.Server. It reuses the same JWT key-source option set as
// github.com/akhenakh/csi-secret-age: a static PEM RSA public key, an inline
// JWKS JSON document, or a refreshable JWKS URL.
//
// The permissions file maps a JWT subject (the value of the configured user
// claim, typically "sub") to the list of DuckDB table/view names it may query.
// The file is watched with fsnotify and reloaded on change, including the
// atomic symlink swap that kubelet performs when updating a ConfigMap volume.
package permissions

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

// Config configures a Manager.
type Config struct {
	// ConfigPath is the path to the YAML permissions file. In Kubernetes this
	// is typically a ConfigMap-mounted file (e.g. /etc/quackjwt/perm.yaml).
	ConfigPath string
	// JWT selects the JWT validation key source and claim constraints.
	JWT JWTKeyConfig
	// UserClaim is the JWT claim whose value identifies the subject. Defaults
	// to "sub" when empty.
	UserClaim string
}

// Snapshot is an immutable point-in-time view of the parsed permissions file.
// Callers must not mutate the returned slices/maps.
type Snapshot struct {
	Admins []string
	// Grants maps a subject to the list of table/view names it may query.
	Grants map[string][]string
}

// Manager validates JWTs against the configured key source and resolves the
// permissions for the resulting subject from a YAML file. It is safe for
// concurrent use. The YAML file is reloaded on change.
type Manager struct {
	configPath string
	keyfunc    jwt.Keyfunc
	userClaim  string
	audience   string
	issuer     string

	mu     sync.RWMutex
	admins []string
	grants map[string][]string
}

// New creates a Manager, loads the permissions file, and prepares the JWT
// verifier. The file is not yet watched; call Watch to start observing it.
func New(cfg Config) (*Manager, error) {
	if cfg.ConfigPath == "" {
		return nil, errors.New("permissions: config path is required")
	}
	if cfg.UserClaim == "" {
		cfg.UserClaim = "sub"
	}

	keyfunc, err := buildJWTKeyfunc(cfg.JWT)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		configPath: cfg.ConfigPath,
		keyfunc:    keyfunc,
		userClaim:  cfg.UserClaim,
		audience:   cfg.JWT.Audience,
		issuer:     cfg.JWT.Issuer,
	}
	if err := m.Load(); err != nil {
		return nil, err
	}
	return m, nil
}

// VerifyToken validates a raw JWT and returns the configured user claim value
// (the subject identity used to key permissions). It is the quackjwt
// TokenVerifier for this Manager.
func (m *Manager) VerifyToken(tokenString string) (string, error) {
	if m.keyfunc == nil {
		return "", errors.New("permissions: JWT validation is not configured")
	}
	token, err := jwt.Parse(tokenString, m.keyfunc)
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}

	if m.audience != "" && !audienceMatches(claims, m.audience) {
		return "", fmt.Errorf("invalid audience; expected %s", m.audience)
	}
	if m.issuer != "" && !issuerMatches(claims, m.issuer) {
		return "", fmt.Errorf("invalid issuer; expected %s", m.issuer)
	}

	username, ok := claims[m.userClaim].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("claim %s not found or empty", m.userClaim)
	}
	return username, nil
}

// Snapshot returns a copy of the currently loaded permissions.
func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := Snapshot{
		Admins: append([]string(nil), m.admins...),
		Grants: make(map[string][]string, len(m.grants)),
	}
	for sub, tables := range m.grants {
		out.Grants[sub] = append([]string(nil), tables...)
	}
	return out
}

// IsAdmin reports whether the subject is listed under admin_users.
func (m *Manager) IsAdmin(sub string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.admins {
		if a == sub {
			return true
		}
	}
	return false
}

// Load (re)reads and parses the permissions file. It is safe to call
// concurrently with VerifyToken / Snapshot. The accepted YAML schema is:
//
//	admin_users:            # optional; subjects that bypass table grants
//	  - alice
//	user_permissions:       # map of subject -> list of table/view names
//	  alice:
//	    - sales
//	    - ops_logs
//	  bob:
//	    - sales_redacted
func (m *Manager) Load() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to read permissions file: %w", err)
	}

	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse permissions file: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.admins = nil
	m.grants = make(map[string][]string)

	for key, node := range raw {
		switch key {
		case "admin_users":
			if err := node.Decode(&m.admins); err != nil {
				return fmt.Errorf("failed to parse admin list: %w", err)
			}
		case "user_permissions":
			var userNode map[string]yaml.Node
			if err := node.Decode(&userNode); err != nil {
				return fmt.Errorf("failed to parse user permissions: %w", err)
			}
			for userKey, userVal := range userNode {
				var tables []string
				if err := userVal.Decode(&tables); err != nil {
					return fmt.Errorf("failed to parse permissions for %s: %w", userKey, err)
				}
				m.grants[userKey] = tables
			}
		default:
			return fmt.Errorf("%w: %q", ErrUnknownKey, key)
		}
	}

	return nil
}

// ErrUnknownKey is referenced by callers that need to distinguish schema errors.
var ErrUnknownKey = errors.New("unknown top-level key in permissions file")

// audienceMatches and issuerMatches are defined in jwt.go.
