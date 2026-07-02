package permissions

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// genRSAKey generates a 2048-bit RSA key pair for tests.
func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

// pubKeyPEM encodes an RSA public key as a PKIX PEM block.
func pubKeyPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// signRS256 returns a compact RS256 JWT with the given claims and kid header.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return s
}

// jwksJSONFor builds a minimal JWKS document containing the given RSA key
// under kid.
func jwksJSONFor(t *testing.T, key *rsa.PublicKey, kid string) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`, kid, n, e)
}

func writePerm(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write perm: %v", err)
	}
}

func mustManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestLoad_YAMLSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, `
admin_users:
  - admin1
user_permissions:
  alice:
    - sales
    - ops_logs
  bob:
    - sales_redacted
`)
	m := mustManager(t, Config{
		ConfigPath: path,
		JWT:        JWTKeyConfig{PublicKeyPEM: pubKeyPEM(t, genRSAKey(t))},
	})

	snap := m.Snapshot()
	if !m.IsAdmin("admin1") {
		t.Error("admin1 should be admin")
	}
	if m.IsAdmin("alice") {
		t.Error("alice should not be admin")
	}
	if got := snap.Grants["alice"]; len(got) != 2 || got[0] != "sales" || got[1] != "ops_logs" {
		t.Errorf("alice grants = %v, want [sales ops_logs]", got)
	}
	if got := snap.Grants["bob"]; len(got) != 1 || got[0] != "sales_redacted" {
		t.Errorf("bob grants = %v, want [sales_redacted]", got)
	}
	// Snapshot must be a copy: mutating it must not affect the manager.
	snap.Grants["alice"] = nil
	if got := m.Snapshot().Grants["alice"]; len(got) != 2 {
		t.Errorf("manager grants mutated via snapshot: %v", got)
	}
}

func TestLoad_UnknownTopLevelKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, `
user_permissions:
  alice:
    - sales
bogus_key:
  - x
`)
	_, err := New(Config{
		ConfigPath: path,
		JWT:        JWTKeyConfig{PublicKeyPEM: pubKeyPEM(t, genRSAKey(t))},
	})
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("New with unknown key: err = %v, want ErrUnknownKey", err)
	}
}

func TestNew_RequiresConfigPath(t *testing.T) {
	if _, err := New(Config{JWT: JWTKeyConfig{PublicKeyPEM: "x"}}); err == nil {
		t.Fatal("expected error when ConfigPath is empty")
	}
}

func TestNew_RejectsMultipleKeySources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, "user_permissions:\n  a:\n    - t\n")
	_, err := New(Config{
		ConfigPath: path,
		JWT: JWTKeyConfig{
			PublicKeyPEM: "x",
			JWKSURL:      "https://example.com/jwks",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "only one JWT key source") {
		t.Fatalf("err = %v, want 'only one JWT key source'", err)
	}
}

func TestVerifyToken_StaticPEM(t *testing.T) {
	key := genRSAKey(t)
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, "user_permissions:\n  alice:\n    - sales\n")
	m := mustManager(t, Config{
		ConfigPath: path,
		JWT:        JWTKeyConfig{PublicKeyPEM: pubKeyPEM(t, key)},
	})

	tok := signRS256(t, key, "", jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	sub, err := m.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if sub != "alice" {
		t.Errorf("sub = %q, want alice", sub)
	}
}

func TestVerifyToken_RejectsWrongKey(t *testing.T) {
	signingKey := genRSAKey(t)
	otherKey := genRSAKey(t)
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, "user_permissions:\n  alice:\n    - sales\n")
	m := mustManager(t, Config{
		ConfigPath: path,
		JWT:        JWTKeyConfig{PublicKeyPEM: pubKeyPEM(t, otherKey)},
	})

	tok := signRS256(t, signingKey, "", jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.VerifyToken(tok); err == nil {
		t.Fatal("VerifyToken should fail for a token signed by a different key")
	}
}

func TestVerifyToken_AudienceAndIssuer(t *testing.T) {
	key := genRSAKey(t)
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, "user_permissions:\n  alice:\n    - sales\n")
	m := mustManager(t, Config{
		ConfigPath: path,
		JWT: JWTKeyConfig{
			PublicKeyPEM: pubKeyPEM(t, key),
			Audience:     "my-client-id",
			Issuer:       "https://accounts.example.com",
		},
	})

	// Missing aud/iss -> rejected.
	tok := signRS256(t, key, "", jwt.MapClaims{
		"sub": "alice", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.VerifyToken(tok); err == nil {
		t.Fatal("VerifyToken should reject token missing aud/iss")
	}

	// Correct aud/iss -> accepted.
	tok = signRS256(t, key, "", jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
		"aud": "my-client-id",
		"iss": "https://accounts.example.com",
	})
	if sub, err := m.VerifyToken(tok); err != nil || sub != "alice" {
		t.Fatalf("VerifyToken(aud/iss ok) = %q, %v, want alice, nil", sub, err)
	}

	// Wrong aud -> rejected.
	tok = signRS256(t, key, "", jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
		"aud": "other-client",
		"iss": "https://accounts.example.com",
	})
	if _, err := m.VerifyToken(tok); err == nil {
		t.Fatal("VerifyToken should reject token with wrong aud")
	}
}

func TestVerifyToken_InlineJWKS(t *testing.T) {
	key := genRSAKey(t)
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, "user_permissions:\n  alice:\n    - sales\n")
	m := mustManager(t, Config{
		ConfigPath: path,
		JWT:        JWTKeyConfig{JWKSJSON: jwksJSONFor(t, &key.PublicKey, "key-1")},
	})

	tok := signRS256(t, key, "key-1", jwt.MapClaims{
		"sub": "alice", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if sub, err := m.VerifyToken(tok); err != nil || sub != "alice" {
		t.Fatalf("VerifyToken(jwks) = %q, %v, want alice, nil", sub, err)
	}

	// Token without kid header is rejected by the JWKS keyfunc.
	tokNoKid := signRS256(t, key, "", jwt.MapClaims{
		"sub": "alice", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.VerifyToken(tokNoKid); err == nil {
		t.Fatal("VerifyToken should reject JWKS-validated token missing kid")
	}

	// Token with unknown kid is rejected.
	tokOther := signRS256(t, genRSAKey(t), "unknown", jwt.MapClaims{
		"sub": "alice", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.VerifyToken(tokOther); err == nil {
		t.Fatal("VerifyToken should reject token with unknown kid")
	}
}

func TestVerifyToken_NotConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, "user_permissions:\n  alice:\n    - sales\n")
	// No key source -> keyfunc is nil.
	m, err := New(Config{ConfigPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.VerifyToken("anything"); err == nil {
		t.Fatal("VerifyToken should fail when no JWT key source is configured")
	}
}

func TestWatch_ReloadOnWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.yaml")
	writePerm(t, path, "user_permissions:\n  alice:\n    - sales\n")
	m := mustManager(t, Config{
		ConfigPath: path,
		JWT:        JWTKeyConfig{PublicKeyPEM: pubKeyPEM(t, genRSAKey(t))},
	})

	reloaded := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- m.Watch(ctx, nil, func() { reloaded <- struct{}{} }) }()

	time.Sleep(100 * time.Millisecond) // let the watcher attach

	// Replace the file content. fsnotify emits a Write event on Linux.
	writePerm(t, path, "user_permissions:\n  bob:\n    - ops_logs\n")

	select {
	case <-reloaded:
	case <-time.After(2 * time.Second):
		t.Fatal("reload callback not invoked after write")
	}

	if _, ok := m.Snapshot().Grants["bob"]; !ok {
		t.Fatal("grants not updated after reload")
	}
	if _, ok := m.Snapshot().Grants["alice"]; ok {
		t.Fatal("old grant should be gone after reload")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Watch returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}

func TestWatch_KubernetesConfigMapSymlinkSwap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Kubernetes ConfigMap inotify behaviour is Linux-specific")
	}

	tmpDir := t.TempDir()
	key := genRSAKey(t)

	// Reproduce the Kubernetes AtomicWriter layout:
	//   perm.yaml -> ..data/perm.yaml
	//   ..data    -> ..<timestamp>/
	//   ..<timestamp>/perm.yaml  (the real file)
	v1Dir := filepath.Join(tmpDir, "..2022_09_22_15_29_04.2914482033")
	if err := os.Mkdir(v1Dir, 0755); err != nil {
		t.Fatalf("mkdir v1: %v", err)
	}
	writePerm(t, filepath.Join(v1Dir, "perm.yaml"), "user_permissions:\n  alice:\n    - sales\n")
	if err := os.Symlink(filepath.Base(v1Dir), filepath.Join(tmpDir, "..data")); err != nil {
		t.Fatalf("symlink ..data: %v", err)
	}
	permPath := filepath.Join(tmpDir, "perm.yaml")
	if err := os.Symlink(filepath.Join("..data", "perm.yaml"), permPath); err != nil {
		t.Fatalf("symlink perm.yaml: %v", err)
	}

	m := mustManager(t, Config{
		ConfigPath: permPath,
		JWT:        JWTKeyConfig{PublicKeyPEM: pubKeyPEM(t, key)},
	})
	if _, ok := m.Snapshot().Grants["alice"]; !ok {
		t.Fatal("initial load missing alice")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- m.Watch(ctx, nil, nil) }()

	time.Sleep(100 * time.Millisecond) // let the watcher attach

	// Simulate a ConfigMap update: new timestamped dir, repoint ..data, drop old.
	v2Dir := filepath.Join(tmpDir, "..2022_09_22_15_29_05.1234567890")
	if err := os.Mkdir(v2Dir, 0755); err != nil {
		t.Fatalf("mkdir v2: %v", err)
	}
	writePerm(t, filepath.Join(v2Dir, "perm.yaml"), "user_permissions:\n  bob:\n    - ops_logs\n")
	if err := os.Remove(filepath.Join(tmpDir, "..data")); err != nil {
		t.Fatalf("remove old ..data: %v", err)
	}
	if err := os.Symlink(filepath.Base(v2Dir), filepath.Join(tmpDir, "..data")); err != nil {
		t.Fatalf("symlink new ..data: %v", err)
	}
	if err := os.RemoveAll(v1Dir); err != nil {
		t.Fatalf("remove old v1 dir: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := m.Snapshot().Grants["bob"]; ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, ok := m.Snapshot().Grants["bob"]; !ok {
		t.Fatal("grants not updated after ConfigMap symlink swap")
	}
	if _, ok := m.Snapshot().Grants["alice"]; ok {
		t.Fatal("old alice grant should be gone after swap")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Watch returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}
