package permissions

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTKeyConfig selects the source of the RSA public key used to validate JWTs.
// Exactly one of PublicKeyPEM, JWKSURL, or JWKSJSON must be set; setting more
// than one is an error. Leaving all unset is only valid when no JWT validation
// is wanted (the Manager.VerifyToken will then reject every token).
type JWTKeyConfig struct {
	PublicKeyPEM    string
	JWKSURL         string
	JWKSJSON        string
	RefreshInterval time.Duration
	Audience        string
	Issuer          string
}

// buildJWTKeyfunc assembles a jwt.Keyfunc from exactly one configured key
// source. It mirrors the option set of csi-secret-age's permission system.
func buildJWTKeyfunc(cfg JWTKeyConfig) (jwt.Keyfunc, error) {
	sourcesSet := 0
	if cfg.PublicKeyPEM != "" {
		sourcesSet++
	}
	if cfg.JWKSURL != "" {
		sourcesSet++
	}
	if cfg.JWKSJSON != "" {
		sourcesSet++
	}
	if sourcesSet == 0 {
		// No JWT key source configured: keyfunc stays nil and VerifyToken
		// rejects every token. This is an error for the oauth-server use case
		// but is allowed at construction time for flexibility.
		return nil, nil
	}
	if sourcesSet > 1 {
		return nil, errors.New("only one JWT key source may be configured: JWT_PUBLIC_KEY, JWT_JWKS_URL, or JWT_JWKS/JWT_JWKS_FILE")
	}

	if cfg.PublicKeyPEM != "" {
		return staticKeyfuncFromPEM(cfg.PublicKeyPEM)
	}
	if cfg.JWKSJSON != "" {
		return staticKeyfuncFromJWKS([]byte(cfg.JWKSJSON))
	}
	return newJWKSKeyfunc(cfg.JWKSURL, cfg.RefreshInterval)
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func staticKeyfuncFromPEM(pemStr string) (jwt.Keyfunc, error) {
	pubKey, err := parseRSAPublicKey(pemStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT public key: %w", err)
	}
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	}, nil
}

// jwk is a minimal JWK representation supporting RSA keys.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

func parseRSAPublicKeyFromJWK(key jwk) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", key.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("invalid key %q modulus: %w", key.Kid, err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("invalid key %q exponent: %w", key.Kid, err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func parseJWKSKeys(data []byte) (map[string]*rsa.PublicKey, error) {
	var resp jwksResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(resp.Keys))
	for _, key := range resp.Keys {
		if key.Kty != "RSA" {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		pub, err := parseRSAPublicKeyFromJWK(key)
		if err != nil {
			return nil, err
		}
		if key.Kid == "" {
			continue
		}
		keys[key.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable RSA signing keys")
	}
	return keys, nil
}

func staticKeyfuncFromJWKS(data []byte) (jwt.Keyfunc, error) {
	keys, err := parseJWKSKeys(data)
	if err != nil {
		return nil, err
	}
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("token header missing kid")
		}
		pub, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("JWKS does not contain key %q", kid)
		}
		return pub, nil
	}, nil
}

// jwksCache fetches and caches a JWKS document from a URL, refreshing on the
// configured interval. It falls back to the stale cache on fetch error so a
// transient IdP outage does not block authentication.
type jwksCache struct {
	url       string
	client    *http.Client
	refresh   time.Duration
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
	mu        sync.RWMutex
}

func newJWKSKeyfunc(url string, refresh time.Duration) (jwt.Keyfunc, error) {
	cache := &jwksCache{
		url:     url,
		client:  &http.Client{Timeout: 10 * time.Second},
		refresh: refresh,
	}
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("token header missing kid")
		}
		pub, err := cache.getKey(kid)
		if err != nil {
			return nil, fmt.Errorf("JWKS lookup failed: %w", err)
		}
		return pub, nil
	}, nil
}

func (c *jwksCache) cached(kid string) (*rsa.PublicKey, bool) {
	if c.refresh <= 0 {
		return nil, false
	}
	if c.keys == nil || time.Since(c.lastFetch) >= c.refresh {
		return nil, false
	}
	pub, ok := c.keys[kid]
	return pub, ok
}

func (c *jwksCache) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	if pub, ok := c.cached(kid); ok {
		c.mu.RUnlock()
		return pub, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock.
	if pub, ok := c.cached(kid); ok {
		return pub, nil
	}

	keys, err := c.fetch()
	if err != nil {
		// On fetch error, fall back to the existing cache if we have one.
		if c.keys != nil {
			if pub, ok := c.keys[kid]; ok {
				return pub, nil
			}
		}
		return nil, err
	}
	c.keys = keys
	c.lastFetch = time.Now()

	pub, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("JWKS does not contain key %q", kid)
	}
	return pub, nil
}

func (c *jwksCache) fetch() (map[string]*rsa.PublicKey, error) {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}
	return parseJWKSKeys(data)
}

func audienceMatches(claims jwt.MapClaims, expected string) bool {
	raw, ok := claims["aud"]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case string:
		return v == expected
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
		return false
	case []interface{}:
		for _, s := range v {
			if str, ok := s.(string); ok && str == expected {
				return true
			}
		}
		return false
	}
	return false
}

func issuerMatches(claims jwt.MapClaims, expected string) bool {
	raw, ok := claims["iss"].(string)
	if !ok {
		return false
	}
	return raw == expected
}
