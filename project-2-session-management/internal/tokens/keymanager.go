package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"

	"github.com/bordenet/identity-deep-dive/project-2-session-management/pkg/models"
)

// TenantKeyManager manages RSA keys for multiple tenants
type TenantKeyManager struct {
	keyCache    map[string]*models.Tenant // In-memory cache of tenant keys
	cacheMutex  sync.RWMutex              // Protects key cache
	keyStore    KeyStore                  // Persistent storage for keys
}

// KeyStore interface for persistent key storage (Redis, Vault, etc.)
type KeyStore interface {
	// StoreKeyPair stores a tenant's RSA key pair
	StoreKeyPair(tenantID string, privateKeyPEM, publicKeyPEM []byte) error
	// GetKeyPair retrieves a tenant's RSA key pair
	GetKeyPair(tenantID string) (privateKeyPEM, publicKeyPEM []byte, err error)
	// DeleteKeyPair deletes a tenant's RSA key pair (for rotation)
	DeleteKeyPair(tenantID string) error
}

// NewTenantKeyManager creates a new tenant key manager
func NewTenantKeyManager(keyStore KeyStore) *TenantKeyManager {
	return &TenantKeyManager{
		keyCache: make(map[string]*models.Tenant),
		keyStore: keyStore,
	}
}

// GetPrivateKey retrieves a tenant's private key (implements KeyManager interface)
func (tkm *TenantKeyManager) GetPrivateKey(tenantID string) (*rsa.PrivateKey, error) {
	tenant, err := tkm.getTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return tenant.PrivateKey, nil
}

// GetPublicKey retrieves a tenant's public key (implements KeyManager interface)
func (tkm *TenantKeyManager) GetPublicKey(tenantID string) (*rsa.PublicKey, error) {
	tenant, err := tkm.getTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return tenant.PublicKey, nil
}

// GetJWKS returns the JWKS document for a tenant
func (tkm *TenantKeyManager) GetJWKS(tenantID string) (*models.JWKSDocument, error) {
	tenant, err := tkm.getTenant(tenantID)
	if err != nil {
		return nil, err
	}

	jwk, err := rsaPublicKeyToJWK(tenant.PublicKey, tenant.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to JWK: %w", err)
	}

	return &models.JWKSDocument{
		Keys: []models.JWK{jwk},
	}, nil
}

// getTenant retrieves a tenant from cache or loads from store
func (tkm *TenantKeyManager) getTenant(tenantID string) (*models.Tenant, error) {
	// Try cache first (read lock)
	tkm.cacheMutex.RLock()
	if tenant, ok := tkm.keyCache[tenantID]; ok {
		tkm.cacheMutex.RUnlock()
		return tenant, nil
	}
	tkm.cacheMutex.RUnlock()

	// Not in cache, acquire write lock and check again (double-check locking)
	tkm.cacheMutex.Lock()
	defer tkm.cacheMutex.Unlock()

	// Check again in case another goroutine loaded it
	if tenant, ok := tkm.keyCache[tenantID]; ok {
		return tenant, nil
	}

	// Try to load from persistent store
	privateKeyPEM, publicKeyPEM, err := tkm.keyStore.GetKeyPair(tenantID)
	if err != nil {
		// Key doesn't exist, generate new key pair
		return tkm.generateAndStoreKeyPair(tenantID)
	}

	// Parse keys from PEM
	privateKey, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Create tenant and cache it
	tenant := &models.Tenant{
		ID:         tenantID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		KeyID:      generateKeyID(tenantID),
	}

	tkm.keyCache[tenantID] = tenant
	return tenant, nil
}

// generateAndStoreKeyPair generates a new RSA key pair for a tenant
func (tkm *TenantKeyManager) generateAndStoreKeyPair(tenantID string) (*models.Tenant, error) {
	// Generate RSA-2048 key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Convert to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Store in persistent storage
	if err := tkm.keyStore.StoreKeyPair(tenantID, privateKeyPEM, publicKeyPEM); err != nil {
		return nil, fmt.Errorf("failed to store key pair: %w", err)
	}

	// Create tenant and cache it
	tenant := &models.Tenant{
		ID:         tenantID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      generateKeyID(tenantID),
	}

	tkm.keyCache[tenantID] = tenant
	return tenant, nil
}

// RotateKey generates a new key pair for a tenant and stores it
func (tkm *TenantKeyManager) RotateKey(tenantID string) error {
	tkm.cacheMutex.Lock()
	defer tkm.cacheMutex.Unlock()

	// Delete old key from cache
	delete(tkm.keyCache, tenantID)

	// Delete old key from store
	if err := tkm.keyStore.DeleteKeyPair(tenantID); err != nil {
		return fmt.Errorf("failed to delete old key: %w", err)
	}

	// Generate new key pair (will be cached automatically)
	_, err := tkm.generateAndStoreKeyPair(tenantID)
	return err
}

// parsePrivateKeyPEM parses a PEM-encoded RSA private key
func parsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// parsePublicKeyPEM parses a PEM-encoded RSA public key
func parsePublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

// rsaPublicKeyToJWK converts an RSA public key to JWK format (RFC 7517)
func rsaPublicKeyToJWK(publicKey *rsa.PublicKey, keyID string) (models.JWK, error) {
	// Convert modulus (n) to base64url
	nBytes := publicKey.N.Bytes()
	n := base64.RawURLEncoding.EncodeToString(nBytes)

	// Convert exponent (e) to base64url
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	return models.JWK{
		KeyType:   "RSA",
		Use:       "sig",
		Algorithm: "RS256",
		KeyID:     keyID,
		Modulus:   n,
		Exponent:  e,
	}, nil
}

// generateKeyID generates a unique key identifier for a tenant
func generateKeyID(tenantID string) string {
	// Simple format: tenant-id-timestamp
	// In production, might include version or rotation counter
	return fmt.Sprintf("%s-key", tenantID)
}
