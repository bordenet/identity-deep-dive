package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

// mockKeyManager implements KeyManager for testing
type mockKeyManager struct {
	keys map[string]*rsa.PrivateKey
}

func (m *mockKeyManager) GetPrivateKey(tenantID string) (*rsa.PrivateKey, error) {
	key, ok := m.keys[tenantID]
	if !ok {
		key, _ = rsa.GenerateKey(rand.Reader, 2048)
		m.keys[tenantID] = key
	}
	return key, nil
}

func (m *mockKeyManager) GetPublicKey(tenantID string) (*rsa.PublicKey, error) {
	key, err := m.GetPrivateKey(tenantID)
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

func newMockKeyManager() *mockKeyManager {
	return &mockKeyManager{
		keys: make(map[string]*rsa.PrivateKey),
	}
}

func TestGenerateAccessToken(t *testing.T) {
	km := newMockKeyManager()
	manager := NewJWTManager("test-issuer", 15*time.Minute, 30*24*time.Hour, km)

	token, expiresAt, err := manager.GenerateAccessToken("tenant1", "user123", "read write", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	if expiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}

	// Validate token
	claims, err := manager.ValidateToken("tenant1", token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Subject != "user123" {
		t.Errorf("Subject = %v, want user123", claims.Subject)
	}

	if claims.TenantID != "tenant1" {
		t.Errorf("TenantID = %v, want tenant1", claims.TenantID)
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	km := newMockKeyManager()
	manager := NewJWTManager("test-issuer", 15*time.Minute, 30*24*time.Hour, km)

	token, err := manager.GenerateRefreshToken("tenant1", "user123", "session456")
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	if token == "" {
		t.Error("Generated refresh token is empty")
	}

	// Validate token
	claims, err := manager.ValidateToken("tenant1", token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Subject != "user123" {
		t.Errorf("Subject = %v, want user123", claims.Subject)
	}

	if claims.TokenType != "refresh" {
		t.Errorf("TokenType = %v, want refresh", claims.TokenType)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	km := newMockKeyManager()
	manager := NewJWTManager("test-issuer", 1*time.Nanosecond, 30*24*time.Hour, km)

	token, _, err := manager.GenerateAccessToken("tenant1", "user123", "read", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = manager.ValidateToken("tenant1", token)
	if err == nil {
		t.Error("ValidateToken should fail for expired token")
	}
}

func TestValidateToken_WrongTenant(t *testing.T) {
	km := newMockKeyManager()
	manager := NewJWTManager("test-issuer", 15*time.Minute, 30*24*time.Hour, km)

	token, _, err := manager.GenerateAccessToken("tenant1", "user123", "read", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	_, err = manager.ValidateToken("tenant2", token)
	if err == nil {
		t.Error("ValidateToken should fail when using wrong tenant key")
	}
}
