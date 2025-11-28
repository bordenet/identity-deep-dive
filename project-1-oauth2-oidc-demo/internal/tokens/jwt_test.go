package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func TestGenerateAccessToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	manager := NewJWTManager(
		privateKey,
		&privateKey.PublicKey,
		"test-issuer",
		15*time.Minute,
		30*24*time.Hour,
		15*time.Minute,
	)

	token, expiresAt, err := manager.GenerateAccessToken("client456", "user123", "read write")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	if expiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}

	// Validate token structure.
	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if claims.Subject != "user123" {
		t.Errorf("Subject = %v, want user123", claims.Subject)
	}

	if claims.ClientID != "client456" {
		t.Errorf("ClientID = %v, want client456", claims.ClientID)
	}

	if claims.Scope != "read write" {
		t.Errorf("Scope = %v, want 'read write'", claims.Scope)
	}
}

func TestValidateAccessToken_Expired(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create manager with very short expiration.
	manager := NewJWTManager(
		privateKey,
		&privateKey.PublicKey,
		"test-issuer",
		1*time.Nanosecond,
		30*24*time.Hour,
		15*time.Minute,
	)

	token, _, err := manager.GenerateAccessToken("client456", "user123", "read")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Wait for token to expire.
	time.Sleep(10 * time.Millisecond)

	_, err = manager.ValidateAccessToken(token)
	if err == nil {
		t.Error("ValidateAccessToken should fail for expired token")
	}
}

func TestValidateAccessToken_InvalidSignature(t *testing.T) {
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}

	manager1 := NewJWTManager(
		privateKey1,
		&privateKey1.PublicKey,
		"test-issuer",
		15*time.Minute,
		30*24*time.Hour,
		15*time.Minute,
	)
	manager2 := NewJWTManager(
		privateKey2,
		&privateKey2.PublicKey,
		"test-issuer",
		15*time.Minute,
		30*24*time.Hour,
		15*time.Minute,
	)

	// Generate token with key1.
	token, _, err := manager1.GenerateAccessToken("client456", "user123", "read")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Try to validate with key2 (should fail)
	_, err = manager2.ValidateAccessToken(token)
	if err == nil {
		t.Error("ValidateAccessToken should fail for token signed with different key")
	}
}
