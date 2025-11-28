// Package tokens provides JWT token generation and multi-tenant key management.
package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/bordenet/identity-deep-dive/project-4-session-management/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

// JWTManager handles JWT token generation and validation.
type JWTManager struct {
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	keyManager      KeyManager // Interface for multi-tenant key management
}

// KeyManager interface for retrieving tenant-specific keys.
type KeyManager interface {
	GetPrivateKey(tenantID string) (*rsa.PrivateKey, error)
	GetPublicKey(tenantID string) (*rsa.PublicKey, error)
}

// NewJWTManager creates a new JWT manager.
func NewJWTManager(
	issuer string,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	keyManager KeyManager,
) *JWTManager {
	return &JWTManager{
		issuer:          issuer,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		keyManager:      keyManager,
	}
}

// GenerateAccessToken generates a new access token (JWT with RS256).
func (jm *JWTManager) GenerateAccessToken(
	tenantID string,
	userID string,
	scope string,
	metadata map[string]string,
) (string, time.Time, error) {
	// Get tenant's private key.
	privateKey, err := jm.keyManager.GetPrivateKey(tenantID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get private key: %w", err)
	}

	// Generate unique token ID.
	tokenID, err := generateTokenID()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(jm.accessTokenTTL)

	// Create claims.
	claims := models.TokenClaims{
		Subject:   userID,
		Issuer:    jm.issuer,
		Audience:  tenantID,
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		JTI:       tokenID,
		TenantID:  tenantID,
		Scope:     scope,
		Metadata:  metadata,
		TokenType: "access",
	}

	// Create token.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":        claims.Subject,
		"iss":        claims.Issuer,
		"aud":        claims.Audience,
		"exp":        claims.ExpiresAt,
		"iat":        claims.IssuedAt,
		"nbf":        claims.NotBefore,
		"jti":        claims.JTI,
		"tenant_id":  claims.TenantID,
		"scope":      claims.Scope,
		"metadata":   claims.Metadata,
		"token_type": claims.TokenType,
	})

	// Sign token.
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// GenerateRefreshToken generates a new refresh token (JWT with RS256).
//
//nolint:funlen // JWT refresh token generation with comprehensive claims
func (jm *JWTManager) GenerateRefreshToken(
	tenantID string,
	userID string,
	scope string,
	metadata map[string]string,
) (string, *models.RefreshToken, error) {
	// Get tenant's private key.
	privateKey, err := jm.keyManager.GetPrivateKey(tenantID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Generate unique token ID.
	tokenID, err := generateTokenID()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(jm.refreshTokenTTL)

	// Create refresh token record.
	refreshToken := &models.RefreshToken{
		ID:        tokenID,
		TenantID:  tenantID,
		UserID:    userID,
		Scope:     scope,
		Metadata:  metadata,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		LastUsed:  now,
	}

	// Create claims.
	claims := models.TokenClaims{
		Subject:   userID,
		Issuer:    jm.issuer,
		Audience:  tenantID,
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		JTI:       tokenID,
		TenantID:  tenantID,
		Scope:     scope,
		Metadata:  metadata,
		TokenType: "refresh",
	}

	// Create token.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":        claims.Subject,
		"iss":        claims.Issuer,
		"aud":        claims.Audience,
		"exp":        claims.ExpiresAt,
		"iat":        claims.IssuedAt,
		"nbf":        claims.NotBefore,
		"jti":        claims.JTI,
		"tenant_id":  claims.TenantID,
		"scope":      claims.Scope,
		"metadata":   claims.Metadata,
		"token_type": claims.TokenType,
	})

	// Sign token.
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, refreshToken, nil
}

// ValidateToken validates a JWT token and returns the claims.
//
//nolint:funlen // JWT validation with comprehensive claim extraction
func (jm *JWTManager) ValidateToken(tokenString string) (*models.TokenClaims, error) {
	// Parse token without validation to extract tenant ID.
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract tenant ID from claims.
	claims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, models.ErrInvalidToken
	}

	tenantID, ok := claims["tenant_id"].(string)
	if !ok {
		return nil, models.ErrTenantIDNotFound
	}

	// Get tenant's public key.
	publicKey, err := jm.keyManager.GetPublicKey(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse and validate token with public key.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method.
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", models.ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		// Check for specific error types.
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, models.ErrTokenExpired
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, models.ErrInvalidToken
	}

	// Extract claims.
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, models.ErrInvalidToken
	}

	// Convert to TokenClaims.
	tokenClaims := &models.TokenClaims{
		Subject:   getStringClaim(mapClaims, "sub"),
		Issuer:    getStringClaim(mapClaims, "iss"),
		Audience:  getStringClaim(mapClaims, "aud"),
		ExpiresAt: getInt64Claim(mapClaims, "exp"),
		IssuedAt:  getInt64Claim(mapClaims, "iat"),
		NotBefore: getInt64Claim(mapClaims, "nbf"),
		JTI:       getStringClaim(mapClaims, "jti"),
		TenantID:  getStringClaim(mapClaims, "tenant_id"),
		Scope:     getStringClaim(mapClaims, "scope"),
		TokenType: getStringClaim(mapClaims, "token_type"),
	}

	// Extract metadata if present.
	if metadata, ok := mapClaims["metadata"].(map[string]interface{}); ok {
		tokenClaims.Metadata = make(map[string]string)
		for k, v := range metadata {
			if strVal, ok := v.(string); ok {
				tokenClaims.Metadata[k] = strVal
			}
		}
	}

	// Verify issuer matches.
	if tokenClaims.Issuer != jm.issuer {
		return nil, fmt.Errorf("%w: expected %s, got %s", models.ErrInvalidIssuer, jm.issuer, tokenClaims.Issuer)
	}

	return tokenClaims, nil
}

// generateTokenID generates a cryptographically random token ID.
func generateTokenID() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Helper functions to extract claims safely.
func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getInt64Claim(claims jwt.MapClaims, key string) int64 {
	if val, ok := claims[key].(float64); ok {
		return int64(val)
	}
	return 0
}
