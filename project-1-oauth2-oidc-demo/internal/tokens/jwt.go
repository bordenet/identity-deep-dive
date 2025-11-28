// Package tokens provides JWT token generation and validation functionality.
package tokens

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

// JWTManager handles JWT token generation and validation.
type JWTManager struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	idTokenTTL      time.Duration
}

// NewJWTManager creates a new JWT manager.
func NewJWTManager(
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	issuer string,
	accessTokenTTL,
	refreshTokenTTL,
	idTokenTTL time.Duration,
) *JWTManager {
	return &JWTManager{
		privateKey:      privateKey,
		publicKey:       publicKey,
		issuer:          issuer,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		idTokenTTL:      idTokenTTL,
	}
}

// AccessTokenClaims represents the claims in an access token.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id,omitempty"` // Empty for client_credentials
}

// GenerateAccessToken generates a JWT access token.
func (jm *JWTManager) GenerateAccessToken(clientID, userID, scope string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(jm.accessTokenTTL)

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jm.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Scope:    scope,
		ClientID: clientID,
		UserID:   userID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(jm.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, expiresAt, nil
}

// ValidateAccessToken validates and parses an access token.
func (jm *JWTManager) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method.
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", models.ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		return jm.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, models.ErrInvalidToken
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, models.ErrInvalidTokenClaims
	}

	return claims, nil
}

// GenerateIDToken generates an OIDC ID token.
func (jm *JWTManager) GenerateIDToken(
	user *models.User,
	clientID string,
	nonce string,
	accessToken string,
	scope string,
) (string, error) {
	now := time.Now()
	expiresAt := now.Add(jm.idTokenTTL)

	claims := models.IDTokenClaims{
		Issuer:    jm.issuer,
		Subject:   user.ID,
		Audience:  clientID,
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Nonce:     nonce,
		AuthTime:  now.Unix(),
	}

	// Add at_hash (access token hash) per OIDC spec.
	if accessToken != "" {
		claims.AccessHash = generateTokenHash(accessToken)
	}

	// Add user profile claims based on scope.
	if models.HasScope(scope, models.ScopeProfile) {
		claims.Name = user.Name
		claims.GivenName = user.GivenName
		claims.FamilyName = user.FamilyName
		claims.Picture = user.Picture
		claims.Profile = user.Profile
	}

	if models.HasScope(scope, models.ScopeEmail) {
		claims.Email = user.Email
		claims.EmailVerified = user.EmailVerified
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(jm.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return signedToken, nil
}

// ValidateIDToken validates and parses an ID token.
func (jm *JWTManager) ValidateIDToken(tokenString string) (*models.IDTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.IDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method.
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", models.ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		return jm.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	if !token.Valid {
		return nil, models.ErrInvalidToken
	}

	claims, ok := token.Claims.(*models.IDTokenClaims)
	if !ok {
		return nil, models.ErrInvalidTokenClaims
	}

	// Validate expiration.
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, models.ErrIDTokenExpired
	}

	return claims, nil
}

// generateTokenHash generates at_hash or c_hash per OIDC spec.
// For RS256: Left-most 128 bits of SHA-256 hash, base64url encoded.
func generateTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	// Take left-most 128 bits (16 bytes)
	halfHash := hash[:16]
	// Base64url encode without padding.
	return base64.RawURLEncoding.EncodeToString(halfHash)
}

// GetPublicKey returns the public key for external verification.
func (jm *JWTManager) GetPublicKey() *rsa.PublicKey {
	return jm.publicKey
}
