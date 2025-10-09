package models

import (
	"errors"
	"time"
)

// Session represents an authenticated user session
type Session struct {
	ID        string            `json:"id"`         // Unique session identifier
	TenantID  string            `json:"tenant_id"`  // Multi-tenant isolation
	UserID    string            `json:"user_id"`    // User identifier
	Scope     string            `json:"scope"`      // OAuth2 scopes
	Metadata  map[string]string `json:"metadata"`   // Custom claims (email, roles, etc.)
	CreatedAt time.Time         `json:"created_at"` // Session creation time
	ExpiresAt time.Time         `json:"expires_at"` // Session expiration
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"` // Always "Bearer"
	ExpiresIn    int    `json:"expires_in"` // Access token TTL in seconds
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	// Standard JWT claims
	Subject   string `json:"sub"` // User ID
	Issuer    string `json:"iss"` // Token issuer
	Audience  string `json:"aud"` // Token audience
	ExpiresAt int64  `json:"exp"` // Expiration time (Unix timestamp)
	IssuedAt  int64  `json:"iat"` // Issued at (Unix timestamp)
	NotBefore int64  `json:"nbf"` // Not before (Unix timestamp)
	JTI       string `json:"jti"` // JWT ID (unique token identifier)

	// Custom claims
	TenantID string            `json:"tenant_id"`          // Multi-tenant isolation
	Scope    string            `json:"scope"`              // OAuth2 scopes
	Metadata map[string]string `json:"metadata,omitempty"` // Custom metadata
	TokenType string           `json:"token_type"`         // "access" or "refresh"
}

// RefreshToken represents a stored refresh token
type RefreshToken struct {
	ID        string            `json:"id"`          // Token ID (jti)
	TenantID  string            `json:"tenant_id"`   // Multi-tenant isolation
	UserID    string            `json:"user_id"`     // User identifier
	Scope     string            `json:"scope"`       // OAuth2 scopes
	Metadata  map[string]string `json:"metadata"`    // Custom metadata
	CreatedAt time.Time         `json:"created_at"`  // Token creation time
	ExpiresAt time.Time         `json:"expires_at"`  // Token expiration
	LastUsed  time.Time         `json:"last_used"`   // Last refresh time
}

// IsExpired checks if the refresh token has expired
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// CreateSessionRequest represents the request to create a new session
type CreateSessionRequest struct {
	TenantID string            `json:"tenant_id"`
	UserID   string            `json:"user_id"`
	Scope    string            `json:"scope"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Validate validates the create session request
func (req *CreateSessionRequest) Validate() error {
	if req.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if req.UserID == "" {
		return errors.New("user_id is required")
	}
	if req.Scope == "" {
		return errors.New("scope is required")
	}
	return nil
}

// ValidateSessionRequest represents the request to validate a session
type ValidateSessionRequest struct {
	AccessToken string `json:"access_token"`
}

// Validate validates the validate session request
func (req *ValidateSessionRequest) Validate() error {
	if req.AccessToken == "" {
		return errors.New("access_token is required")
	}
	return nil
}

// ValidateSessionResponse represents the response to session validation
type ValidateSessionResponse struct {
	Valid bool         `json:"valid"`
	Claims *TokenClaims `json:"claims,omitempty"`
	Error  string       `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RefreshSessionRequest represents the request to refresh a session
type RefreshSessionRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Validate validates the refresh session request
func (req *RefreshSessionRequest) Validate() error {
	if req.RefreshToken == "" {
		return errors.New("refresh_token is required")
	}
	return nil
}

// RevokeSessionRequest represents the request to revoke a session
type RevokeSessionRequest struct {
	Token  string `json:"token,omitempty"`   // Specific token to revoke
	Reason string `json:"reason,omitempty"`  // Reason for revocation
}

// Validate validates the revoke session request
func (req *RevokeSessionRequest) Validate() error {
	if req.Token == "" {
		return errors.New("token is required")
	}
	return nil
}

// RevokeAllSessionsRequest represents the request to revoke all user sessions
type RevokeAllSessionsRequest struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason,omitempty"`
}

// Validate validates the revoke all sessions request
func (req *RevokeAllSessionsRequest) Validate() error {
	if req.UserID == "" {
		return errors.New("user_id is required")
	}
	if req.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	return nil
}

// RevokeAllSessionsResponse represents the response to revoking all sessions
type RevokeAllSessionsResponse struct {
	RevokedCount int `json:"revoked_count"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status        string `json:"status"`         // "healthy" or "unhealthy"
	Redis         string `json:"redis"`          // Redis connection status
	UptimeSeconds int64  `json:"uptime_seconds"` // Server uptime
}

// Error codes for session management
const (
	ErrCodeInvalidToken     = "invalid_token"
	ErrCodeExpiredToken     = "token_expired"
	ErrCodeRevokedToken     = "token_revoked"
	ErrCodeInvalidSignature = "invalid_signature"
	ErrCodeInvalidRequest   = "invalid_request"
	ErrCodeInternalError    = "internal_error"
	ErrCodeUnauthorized     = "unauthorized"
)

// Common errors
var (
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenRevoked        = errors.New("token has been revoked")
	ErrInvalidSignature    = errors.New("invalid token signature")
	ErrInvalidToken        = errors.New("invalid token format")
	ErrTenantNotFound      = errors.New("tenant not found")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrInvalidRequest      = errors.New("invalid request")
)
