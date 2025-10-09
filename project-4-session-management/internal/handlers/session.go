package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bordenet/identity-deep-dive/project-2-session-management/internal/session"
	"github.com/bordenet/identity-deep-dive/project-2-session-management/internal/tokens"
	"github.com/bordenet/identity-deep-dive/project-2-session-management/pkg/models"
)

// SessionHandler handles session management endpoints
type SessionHandler struct {
	jwtManager   *tokens.JWTManager
	sessionStore *session.RedisStore
}

// NewSessionHandler creates a new session handler
func NewSessionHandler(jwtManager *tokens.JWTManager, sessionStore *session.RedisStore) *SessionHandler {
	return &SessionHandler{
		jwtManager:   jwtManager,
		sessionStore: sessionStore,
	}
}

// CreateSession handles POST /sessions
func (h *SessionHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req models.CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, "Invalid request body")
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, err.Error())
		return
	}

	// Generate access token
	accessToken, expiresAt, err := h.jwtManager.GenerateAccessToken(
		req.TenantID,
		req.UserID,
		req.Scope,
		req.Metadata,
	)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to generate access token: %v", err))
		return
	}

	// Generate refresh token
	refreshTokenString, refreshToken, err := h.jwtManager.GenerateRefreshToken(
		req.TenantID,
		req.UserID,
		req.Scope,
		req.Metadata,
	)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to generate refresh token: %v", err))
		return
	}

	// Store refresh token in Redis
	if err := h.sessionStore.StoreRefreshToken(r.Context(), refreshToken); err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to store refresh token: %v", err))
		return
	}

	// Build response
	response := models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(expiresAt).Seconds()),
	}

	h.writeJSON(w, http.StatusCreated, response)
}

// ValidateSession handles POST /sessions/validate
func (h *SessionHandler) ValidateSession(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req models.ValidateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, "Invalid request body")
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, err.Error())
		return
	}

	// Validate JWT token
	claims, err := h.jwtManager.ValidateToken(req.AccessToken)
	if err != nil {
		// Map errors to appropriate response codes
		if err == models.ErrTokenExpired {
			response := models.ValidateSessionResponse{
				Valid:            false,
				Error:            models.ErrCodeExpiredToken,
				ErrorDescription: "Access token has expired",
			}
			h.writeJSON(w, http.StatusUnauthorized, response)
			return
		}

		if err == models.ErrInvalidSignature || err == models.ErrInvalidToken {
			response := models.ValidateSessionResponse{
				Valid:            false,
				Error:            models.ErrCodeInvalidToken,
				ErrorDescription: "Invalid token signature or format",
			}
			h.writeJSON(w, http.StatusUnauthorized, response)
			return
		}

		h.writeError(w, http.StatusUnauthorized, models.ErrCodeInvalidToken,
			fmt.Sprintf("Token validation failed: %v", err))
		return
	}

	// Check revocation blocklist
	isRevoked, err := h.sessionStore.IsTokenRevoked(r.Context(), claims.TenantID, claims.JTI)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to check revocation: %v", err))
		return
	}

	if isRevoked {
		response := models.ValidateSessionResponse{
			Valid:            false,
			Error:            models.ErrCodeRevokedToken,
			ErrorDescription: "Token has been revoked",
		}
		h.writeJSON(w, http.StatusUnauthorized, response)
		return
	}

	// Token is valid
	response := models.ValidateSessionResponse{
		Valid:  true,
		Claims: claims,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// RefreshSession handles POST /sessions/refresh
func (h *SessionHandler) RefreshSession(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req models.RefreshSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, "Invalid request body")
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, err.Error())
		return
	}

	// Validate refresh token
	claims, err := h.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		if err == models.ErrTokenExpired {
			h.writeError(w, http.StatusUnauthorized, models.ErrCodeExpiredToken, "Refresh token has expired")
			return
		}
		h.writeError(w, http.StatusUnauthorized, models.ErrCodeInvalidToken,
			fmt.Sprintf("Invalid refresh token: %v", err))
		return
	}

	// Verify it's a refresh token
	if claims.TokenType != "refresh" {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest,
			"Token is not a refresh token")
		return
	}

	// Check if refresh token exists in Redis
	storedToken, err := h.sessionStore.GetRefreshToken(r.Context(), claims.TenantID, claims.JTI)
	if err == models.ErrRefreshTokenNotFound {
		h.writeError(w, http.StatusUnauthorized, models.ErrCodeInvalidToken,
			"Refresh token not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to get refresh token: %v", err))
		return
	}

	// Check if refresh token is revoked
	isRevoked, err := h.sessionStore.IsTokenRevoked(r.Context(), claims.TenantID, claims.JTI)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to check revocation: %v", err))
		return
	}

	if isRevoked {
		h.writeError(w, http.StatusUnauthorized, models.ErrCodeRevokedToken,
			"Refresh token has been revoked")
		return
	}

	// Generate new access token (same claims as refresh token)
	accessToken, expiresAt, err := h.jwtManager.GenerateAccessToken(
		storedToken.TenantID,
		storedToken.UserID,
		storedToken.Scope,
		storedToken.Metadata,
	)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to generate access token: %v", err))
		return
	}

	// Update last used timestamp
	if err := h.sessionStore.UpdateRefreshTokenLastUsed(r.Context(), claims.TenantID, claims.JTI); err != nil {
		// Log error but don't fail the request
		// This is a non-critical operation
	}

	// Build response (reuse same refresh token - no rotation for simplicity)
	response := models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(expiresAt).Seconds()),
	}

	h.writeJSON(w, http.StatusOK, response)
}

// RevokeSession handles POST /sessions/revoke
func (h *SessionHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req models.RevokeSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, "Invalid request body")
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, err.Error())
		return
	}

	// Validate token to extract claims
	claims, err := h.jwtManager.ValidateToken(req.Token)
	if err != nil {
		// Allow revoking already-expired tokens (for cleanup)
		if err != models.ErrTokenExpired {
			h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidToken,
				fmt.Sprintf("Invalid token: %v", err))
			return
		}
	}

	// Calculate TTL (time until token would naturally expire)
	var ttl time.Duration
	if claims != nil {
		expiresAt := time.Unix(claims.ExpiresAt, 0)
		ttl = time.Until(expiresAt)
		if ttl < 0 {
			ttl = time.Hour // Already expired, but add to blocklist for 1 hour anyway
		}
	} else {
		ttl = time.Hour // If we can't parse expiration, use default TTL
	}

	// Add to revocation blocklist
	if err := h.sessionStore.RevokeToken(r.Context(), claims.TenantID, claims.JTI, ttl); err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to revoke token: %v", err))
		return
	}

	// If it's a refresh token, also delete from Redis
	if claims != nil && claims.TokenType == "refresh" {
		h.sessionStore.DeleteRefreshToken(r.Context(), claims.TenantID, claims.JTI)
		// Ignore error - token might already be deleted
	}

	w.WriteHeader(http.StatusNoContent)
}

// RevokeAllSessions handles POST /sessions/revoke-all
func (h *SessionHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req models.RevokeAllSessionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, "Invalid request body")
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.writeError(w, http.StatusBadRequest, models.ErrCodeInvalidRequest, err.Error())
		return
	}

	// Revoke all tokens for this user
	count, err := h.sessionStore.RevokeAllUserTokens(r.Context(), req.TenantID, req.UserID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, models.ErrCodeInternalError,
			fmt.Sprintf("Failed to revoke tokens: %v", err))
		return
	}

	// Build response
	response := models.RevokeAllSessionsResponse{
		RevokedCount: count,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// Helper functions

func (h *SessionHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *SessionHandler) writeError(w http.ResponseWriter, status int, errorCode, description string) {
	response := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}
	h.writeJSON(w, status, response)
}
