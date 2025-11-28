package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/tokens"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
	"github.com/rs/zerolog/log"
)

// UserInfoHandler handles the OIDC UserInfo endpoint.
type UserInfoHandler struct {
	jwtManager *tokens.JWTManager
	userStore  UserStore
}

// NewUserInfoHandler creates a new UserInfo handler.
func NewUserInfoHandler(jwtManager *tokens.JWTManager, userStore UserStore) *UserInfoHandler {
	return &UserInfoHandler{
		jwtManager: jwtManager,
		userStore:  userStore,
	}
}

// ServeHTTP handles GET /userinfo requests.
func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("MERMAID: UserInfo Endpoint: 5. GET /userinfo (optional)")
	// Only accept GET requests.
	if r.Method != http.MethodGet {
		h.writeError(w, "invalid_request", "Only GET method allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract access token from Authorization header.
	accessToken, err := h.extractBearerToken(r)
	if err != nil {
		h.writeError(w, "invalid_token", err.Error(), http.StatusUnauthorized)
		return
	}

	// Validate access token.
	claims, err := h.jwtManager.ValidateAccessToken(accessToken)
	if err != nil {
		h.writeError(w, "invalid_token", "Access token validation failed", http.StatusUnauthorized)
		return
	}

	// Get user from database.
	user, err := h.userStore.GetUser(r.Context(), claims.UserID)
	if err != nil {
		h.writeError(w, "server_error", "Failed to retrieve user", http.StatusInternalServerError)
		return
	}

	// Build UserInfo response based on scope.
	userInfo := h.buildUserInfoResponse(user, claims.Scope)

	// Write response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

// extractBearerToken extracts the Bearer token from Authorization header.
func (h *UserInfoHandler) extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &UserInfoError{Code: "invalid_request", Description: "Missing Authorization header"}
	}

	// Authorization: Bearer <token>.
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", &UserInfoError{Code: "invalid_request", Description: "Invalid Authorization header format"}
	}

	return parts[1], nil
}

// buildUserInfoResponse builds the UserInfo response based on scope.
func (h *UserInfoHandler) buildUserInfoResponse(user *models.User, scope string) *models.UserInfoResponse {
	// Subject is always included.
	response := &models.UserInfoResponse{
		Subject: user.ID,
	}

	// Add profile claims if profile scope requested.
	if models.HasScope(scope, models.ScopeProfile) {
		response.Name = user.Name
		response.GivenName = user.GivenName
		response.FamilyName = user.FamilyName
		response.Picture = user.Picture
		response.Profile = user.Profile
	}

	// Add email claims if email scope requested.
	if models.HasScope(scope, models.ScopeEmail) {
		response.Email = user.Email
		response.EmailVerified = user.EmailVerified
	}

	return response
}

// UserInfoError represents a UserInfo endpoint error.
type UserInfoError struct {
	Code        string
	Description string
}

func (e *UserInfoError) Error() string {
	return e.Description
}

// writeError writes an error response.
func (h *UserInfoHandler) writeError(w http.ResponseWriter, errorCode, description string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	errorResp := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}

	if err := json.NewEncoder(w).Encode(errorResp); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}
