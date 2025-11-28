package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/tokens"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
	"github.com/rs/zerolog/log"
)

// TokenHandler handles the OAuth2/OIDC token endpoint.
type TokenHandler struct {
	sessionStore SessionStoreExtended
	jwtManager   *tokens.JWTManager
	userStore    UserStore
}

// SessionStoreExtended extends SessionStore with token operations.
type SessionStoreExtended interface {
	SessionStore
	GetAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error)
	InvalidateAuthorizationCode(ctx context.Context, code string) error
	StoreRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
}

// UserStore interface for retrieving user information.
type UserStore interface {
	GetUser(ctx context.Context, userID string) (*models.User, error)
}

// NewTokenHandler creates a new token handler.
func NewTokenHandler(sessionStore SessionStoreExtended, jwtManager *tokens.JWTManager, userStore UserStore) *TokenHandler {
	return &TokenHandler{
		sessionStore: sessionStore,
		jwtManager:   jwtManager,
		userStore:    userStore,
	}
}

// ServeHTTP handles POST /oauth2/token requests.
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("MERMAID: Token Endpoint: 4. Token request with code_verifier")
	// Only accept POST requests.
	if r.Method != http.MethodPost {
		h.writeError(w, models.ErrorInvalidRequest, "Only POST method allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body.
	if err := r.ParseForm(); err != nil {
		h.writeError(w, models.ErrorInvalidRequest, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Parse token request.
	tokenReq := &models.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		CodeVerifier: r.FormValue("code_verifier"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
	}

	// Validate grant_type.
	if tokenReq.GrantType == "" {
		h.writeError(w, models.ErrorInvalidRequest, "grant_type is required", http.StatusBadRequest)
		return
	}

	// Route to appropriate grant type handler.
	var tokenResp *models.TokenResponse
	var err error

	switch tokenReq.GrantType {
	case "authorization_code":
		tokenResp, err = h.handleAuthorizationCodeGrant(r.Context(), tokenReq)
	case "refresh_token":
		tokenResp, err = h.handleRefreshTokenGrant(r.Context(), tokenReq)
	case "client_credentials":
		tokenResp, err = h.handleClientCredentialsGrant(r.Context(), tokenReq)
	default:
		h.writeError(w, models.ErrorUnsupportedGrantType, fmt.Sprintf("Unsupported grant_type: %s", tokenReq.GrantType), http.StatusBadRequest)
		return
	}

	if err != nil {
		// Error already has proper OAuth2 error code.
		h.writeError(w, err.Error(), "", http.StatusBadRequest)
		return
	}

	// Write successful token response.
	h.writeTokenResponse(w, tokenResp)
}

// handleAuthorizationCodeGrant handles the authorization_code grant type.
//
//nolint:funlen,gocyclo // OAuth2 authorization code flow with comprehensive validation
func (h *TokenHandler) handleAuthorizationCodeGrant(ctx context.Context, req *models.TokenRequest) (*models.TokenResponse, error) {
	// Validate required parameters.
	if req.Code == "" {
		return nil, models.ErrInvalidRequest
	}
	if req.ClientID == "" {
		return nil, models.ErrInvalidRequest
	}
	if req.RedirectURI == "" {
		return nil, models.ErrInvalidRequest
	}

	// Retrieve authorization code from Redis.
	authCode, err := h.sessionStore.GetAuthorizationCode(ctx, req.Code)
	if err != nil {
		return nil, models.ErrInvalidGrant
	}

	// Validate authorization code.
	if authCode.Used {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidGrant, models.ErrCodeAlreadyUsed)
	}
	if authCode.IsExpired() {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidGrant, models.ErrCodeExpired)
	}
	if authCode.ClientID != req.ClientID {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidGrant, models.ErrClientIDMismatch)
	}
	if authCode.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidGrant, models.ErrRedirectURIMismatch)
	}

	// Validate client.
	client, err := h.sessionStore.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, models.ErrInvalidClient
	}

	// Validate client authentication.
	if !client.IsPublic() {
		// Confidential client - require client_secret.
		if req.ClientSecret != client.Secret {
			return nil, fmt.Errorf("%w: %w", models.ErrInvalidClient, models.ErrInvalidClientSecret)
		}
	}

	log.Debug().Msg("MERMAID: Token Endpoint: 5. Token endpoint validates PKCE")
	// Validate PKCE.
	if err := tokens.ValidatePKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
		return nil, fmt.Errorf("%s: PKCE validation failed: %w", models.ErrorInvalidGrant, err)
	}

	// Mark authorization code as used (one-time use).
	if err := h.sessionStore.InvalidateAuthorizationCode(ctx, req.Code); err != nil {
		return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
	}

	// Get user information.
	user, err := h.userStore.GetUser(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
	}

	// Generate access token.
	accessToken, expiresAt, err := h.jwtManager.GenerateAccessToken(client.ID, user.ID, authCode.Scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
	}

	// Calculate expires_in (seconds until expiration).
	expiresIn := int(time.Until(expiresAt).Seconds())

	// Build token response.
	tokenResp := &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       authCode.Scope,
	}

	// Generate refresh token (optional, for long-lived sessions).
	if models.HasScope(authCode.Scope, "offline_access") {
		refreshToken, err := h.generateRefreshToken(ctx, client.ID, user.ID, authCode.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
		}
		tokenResp.RefreshToken = refreshToken
	}

	// Generate ID token if OIDC scope requested.
	if models.HasScope(authCode.Scope, models.ScopeOpenID) {
		idToken, err := h.jwtManager.GenerateIDToken(user, client.ID, authCode.Nonce, accessToken, authCode.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
		}
		tokenResp.IDToken = idToken
	}

	return tokenResp, nil
}

// handleRefreshTokenGrant handles the refresh_token grant type.
//
//nolint:funlen // OAuth2 refresh token flow with comprehensive validation
func (h *TokenHandler) handleRefreshTokenGrant(ctx context.Context, req *models.TokenRequest) (*models.TokenResponse, error) {
	// Validate required parameters.
	if req.RefreshToken == "" {
		return nil, models.ErrInvalidRequest
	}
	if req.ClientID == "" {
		return nil, models.ErrInvalidRequest
	}

	// Retrieve refresh token from Redis.
	refreshToken, err := h.sessionStore.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, models.ErrInvalidGrant
	}

	// Validate refresh token.
	if refreshToken.Revoked {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidGrant, models.ErrRefreshTokenRevoked)
	}
	if refreshToken.IsExpired() {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidGrant, models.ErrRefreshTokenExpired)
	}
	if refreshToken.ClientID != req.ClientID {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidGrant, models.ErrClientIDMismatch)
	}

	// Validate client.
	client, err := h.sessionStore.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, models.ErrInvalidClient
	}

	// Validate client authentication.
	if !client.IsPublic() {
		if req.ClientSecret != client.Secret {
			return nil, fmt.Errorf("%w: %w", models.ErrInvalidClient, models.ErrInvalidClientSecret)
		}
	}

	// Get user information.
	user, err := h.userStore.GetUser(ctx, refreshToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
	}

	// Generate new access token.
	accessToken, expiresAt, err := h.jwtManager.GenerateAccessToken(client.ID, user.ID, refreshToken.Scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
	}

	expiresIn := int(time.Until(expiresAt).Seconds())

	// Build token response.
	tokenResp := &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       refreshToken.Scope,
	}

	// Generate new ID token if OIDC.
	if models.HasScope(refreshToken.Scope, models.ScopeOpenID) {
		idToken, err := h.jwtManager.GenerateIDToken(user, client.ID, "", accessToken, refreshToken.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
		}
		tokenResp.IDToken = idToken
	}

	// NOTE: Refresh token rotation (issue new refresh token, revoke old one) is optional for this learning exercise.

	return tokenResp, nil
}

// handleClientCredentialsGrant handles the client_credentials grant type (service-to-service).
func (h *TokenHandler) handleClientCredentialsGrant(ctx context.Context, req *models.TokenRequest) (*models.TokenResponse, error) {
	// Validate required parameters.
	if req.ClientID == "" {
		return nil, models.ErrInvalidRequest
	}

	// Validate client.
	client, err := h.sessionStore.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, models.ErrInvalidClient
	}

	// Client credentials grant requires confidential client.
	if client.IsPublic() {
		return nil, fmt.Errorf("%w: %w", models.ErrUnauthorizedClient, models.ErrPublicClientNotAllowed)
	}

	// Validate client_secret.
	if req.ClientSecret != client.Secret {
		return nil, fmt.Errorf("%w: %w", models.ErrInvalidClient, models.ErrInvalidClientSecret)
	}

	// Determine scope (use requested scope or default to client's allowed scopes).
	scope := req.Scope
	if scope == "" && len(client.Scopes) > 0 {
		scope = client.Scopes[0] // Use first allowed scope as default.
	}

	// Generate access token (no user context for client_credentials).
	accessToken, expiresAt, err := h.jwtManager.GenerateAccessToken(client.ID, "", scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", models.ErrServerError, err)
	}

	expiresIn := int(time.Until(expiresAt).Seconds())

	// Build token response (no refresh token or ID token for client_credentials).
	tokenResp := &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       scope,
	}

	return tokenResp, nil
}

// generateRefreshToken creates and stores a refresh token.
func (h *TokenHandler) generateRefreshToken(ctx context.Context, clientID, userID, scope string) (string, error) {
	// Generate random refresh token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	tokenString := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Create refresh token.
	refreshToken := &models.RefreshToken{
		Token:     tokenString,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days.
		Revoked:   false,
	}

	// Store in Redis.
	if err := h.sessionStore.StoreRefreshToken(ctx, refreshToken); err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return tokenString, nil
}

// writeTokenResponse writes a successful token response.
func (h *TokenHandler) writeTokenResponse(w http.ResponseWriter, tokenResp *models.TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(tokenResp); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

// writeError writes an OAuth2 error response.
func (h *TokenHandler) writeError(w http.ResponseWriter, errorCode, description string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	errorResp := models.ErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	}

	if err := json.NewEncoder(w).Encode(errorResp); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}
