package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
	"github.com/rs/zerolog/log"
)

// AuthorizeHandler handles the OAuth2/OIDC authorization endpoint
type AuthorizeHandler struct {
	sessionStore SessionStore
}

// SessionStore interface for storing authorization codes
type SessionStore interface {
	GetClient(ctx context.Context, clientID string) (*models.Client, error)
	StoreAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error
}

// NewAuthorizeHandler creates a new authorize handler
func NewAuthorizeHandler(sessionStore SessionStore) *AuthorizeHandler {
	return &AuthorizeHandler{
		sessionStore: sessionStore,
	}
}

// ServeHTTP handles GET /authorize requests
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("MERMAID: AuthZ Server: 2. GET /authorize + PKCE challenge")
	// Only accept GET requests
	if r.Method != http.MethodGet {
		h.writeError(w, r, models.ErrorInvalidRequest, "Only GET method allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse and validate request
	authReq, err := h.parseAuthorizationRequest(r)
	if err != nil {
		h.writeError(w, r, models.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate client
	client, err := h.sessionStore.GetClient(r.Context(), authReq.ClientID)
	if err != nil {
		h.writeError(w, r, models.ErrorInvalidClient, "Client not found", http.StatusUnauthorized)
		return
	}

	// Validate redirect URI
	if !client.ValidateRedirectURI(authReq.RedirectURI) {
		// Per OAuth2 spec: if redirect_uri is invalid, DO NOT redirect (prevents open redirect)
		h.writeErrorPage(w, "Invalid redirect_uri")
		return
	}

	// Validate response_type
	if authReq.ResponseType != "code" {
		h.redirectError(w, r, authReq.RedirectURI, authReq.State, models.ErrorUnsupportedResponseType, "Only 'code' response_type supported")
		return
	}

	// Validate PKCE for public clients
	if client.IsPublic() && authReq.CodeChallenge == "" {
		h.redirectError(w, r, authReq.RedirectURI, authReq.State, models.ErrorInvalidRequest, "PKCE required for public clients")
		return
	}

	// TODO: In real implementation, show login page and get user authentication
	// For now, we'll simulate an authenticated user
	userID := h.getAuthenticatedUser(r)
	if userID == "" {
		// TODO: Redirect to login page, then back here after authentication
		h.writeErrorPage(w, "Not authenticated - login page not implemented yet")
		return
	}

	log.Debug().Msg("MERMAID: AuthZ Server: 3. AuthZ Server stores code_challenge with code")
	// Generate authorization code
	code, err := h.generateAuthorizationCode(r.Context(), authReq, userID)
	if err != nil {
		h.redirectError(w, r, authReq.RedirectURI, authReq.State, models.ErrorServerError, "Failed to generate authorization code")
		return
	}

	// Redirect back to client with authorization code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectURI, code.Code, authReq.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// parseAuthorizationRequest parses and validates the authorization request
func (h *AuthorizeHandler) parseAuthorizationRequest(r *http.Request) (*models.AuthorizationRequest, error) {
	query := r.URL.Query()

	authReq := &models.AuthorizationRequest{
		ResponseType:        query.Get("response_type"),
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		Nonce:               query.Get("nonce"),
	}

	// Validate required parameters
	if authReq.ResponseType == "" {
		return nil, fmt.Errorf("response_type is required")
	}
	if authReq.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if authReq.RedirectURI == "" {
		return nil, fmt.Errorf("redirect_uri is required")
	}
	if authReq.State == "" {
		return nil, fmt.Errorf("state is required (CSRF protection)")
	}

	// Validate OIDC requirements
	if models.HasScope(authReq.Scope, models.ScopeOpenID) {
		// OIDC request - nonce recommended
		if authReq.Nonce == "" {
			// Nonce is recommended for OIDC but not strictly required for code flow
			// We'll allow it but log a warning in production
		}
	}

	// Default code_challenge_method to plain if not specified
	if authReq.CodeChallenge != "" && authReq.CodeChallengeMethod == "" {
		authReq.CodeChallengeMethod = "plain"
	}

	return authReq, nil
}

// generateAuthorizationCode creates and stores an authorization code
func (h *AuthorizeHandler) generateAuthorizationCode(ctx context.Context, authReq *models.AuthorizationRequest, userID string) (*models.AuthorizationCode, error) {
	// Generate random authorization code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random code: %w", err)
	}
	codeString := base64.RawURLEncoding.EncodeToString(codeBytes)

	// Create authorization code
	code := &models.AuthorizationCode{
		Code:                codeString,
		ClientID:            authReq.ClientID,
		UserID:              userID,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		ExpiresAt:           time.Now().Add(10 * time.Minute), // 10 minute expiry
		Used:                false,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		Nonce:               authReq.Nonce,
	}

	// Store in Redis
	if err := h.sessionStore.StoreAuthorizationCode(ctx, code); err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// getAuthenticatedUser returns the currently authenticated user ID
// TODO: Implement real session management -- unnecessary for this learning exercise (@bordenet)
func (h *AuthorizeHandler) getAuthenticatedUser(r *http.Request) string {
	// Check for session cookie or other authentication mechanism
	// For now, return a demo user ID
	// In production, this would:
	// 1. Check session cookie
	// 2. Validate session in Redis
	// 3. Return user ID from session
	// 4. Or return "" if not authenticated (redirect to login)

	// Demo: return a test user ID
	return "demo-user-123"
}

// writeError writes an OAuth2 error response
func (h *AuthorizeHandler) writeError(w http.ResponseWriter, r *http.Request, errorCode, description string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	fmt.Fprintf(w, `{"error":"%s","error_description":"%s"}`, errorCode, description)
}

// writeErrorPage writes an HTML error page (for cases where redirect is unsafe)
func (h *AuthorizeHandler) writeErrorPage(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Authorization Error</title></head>
<body>
<h1>Authorization Error</h1>
<p>%s</p>
</body>
</html>`, message)
}

// redirectError redirects to client with error in query parameters
func (h *AuthorizeHandler) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, description string) {
	redirectURL := fmt.Sprintf("%s?error=%s&error_description=%s&state=%s", redirectURI, errorCode, description, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
