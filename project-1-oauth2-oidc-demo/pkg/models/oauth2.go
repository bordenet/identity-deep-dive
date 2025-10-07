package models

import "time"

// Client represents an OAuth2 client application
type Client struct {
	ID           string   `json:"client_id"`
	Secret       string   `json:"client_secret,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name"`
	Type         string   `json:"type"` // "public" or "confidential"
	Scopes       []string `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

// IsPublic returns true if this is a public client (requires PKCE)
func (c *Client) IsPublic() bool {
	return c.Type == "public"
}

// ValidateRedirectURI checks if the provided URI is registered for this client
func (c *Client) ValidateRedirectURI(uri string) bool {
	for _, registered := range c.RedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ResponseType string `json:"response_type"` // "code" for authorization code flow
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"` // CSRF protection

	// PKCE parameters (RFC 7636)
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"` // "S256" or "plain"

	// OIDC parameters
	Nonce string `json:"nonce,omitempty"` // OIDC replay protection
}

// AuthorizationCode represents an issued authorization code
type AuthorizationCode struct {
	Code         string    `json:"code"`
	ClientID     string    `json:"client_id"`
	UserID       string    `json:"user_id"`
	RedirectURI  string    `json:"redirect_uri"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
	Used         bool      `json:"used"`

	// PKCE
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// OIDC
	Nonce string `json:"nonce,omitempty"`
}

// IsExpired returns true if the authorization code has expired
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string `json:"grant_type"` // "authorization_code", "client_credentials", "refresh_token"
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`

	// PKCE
	CodeVerifier string `json:"code_verifier,omitempty"`

	// Refresh token flow
	RefreshToken string `json:"refresh_token,omitempty"`

	// Client credentials flow
	Scope string `json:"scope,omitempty"`
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // "Bearer"
	ExpiresIn    int    `json:"expires_in"` // seconds
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// OIDC
	IDToken string `json:"id_token,omitempty"`
}

// AccessToken represents an issued access token
type AccessToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id,omitempty"` // Empty for client credentials
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// IsExpired returns true if the access token has expired
func (at *AccessToken) IsExpired() bool {
	return time.Now().After(at.ExpiresAt)
}

// RefreshToken represents an issued refresh token
type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// IsExpired returns true if the refresh token has expired
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// ErrorResponse represents an OAuth2 error response
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// OAuth2 error codes (RFC 6749 Section 5.2)
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorAccessDenied            = "access_denied"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorServerError             = "server_error"
	ErrorTemporarilyUnavailable  = "temporarily_unavailable"
)
