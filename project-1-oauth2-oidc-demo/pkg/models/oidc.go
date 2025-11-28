package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents an authenticated user.
type User struct {
	ID            string    `json:"sub"` // Subject identifier (OIDC standard claim).
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	GivenName     string    `json:"given_name,omitempty"`
	FamilyName    string    `json:"family_name,omitempty"`
	Picture       string    `json:"picture,omitempty"`
	Profile       string    `json:"profile,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// IDTokenClaims represents OIDC ID Token claims (JWT payload).
type IDTokenClaims struct {
	// Standard JWT claims (RFC 7519).
	Issuer    string `json:"iss"`           // Issuer (authorization server URL).
	Subject   string `json:"sub"`           // Subject (user ID).
	Audience  string `json:"aud"`           // Audience (client ID).
	ExpiresAt int64  `json:"exp"`           // Expiration time (Unix timestamp).
	IssuedAt  int64  `json:"iat"`           // Issued at (Unix timestamp).
	NotBefore int64  `json:"nbf,omitempty"` // Not before (Unix timestamp).

	// OIDC-specific claims.
	Nonce      string `json:"nonce,omitempty"`     // Replay protection.
	AuthTime   int64  `json:"auth_time,omitempty"` // Time of authentication.
	AccessHash string `json:"at_hash,omitempty"`   // Access token hash.
	CodeHash   string `json:"c_hash,omitempty"`    // Authorization code hash.

	// User profile claims (optional, based on scope).
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Profile       string `json:"profile,omitempty"`
}

// GetExpirationTime implements jwt.Claims interface.
func (c *IDTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.Claims interface.
func (c *IDTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.Claims interface.
func (c *IDTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}

// GetIssuer implements jwt.Claims interface.
func (c *IDTokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.Claims interface.
func (c *IDTokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// GetAudience implements jwt.Claims interface.
func (c *IDTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}

// UserInfoResponse represents the OIDC UserInfo endpoint response.
type UserInfoResponse struct {
	Subject       string `json:"sub"` // Required.
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Profile       string `json:"profile,omitempty"`
}

// OIDCDiscoveryDocument represents the OpenID Connect discovery document.
// Served at /.well-known/openid-configuration.
type OIDCDiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSUri                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// OIDC standard scopes.
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeAddress = "address"
	ScopePhone   = "phone"
)

// HasScope checks if a space-separated scope string contains the given scope.
func HasScope(scopes, scope string) bool {
	if scopes == "" {
		return false
	}
	for i := 0; i < len(scopes); {
		j := i
		for j < len(scopes) && scopes[j] != ' ' {
			j++
		}
		if scopes[i:j] == scope {
			return true
		}
		i = j + 1
	}
	return false
}
