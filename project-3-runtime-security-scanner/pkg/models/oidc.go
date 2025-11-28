// Package models provides data models for OAuth2/OIDC runtime security scanning.
package models

// OIDCDiscoveryDocument represents the OIDC discovery document.
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata.
type OIDCDiscoveryDocument struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSURI                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
}
