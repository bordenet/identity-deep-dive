package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
)

// DiscoveryHandler handles the OIDC Discovery endpoint.
type DiscoveryHandler struct {
	issuer    string
	publicKey *rsa.PublicKey
}

// NewDiscoveryHandler creates a new discovery handler.
func NewDiscoveryHandler(issuer string, publicKey *rsa.PublicKey) *DiscoveryHandler {
	return &DiscoveryHandler{
		issuer:    issuer,
		publicKey: publicKey,
	}
}

// ServeHTTP handles GET /.well-known/openid-configuration.
//
//nolint:funlen // OIDC discovery endpoint with comprehensive metadata
func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method allowed", http.StatusMethodNotAllowed)
		return
	}

	doc := &models.OIDCDiscoveryDocument{
		Issuer:                h.issuer,
		AuthorizationEndpoint: h.issuer + "/authorize",
		TokenEndpoint:         h.issuer + "/oauth2/token",
		UserInfoEndpoint:      h.issuer + "/userinfo",
		JWKSUri:               h.issuer + "/.well-known/jwks.json",
		RevocationEndpoint:    h.issuer + "/oauth2/revoke",
		ResponseTypesSupported: []string{
			"code",
			"token",
			"id_token",
			"code id_token",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"address",
			"phone",
			"offline_access",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
		},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"nonce",
			"name",
			"given_name",
			"family_name",
			"email",
			"email_verified",
			"picture",
			"profile",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
			"plain",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

// JWKSHandler handles the JWKs endpoint.
type JWKSHandler struct {
	publicKey *rsa.PublicKey
}

// NewJWKSHandler creates a new JWKs handler.
func NewJWKSHandler(publicKey *rsa.PublicKey) *JWKSHandler {
	return &JWKSHandler{
		publicKey: publicKey,
	}
}

// ServeHTTP handles GET /.well-known/jwks.json.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method allowed", http.StatusMethodNotAllowed)
		return
	}

	// Convert RSA public key to JWK format.
	jwk := h.rsaPublicKeyToJWK(h.publicKey)

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

// rsaPublicKeyToJWK converts an RSA public key to JWK format.
func (h *JWKSHandler) rsaPublicKeyToJWK(pubKey *rsa.PublicKey) map[string]interface{} {
	// Encode modulus (n) and exponent (e) as base64url.
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

	return map[string]interface{}{
		"kty": "RSA",     // Key type
		"use": "sig",     // Public key use (signature)
		"alg": "RS256",   // Algorithm
		"kid": "default", // Key ID
		"n":   n,         // Modulus
		"e":   e,         // Exponent
	}
}
