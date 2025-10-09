package models

import (
	"crypto/rsa"
	"time"
)

// Tenant represents a tenant with isolated signing keys
type Tenant struct {
	ID         string    `json:"id"`          // Tenant identifier
	Name       string    `json:"name"`        // Human-readable name
	PrivateKey *rsa.PrivateKey `json:"-"` // RSA private key (never serialized)
	PublicKey  *rsa.PublicKey  `json:"-"` // RSA public key
	KeyID      string    `json:"key_id"`      // Key identifier for JWKS
	CreatedAt  time.Time `json:"created_at"`  // Tenant creation time
	UpdatedAt  time.Time `json:"updated_at"`  // Last key rotation
}

// JWKSDocument represents a JSON Web Key Set document (RFC 7517)
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key (RFC 7517)
type JWK struct {
	KeyType   string `json:"kty"`           // Key type ("RSA")
	Use       string `json:"use"`           // Key use ("sig" for signature)
	Algorithm string `json:"alg"`           // Algorithm ("RS256")
	KeyID     string `json:"kid"`           // Key ID
	Modulus   string `json:"n"`             // RSA modulus (base64url)
	Exponent  string `json:"e"`             // RSA exponent (base64url)
}
