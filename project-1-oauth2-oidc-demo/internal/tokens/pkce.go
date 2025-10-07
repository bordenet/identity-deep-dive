package tokens

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCEMethod represents the code challenge method
type PKCEMethod string

const (
	// PKCEMethodPlain uses the code verifier as-is (not recommended)
	PKCEMethodPlain PKCEMethod = "plain"
	// PKCEMethodS256 uses SHA-256 hash of code verifier (recommended)
	PKCEMethodS256 PKCEMethod = "S256"
)

// ValidatePKCE validates the code verifier against the code challenge
// Per RFC 7636: https://tools.ietf.org/html/rfc7636
func ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeChallenge == "" {
		// No PKCE was used (allowed for confidential clients)
		return nil
	}

	if codeVerifier == "" {
		return fmt.Errorf("code_verifier required when code_challenge was provided")
	}

	// Validate code verifier format (RFC 7636 Section 4.1)
	// ABNF: code-verifier = 43*128unreserved
	// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return fmt.Errorf("code_verifier must be 43-128 characters")
	}

	var expectedChallenge string

	switch PKCEMethod(codeChallengeMethod) {
	case PKCEMethodPlain:
		// plain: challenge = verifier
		expectedChallenge = codeVerifier

	case PKCEMethodS256:
		// S256: challenge = BASE64URL(SHA256(verifier))
		hash := sha256.Sum256([]byte(codeVerifier))
		expectedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	default:
		return fmt.Errorf("unsupported code_challenge_method: %s (supported: plain, S256)", codeChallengeMethod)
	}

	if expectedChallenge != codeChallenge {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}

// GenerateCodeChallenge generates a code challenge from a code verifier
// This is typically done by the client, but we provide it here for testing
func GenerateCodeChallenge(codeVerifier string, method PKCEMethod) (string, error) {
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return "", fmt.Errorf("code_verifier must be 43-128 characters")
	}

	switch method {
	case PKCEMethodPlain:
		return codeVerifier, nil

	case PKCEMethodS256:
		hash := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(hash[:]), nil

	default:
		return "", fmt.Errorf("unsupported method: %s", method)
	}
}
