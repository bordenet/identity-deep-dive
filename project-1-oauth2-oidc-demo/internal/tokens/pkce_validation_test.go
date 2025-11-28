package tokens

import (
	"testing"
)

// TestPKCEValidation tests the critical PKCE validation logic.
//
//nolint:funlen // Test function with comprehensive test cases
func TestPKCEValidation(t *testing.T) {
	tests := []struct {
		name          string
		verifier      string
		challenge     string
		method        string
		shouldSucceed bool
	}{
		{
			name:          "Valid S256 challenge",
			verifier:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:        "S256",
			shouldSucceed: true,
		},
		{
			name:          "Valid plain challenge",
			verifier:      "test-verifier-123456789012345678901234567890123",
			challenge:     "test-verifier-123456789012345678901234567890123",
			method:        "plain",
			shouldSucceed: true,
		},
		{
			name:          "Invalid S256 challenge - wrong hash",
			verifier:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge:     "wrong-challenge",
			method:        "S256",
			shouldSucceed: false,
		},
		{
			name:          "Invalid plain challenge - mismatch",
			verifier:      "test-verifier-123456789012345678901234567890123",
			challenge:     "different-challenge-1234567890123456789012345",
			method:        "plain",
			shouldSucceed: false,
		},
		{
			name:          "Empty verifier",
			verifier:      "",
			challenge:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:        "S256",
			shouldSucceed: false,
		},
		{
			name:          "Empty challenge - allowed for confidential clients",
			verifier:      "",
			challenge:     "",
			method:        "S256",
			shouldSucceed: true, // ValidatePKCE returns nil when challenge is empty.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.verifier, tt.challenge, tt.method)

			if tt.shouldSucceed && err != nil {
				t.Errorf("Expected validation to succeed, but got error: %v", err)
			}

			if !tt.shouldSucceed && err == nil {
				t.Errorf("Expected validation to fail, but it succeeded")
			}
		})
	}
}

// TestPKCEChallengeGeneration verifies that challenge generation is deterministic.
func TestPKCEChallengeGeneration(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	challenge, err := GenerateCodeChallenge(verifier, PKCEMethodS256)
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	if challenge != expectedChallenge {
		t.Errorf("Challenge generation mismatch.\nExpected: %s\nGot: %s", expectedChallenge, challenge)
	}

	// Verify it's deterministic.
	challenge2, err := GenerateCodeChallenge(verifier, PKCEMethodS256)
	if err != nil {
		t.Fatalf("Failed to generate second challenge: %v", err)
	}
	if challenge != challenge2 {
		t.Error("Challenge generation is not deterministic")
	}
}
