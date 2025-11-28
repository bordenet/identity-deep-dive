package tokens

import (
	"strings"
	"testing"
)

func TestGenerateCodeChallenge(t *testing.T) {
	// Generate a valid verifier (43-128 chars)
	verifier := strings.Repeat("a", 43)

	tests := []struct {
		name    string
		method  PKCEMethod
		wantErr bool
	}{
		{
			name:    "S256 method",
			method:  PKCEMethodS256,
			wantErr: false,
		},
		{
			name:    "plain method",
			method:  PKCEMethodPlain,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, err := GenerateCodeChallenge(verifier, tt.method)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCodeChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && challenge == "" {
				t.Error("GenerateCodeChallenge() returned empty challenge")
			}

			// For S256, challenge should be 43 characters (base64url of SHA256)
			if tt.method == PKCEMethodS256 && len(challenge) != 43 {
				t.Errorf("S256 challenge length = %d, want 43", len(challenge))
			}

			// For plain, challenge should equal verifier.
			if tt.method == PKCEMethodPlain && challenge != verifier {
				t.Error("Plain challenge should equal verifier")
			}
		})
	}
}

//nolint:funlen // Test function with comprehensive test cases
func TestValidatePKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	s256Challenge, err := GenerateCodeChallenge(verifier, PKCEMethodS256)
	if err != nil {
		t.Fatalf("Failed to generate S256 challenge: %v", err)
	}
	plainChallenge, err := GenerateCodeChallenge(verifier, PKCEMethodPlain)
	if err != nil {
		t.Fatalf("Failed to generate plain challenge: %v", err)
	}

	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		wantErr             bool
		errContains         string
	}{
		{
			name:                "valid S256",
			codeVerifier:        verifier,
			codeChallenge:       s256Challenge,
			codeChallengeMethod: "S256",
			wantErr:             false,
		},
		{
			name:                "valid plain",
			codeVerifier:        verifier,
			codeChallenge:       plainChallenge,
			codeChallengeMethod: "plain",
			wantErr:             false,
		},
		{
			name:                "invalid verifier",
			codeVerifier:        "wrong",
			codeChallenge:       s256Challenge,
			codeChallengeMethod: "S256",
			wantErr:             true,
			errContains:         "43-128 characters",
		},
		{
			name:                "mismatched S256",
			codeVerifier:        strings.Repeat("b", 43),
			codeChallenge:       s256Challenge,
			codeChallengeMethod: "S256",
			wantErr:             true,
			errContains:         "does not match",
		},
		{
			name:                "no PKCE",
			codeVerifier:        "",
			codeChallenge:       "",
			codeChallengeMethod: "",
			wantErr:             false,
		},
		{
			name:                "missing verifier",
			codeVerifier:        "",
			codeChallenge:       s256Challenge,
			codeChallengeMethod: "S256",
			wantErr:             true,
			errContains:         "code_verifier required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePKCE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("ValidatePKCE() error = %v, should contain %v", err, tt.errContains)
			}
		})
	}
}
