package detector

import (
	"testing"

	"github.com/yourusername/identity-security-scanner/pkg/models"
)

func TestDetectAlgorithmConfusion(t *testing.T) {
	tests := []struct {
		name      string
		config    *models.JWTConfig
		wantIssue bool
	}{
		{
			name: "none algorithm",
			config: &models.JWTConfig{
				Algorithm: "none",
			},
			wantIssue: true,
		},
		{
			name: "HS256 algorithm",
			config: &models.JWTConfig{
				Algorithm: "HS256",
			},
			wantIssue: false,
		},
		{
			name: "RS256 algorithm",
			config: &models.JWTConfig{
				Algorithm: "RS256",
			},
			wantIssue: false,
		},
	}

	detector := NewJWTDetector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detector.Detect(tt.config)
			hasAlgConfusion := false
			for _, issue := range issues {
				if issue.RuleID == "jwt-algorithm-none" || issue.RuleID == "jwt-algorithm-confusion" {
					hasAlgConfusion = true
					break
				}
			}

			if hasAlgConfusion != tt.wantIssue {
				t.Errorf("DetectAlgorithmConfusion() found issue = %v, want %v", hasAlgConfusion, tt.wantIssue)
			}
		})
	}
}

func TestDetectWeakSigningKey(t *testing.T) {
	tests := []struct {
		name      string
		config    *models.JWTConfig
		wantIssue bool
	}{
		{
			name: "weak HMAC key",
			config: &models.JWTConfig{
				Algorithm:  "HS256",
				SigningKey: "short",
			},
			wantIssue: true,
		},
		{
			name: "strong HMAC key",
			config: &models.JWTConfig{
				Algorithm:  "HS256",
				SigningKey: "this_is_a_strong_secret_key_with_sufficient_length",
			},
			wantIssue: false,
		},
		{
			name: "RSA algorithm (not applicable)",
			config: &models.JWTConfig{
				Algorithm:  "RS256",
				SigningKey: "short",
			},
			wantIssue: false,
		},
	}

	detector := NewJWTDetector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detector.Detect(tt.config)
			hasWeakKey := false
			for _, issue := range issues {
				if issue.RuleID == "jwt-weak-signing-key" {
					hasWeakKey = true
					break
				}
			}

			if hasWeakKey != tt.wantIssue {
				t.Errorf("DetectWeakSigningKey() found issue = %v, want %v", hasWeakKey, tt.wantIssue)
			}
		})
	}
}

func TestDetectMissingExpiration(t *testing.T) {
	tests := []struct {
		name      string
		config    *models.JWTConfig
		wantIssue bool
	}{
		{
			name: "missing expiration",
			config: &models.JWTConfig{
				ExpirationTime: 0,
			},
			wantIssue: true,
		},
		{
			name: "valid expiration",
			config: &models.JWTConfig{
				ExpirationTime: 900,
			},
			wantIssue: false,
		},
	}

	detector := NewJWTDetector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detector.Detect(tt.config)
			hasMissingExp := false
			for _, issue := range issues {
				if issue.RuleID == "jwt-missing-expiration" {
					hasMissingExp = true
					break
				}
			}

			if hasMissingExp != tt.wantIssue {
				t.Errorf("DetectMissingExpiration() found issue = %v, want %v", hasMissingExp, tt.wantIssue)
			}
		})
	}
}

func TestDetectExcessiveLifetime(t *testing.T) {
	tests := []struct {
		name      string
		config    *models.JWTConfig
		wantIssue bool
	}{
		{
			name: "excessive lifetime (2 hours)",
			config: &models.JWTConfig{
				ExpirationTime: 7200,
			},
			wantIssue: true,
		},
		{
			name: "acceptable lifetime (15 minutes)",
			config: &models.JWTConfig{
				ExpirationTime: 900,
			},
			wantIssue: false,
		},
		{
			name: "boundary (1 hour)",
			config: &models.JWTConfig{
				ExpirationTime: 3600,
			},
			wantIssue: false,
		},
	}

	detector := NewJWTDetector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detector.Detect(tt.config)
			hasExcessiveLifetime := false
			for _, issue := range issues {
				if issue.RuleID == "jwt-excessive-lifetime" {
					hasExcessiveLifetime = true
					break
				}
			}

			if hasExcessiveLifetime != tt.wantIssue {
				t.Errorf("DetectExcessiveLifetime() found issue = %v, want %v", hasExcessiveLifetime, tt.wantIssue)
			}
		})
	}
}
