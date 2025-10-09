package detector

import (
	"testing"

	"github.com/yourusername/identity-security-scanner/pkg/models"
)

func TestDetectWeakClientSecret(t *testing.T) {
	tests := []struct {
		name      string
		config    *models.OAuth2Config
		wantIssue bool
	}{
		{
			name: "weak secret",
			config: &models.OAuth2Config{
				ClientSecret: "weak",
			},
			wantIssue: true,
		},
		{
			name: "strong secret",
			config: &models.OAuth2Config{
				ClientSecret: "strong_secret_with_32_characters_minimum_length",
			},
			wantIssue: false,
		},
		{
			name: "empty secret",
			config: &models.OAuth2Config{
				ClientSecret: "",
			},
			wantIssue: true,
		},
	}

	detector := NewOAuth2Detector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detector.Detect(tt.config)
			hasWeakSecret := false
			for _, issue := range issues {
				if issue.RuleID == "oauth2-weak-client-secret" {
					hasWeakSecret = true
					break
				}
			}

			if hasWeakSecret != tt.wantIssue {
				t.Errorf("DetectWeakClientSecret() found issue = %v, want %v", hasWeakSecret, tt.wantIssue)
			}
		})
	}
}

func TestDetectInsecureRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		config      *models.OAuth2Config
		wantIssue   bool
		description string
	}{
		{
			name: "http redirect",
			config: &models.OAuth2Config{
				RedirectURIs: []string{"http://example.com/callback"},
			},
			wantIssue:   true,
			description: "HTTP URIs are insecure",
		},
		{
			name: "https redirect",
			config: &models.OAuth2Config{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			wantIssue:   false,
			description: "HTTPS URIs are secure",
		},
		{
			name: "wildcard redirect",
			config: &models.OAuth2Config{
				RedirectURIs: []string{"https://*.example.com/callback"},
			},
			wantIssue:   true,
			description: "Wildcards are insecure",
		},
		{
			name: "localhost http allowed",
			config: &models.OAuth2Config{
				RedirectURIs: []string{"http://localhost:3000/callback"},
			},
			wantIssue:   false,
			description: "Localhost HTTP is allowed for development",
		},
	}

	detector := NewOAuth2Detector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detector.Detect(tt.config)
			hasInsecureRedirect := false
			for _, issue := range issues {
				if issue.RuleID == "oauth2-insecure-redirect-uri" {
					hasInsecureRedirect = true
					break
				}
			}

			if hasInsecureRedirect != tt.wantIssue {
				t.Errorf("DetectInsecureRedirectURI() found issue = %v, want %v (%s)", hasInsecureRedirect, tt.wantIssue, tt.description)
			}
		})
	}
}

func TestDetectMissingPKCE(t *testing.T) {
	tests := []struct {
		name      string
		config    *models.OAuth2Config
		wantIssue bool
	}{
		{
			name: "PKCE required for public client",
			config: &models.OAuth2Config{
				ClientType:    "public",
				PKCERequired:  false,
				ResponseTypes: []string{"code"},
			},
			wantIssue: true,
		},
		{
			name: "PKCE enabled for public client",
			config: &models.OAuth2Config{
				ClientType:    "public",
				PKCERequired:  true,
				ResponseTypes: []string{"code"},
			},
			wantIssue: false,
		},
		{
			name: "confidential client without PKCE ok",
			config: &models.OAuth2Config{
				ClientType:    "confidential",
				PKCERequired:  false,
				ResponseTypes: []string{"code"},
			},
			wantIssue: false,
		},
	}

	detector := NewOAuth2Detector()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detector.Detect(tt.config)
			hasMissingPKCE := false
			for _, issue := range issues {
				if issue.RuleID == "oauth2-pkce-not-required" {
					hasMissingPKCE = true
					break
				}
			}

			if hasMissingPKCE != tt.wantIssue {
				t.Errorf("DetectMissingPKCE() found issue = %v, want %v", hasMissingPKCE, tt.wantIssue)
			}
		})
	}
}
