package scanner

import (
	"context"

	"github.com/bordenet/identity-deep-dive/project-3-runtime-security-scanner/pkg/models"
)

// Scanner orchestrates the different attack modules.

type Scanner struct {
	issuer string
	doc    *models.OIDCDiscoveryDocument
}

// NewScanner creates a new scanner.
func NewScanner(issuer string, doc *models.OIDCDiscoveryDocument) *Scanner {
	return &Scanner{
		issuer: issuer,
		doc:    doc,
	}
}

// Run runs all the attack modules.
func (s *Scanner) Run(ctx context.Context) []string {
	var results []string

	// Run CSRF check
	csrfResult := s.checkCSRF(ctx)
	results = append(results, csrfResult)

	// Run Authorization Code Interception check
	authCodeResult := s.checkAuthCodeInterception(ctx)
	results = append(results, authCodeResult)

	// Run Token Replay check
	tokenReplayResult := s.checkTokenReplay(ctx)
	results = append(results, tokenReplayResult)

	return results
}

func (s *Scanner) checkAuthCodeInterception(ctx context.Context) string {
	// Implementation of the Authorization Code Interception check will go here.
	return "Authorization Code Interception check: not implemented"
}

func (s *Scanner) checkTokenReplay(ctx context.Context) string {
	// Implementation of the Token Replay check will go here.
	return "Token Replay check: not implemented"
}
