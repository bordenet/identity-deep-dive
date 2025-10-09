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
	// This check would attempt to intercept an authorization code and exchange it for tokens
	// In a real implementation, this would:
	// 1. Initiate an OAuth2 flow with PKCE
	// 2. Attempt to intercept the authorization code
	// 3. Try to exchange the code without providing the PKCE code_verifier
	// 4. If successful, the server is vulnerable (PKCE not enforced)

	// For now, return a placeholder indicating the check is not fully implemented
	// This is intentional - implementing a full authorization code interception test
	// requires a headless browser or HTTP client that can handle redirects and cookies
	return "Authorization Code Interception check: SKIPPED (requires full OAuth2 flow simulation)"
}

func (s *Scanner) checkTokenReplay(ctx context.Context) string {
	// This check would attempt to replay a token multiple times
	// In a real implementation, this would:
	// 1. Obtain a valid access token via OAuth2 flow
	// 2. Use the token to access a protected resource
	// 3. Attempt to use the same token again after revocation or expiration
	// 4. If successful, the server is vulnerable (token replay not prevented)

	// For now, return a placeholder indicating the check is not fully implemented
	// This requires obtaining valid tokens from the target server first
	return "Token Replay check: SKIPPED (requires valid token from target)"
}
