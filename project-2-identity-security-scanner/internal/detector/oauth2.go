// Package detector provides vulnerability detectors for OAuth2 configurations.
package detector

import (
	"fmt"
	"strings"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/internal/parser"
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
)

// WeakClientSecretDetector checks for weak OAuth2 client secrets.
type WeakClientSecretDetector struct {
	MinLength int
}

// NewWeakClientSecretDetector creates a new weak client secret detector.
func NewWeakClientSecretDetector() *WeakClientSecretDetector {
	return &WeakClientSecretDetector{MinLength: 32}
}

// Name returns the detector name.
func (d *WeakClientSecretDetector) Name() string {
	return "WeakClientSecret"
}

// Detect finds weak client secret vulnerabilities.
func (d *WeakClientSecretDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	// Search for client_secret fields in various common paths.
	searchPaths := []string{
		"$.oauth2.providers[*].client_secret",
		"$.oauth2.client_secret",
		"$.client_secret",
		"$.providers[*].client_secret",
		"$.auth.client_secret",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if secret, ok := node.Value.(string); ok {
				// Skip references to secret managers.
				if strings.HasPrefix(secret, "${") || strings.HasPrefix(secret, "{{") {
					continue
				}

				if len(secret) < d.MinLength {
					findings = append(findings, models.Finding{
						RuleID:      "OAUTH2-001",
						Title:       "Weak Client Secret",
						Description: fmt.Sprintf("The client secret is only %d characters long.", len(secret)),
						Severity:    models.SeverityCritical,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryOAuth2,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "Attackers can brute force short secrets, gaining unauthorized access to protected resources. This allows impersonation of the legitimate client application.",
						Remediation: []string{
							fmt.Sprintf("Generate a cryptographically random secret with at least %d characters", d.MinLength),
							"Use a secure random generator: openssl rand -base64 32",
							"Store secrets in a secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)",
							"Use environment variables or secret references instead of hardcoded values",
						},
						References: []string{
							"RFC 6749 Section 2.3.1 (Client Password)",
							"OWASP ASVS v4.0 Section 2.6.3",
							"CWE-521: Weak Password Requirements",
						},
						CWE:      "CWE-521",
						RawValue: models.RedactSecret(secret),
					})
				}
			}
		}
	}

	return findings
}

// InsecureRedirectURIDetector checks for insecure redirect URIs.
type InsecureRedirectURIDetector struct{}

// NewInsecureRedirectURIDetector creates a new insecure redirect URI detector.
func NewInsecureRedirectURIDetector() *InsecureRedirectURIDetector {
	return &InsecureRedirectURIDetector{}
}

// Name returns the detector name.
func (d *InsecureRedirectURIDetector) Name() string {
	return "InsecureRedirectURI"
}

// Detect finds insecure redirect URI vulnerabilities.
//
//nolint:funlen // Comprehensive OAuth2 redirect URI validation
func (d *InsecureRedirectURIDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	searchPaths := []string{
		"$.oauth2.providers[*].redirect_uris[*]",
		"$.oauth2.redirect_uris[*]",
		"$.redirect_uris[*]",
		"$.providers[*].redirect_uris[*]",
		"$.auth.redirect_uri",
		"$.oauth2.redirect_uri",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if uri, ok := node.Value.(string); ok {
				// Check for HTTP (non-localhost).
				if strings.HasPrefix(uri, "http://") && !strings.Contains(uri, "localhost") && !strings.Contains(uri, "127.0.0.1") {
					findings = append(findings, models.Finding{
						RuleID:      "OAUTH2-002",
						Title:       "Insecure Redirect URI (HTTP)",
						Description: fmt.Sprintf("HTTP redirect URI detected: %s", uri),
						Severity:    models.SeverityCritical,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryOAuth2,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "HTTP allows man-in-the-middle attacks to intercept authorization codes, leading to account takeover. Attackers on the network can steal tokens and impersonate users.",
						Remediation: []string{
							"Use HTTPS for all redirect URIs in production",
							"HTTP localhost is acceptable for development only",
							fmt.Sprintf("Update to: %s", strings.Replace(uri, "http://", "https://", 1)),
							"Ensure valid TLS certificates are configured",
						},
						References: []string{
							"RFC 6749 Section 3.1.2.1",
							"OAuth 2.0 Security Best Current Practice",
							"CWE-319: Cleartext Transmission of Sensitive Information",
						},
						CWE:      "CWE-319",
						RawValue: uri,
					})
				}

				// Check for wildcard.
				if strings.Contains(uri, "*") {
					findings = append(findings, models.Finding{
						RuleID:      "OAUTH2-002",
						Title:       "Wildcard Redirect URI",
						Description: fmt.Sprintf("Wildcard redirect URI detected: %s", uri),
						Severity:    models.SeverityCritical,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryOAuth2,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "Wildcard redirect URIs enable open redirect attacks. Attackers can redirect users to malicious sites after authentication, stealing credentials or tokens.",
						Remediation: []string{
							"Remove wildcard from redirect URI",
							"Register exact redirect URIs for each client",
							"If multiple URIs needed, register them individually",
							"Never use wildcards in production configurations",
						},
						References: []string{
							"RFC 6749 Section 3.1.2",
							"OAuth 2.0 Security Best Current Practice Section 4.1.3",
							"CWE-601: URL Redirection to Untrusted Site",
						},
						CWE:      "CWE-601",
						RawValue: uri,
					})
				}
			}
		}
	}

	return findings
}

// MissingPKCEDetector checks for missing PKCE enforcement.
type MissingPKCEDetector struct{}

// NewMissingPKCEDetector creates a new missing PKCE detector.
func NewMissingPKCEDetector() *MissingPKCEDetector {
	return &MissingPKCEDetector{}
}

// Name returns the detector name.
func (d *MissingPKCEDetector) Name() string {
	return "MissingPKCE"
}

// Detect finds missing PKCE vulnerabilities.
func (d *MissingPKCEDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	// Check for public clients without PKCE.
	searchPaths := []string{
		"$.oauth2.providers[*]",
		"$.providers[*]",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			provider, ok := node.Value.(map[string]interface{})
			if !ok {
				continue
			}
			// Check if it's a public client (mobile, SPA).
			clientType, hasType := provider["client_type"]
			pkceRequired, hasPKCE := provider["pkce_required"]
			pkceEnforced, hasEnforced := provider["pkce_enforced"]
			requirePKCE, hasRequire := provider["require_pkce"]

			isPublicClient := hasType && (clientType == "public" || clientType == "mobile" || clientType == "spa")
			pkceEnabled := (hasPKCE && pkceRequired == true) ||
				(hasEnforced && pkceEnforced == true) ||
				(hasRequire && requirePKCE == true)

			if isPublicClient && !pkceEnabled {
				findings = append(findings, models.Finding{
					RuleID:      "OAUTH2-003",
					Title:       "Missing PKCE Enforcement",
					Description: fmt.Sprintf("Public client (type: %v) does not enforce PKCE", clientType),
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    models.CategoryOAuth2,
					File:        tree.Metadata.Filename,
					Line:        node.Line,
					Column:      node.Column,
					Risk:        "Without PKCE, public clients (mobile apps, SPAs) are vulnerable to authorization code interception attacks. Attackers can steal authorization codes and exchange them for access tokens.",
					Remediation: []string{
						"Enable PKCE for all public clients: pkce_required: true",
						"PKCE is mandatory for mobile and single-page applications",
						"Use code_challenge_method: S256 (SHA-256)",
						"Reject authorization requests without PKCE parameters",
					},
					References: []string{
						"RFC 7636 - Proof Key for Code Exchange (PKCE)",
						"OAuth 2.0 for Native Apps (RFC 8252)",
						"OAuth 2.0 Security Best Current Practice Section 2.1.1",
					},
					CWE: "CWE-319",
				})
			}
		}
	}

	return findings
}

// OverlyPermissiveScopesDetector checks for overly broad scopes.
type OverlyPermissiveScopesDetector struct{}

// NewOverlyPermissiveScopesDetector creates a new overly permissive scopes detector.
func NewOverlyPermissiveScopesDetector() *OverlyPermissiveScopesDetector {
	return &OverlyPermissiveScopesDetector{}
}

// Name returns the detector name.
func (d *OverlyPermissiveScopesDetector) Name() string {
	return "OverlyPermissiveScopes"
}

// Detect finds overly permissive scope vulnerabilities.
func (d *OverlyPermissiveScopesDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	dangerousScopes := map[string]string{
		"admin":      "Full administrative access",
		"*":          "Wildcard scope (all permissions)",
		"root":       "Root-level access",
		"superuser":  "Super user privileges",
		"write:all":  "Write access to all resources",
		"delete:all": "Delete access to all resources",
	}

	searchPaths := []string{
		"$.oauth2.providers[*].scopes[*]",
		"$.oauth2.default_scopes[*]",
		"$.scopes[*]",
		"$.default_scopes[*]",
		"$.providers[*].scopes[*]",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if scope, ok := node.Value.(string); ok {
				if description, isDangerous := dangerousScopes[scope]; isDangerous {
					findings = append(findings, models.Finding{
						RuleID:      "OAUTH2-004",
						Title:       "Overly Permissive Scope",
						Description: fmt.Sprintf("Dangerous scope detected: %s (%s)", scope, description),
						Severity:    models.SeverityHigh,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryOAuth2,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "Overly permissive scopes violate the principle of least privilege. If tokens are compromised, attackers gain excessive access to resources beyond what the application requires.",
						Remediation: []string{
							"Use specific, granular scopes instead of broad permissions",
							"Follow the principle of least privilege",
							"Define scopes based on actual resource access needs",
							"Example: Replace 'admin' with 'read:users write:users'",
							"Review and minimize default scopes",
						},
						References: []string{
							"RFC 6749 Section 3.3 (Access Token Scope)",
							"OAuth 2.0 Security Best Current Practice Section 4.4.1",
							"OWASP ASVS v4.0 Section 4.1.3",
						},
						RawValue: scope,
					})
				}
			}
		}
	}

	return findings
}

// DeprecatedFlowsDetector checks for deprecated OAuth2 flows.
type DeprecatedFlowsDetector struct{}

// NewDeprecatedFlowsDetector creates a new deprecated flows detector.
func NewDeprecatedFlowsDetector() *DeprecatedFlowsDetector {
	return &DeprecatedFlowsDetector{}
}

// Name returns the detector name.
func (d *DeprecatedFlowsDetector) Name() string {
	return "DeprecatedFlows"
}

// Detect finds deprecated flow vulnerabilities.
//
//nolint:funlen // Comprehensive OAuth2 deprecated flow detection
func (d *DeprecatedFlowsDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	deprecatedFlows := map[string]struct {
		name     string
		severity models.Severity
		reason   string
	}{
		"implicit": {
			name:     "Implicit Flow",
			severity: models.SeverityHigh,
			reason:   "Exposes tokens in browser history and is vulnerable to token leakage",
		},
		"password": {
			name:     "Resource Owner Password Credentials",
			severity: models.SeverityMedium,
			reason:   "Requires users to share passwords with third-party applications",
		},
		"resource_owner_password_credentials": {
			name:     "Resource Owner Password Credentials",
			severity: models.SeverityMedium,
			reason:   "Requires users to share passwords with third-party applications",
		},
	}

	searchPaths := []string{
		"$.oauth2.providers[*].grant_types[*]",
		"$.oauth2.grant_types[*]",
		"$.grant_types[*]",
		"$.providers[*].grant_types[*]",
		"$.allowed_grant_types[*]",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if grantType, ok := node.Value.(string); ok {
				if deprecated, isDeprecated := deprecatedFlows[grantType]; isDeprecated {
					findings = append(findings, models.Finding{
						RuleID:      "OAUTH2-005",
						Title:       fmt.Sprintf("Deprecated Flow: %s", deprecated.name),
						Description: fmt.Sprintf("Deprecated grant type '%s' is enabled", grantType),
						Severity:    deprecated.severity,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryOAuth2,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        fmt.Sprintf("The %s flow is deprecated due to security concerns: %s. Modern applications should use Authorization Code flow with PKCE.", deprecated.name, deprecated.reason),
						Remediation: []string{
							fmt.Sprintf("Remove '%s' from allowed grant types", grantType),
							"Use Authorization Code flow with PKCE for public clients",
							"Use Client Credentials flow for service-to-service authentication",
							"Migrate existing integrations to secure flows",
						},
						References: []string{
							"OAuth 2.0 Security Best Current Practice",
							"OAuth 2.0 for Browser-Based Apps",
							"RFC 6749 (original specification, now superseded for these flows)",
						},
						RawValue: grantType,
					})
				}
			}
		}
	}

	return findings
}

// MissingStateParameterDetector checks for missing state parameter requirement.
type MissingStateParameterDetector struct{}

// NewMissingStateParameterDetector creates a new missing state parameter detector.
func NewMissingStateParameterDetector() *MissingStateParameterDetector {
	return &MissingStateParameterDetector{}
}

// Name returns the detector name.
func (d *MissingStateParameterDetector) Name() string {
	return "MissingStateParameter"
}

// Detect finds missing state parameter vulnerabilities.
//
//nolint:funlen // Comprehensive OAuth2 state parameter validation
func (d *MissingStateParameterDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	searchPaths := []string{
		"$.oauth2.providers[*]",
		"$.oauth2",
		"$.providers[*]",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			config, ok := node.Value.(map[string]interface{})
			if !ok {
				continue
			}
			requireState, hasRequire := config["require_state"]
			stateRequired, hasState := config["state_required"]
			enforceState, hasEnforce := config["enforce_state"]

			stateEnabled := (hasRequire && requireState == true) ||
				(hasState && stateRequired == true) ||
				(hasEnforce && enforceState == true)

			// If any state config exists and it's false, that's a finding.
			if (hasRequire && requireState == false) ||
				(hasState && stateRequired == false) ||
				(hasEnforce && enforceState == false) {
				findings = append(findings, models.Finding{
					RuleID:      "OAUTH2-006",
					Title:       "State Parameter Not Required",
					Description: "OAuth2 configuration does not require state parameter in authorization requests",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    models.CategoryOAuth2,
					File:        tree.Metadata.Filename,
					Line:        node.Line,
					Column:      node.Column,
					Risk:        "Missing state parameter enables CSRF attacks on the OAuth2 flow. Attackers can trick users into authorizing malicious applications or linking accounts without consent.",
					Remediation: []string{
						"Enable state parameter requirement: require_state: true",
						"Generate cryptographically random state values",
						"Validate state parameter on callback",
						"Reject authorization requests without state parameter",
					},
					References: []string{
						"RFC 6749 Section 10.12 (CSRF Protection)",
						"OAuth 2.0 Security Best Current Practice Section 4.7",
						"CWE-352: Cross-Site Request Forgery (CSRF)",
					},
					CWE: "CWE-352",
				})
			} else if !stateEnabled && (hasRequire || hasState || hasEnforce) {
				// State config exists but is not explicitly enabled - potential misconfiguration.
				findings = append(findings, models.Finding{
					RuleID:      "OAUTH2-006",
					Title:       "State Parameter Configuration Unclear",
					Description: "OAuth2 state parameter requirement is not explicitly configured",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceMedium,
					Category:    models.CategoryOAuth2,
					File:        tree.Metadata.Filename,
					Line:        node.Line,
					Column:      node.Column,
					Risk:        "Unclear state parameter configuration may lead to CSRF vulnerabilities if the default behavior doesn't enforce state validation.",
					Remediation: []string{
						"Explicitly enable state parameter: require_state: true",
						"Document state parameter requirements",
						"Ensure validation is enforced in authorization flow",
					},
					References: []string{
						"RFC 6749 Section 10.12",
						"OAuth 2.0 Security Best Current Practice",
					},
					CWE: "CWE-352",
				})
			}
		}
	}

	return findings
}
