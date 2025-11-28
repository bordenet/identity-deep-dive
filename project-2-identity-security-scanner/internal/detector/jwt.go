// Package detector provides vulnerability detectors for JWT configurations.
package detector

import (
	"fmt"
	"log"
	"strings"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/internal/parser"
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
)

// AlgorithmConfusionDetector checks for "none" algorithm acceptance.
type AlgorithmConfusionDetector struct{}

// NewAlgorithmConfusionDetector creates a new algorithm confusion detector.
func NewAlgorithmConfusionDetector() *AlgorithmConfusionDetector {
	return &AlgorithmConfusionDetector{}
}

// Name returns the detector name.
func (d *AlgorithmConfusionDetector) Name() string {
	return "AlgorithmConfusion"
}

// Detect finds algorithm confusion vulnerabilities.
func (d *AlgorithmConfusionDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	searchPaths := []string{
		"$.jwt.algorithm",
		"$.jwt.allowed_algorithms[*]",
		"$.jwt.algorithms[*]",
		"$.token.algorithm",
		"$.token.allowed_algorithms[*]",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if alg, ok := node.Value.(string); ok {
				if strings.EqualFold(alg, "none") {
					findings = append(findings, models.Finding{
						RuleID:      "JWT-001",
						Title:       "Algorithm Confusion Attack - 'none' Algorithm",
						Description: "JWT configuration accepts 'none' algorithm, allowing unsigned tokens",
						Severity:    models.SeverityCritical,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryJWT,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "The 'none' algorithm allows JWT tokens without any signature. Attackers can forge arbitrary tokens by setting alg: 'none' in the header, completely bypassing authentication and authorization checks.",
						Remediation: []string{
							"Remove 'none' from allowed algorithms list",
							"Use strong signing algorithms: RS256, ES256, or HS256 with strong secrets",
							"Explicitly validate algorithm in token verification",
							"Reject tokens with 'none' algorithm in production",
						},
						References: []string{
							"RFC 7519 Section 6 (Unsecured JWTs)",
							"Critical vulnerabilities in JSON Web Token libraries",
							"CWE-347: Improper Verification of Cryptographic Signature",
						},
						CWE:      "CWE-347",
						RawValue: alg,
					})
				}
			}
		}
	}

	return findings
}

// WeakSigningAlgorithmDetector checks for weak JWT signing algorithms.
type WeakSigningAlgorithmDetector struct{}

// NewWeakSigningAlgorithmDetector creates a new weak signing algorithm detector.
func NewWeakSigningAlgorithmDetector() *WeakSigningAlgorithmDetector {
	return &WeakSigningAlgorithmDetector{}
}

// Name returns the detector name.
func (d *WeakSigningAlgorithmDetector) Name() string {
	return "WeakSigningAlgorithm"
}

// Detect finds weak signing algorithm vulnerabilities.
func (d *WeakSigningAlgorithmDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	// Check for HS256 with short secrets.
	searchPaths := []string{
		"$.jwt",
		"$.token",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if config, ok := node.Value.(map[string]interface{}); ok {
				algorithm, hasAlg := config["algorithm"]
				secret, hasSecret := config["secret"]

				if hasAlg && algorithm == "HS256" && hasSecret {
					if secretStr, ok := secret.(string); ok {
						// Skip secret references.
						if strings.HasPrefix(secretStr, "${") || strings.HasPrefix(secretStr, "{{") {
							continue
						}

						if len(secretStr) < 32 {
							findings = append(findings, models.Finding{
								RuleID:      "JWT-002",
								Title:       "Weak JWT Signing Secret",
								Description: fmt.Sprintf("HS256 algorithm used with short secret (%d bytes)", len(secretStr)),
								Severity:    models.SeverityHigh,
								Confidence:  models.ConfidenceHigh,
								Category:    models.CategoryJWT,
								File:        tree.Metadata.Filename,
								Line:        node.Line,
								Column:      node.Column,
								Risk:        "Short HMAC secrets are vulnerable to brute force attacks. Attackers can discover the secret and forge valid JWT tokens, bypassing all authentication checks.",
								Remediation: []string{
									"Use secrets with at least 256 bits (32 bytes) for HS256",
									"Generate secret: openssl rand -base64 32",
									"Consider using asymmetric algorithms (RS256, ES256) instead",
									"Store secrets in secret manager, never in configuration files",
								},
								References: []string{
									"RFC 7518 Section 3.2 (HMAC with SHA-2 Functions)",
									"OWASP ASVS v4.0 Section 2.6.3",
									"CWE-326: Inadequate Encryption Strength",
								},
								CWE:      "CWE-326",
								RawValue: models.RedactSecret(secretStr),
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// MissingExpirationDetector checks for missing expiration claim requirement.
type MissingExpirationDetector struct{}

// NewMissingExpirationDetector creates a new missing expiration detector.
func NewMissingExpirationDetector() *MissingExpirationDetector {
	return &MissingExpirationDetector{}
}

// Name returns the detector name.
func (d *MissingExpirationDetector) Name() string {
	return "MissingExpiration"
}

// Detect finds missing expiration vulnerabilities.
//
//nolint:dupl // Intentional pattern: each detector follows same structure but checks different config keys.
func (d *MissingExpirationDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	searchPaths := []string{
		"$.jwt",
		"$.token",
		"$.jwt.validation",
		"$.token.validation",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if config, ok := node.Value.(map[string]interface{}); ok {
				requireExp, hasRequire := config["require_exp"]
				validateExp, hasValidate := config["validate_expiration"]
				checkExp, hasCheck := config["check_expiration"]

				// If explicitly set to false, that's a finding.
				if (hasRequire && requireExp == false) ||
					(hasValidate && validateExp == false) ||
					(hasCheck && checkExp == false) {

					findings = append(findings, models.Finding{
						RuleID:      "JWT-003",
						Title:       "JWT Expiration Validation Disabled",
						Description: "JWT configuration does not require or validate expiration (exp) claim",
						Severity:    models.SeverityHigh,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryJWT,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "Without expiration validation, JWT tokens remain valid indefinitely. Stolen tokens can be used forever, even after user logout or password changes. This violates security best practices for session management.",
						Remediation: []string{
							"Enable expiration validation: require_exp: true",
							"Set appropriate token lifetimes (e.g., 15 minutes for access tokens)",
							"Implement token refresh mechanism for long-lived sessions",
							"Validate exp claim in all token verification code",
						},
						References: []string{
							"RFC 7519 Section 4.1.4 (exp Claim)",
							"OAuth 2.0 Security Best Current Practice",
							"OWASP JWT Cheat Sheet",
						},
					})
				}
			}
		}
	}

	return findings
}

// ExcessiveTokenLifetimeDetector checks for overly long JWT lifetimes.
type ExcessiveTokenLifetimeDetector struct{}

// NewExcessiveTokenLifetimeDetector creates a new excessive token lifetime detector.
func NewExcessiveTokenLifetimeDetector() *ExcessiveTokenLifetimeDetector {
	return &ExcessiveTokenLifetimeDetector{}
}

// Name returns the detector name.
func (d *ExcessiveTokenLifetimeDetector) Name() string {
	return "ExcessiveTokenLifetime"
}

// Detect finds excessive token lifetime vulnerabilities.
//
//nolint:dupl // Similar structure to MissingExpirationDetector but different validation logic
func (d *ExcessiveTokenLifetimeDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	searchPaths := []string{
		"$.jwt.expiration",
		"$.jwt.ttl",
		"$.jwt.expires_in",
		"$.token.expiration",
		"$.token.ttl",
		"$.access_token_ttl",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			var seconds int
			switch v := node.Value.(type) {
			case int:
				seconds = v
			case int64:
				seconds = int(v)
			case float64:
				seconds = int(v)
			case string:
				// Parse duration strings like "24h", "1d".
				seconds = parseDurationToSeconds(v)
			}

			if seconds > 3600 { // More than 1 hour.
				findings = append(findings, models.Finding{
					RuleID:      "JWT-004",
					Title:       "Excessive JWT Token Lifetime",
					Description: fmt.Sprintf("JWT token lifetime is %d seconds (%s), exceeding recommended 1 hour", seconds, formatDuration(seconds)),
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceHigh,
					Category:    models.CategoryJWT,
					File:        tree.Metadata.Filename,
					Line:        node.Line,
					Column:      node.Column,
					Risk:        "Long-lived access tokens increase the window of opportunity for attackers. If a token is stolen, it remains valid for an extended period. Short-lived tokens with refresh mechanisms are more secure.",
					Remediation: []string{
						"Reduce access token lifetime to 15-60 minutes",
						"Use refresh tokens for long-lived sessions",
						"Implement token refresh flow with secure refresh tokens",
						"Consider stateful tokens for sensitive operations",
					},
					References: []string{
						"OAuth 2.0 Security Best Current Practice Section 4.5",
						"RFC 6749 Section 1.5 (Refresh Tokens)",
						"OWASP JWT Cheat Sheet - Token Lifetime",
					},
					RawValue: fmt.Sprintf("%v", node.Value),
				})
			}
		}
	}

	return findings
}

// MissingAudienceValidationDetector checks for missing audience validation.
type MissingAudienceValidationDetector struct{}

// NewMissingAudienceValidationDetector creates a new missing audience validation detector.
func NewMissingAudienceValidationDetector() *MissingAudienceValidationDetector {
	return &MissingAudienceValidationDetector{}
}

// Name returns the detector name.
func (d *MissingAudienceValidationDetector) Name() string {
	return "MissingAudienceValidation"
}

// Detect finds missing audience validation vulnerabilities.
//
//nolint:dupl // Similar structure to ExcessiveTokenLifetimeDetector but different validation logic
func (d *MissingAudienceValidationDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	searchPaths := []string{
		"$.jwt",
		"$.token",
		"$.jwt.validation",
		"$.token.validation",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if config, ok := node.Value.(map[string]interface{}); ok {
				validateAud, hasValidate := config["validate_audience"]
				checkAud, hasCheck := config["check_audience"]
				verifyAud, hasVerify := config["verify_audience"]

				// If explicitly set to false, that's a finding.
				if (hasValidate && validateAud == false) ||
					(hasCheck && checkAud == false) ||
					(hasVerify && verifyAud == false) {

					findings = append(findings, models.Finding{
						RuleID:      "JWT-005",
						Title:       "JWT Audience Validation Disabled",
						Description: "JWT configuration does not validate audience (aud) claim",
						Severity:    models.SeverityHigh,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryJWT,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "Without audience validation, tokens intended for one service can be used for another. Attackers can reuse tokens across services, potentially escalating privileges or accessing unauthorized resources.",
						Remediation: []string{
							"Enable audience validation: validate_audience: true",
							"Specify expected audience in configuration",
							"Reject tokens with missing or incorrect aud claim",
							"Use unique audience identifiers for each service",
						},
						References: []string{
							"RFC 7519 Section 4.1.3 (aud Claim)",
							"JWT Best Current Practice Section 3.1",
							"OWASP JWT Cheat Sheet - Audience Validation",
						},
					})
				}
			}
		}
	}

	return findings
}

// HardcodedSecretDetector checks for hardcoded JWT secrets.
type HardcodedSecretDetector struct{}

// NewHardcodedSecretDetector creates a new hardcoded secret detector.
func NewHardcodedSecretDetector() *HardcodedSecretDetector {
	return &HardcodedSecretDetector{}
}

// Name returns the detector name.
func (d *HardcodedSecretDetector) Name() string {
	return "HardcodedSecret"
}

// Detect finds hardcoded secret vulnerabilities.
func (d *HardcodedSecretDetector) Detect(tree *models.ConfigTree) []models.Finding {
	findings := []models.Finding{}

	searchPaths := []string{
		"$.jwt.secret",
		"$.jwt.key",
		"$.jwt.signing_key",
		"$.token.secret",
		"$.token.key",
		"$.jwt_secret",
	}

	for _, path := range searchPaths {
		nodes := parser.SelectAll(tree, path)
		for _, node := range nodes {
			if secret, ok := node.Value.(string); ok {
				// Check if it's a hardcoded value (not a reference).
				if !strings.HasPrefix(secret, "${") && !strings.HasPrefix(secret, "{{") &&
					!strings.Contains(secret, "ENV") && !strings.Contains(secret, "SECRET") {

					findings = append(findings, models.Finding{
						RuleID:      "JWT-006",
						Title:       "Hardcoded JWT Secret",
						Description: "JWT secret is hardcoded in configuration file",
						Severity:    models.SeverityCritical,
						Confidence:  models.ConfidenceHigh,
						Category:    models.CategoryJWT,
						File:        tree.Metadata.Filename,
						Line:        node.Line,
						Column:      node.Column,
						Risk:        "Hardcoded secrets in configuration files are exposed in version control, logs, and backups. Anyone with repository access can forge JWT tokens. This is a critical security vulnerability.",
						Remediation: []string{
							"Move secret to environment variable: ${JWT_SECRET}",
							"Use secret manager: ${aws:secretsmanager:jwt-secret}",
							"Never commit secrets to version control",
							"Rotate secret immediately if already committed",
							"Use .gitignore to prevent future commits of secret files",
						},
						References: []string{
							"OWASP Top 10 A02:2021 - Cryptographic Failures",
							"CWE-798: Use of Hard-coded Credentials",
							"OWASP ASVS v4.0 Section 2.10.1",
						},
						CWE:      "CWE-798",
						RawValue: models.RedactSecret(secret),
					})
				}
			}
		}
	}

	return findings
}

// Helper functions.

func parseDurationToSeconds(duration string) int {
	duration = strings.TrimSpace(strings.ToLower(duration))

	// Try to parse as plain integer first (no unit means seconds).
	var value int
	if _, err := fmt.Sscanf(duration, "%d", &value); err == nil {
		// Check if there's more content after the number.
		var rest string
		n, scanErr := fmt.Sscanf(duration, "%d%s", &value, &rest)
		if scanErr == nil && n == 1 {
			// Just a number, treat as seconds.
			return value
		}
		// Has a unit, parse it below.
	}

	// Parse duration formats with units: 24h, 1d, 60m, 3600s.
	var unit string
	if _, err := fmt.Sscanf(duration, "%d%s", &value, &unit); err != nil {
		log.Printf("parseDurationToSeconds: failed to parse duration %q: %v", duration, err)
		return -1
	}

	switch unit {
	case "s", "sec", "second", "seconds":
		return value
	case "m", "min", "minute", "minutes":
		return value * 60
	case "h", "hr", "hour", "hours":
		return value * 3600
	case "d", "day", "days":
		return value * 86400
	case "w", "week", "weeks":
		return value * 604800
	default:
		// Unknown unit, treat as seconds.
		return value
	}
}

func formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%d seconds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%d minutes", seconds/60)
	}
	if seconds < 86400 {
		return fmt.Sprintf("%.1f hours", float64(seconds)/3600)
	}
	return fmt.Sprintf("%.1f days", float64(seconds)/86400)
}
