// Package rules provides vulnerability detection rule registry.
package rules

import (
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/internal/detector"
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
)

// Registry holds all security rules.
type Registry struct {
	rules []models.Rule
}

// NewRegistry creates a new rule registry with all built-in rules.
func NewRegistry() *Registry {
	r := &Registry{
		rules: []models.Rule{},
	}
	r.loadBuiltInRules()
	return r
}

// loadBuiltInRules loads all built-in security rules.
//
//nolint:funlen,dupl // Comprehensive built-in rule definitions
func (r *Registry) loadBuiltInRules() {
	// OAuth2 rules.
	r.rules = append(r.rules, models.Rule{
		ID:          "OAUTH2-001",
		Name:        "Weak Client Secret",
		Description: "Detects OAuth2 client secrets that are too short",
		Severity:    models.SeverityCritical,
		Category:    models.CategoryOAuth2,
		Detector:    detector.NewWeakClientSecretDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "OAUTH2-002",
		Name:        "Insecure Redirect URI",
		Description: "Detects HTTP redirect URIs and wildcard patterns",
		Severity:    models.SeverityCritical,
		Category:    models.CategoryOAuth2,
		Detector:    detector.NewInsecureRedirectURIDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "OAUTH2-003",
		Name:        "Missing PKCE Enforcement",
		Description: "Detects public clients without PKCE requirement",
		Severity:    models.SeverityHigh,
		Category:    models.CategoryOAuth2,
		Detector:    detector.NewMissingPKCEDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "OAUTH2-004",
		Name:        "Overly Permissive Scopes",
		Description: "Detects dangerous OAuth2 scopes like admin or wildcard",
		Severity:    models.SeverityHigh,
		Category:    models.CategoryOAuth2,
		Detector:    detector.NewOverlyPermissiveScopesDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "OAUTH2-005",
		Name:        "Deprecated Flows",
		Description: "Detects deprecated OAuth2 flows (implicit, password)",
		Severity:    models.SeverityHigh,
		Category:    models.CategoryOAuth2,
		Detector:    detector.NewDeprecatedFlowsDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "OAUTH2-006",
		Name:        "Missing State Parameter",
		Description: "Detects missing state parameter requirement (CSRF risk)",
		Severity:    models.SeverityHigh,
		Category:    models.CategoryOAuth2,
		Detector:    detector.NewMissingStateParameterDetector(),
		Enabled:     true,
	})

	// JWT rules.
	r.rules = append(r.rules, models.Rule{
		ID:          "JWT-001",
		Name:        "Algorithm Confusion",
		Description: "Detects JWT 'none' algorithm acceptance",
		Severity:    models.SeverityCritical,
		Category:    models.CategoryJWT,
		Detector:    detector.NewAlgorithmConfusionDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "JWT-002",
		Name:        "Weak Signing Algorithm",
		Description: "Detects weak JWT signing secrets",
		Severity:    models.SeverityHigh,
		Category:    models.CategoryJWT,
		Detector:    detector.NewWeakSigningAlgorithmDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "JWT-003",
		Name:        "Missing Expiration",
		Description: "Detects missing JWT expiration validation",
		Severity:    models.SeverityHigh,
		Category:    models.CategoryJWT,
		Detector:    detector.NewMissingExpirationDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "JWT-004",
		Name:        "Excessive Token Lifetime",
		Description: "Detects overly long JWT token lifetimes",
		Severity:    models.SeverityMedium,
		Category:    models.CategoryJWT,
		Detector:    detector.NewExcessiveTokenLifetimeDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "JWT-005",
		Name:        "Missing Audience Validation",
		Description: "Detects missing JWT audience validation",
		Severity:    models.SeverityHigh,
		Category:    models.CategoryJWT,
		Detector:    detector.NewMissingAudienceValidationDetector(),
		Enabled:     true,
	})

	r.rules = append(r.rules, models.Rule{
		ID:          "JWT-006",
		Name:        "Hardcoded Secret",
		Description: "Detects hardcoded JWT secrets in configuration",
		Severity:    models.SeverityCritical,
		Category:    models.CategoryJWT,
		Detector:    detector.NewHardcodedSecretDetector(),
		Enabled:     true,
	})
}

// GetRules returns all enabled rules.
func (r *Registry) GetRules() []models.Rule {
	enabled := []models.Rule{}
	for _, rule := range r.rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}

// GetRuleByID returns a rule by its ID.
func (r *Registry) GetRuleByID(id string) *models.Rule {
	for _, rule := range r.rules {
		if rule.ID == id {
			return &rule
		}
	}
	return nil
}

// DisableRule disables a rule by ID.
func (r *Registry) DisableRule(id string) {
	for i := range r.rules {
		if r.rules[i].ID == id {
			r.rules[i].Enabled = false
			return
		}
	}
}

// OverrideSeverity changes the severity of a rule.
func (r *Registry) OverrideSeverity(id string, severity models.Severity) {
	for i := range r.rules {
		if r.rules[i].ID == id {
			r.rules[i].Severity = severity
			return
		}
	}
}

// ListRules returns a list of all rules with their metadata.
func (r *Registry) ListRules() []struct {
	ID          string
	Name        string
	Description string
	Severity    models.Severity
	Category    models.Category
	Enabled     bool
} {
	list := make([]struct {
		ID          string
		Name        string
		Description string
		Severity    models.Severity
		Category    models.Category
		Enabled     bool
	}, len(r.rules))

	for i, rule := range r.rules {
		list[i] = struct {
			ID          string
			Name        string
			Description string
			Severity    models.Severity
			Category    models.Category
			Enabled     bool
		}{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Severity:    rule.Severity,
			Category:    rule.Category,
			Enabled:     rule.Enabled,
		}
	}

	return list
}
