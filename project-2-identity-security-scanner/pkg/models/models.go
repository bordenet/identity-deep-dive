// Package models provides data models for security scanning results.
package models

import "time"

// Severity represents the severity level of a security finding.
type Severity string

// Severity levels for security findings.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence represents how confident we are in the finding.
type Confidence string

// Confidence levels for security findings.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Category represents the type of security check.
type Category string

// Category types for security findings.
const (
	CategoryOAuth2 Category = "oauth2"
	CategoryOIDC   Category = "oidc"
	CategoryJWT    Category = "jwt"
	CategorySAML   Category = "saml"
)

// Finding represents a security issue discovered during scanning.
type Finding struct {
	RuleID      string     `json:"rule_id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Category    Category   `json:"category"`
	File        string     `json:"file"`
	Line        int        `json:"line"`
	Column      int        `json:"column"`
	Risk        string     `json:"risk"`
	Remediation []string   `json:"remediation"`
	References  []string   `json:"references"`
	CWE         string     `json:"cwe,omitempty"`
	RawValue    string     `json:"raw_value,omitempty"` // Redacted in output.
}

// ConfigTree represents a parsed configuration file.
type ConfigTree struct {
	Root     map[string]interface{}
	Metadata FileMetadata
}

// FileMetadata contains information about the source file.
type FileMetadata struct {
	Filename string
	Format   string // "yaml", "json", "toml", "env".
	LineMap  map[string]int
}

// ConfigNode represents a value with location information.
type ConfigNode struct {
	Path   string
	Value  interface{}
	Line   int
	Column int
}

// ScanResult represents the complete scan results.
type ScanResult struct {
	ScannerVersion string          `json:"scanner_version"`
	ScanTime       time.Time       `json:"scan_time"`
	Duration       time.Duration   `json:"duration"`
	FilesScanned   []string        `json:"files_scanned"`
	Summary        SeveritySummary `json:"summary"`
	Findings       []Finding       `json:"findings"`
}

// SeveritySummary provides a count of findings by severity.
type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Rule defines a security check.
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Category    Category
	Detector    Detector
	Remediation string
	References  []string
	CWE         string
	Enabled     bool
}

// Detector interface for vulnerability detection.
type Detector interface {
	Detect(tree *ConfigTree) []Finding
	Name() string
}

// ScanConfig holds scanner configuration.
type ScanConfig struct {
	Include          []string
	Exclude          []string
	FailOn           []Severity
	Format           string
	SeverityOverride map[string]Severity
	DisabledRules    []string
	CustomRulesDir   string
}

// ExitCode returns the appropriate exit code based on findings.
func (sr *ScanResult) ExitCode(failOn []Severity) int {
	if sr.Summary.Total == 0 {
		return 0
	}

	for _, severity := range failOn {
		switch severity {
		case SeverityCritical:
			if sr.Summary.Critical > 0 {
				return 1
			}
		case SeverityHigh:
			if sr.Summary.High > 0 {
				return 1
			}
		case SeverityMedium:
			if sr.Summary.Medium > 0 {
				return 2
			}
		case SeverityLow:
			if sr.Summary.Low > 0 {
				return 2
			}
		}
	}

	return 0
}

// RedactSecret redacts sensitive values for display.
func RedactSecret(secret string) string {
	if secret == "" {
		return "[EMPTY]"
	}
	if len(secret) <= 4 {
		return "[REDACTED]"
	}
	// Show first 2 and last 2 characters only.
	return secret[:2] + "..." + secret[len(secret)-2:]
}

// CalculateSummary generates severity summary from findings.
func CalculateSummary(findings []Finding) SeveritySummary {
	summary := SeveritySummary{}
	for i := range findings {
		switch findings[i].Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		case SeverityInfo:
			summary.Info++
		}
	}
	summary.Total = len(findings)
	return summary
}
