// Package scanner provides configuration file scanning and vulnerability detection.
package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/internal/parser"
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/internal/rules"
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
)

// Scanner performs security scanning on configuration files.
type Scanner struct {
	registry       *rules.Registry
	parserRegistry *parser.Registry
	config         *models.ScanConfig
}

// New creates a new scanner instance.
func New(config *models.ScanConfig) *Scanner {
	return &Scanner{
		registry:       rules.NewRegistry(),
		parserRegistry: parser.NewRegistry(),
		config:         config,
	}
}

// ScanFiles scans multiple files and returns aggregated results.
func (s *Scanner) ScanFiles(files []string) (*models.ScanResult, error) {
	startTime := time.Now()

	allFindings := []models.Finding{}
	scannedFiles := []string{}

	for _, file := range files {
		findings, err := s.ScanFile(file)
		if err != nil {
			// Log error but continue with other files.
			fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", file, err)
			continue
		}

		allFindings = append(allFindings, findings...)
		scannedFiles = append(scannedFiles, file)
	}

	// Apply severity overrides and filter disabled rules.
	allFindings = s.applyConfiguration(allFindings)

	// Calculate summary.
	summary := models.CalculateSummary(allFindings)

	result := &models.ScanResult{
		ScannerVersion: "1.0.0",
		ScanTime:       startTime,
		Duration:       time.Since(startTime),
		FilesScanned:   scannedFiles,
		Summary:        summary,
		Findings:       allFindings,
	}

	return result, nil
}

// ScanFile scans a single configuration file.
func (s *Scanner) ScanFile(filename string) ([]models.Finding, error) {
	// Get appropriate parser.
	p, err := s.parserRegistry.GetParser(filename)
	if err != nil {
		return nil, fmt.Errorf("no parser for file %s: %w", filename, err)
	}

	// Parse file.
	yamlParser, ok := p.(*parser.YAMLParser)
	if !ok {
		return nil, fmt.Errorf("%w for file %s", models.ErrUnexpectedParserType, filename)
	}
	tree, err := yamlParser.ParseFile(filename)
	if err != nil {
		// Try JSON parser if YAML fails.
		jsonParser := parser.NewJSONParser()
		if jsonParser.SupportsFormat(filename) {
			tree, err = jsonParser.ParseFile(filename)
			if err != nil {
				return nil, fmt.Errorf("failed to parse file: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse file: %w", err)
		}
	}

	// Run all rules against the parsed config.
	findings := []models.Finding{}
	enabledRules := s.registry.GetRules()

	for i := range enabledRules {
		if s.isRuleDisabled(enabledRules[i].ID) {
			continue
		}

		ruleFindings := enabledRules[i].Detector.Detect(tree)
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

// DiscoverFiles finds all configuration files matching patterns.
func (s *Scanner) DiscoverFiles(paths []string) ([]string, error) {
	files := []string{}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to access path %s: %w", path, err)
		}

		if info.IsDir() {
			// Walk directory.
			err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
					// Check if should be excluded.
					if s.shouldExclude(filePath) {
						return filepath.SkipDir
					}
					return nil
				}

				// Check if file matches include patterns and should not be excluded.
				if s.shouldInclude(filePath) && !s.shouldExclude(filePath) {
					files = append(files, filePath)
				}

				return nil
			})
			if err != nil {
				return nil, err
			}
		} else if s.shouldInclude(path) && !s.shouldExclude(path) {
			// Single file.
			files = append(files, path)
		}
	}

	return files, nil
}

func (s *Scanner) shouldInclude(path string) bool {
	if len(s.config.Include) == 0 {
		// Default: include common config files.
		ext := filepath.Ext(path)
		return ext == ".yaml" || ext == ".yml" || ext == ".json"
	}

	for _, pattern := range s.config.Include {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
	}

	return false
}

func (s *Scanner) shouldExclude(path string) bool {
	// Always exclude common directories.
	base := filepath.Base(path)
	if base == "node_modules" || base == "vendor" || base == ".git" || base == "dist" || base == "build" {
		return true
	}

	for _, pattern := range s.config.Exclude {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
	}

	return false
}

func (s *Scanner) isRuleDisabled(ruleID string) bool {
	for _, disabled := range s.config.DisabledRules {
		if disabled == ruleID {
			return true
		}
	}
	return false
}

func (s *Scanner) applyConfiguration(findings []models.Finding) []models.Finding {
	result := []models.Finding{}

	for i := range findings {
		// Apply severity override if configured.
		if override, ok := s.config.SeverityOverride[findings[i].RuleID]; ok {
			findings[i].Severity = override
		}

		result = append(result, findings[i])
	}

	return result
}
