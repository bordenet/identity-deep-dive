// Package main provides the identity security scanner CLI.
package main

import (
	"fmt"
	"os"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/internal/report"
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/internal/scanner"
	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
	"github.com/spf13/cobra"
)

var (
	format       string
	failOn       []string
	include      []string
	exclude      []string
	disableRules []string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "identity-scanner",
		Short: "Identity Security Scanner - Static analysis for OAuth2/OIDC/JWT configurations",
		Long: `Identity Security Scanner performs static analysis on OAuth2, OIDC, JWT, and SAML
configurations to detect security misconfigurations before they reach production.

Detects 12+ vulnerability types including:
  - Weak client secrets
  - Insecure redirect URIs
  - Missing PKCE enforcement
  - JWT algorithm confusion
  - Hardcoded secrets
  - And more...`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan configuration files for security issues",
		Long: `Scan one or more configuration files or directories for identity security issues.

Examples:
  # Scan a single file
  identity-scanner scan config/oauth2.yaml

  # Scan a directory
  identity-scanner scan config/

  # Scan multiple paths
  identity-scanner scan config/ auth/

  # Output as JSON
  identity-scanner scan config/ --format json

  # Fail on critical issues only
  identity-scanner scan config/ --fail-on critical`,
		Args: cobra.MinimumNArgs(1),
		RunE: runScan,
	}

	scanCmd.Flags().StringVarP(&format, "format", "f", "human", "Output format (human, json)")
	scanCmd.Flags().StringSliceVar(&failOn, "fail-on", []string{"critical", "high"}, "Fail on severities (critical,high,medium,low)")
	scanCmd.Flags().StringSliceVar(&include, "include", []string{}, "Include file patterns")
	scanCmd.Flags().StringSliceVar(&exclude, "exclude", []string{}, "Exclude file patterns")
	scanCmd.Flags().StringSliceVar(&disableRules, "disable-rule", []string{}, "Disable specific rules by ID")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("Identity Security Scanner v1.0.0")
		},
	}

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(_ *cobra.Command, args []string) error {
	// Build scan configuration.
	config := models.ScanConfig{
		Include:       include,
		Exclude:       exclude,
		DisabledRules: disableRules,
		Format:        format,
	}

	// Parse failOn severities.
	for _, s := range failOn {
		config.FailOn = append(config.FailOn, models.Severity(s))
	}

	// Create scanner.
	s := scanner.New(&config)

	// Discover files.
	files, err := s.DiscoverFiles(args)
	if err != nil {
		return fmt.Errorf("failed to discover files: %w", err)
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No configuration files found to scan")
		return nil
	}

	// Scan files.
	result, err := s.ScanFiles(files)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Generate report.
	var reportGen interface {
		Generate(*models.ScanResult) ([]byte, error)
		Format() string
	}

	switch format {
	case "json":
		reportGen = report.NewJSONReportGenerator()
	default:
		reportGen = report.NewHumanReportGenerator()
	}

	output, err := reportGen.Generate(result)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Print report.
	fmt.Println(string(output))

	// Exit with appropriate code.
	exitCode := result.ExitCode(config.FailOn)
	os.Exit(exitCode)

	return nil
}
