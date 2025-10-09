package report

import (
	"fmt"
	"strings"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
	"github.com/fatih/color"
)

// HumanReportGenerator generates human-readable terminal output
type HumanReportGenerator struct {
	UseColor bool
}

// NewHumanReportGenerator creates a new human-readable report generator
func NewHumanReportGenerator() *HumanReportGenerator {
	return &HumanReportGenerator{
		UseColor: true,
	}
}

// Generate creates a human-readable report
func (h *HumanReportGenerator) Generate(result *models.ScanResult) ([]byte, error) {
	var output strings.Builder

	// Header
	output.WriteString(h.formatHeader(result))
	output.WriteString("\n")

	// Summary
	output.WriteString(h.formatSummary(result))
	output.WriteString("\n")

	// Findings
	if len(result.Findings) > 0 {
		output.WriteString(h.formatFindings(result.Findings))
	} else {
		output.WriteString(h.colorize("✓ No security issues found!\n\n", color.FgGreen))
	}

	// Footer
	output.WriteString(h.formatFooter(result))

	return []byte(output.String()), nil
}

// Format returns the format name
func (h *HumanReportGenerator) Format() string {
	return "human"
}

func (h *HumanReportGenerator) formatHeader(result *models.ScanResult) string {
	var out strings.Builder

	out.WriteString(h.colorize("═══════════════════════════════════════════════════════════════\n", color.FgCyan))
	out.WriteString(h.colorize("  Identity Security Scanner v"+result.ScannerVersion+"\n", color.FgCyan, color.Bold))
	out.WriteString(h.colorize("═══════════════════════════════════════════════════════════════\n\n", color.FgCyan))

	out.WriteString(fmt.Sprintf("Scan Time:  %s\n", result.ScanTime.Format("2006-01-02 15:04:05 MST")))
	out.WriteString(fmt.Sprintf("Duration:   %s\n", result.Duration.String()))
	out.WriteString(fmt.Sprintf("Files:      %d scanned\n", len(result.FilesScanned)))

	return out.String()
}

func (h *HumanReportGenerator) formatSummary(result *models.ScanResult) string {
	var out strings.Builder

	out.WriteString(h.colorize("\n━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", color.FgCyan))

	// Format summary with colors
	if result.Summary.Critical > 0 {
		out.WriteString(h.colorize(fmt.Sprintf("  Critical: %d\n", result.Summary.Critical), color.FgRed, color.Bold))
	}
	if result.Summary.High > 0 {
		out.WriteString(h.colorize(fmt.Sprintf("  High:     %d\n", result.Summary.High), color.FgRed))
	}
	if result.Summary.Medium > 0 {
		out.WriteString(h.colorize(fmt.Sprintf("  Medium:   %d\n", result.Summary.Medium), color.FgYellow))
	}
	if result.Summary.Low > 0 {
		out.WriteString(h.colorize(fmt.Sprintf("  Low:      %d\n", result.Summary.Low), color.FgBlue))
	}
	if result.Summary.Info > 0 {
		out.WriteString(h.colorize(fmt.Sprintf("  Info:     %d\n", result.Summary.Info), color.FgWhite))
	}

	if result.Summary.Total == 0 {
		out.WriteString(h.colorize("  No issues found\n", color.FgGreen))
	}

	return out.String()
}

func (h *HumanReportGenerator) formatFindings(findings []models.Finding) string {
	var out strings.Builder

	out.WriteString(h.colorize("\n━━━ Findings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", color.FgCyan))

	for i, finding := range findings {
		out.WriteString(h.formatFinding(&finding, i+1))
		out.WriteString("\n")
	}

	return out.String()
}

func (h *HumanReportGenerator) formatFinding(finding *models.Finding, number int) string {
	var out strings.Builder

	// Finding header with severity badge
	severityBadge := h.formatSeverityBadge(finding.Severity)
	out.WriteString(fmt.Sprintf("%s %s\n", severityBadge, h.colorize(finding.Title, color.Bold)))

	// Location
	location := fmt.Sprintf("%s:%d", finding.File, finding.Line)
	out.WriteString(h.colorize("  Location: ", color.FgWhite) + location + "\n")
	out.WriteString(h.colorize("  Rule ID:  ", color.FgWhite) + finding.RuleID + "\n")

	// Description
	out.WriteString(h.colorize("\n  Description:\n", color.FgWhite))
	out.WriteString(h.wrapText(finding.Description, "    "))
	out.WriteString("\n")

	// Risk
	if finding.Risk != "" {
		out.WriteString(h.colorize("\n  Risk:\n", color.FgYellow))
		out.WriteString(h.wrapText(finding.Risk, "    "))
		out.WriteString("\n")
	}

	// Remediation
	if len(finding.Remediation) > 0 {
		out.WriteString(h.colorize("\n  Remediation:\n", color.FgGreen))
		for _, step := range finding.Remediation {
			out.WriteString("    • " + step + "\n")
		}
	}

	// References
	if len(finding.References) > 0 {
		out.WriteString(h.colorize("\n  References:\n", color.FgCyan))
		for _, ref := range finding.References {
			out.WriteString("    - " + ref + "\n")
		}
	}

	out.WriteString(h.colorize("\n─────────────────────────────────────────────────────────────\n", color.FgWhite))

	return out.String()
}

func (h *HumanReportGenerator) formatSeverityBadge(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return h.colorize("[CRITICAL]", color.FgRed, color.Bold)
	case models.SeverityHigh:
		return h.colorize("[HIGH]    ", color.FgRed)
	case models.SeverityMedium:
		return h.colorize("[MEDIUM]  ", color.FgYellow)
	case models.SeverityLow:
		return h.colorize("[LOW]     ", color.FgBlue)
	case models.SeverityInfo:
		return h.colorize("[INFO]    ", color.FgWhite)
	default:
		return "[UNKNOWN] "
	}
}

func (h *HumanReportGenerator) formatFooter(result *models.ScanResult) string {
	var out strings.Builder

	out.WriteString("\n")
	out.WriteString(h.colorize("═══════════════════════════════════════════════════════════════\n", color.FgCyan))

	if result.Summary.Total > 0 {
		exitCode := result.ExitCode([]models.Severity{models.SeverityCritical, models.SeverityHigh})
		msg := fmt.Sprintf("Scan complete. Found %d issue(s) - Exit code: %d\n", result.Summary.Total, exitCode)
		if exitCode > 0 {
			out.WriteString(h.colorize(msg, color.FgRed, color.Bold))
		} else {
			out.WriteString(h.colorize(msg, color.FgYellow))
		}
	} else {
		out.WriteString(h.colorize("Scan complete. No issues found - Exit code: 0\n", color.FgGreen, color.Bold))
	}

	out.WriteString(h.colorize("═══════════════════════════════════════════════════════════════\n", color.FgCyan))

	return out.String()
}

func (h *HumanReportGenerator) wrapText(text string, indent string) string {
	// Simple word wrapping at 60 characters
	words := strings.Fields(text)
	var lines []string
	var currentLine string

	for _, word := range words {
		if len(currentLine)+len(word)+1 > 60 {
			lines = append(lines, indent+currentLine)
			currentLine = word
		} else {
			if currentLine != "" {
				currentLine += " "
			}
			currentLine += word
		}
	}

	if currentLine != "" {
		lines = append(lines, indent+currentLine)
	}

	return strings.Join(lines, "\n")
}

func (h *HumanReportGenerator) colorize(text string, attrs ...color.Attribute) string {
	if !h.UseColor {
		return text
	}
	c := color.New(attrs...)
	return c.Sprint(text)
}
