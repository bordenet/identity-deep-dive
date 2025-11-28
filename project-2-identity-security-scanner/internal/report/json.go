package report

import (
	"encoding/json"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
)

// JSONReportGenerator generates JSON output.
type JSONReportGenerator struct{}

// NewJSONReportGenerator creates a new JSON report generator.
func NewJSONReportGenerator() *JSONReportGenerator {
	return &JSONReportGenerator{}
}

// Generate creates a JSON report.
func (j *JSONReportGenerator) Generate(result *models.ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// Format returns the format name.
func (j *JSONReportGenerator) Format() string {
	return "json"
}
