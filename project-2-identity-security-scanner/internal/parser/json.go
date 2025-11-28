// Package parser provides configuration file parsing utilities.
package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
)

// JSONParser parses JSON configuration files.
type JSONParser struct{}

// NewJSONParser creates a new JSON parser.
func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

// Parse parses JSON content into a ConfigTree.
func (p *JSONParser) Parse(filename string, content []byte) (*models.ConfigTree, error) {
	var root map[string]interface{}

	if err := json.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// For JSON, we can't easily get line numbers without a custom decoder.
	// For now, we'll use a simple line map.
	lineMap := make(map[string]int)
	p.buildLineMap(root, "", lineMap, string(content))

	return &models.ConfigTree{
		Root: root,
		Metadata: models.FileMetadata{
			Filename: filename,
			Format:   "json",
			LineMap:  lineMap,
		},
	}, nil
}

// SupportsFormat checks if this parser supports the given file.
func (p *JSONParser) SupportsFormat(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".json")
}

// buildLineMap attempts to map JSON paths to line numbers.
// This is a best-effort approach based on content scanning.
func (p *JSONParser) buildLineMap(obj interface{}, path string, lineMap map[string]int, content string) {
	switch v := obj.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newPath := key
			if path != "" {
				newPath = path + "." + key
			}

			// Try to find the line number by searching for the key in content.
			lines := strings.Split(content, "\n")
			searchKey := fmt.Sprintf("\"%s\"", key)
			for lineNum, line := range lines {
				if strings.Contains(line, searchKey) {
					lineMap[newPath] = lineNum + 1
					break
				}
			}

			p.buildLineMap(value, newPath, lineMap, content)
		}

	case []interface{}:
		for i, item := range v {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			p.buildLineMap(item, itemPath, lineMap, content)
		}
	}
}

// ParseFile is a convenience method to parse a file directly.
func (p *JSONParser) ParseFile(filename string) (*models.ConfigTree, error) {
	//nolint:gosec // G304: Filename is user-provided for scanning purposes.
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return p.Parse(filename, content)
}
