package parser

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
)

var (
	// ErrNoParser is returned when no parser is found for a file.
	ErrNoParser = errors.New("no parser found for file")
)

// Parser interface for configuration file parsers.
type Parser interface {
	Parse(filename string, content []byte) (*models.ConfigTree, error)
	SupportsFormat(filename string) bool
}

// Registry holds all available parsers.
type Registry struct {
	parsers []Parser
}

// NewRegistry creates a new parser registry with default parsers.
func NewRegistry() *Registry {
	return &Registry{
		parsers: []Parser{
			NewYAMLParser(),
			NewJSONParser(),
		},
	}
}

// GetParser returns the appropriate parser for a filename.
func (r *Registry) GetParser(filename string) (Parser, error) {
	for _, parser := range r.parsers {
		if parser.SupportsFormat(filename) {
			return parser, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNoParser, filename)
}

// SelectAll finds all values matching a simple JSONPath-like selector.
// Supports: $.key, $.key.nested, $.key[*], $.key[*].nested.
func SelectAll(tree *models.ConfigTree, selector string) []models.ConfigNode {
	results := []models.ConfigNode{}

	// Remove leading "$." if present.
	path := strings.TrimPrefix(selector, "$.")
	parts := parsePathParts(path)

	walkPath(tree.Root, parts, "", &results, tree.Metadata.LineMap)

	return results
}

// parsePathParts splits a path like "oauth2.providers[*].client_secret" into parts.
func parsePathParts(path string) []string {
	// Simple split on dots and array indicators.
	parts := []string{}
	current := ""

	for i := 0; i < len(path); i++ {
		ch := path[i]
		switch ch {
		case '.':
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		case '[':
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
			// Look for closing bracket.
			end := strings.Index(path[i:], "]")
			if end > 0 {
				arrayPart := path[i : i+end+1]
				parts = append(parts, arrayPart)
				i += end
			}
		default:
			current += string(ch)
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

// walkPath recursively walks the config tree following the path.
func walkPath(current interface{}, parts []string, currentPath string, results *[]models.ConfigNode, lineMap map[string]int) {
	if len(parts) == 0 {
		// Reached the end of the path.
		*results = append(*results, models.ConfigNode{
			Path:   currentPath,
			Value:  current,
			Line:   getLine(currentPath, lineMap),
			Column: 0,
		})
		return
	}

	part := parts[0]
	remaining := parts[1:]

	// Handle map access.
	if m, ok := current.(map[string]interface{}); ok {
		if part == "[*]" {
			// Wildcard on a map - iterate all values.
			for key, value := range m {
				newPath := buildPath(currentPath, key)
				walkPath(value, remaining, newPath, results, lineMap)
			}
		} else {
			// Direct key access.
			if value, exists := m[part]; exists {
				newPath := buildPath(currentPath, part)
				walkPath(value, remaining, newPath, results, lineMap)
			}
		}
	}

	// Handle array access.
	if arr, ok := current.([]interface{}); ok {
		if part == "[*]" {
			// Wildcard on array - iterate all elements.
			for i, value := range arr {
				newPath := fmt.Sprintf("%s[%d]", currentPath, i)
				walkPath(value, remaining, newPath, results, lineMap)
			}
		}
	}
}

// buildPath constructs a path string.
func buildPath(current, next string) string {
	if current == "" {
		return next
	}
	return current + "." + next
}

// getLine retrieves the line number for a path.
func getLine(path string, lineMap map[string]int) int {
	if line, ok := lineMap[path]; ok {
		return line
	}
	// Try parent paths.
	parts := strings.Split(path, ".")
	for i := len(parts) - 1; i > 0; i-- {
		parentPath := strings.Join(parts[:i], ".")
		if line, ok := lineMap[parentPath]; ok {
			return line
		}
	}
	return 0
}

// GetValue retrieves a single value from the config tree by path.
func GetValue(tree *models.ConfigTree, path string) (interface{}, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")

	current := interface{}(tree.Root)
	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			if value, exists := m[part]; exists {
				current = value
			} else {
				return nil, false
			}
		} else {
			return nil, false
		}
	}

	return current, true
}

// GetString retrieves a string value from the config tree.
func GetString(tree *models.ConfigTree, path string) (string, bool) {
	value, ok := GetValue(tree, path)
	if !ok {
		return "", false
	}
	if str, ok := value.(string); ok {
		return str, true
	}
	return "", false
}

// GetStringSlice retrieves a string slice from the config tree.
func GetStringSlice(tree *models.ConfigTree, path string) ([]string, bool) {
	value, ok := GetValue(tree, path)
	if !ok {
		return nil, false
	}

	// Handle []interface{} conversion.
	if arr, ok := value.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, true
	}

	// Handle []string directly.
	if arr, ok := value.([]string); ok {
		return arr, true
	}

	return nil, false
}

// GetInt retrieves an integer value from the config tree.
func GetInt(tree *models.ConfigTree, path string) (int, bool) {
	value, ok := GetValue(tree, path)
	if !ok {
		return 0, false
	}

	// Handle different numeric types.
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}

	return 0, false
}

// GetBool retrieves a boolean value from the config tree.
func GetBool(tree *models.ConfigTree, path string) (boolValue bool, found bool) {
	value, ok := GetValue(tree, path)
	if !ok {
		return false, false
	}
	if b, ok := value.(bool); ok {
		return b, true
	}
	return false, false
}

// MatchesGlob checks if a filename matches a glob pattern.
func MatchesGlob(filename, pattern string) bool {
	matched, err := filepath.Match(pattern, filepath.Base(filename))
	if err != nil {
		return false
	}
	return matched
}
