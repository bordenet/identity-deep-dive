package parser

import (
	"fmt"
	"os"
	"strings"

	"github.com/bordenet/identity-deep-dive/project-2-identity-security-scanner/pkg/models"
	"gopkg.in/yaml.v3"
)

// YAMLParser parses YAML configuration files.
type YAMLParser struct{}

// NewYAMLParser creates a new YAML parser.
func NewYAMLParser() *YAMLParser {
	return &YAMLParser{}
}

// Parse parses YAML content into a ConfigTree.
func (p *YAMLParser) Parse(filename string, content []byte) (*models.ConfigTree, error) {
	var root map[string]interface{}
	var node yaml.Node

	// Parse with line number tracking.
	if err := yaml.Unmarshal(content, &node); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Convert to map with line numbers.
	lineMap := make(map[string]int)
	root = p.convertNode(&node, "", lineMap).(map[string]interface{})

	return &models.ConfigTree{
		Root: root,
		Metadata: models.FileMetadata{
			Filename: filename,
			Format:   "yaml",
			LineMap:  lineMap,
		},
	}, nil
}

// SupportsFormat checks if this parser supports the given file.
func (p *YAMLParser) SupportsFormat(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

// convertNode converts yaml.Node to interface{} while tracking line numbers.
func (p *YAMLParser) convertNode(node *yaml.Node, path string, lineMap map[string]int) interface{} {
	if node == nil {
		return nil
	}

	// Track line number for this path.
	if path != "" {
		lineMap[path] = node.Line
	}

	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) > 0 {
			return p.convertNode(node.Content[0], path, lineMap)
		}
		return nil

	case yaml.MappingNode:
		result := make(map[string]interface{})
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			newPath := path
			if newPath == "" {
				newPath = key
			} else {
				newPath = path + "." + key
			}

			result[key] = p.convertNode(valueNode, newPath, lineMap)
		}
		return result

	case yaml.SequenceNode:
		result := make([]interface{}, 0, len(node.Content))
		for i, child := range node.Content {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			result = append(result, p.convertNode(child, itemPath, lineMap))
		}
		return result

	case yaml.ScalarNode:
		// Store line number for scalar values.
		lineMap[path] = node.Line
		return node.Value

	case yaml.AliasNode:
		return p.convertNode(node.Alias, path, lineMap)
	}

	return nil
}

// ParseFile is a convenience method to parse a file directly.
func (p *YAMLParser) ParseFile(filename string) (*models.ConfigTree, error) {
	//nolint:gosec // G304: Filename is user-provided for scanning purposes.
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return p.Parse(filename, content)
}
