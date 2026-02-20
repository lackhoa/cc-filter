package rules

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rules struct {
	FileBlocks []string `yaml:"file_blocks"`
}

func LoadRules() (*Rules, error) {
	// start with defaults
	defaultRules, err := loadDefaultRules()
	if err != nil {
		return nil, err
	}

	// merge user config if exists
	userConfigPath := getUserConfigPath()
	if data, err := os.ReadFile(userConfigPath); err == nil {
		var userRules Rules
		if err := yaml.Unmarshal(data, &userRules); err == nil {
			defaultRules = mergeRules(defaultRules, &userRules)
		}
	}

	// merge project config if exists
	projectConfigPath := "config.yaml"
	if data, err := os.ReadFile(projectConfigPath); err == nil {
		var projectRules Rules
		if err := yaml.Unmarshal(data, &projectRules); err == nil {
			defaultRules = mergeRules(defaultRules, &projectRules)
		}
	}

	return defaultRules, nil
}

func loadDefaultRules() (*Rules, error) {
	configPath := "configs/default-rules.yaml"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return getMinimalDefaultRules(), nil
	}

	var rules Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}

	return &rules, nil
}

func getMinimalDefaultRules() *Rules {
	return &Rules{
		FileBlocks: []string{
			".env", ".env.local", "*.key", "*.pem", "*secret*",
		},
	}
}

func getUserConfigPath() string {
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".cc-filter", "config.yaml")
	}
	return ""
}

func mergeRules(base *Rules, override *Rules) *Rules {
	return &Rules{
		FileBlocks: mergeStringSlices(base.FileBlocks, override.FileBlocks),
	}
}

func mergeStringSlices(base, override []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range base {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	for _, item := range override {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// containsBlockedPattern checks if text contains any of the file_blocks patterns
func (r *Rules) containsBlockedPattern(text string) (bool, string) {
	textLower := strings.ToLower(text)

	for _, pattern := range r.FileBlocks {
		patternLower := strings.ToLower(pattern)

		if strings.Contains(pattern, "*") {
			// For glob patterns like *.key, check if any word in the text matches
			for _, word := range strings.Fields(textLower) {
				if matched, _ := filepath.Match(patternLower, word); matched {
					return true, pattern
				}
			}
		} else {
			if strings.Contains(textLower, patternLower) {
				return true, pattern
			}
		}
	}

	return false, ""
}

func (r *Rules) ShouldBlockFile(path string) (bool, string) {
	if blocked, pattern := r.containsBlockedPattern(path); blocked {
		return true, "Access denied to sensitive file matching '" + pattern + "': " + path
	}
	return false, ""
}

// Commands that read/output file contents
var contentReadingVerbs = []string{
	"cat", "head", "tail", "less", "more", "type",
	"grep", "rg", "awk", "sed",
	"source", "printenv", "export",
}

func (r *Rules) ShouldBlockCommand(cmd string) (bool, string) {
	cmdLower := strings.ToLower(cmd)

	// Only block if the command both reads content AND references a blocked file
	hasReadVerb := false
	for _, verb := range contentReadingVerbs {
		// Check if the verb appears as a word (at start, after pipe, after &&, after ;)
		if strings.HasPrefix(cmdLower, verb+" ") ||
			strings.HasPrefix(cmdLower, verb+"\t") ||
			strings.Contains(cmdLower, "| "+verb) ||
			strings.Contains(cmdLower, "&& "+verb) ||
			strings.Contains(cmdLower, "; "+verb) {
			hasReadVerb = true
			break
		}
	}

	if !hasReadVerb {
		return false, ""
	}

	if blocked, pattern := r.containsBlockedPattern(cmd); blocked {
		return true, "Command may expose blocked file '" + pattern + "': " + cmd
	}
	return false, ""
}
