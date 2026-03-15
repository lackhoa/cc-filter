package rules

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type SafeCommands struct {
	AllowedCommands    []string `yaml:"allowed_commands"`
	AllowedPipeTargets []string `yaml:"allowed_pipe_targets"`
}

type Rules struct {
	FileBlocks   []string      `yaml:"file_blocks"`
	SafeCommands *SafeCommands `yaml:"safe_commands"`
}

// Shell token types
type tokenType int

const (
	tokWord       tokenType = iota
	tokPipe                 // |
	tokAnd                  // &&
	tokOr                   // ||
	tokSemicolon            // ;
	tokBackground           // &
)

type token struct {
	typ   tokenType
	value string
}

func isWordChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-' || ch == '_' || ch == '.' || ch == '/' ||
		ch == '~' || ch == '@' || ch == ':' || ch == '=' ||
		ch == '+' || ch == '%' || ch == ',' || ch == '*' || ch == '?'
}

// tokenize splits a shell command into words and operators.
// Returns nil if the command contains unsafe or unparseable constructs
// (backticks, $(), redirections, unclosed quotes).
func tokenize(cmd string) []token {
	var tokens []token
	i := 0
	for i < len(cmd) {
		ch := cmd[i]
		if ch == ' ' || ch == '\t' {
			i++
			continue
		}

		if ch == '`' || ch == '>' || ch == '<' {
			return nil
		}
		if ch == ';' {
			tokens = append(tokens, token{tokSemicolon, ";"})
			i++
			continue
		}
		if ch == '&' {
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				tokens = append(tokens, token{tokAnd, "&&"})
				i += 2
				continue
			}
			tokens = append(tokens, token{tokBackground, "&"})
			i++
			continue
		}
		if ch == '|' {
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				tokens = append(tokens, token{tokOr, "||"})
				i += 2
				continue
			}
			tokens = append(tokens, token{tokPipe, "|"})
			i++
			continue
		}
		if ch == '$' && i+1 < len(cmd) && cmd[i+1] == '(' {
			return nil
		}

		// Parse a word (handles quoted strings)
		var word strings.Builder
		for i < len(cmd) {
			ch = cmd[i]
			// NOTE Handle single quote
			if ch == '\'' {
				i++
				for i < len(cmd) && cmd[i] != '\'' {
					word.WriteByte(cmd[i])
					i++
				}
				if i >= len(cmd) {
					// unclosed single quote
					return nil
				}
				i++
				continue
			}

			// NOTE Handle double quote
			if ch == '"' {
				i++
				for i < len(cmd) && cmd[i] != '"' {
					// NOTE: backticks and $() are still live inside double quotes in shell
					if cmd[i] == '`' || (cmd[i] == '$' && i+1 < len(cmd) && cmd[i+1] == '(') {
						return nil
					}
					word.WriteByte(cmd[i])
					i++
				}
				if i >= len(cmd) {
					// unclosed double quote
					return nil
				}
				i++
				continue
			}

			if !isWordChar(ch) {
				break
			}

			// NOTE normal characters
			word.WriteByte(ch)
			i++
		}
		if word.Len() == 0 {
			return nil
		}
		tokens = append(tokens, token{tokWord, word.String()})
	}
	return tokens
}

// IsCommandSafe checks if a command is safe to auto-approve
func (r *Rules) IsCommandSafe(command string) bool {
	if r.SafeCommands == nil {
		return false
	}

	tokens := tokenize(strings.TrimSpace(command))
	if len(tokens) == 0 {
		return false
	}

	// Append sentinel so the loop validates the last command too
	tokens = append(tokens, token{tokSemicolon, ";"})

	var words []string
	isPipeTarget := false

	for _, tok := range tokens {
		if tok.typ == tokWord {
			words = append(words, tok.value)
			continue
		}
		// Hit an operator — validate the accumulated command
		if len(words) == 0 {
			return false // operator with no preceding command (e.g. "| ls", "&& ls")
		}
		if isPipeTarget {
			if !r.matchesPipeTarget(words) {
				return false
			}
		} else {
			if !r.matchesAllowedCommand(words) {
				return false
			}
		}
		words = nil
		isPipeTarget = tok.typ == tokPipe
	}
	return true
}

func matchesAnyPrefix(words []string, prefixes []string) bool {
	for _, prefix := range prefixes {
		prefixWords := strings.Fields(prefix)
		if len(words) >= len(prefixWords) {
			match := true
			for i, pw := range prefixWords {
				if words[i] != pw {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

func (r *Rules) matchesAllowedCommand(words []string) bool {
	return matchesAnyPrefix(words, r.SafeCommands.AllowedCommands)
}

func (r *Rules) matchesPipeTarget(words []string) bool {
	return matchesAnyPrefix(words, r.SafeCommands.AllowedPipeTargets)
}

func (r *Rules) IsSSHCommandSafe(command string) bool {
	server, remoteCmd := parseSSHCommand(command)
	if server == "" || remoteCmd == "" {
		return false
	}
	return r.IsCommandSafe(remoteCmd)
}

func parseSSHCommand(command string) (server, remoteCmd string) {
	command = strings.TrimSpace(command)
	if !strings.HasPrefix(command, "ssh ") {
		return "", ""
	}

	rest := strings.TrimSpace(command[4:])

	// First token is the server (must not start with -)
	spaceIdx := strings.IndexAny(rest, " \t")
	if spaceIdx == -1 {
		return "", ""
	}

	server = rest[:spaceIdx]
	if strings.HasPrefix(server, "-") {
		// SSH flags not supported — fall through to normal permission system
		return "", ""
	}

	remoteCmd = strings.TrimSpace(rest[spaceIdx:])

	// Strip outer quotes if the entire remote command is quoted
	if len(remoteCmd) >= 2 {
		if (remoteCmd[0] == '"' && remoteCmd[len(remoteCmd)-1] == '"') ||
			(remoteCmd[0] == '\'' && remoteCmd[len(remoteCmd)-1] == '\'') {
			remoteCmd = remoteCmd[1 : len(remoteCmd)-1]
		}
	}

	return server, remoteCmd
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

	return defaultRules, nil
}

func loadDefaultRules() (*Rules, error) {
	var rules Rules
	if err := yaml.Unmarshal([]byte(defaultRulesYAML), &rules); err != nil {
		return nil, err
	}
	return &rules, nil
}

// NOTE: keep in sync with configs/default-rules.yaml
var defaultRulesYAML = `
file_blocks:
  - ".env"
  - ".env.local"
  - ".env.development"
  - ".env.production"
  - ".env.staging"
  - ".env.test"
  - "config.json"
  - "secrets.json"
  - "credentials.json"
  - "auth.json"
  - "keys.json"
  - "*.key"
  - "*.pem"
  - "*.p12"
  - "*.pfx"
  - "*secret*"
  - "*credential*"

safe_commands:
  allowed_commands:
    - "ls"
    - "cd"
    - "pwd"
    - "which"
    - "file"
    - "stat"
    - "date"
    - "echo"
    - "df"
    - "du"
    - "ps"
    - "uptime"
    - "free"
    - "whoami"
    - "hostname"
    - "uname"
    - "id"
    - "docker ps"
    - "docker stats"
    - "docker logs"
    - "docker inspect"
    - "docker compose ps"
    - "docker compose ls"
    - "docker compose logs"
    - "ffprobe"
    - "git status"
    - "git log"
    - "git diff"
    - "git branch"
    - "git remote"
    - "git show"
    - "pip list"
    - "pip show"
    - "python --version"
    - "node --version"
    - "go version"
    - "systemctl status"
    - "journalctl"
  allowed_pipe_targets:
    - "head"
    - "tail"
    - "grep"
    - "wc"
    - "sort"
    - "uniq"
    - "awk"
    - "sed"
    - "cut"
    - "tr"
`

func getUserConfigPath() string {
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".cc-filter", "config.yaml")
	}
	return ""
}

func mergeRules(base *Rules, override *Rules) *Rules {
	return &Rules{
		FileBlocks:   mergeStringSlices(base.FileBlocks, override.FileBlocks),
		SafeCommands: mergeSafeCommands(base.SafeCommands, override.SafeCommands),
	}
}

func mergeSafeCommands(base, override *SafeCommands) *SafeCommands {
	if base == nil && override == nil {
		return nil
	}
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}
	return &SafeCommands{
		AllowedCommands:    mergeStringSlices(base.AllowedCommands, override.AllowedCommands),
		AllowedPipeTargets: mergeStringSlices(base.AllowedPipeTargets, override.AllowedPipeTargets),
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

// splitPathSegments splits a path into segments by / or \
func splitPathSegments(path string) []string {
	// Normalize to forward slashes, then split
	normalized := strings.ReplaceAll(path, "\\", "/")
	return strings.Split(normalized, "/")
}

// containsBlockedPattern checks if text contains any of the file_blocks patterns
func (r *Rules) containsBlockedPattern(text string) (bool, string) {
	textLower := strings.ToLower(text)

	for _, pattern := range r.FileBlocks {
		patternLower := strings.ToLower(pattern)

		if strings.Contains(pattern, "*") {
			// Match glob patterns against each path segment in the text.
			// This handles patterns like "*.key" or "*secret*" matching
			// individual components of a file path.
			segments := splitPathSegments(textLower)
			for _, seg := range segments {
				if matched, _ := filepath.Match(patternLower, seg); matched {
					return true, pattern
				}
			}
			// Also check whitespace-separated words (for command matching)
			for _, word := range strings.Fields(textLower) {
				for _, seg := range splitPathSegments(word) {
					if matched, _ := filepath.Match(patternLower, seg); matched {
						return true, pattern
					}
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
