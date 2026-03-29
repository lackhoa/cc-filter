package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/syntax"
)

type SafeCommands struct {
	AllowedCommands    []string            `yaml:"allowed_commands"`
	LocalOnlyCommands  []string            `yaml:"local_only_commands"`
	AllowedPipeTargets []string            `yaml:"allowed_pipe_targets"`
	FileReadCommands   []string            `yaml:"file_read_commands"`
	FileSearchCommands []string            `yaml:"file_search_commands"`
	AllowedFiles       []string            `yaml:"allowed_files"`
	BlockedArgs        map[string][]string `yaml:"blocked_args"`
}

type Rules struct {
	FileBlocks   []string      `yaml:"file_blocks"`
	SafeCommands *SafeCommands `yaml:"safe_commands"`
}

// wordToString extracts a plain string from a syntax.Word.
// Returns ("", false) if the word contains any expansions ($var, $(cmd), etc.)
func wordToString(word *syntax.Word) (string, bool) {
	var sb strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return "", false
				}
				sb.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// isRedirectSafe checks if a redirect is harmless (fd duplication or /dev/null)
func isRedirectSafe(redir *syntax.Redirect) bool {
	// NOTE fd duplication like 2>&1 — just moves output between fds, harmless
	if redir.Op == syntax.DplOut || redir.Op == syntax.DplIn {
		target, ok := wordToString(redir.Word)
		if !ok {
			return false
		}
		// Allow >&1, >&2, <&0, etc. (single digit fd) and >&- (close fd)
		return (len(target) == 1 && target[0] >= '0' && target[0] <= '9') || target == "-"
	}

	// NOTE output to /dev/null — discarding output, harmless
	if redir.Op == syntax.RdrOut || redir.Op == syntax.AppOut {
		target, ok := wordToString(redir.Word)
		return ok && target == "/dev/null"
	}

	return false
}

// argsToStrings extracts plain strings from a list of syntax.Word.
// Returns nil if any word contains expansions.
func argsToStrings(args []*syntax.Word) []string {
	words := make([]string, 0, len(args))
	for _, arg := range args {
		s, ok := wordToString(arg)
		if !ok {
			return nil
		}
		words = append(words, s)
	}
	return words
}

// isStmtSafe checks if a single statement (with its redirects) is safe.
// isLocal controls whether local_only_commands are checked (false for SSH).
func (r *Rules) isStmtSafe(stmt *syntax.Stmt, isPipeTarget bool, isLocal bool) bool {
	// NOTE Negated = "! cmd" (negate exit code), Coprocess = "coproc cmd" (run as coprocess)
	// Neither is expected in safe read-only commands, reject to be safe
	if stmt.Negated || stmt.Coprocess {
		return false
	}

	for _, redir := range stmt.Redirs {
		if !isRedirectSafe(redir) {
			return false
		}
	}

	if stmt.Cmd == nil {
		return false
	}

	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		// NOTE CallExpr = simple command or bare assignment (FOO=bar)
		if len(cmd.Args) == 0 {
			return false
		}
		words := argsToStrings(cmd.Args)
		if words == nil {
			return false
		}
		if isPipeTarget {
			return r.matchesPipeTarget(words)
		}
		if r.matchesAllowedCommand(words, isLocal) {
			return true
		}
		if r.matchesSafeSSHCommand(words) {
			return true
		}
		return r.matchesSafeFileReadCommand(words)

	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe, syntax.PipeAll:
			return r.isStmtSafe(cmd.X, isPipeTarget, isLocal) && r.isStmtSafe(cmd.Y, true, isLocal)
		case syntax.AndStmt, syntax.OrStmt:
			return r.isStmtSafe(cmd.X, isPipeTarget, isLocal) && r.isStmtSafe(cmd.Y, isPipeTarget, isLocal)
		default:
			return false
		}

	default:
		// Subshells, if/for/while, functions, etc. — not auto-approved
		return false
	}
}

// IsLocalCommandSafe checks if a local command is safe to auto-approve (includes local_only_commands).
func (r *Rules) IsLocalCommandSafe(command string) bool {
	return r.isCommandSafeWith(command, true)
}

// IsRemoteCommandSafe checks if a command is safe when run via SSH (excludes local_only_commands).
func (r *Rules) IsRemoteCommandSafe(command string) bool {
	return r.isCommandSafeWith(command, false)
}

func (r *Rules) isCommandSafeWith(command string, isLocal bool) bool {
	if r.SafeCommands == nil {
		return false
	}

	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}

	parser := syntax.NewParser(syntax.KeepComments(false))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}

	for _, stmt := range file.Stmts {
		if !r.isStmtSafe(stmt, false, isLocal) {
			return false
		}
	}
	return true
}

func matchesAnyPrefix(words []string, prefixes []string) bool {
	for _, prefix := range prefixes {
		prefixWords := strings.Fields(prefix)
		if len(words) >= len(prefixWords) {
			match := true
			for i, pw := range prefixWords {
				if matched, _ := filepath.Match(pw, words[i]); !matched {
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

// HACK: docker compose accepts global flags between "compose" and the subcommand
// (e.g. "docker compose -p myproject ps"), but our prefix matching is positional.
// We strip known global flags so "docker compose -p myproject ps" matches "docker compose ps".
func stripDockerComposeGlobalFlags(words []string) []string {
	if len(words) < 3 || words[0] != "docker" || words[1] != "compose" {
		return words
	}

	// NOTE: these global flags consume the next argument as their value
	flagsWithValue := map[string]bool{
		"-p": true, "--project-name": true,
		"-f": true, "--file": true,
		"--project-directory": true,
		"--env-file":          true,
		"--profile":           true,
		"--progress":          true,
		"--ansi":              true,
	}

	result := []string{"docker", "compose"}
	i := 2
	for i < len(words) {
		if flagsWithValue[words[i]] {
			i += 2 // skip flag and its value
		} else if strings.HasPrefix(words[i], "-") {
			i++ // skip boolean flags (e.g. --dry-run, --verbose)
		} else {
			// reached the subcommand — keep it and everything after
			result = append(result, words[i:]...)
			break
		}
	}
	return result
}

func (r *Rules) matchesAllowedCommand(words []string, isLocal bool) bool {
	normalized := stripDockerComposeGlobalFlags(words)
	matched := matchesAnyPrefix(normalized, r.SafeCommands.AllowedCommands) ||
		(isLocal && matchesAnyPrefix(normalized, r.SafeCommands.LocalOnlyCommands))
	// NOTE: check blocked args against original words, not normalized
	return matched && !r.hasBlockedArgs(words)
}

func (r *Rules) hasBlockedArgs(words []string) bool {
	if r.SafeCommands.BlockedArgs == nil {
		return false
	}
	cmd := words[0]
	blocked, ok := r.SafeCommands.BlockedArgs[cmd]
	if !ok {
		return false
	}
	for _, word := range words[1:] {
		if slices.Contains(blocked, word) {
			return true
		}
	}
	return false
}

func (r *Rules) matchesPipeTarget(words []string) bool {
	return matchesAnyPrefix(words, r.SafeCommands.AllowedPipeTargets)
}

// matchesSafeFileReadCommand checks if a file-reading command is safe.
// Two kinds:
//   - FileReadCommands (cat, head, tail): ALL non-flag args are files, must match AllowedFiles
//   - FileSearchCommands (grep): first non-flag arg is a search pattern (skip it),
//     remaining non-flag args are files and must match AllowedFiles
func (r *Rules) matchesSafeFileReadCommand(words []string) bool {
	cmd := words[0]
	skipFirstArg := false

	if slices.Contains(r.SafeCommands.FileSearchCommands, cmd) {
		skipFirstArg = true
	} else if !slices.Contains(r.SafeCommands.FileReadCommands, cmd) {
		return false
	}

	hasFileArg := false
	skippedSearchPattern := false
	for _, arg := range words[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// NOTE for search commands like grep, the first non-flag arg is the search pattern
		if skipFirstArg && !skippedSearchPattern {
			skippedSearchPattern = true
			continue
		}
		if !matchesAnyFilePattern(filepath.Base(arg), r.SafeCommands.AllowedFiles) {
			return false
		}
		hasFileArg = true
	}
	return hasFileArg
}

func matchesAnyFilePattern(basename string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, basename); matched {
			return true
		}
	}
	return false
}

// matchesSafeSSHCommand checks if a command is an SSH invocation with a safe remote command.
// Rejects SSH with flags (e.g. -t, -p) for safety.
func (r *Rules) matchesSafeSSHCommand(words []string) bool {
	// NOTE need at least: ssh <host> <command>
	if words[0] != "ssh" || len(words) < 3 {
		return false
	}
	if strings.HasPrefix(words[1], "-") {
		return false
	}
	// NOTE SSH concatenates remaining args with spaces for the remote shell
	remoteCmd := strings.Join(words[2:], " ")
	return r.IsRemoteCommandSafe(remoteCmd)
}

func LoadRules() (*Rules, error) {
	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", configPath, err)
	}

	var rules Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", configPath, err)
	}
	return &rules, nil
}

func getConfigPath() string {
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".cc-filter", "config.yaml")
	}
	return ""
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
