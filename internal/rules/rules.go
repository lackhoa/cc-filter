package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	AllowedArgs        map[string][]string `yaml:"allowed_args"`
}

type Rules struct {
	FileBlocks       []string      `yaml:"file_blocks"`
	AutoApprovePaths []string      `yaml:"auto_approve_paths"`
	SafeCommands     *SafeCommands `yaml:"safe_commands"`
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
		if r.matchesSafeScpCommand(words) {
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
		if matchesPrefixWithFlagSkip(words, prefixWords) {
			return true
		}
	}
	return false
}

// matchesPrefixWithFlagSkip matches pattern tokens against command tokens in order,
// skipping over flag-like tokens (starting with "-") and their values.
// After all pattern tokens are matched, remaining command tokens are ignored (prefix match).
//
// Example: "docker compose -f prod.yml ps -a" against pattern "docker compose ps"
//
//	word            pattern token   lastWasFlag   action
//	"docker"        "docker"        false         matches → advance both
//	"compose"       "compose"       false         matches → advance both
//	"-f"            "ps"            false         flag → skip, set lastWasFlag=true
//	"prod.yml"      "ps"            true          no match, but lastWasFlag → skip as flag value
//	"ps"            "ps"            false         matches → advance both
//	(done)                                        all pattern tokens matched → success
func matchesPrefixWithFlagSkip(words []string, pattern []string) bool {
	return matchFlagSkip(words, 0, pattern, 0, false)
}

func matchFlagSkip(words []string, wordIdx int, pattern []string, patternIdx int, lastWasFlag bool) bool {
	if patternIdx >= len(pattern) {
		return true
	}
	if wordIdx >= len(words) {
		return false
	}

	word := words[wordIdx]

	// Flag token: skip it
	if strings.HasPrefix(word, "-") {
		return matchFlagSkip(words, wordIdx+1, pattern, patternIdx, true)
	}

	// Non-flag token: try to match against current pattern token
	if matched, _ := filepath.Match(pattern[patternIdx], word); matched {
		return matchFlagSkip(words, wordIdx+1, pattern, patternIdx+1, false)
	}

	// Doesn't match. If previous token was a flag, this might be its value — skip it.
	if lastWasFlag {
		return matchFlagSkip(words, wordIdx+1, pattern, patternIdx, false)
	}

	return false
}

func (r *Rules) matchesAllowedCommand(words []string, isLocal bool) bool {
	matched := matchesAnyPrefix(words, r.SafeCommands.AllowedCommands) ||
		(isLocal && matchesAnyPrefix(words, r.SafeCommands.LocalOnlyCommands))
	return matched && !r.hasBlockedArgs(words) && !r.hasDisallowedArgs(words)
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

// hasOnlyAllowedArgs returns true if the command has an allowed_args entry
// and all flag-like arguments (starting with "-") are in the allow list.
// Non-flag arguments (URLs, paths, etc.) are always permitted.
// Returns false (not restricted) if the command has no allowed_args entry.
func (r *Rules) hasDisallowedArgs(words []string) bool {
	if r.SafeCommands.AllowedArgs == nil {
		return false
	}
	cmd := words[0]
	allowed, ok := r.SafeCommands.AllowedArgs[cmd]
	if !ok {
		return false
	}
	for _, word := range words[1:] {
		if strings.HasPrefix(word, "-") && !slices.Contains(allowed, word) {
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

// matchesSafeScpCommand checks if an scp invocation is a safe download (remote → local).
// Only allows: scp [safe-flags] remote:path local_path
func (r *Rules) matchesSafeScpCommand(words []string) bool {
	if words[0] != "scp" || len(words) < 3 {
		return false
	}

	safeBoolFlags := map[string]bool{"-r": true, "-q": true, "-C": true, "-p": true, "-v": true}
	flagsWithValue := map[string]bool{"-P": true}

	var args []string
	i := 1
	for i < len(words) {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			args = append(args, w)
			i++
			continue
		}
		if flagsWithValue[w] {
			i += 2
			continue
		}
		if safeBoolFlags[w] {
			i++
			continue
		}
		return false
	}

	if len(args) != 2 {
		return false
	}

	source, dest := args[0], args[1]
	// NOTE only allow download: source must be remote (has ':'), dest must be local (no ':')
	return strings.Contains(source, ":") && !strings.Contains(dest, ":")
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

// expandHome expands a leading "~" to the current user's home directory.
// Supports "~", "~/", and "~\" prefixes. Other forms (e.g. "~user/...") pass through.
func expandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if len(path) == 1 {
		return home
	}
	if path[1] == '/' || path[1] == '\\' {
		return filepath.Join(home, path[2:])
	}
	return path
}

// normalizePathForCompare returns a canonical form of a path suitable for
// prefix comparison: absolute-cleaned, forward slashes, lowercased on Windows.
func normalizePathForCompare(p string) string {
	p = filepath.Clean(p)
	p = strings.ReplaceAll(p, "\\", "/")
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// IsUnderAutoApprovePath returns true if filePath is strictly inside one of
// the configured auto_approve_paths directories. Expands "~" and is
// case-insensitive on Windows. The directory itself is not considered "inside".
func (r *Rules) IsUnderAutoApprovePath(filePath string) bool {
	if len(r.AutoApprovePaths) == 0 || filePath == "" {
		return false
	}

	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}
	normFile := normalizePathForCompare(absFile)

	for _, dir := range r.AutoApprovePaths {
		expanded := expandHome(dir)
		absDir, err := filepath.Abs(expanded)
		if err != nil {
			continue
		}
		normDir := normalizePathForCompare(absDir)
		if strings.HasPrefix(normFile, normDir+"/") {
			return true
		}
	}
	return false
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
