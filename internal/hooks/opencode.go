package hooks

import (
	"encoding/json"

	"cc-filter/internal/rules"
)

// OpencodeHookProcessor handles permission envelopes sent by the opencode
// bridge plugin (~/.config/opencode/plugin/cc-filter.ts). It shares the same
// rules engine as the Claude path — no allow/deny logic is duplicated in JS.
//
// Option A (deny-list): opencode default-allows tool calls, so this processor
// only needs to flag known-bad ones. The plugin calls cc-filter from
// `tool.execute.before` and throws when the decision is "deny", which hard-
// blocks the call even though opencode's own permission would have allowed it.
type OpencodeHookProcessor struct {
	rules *rules.Rules
}

func NewOpencodeHookProcessor(rules *rules.Rules) *OpencodeHookProcessor {
	return &OpencodeHookProcessor{
		rules: rules,
	}
}

// CanHandle keys on source=="opencode" so it never collides with Claude
// payloads (which carry hook_event_name instead).
func (o *OpencodeHookProcessor) CanHandle(input map[string]interface{}) bool {
	source, _ := input["source"].(string)
	return source == "opencode"
}

func (o *OpencodeHookProcessor) Process(input map[string]interface{}) (string, error) {
	tool, _ := input["tool"].(string)
	args, _ := input["args"].(map[string]interface{})

	if blocked, reason := o.shouldBlock(tool, args); blocked {
		return opencodeDecision("deny", reason)
	}
	return opencodeDecision("allow", "")
}

// shouldBlock mirrors the Claude path's protections, mapped onto opencode's
// tool/arg names. Unlike Claude, bash is load-bearing here: there is no
// permission dialog in deny-list mode, so ShouldBlockCommand is what stops
// `cat ~/.env`, `printenv`, `source secrets`, etc. from silently leaking.
func (o *OpencodeHookProcessor) shouldBlock(tool string, args map[string]interface{}) (bool, string) {
	switch tool {
	case "bash":
		if command, ok := args["command"].(string); ok {
			return o.rules.ShouldBlockCommand(command)
		}
	case "read", "edit", "write":
		if filePath, ok := args["filePath"].(string); ok {
			return o.rules.ShouldBlockFile(filePath)
		}
	case "grep":
		// Check the search path and the file-glob filter, NOT `pattern`:
		// pattern is the search regex, so blocking on it would falsely deny
		// e.g. `grep "secret" file.txt`. Mirrors Claude's path+glob (not the
		// regex) coverage in extractCheckablePaths.
		for _, key := range []string{"path", "include"} {
			if p, ok := args[key].(string); ok && p != "" {
				if blocked, reason := o.rules.ShouldBlockFile(p); blocked {
					return true, reason
				}
			}
		}
	}
	return false, ""
}

func opencodeDecision(decision, reason string) (string, error) {
	response := map[string]interface{}{
		"decision": decision,
	}
	if reason != "" {
		response["reason"] = reason
	}
	responseJSON, err := json.Marshal(response)
	return string(responseJSON), err
}
