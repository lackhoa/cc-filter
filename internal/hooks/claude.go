package hooks

import (
	"encoding/json"

	"cc-filter/internal/rules"
)

type ClaudeHookProcessor struct {
	rules *rules.Rules
}

func NewClaudeHookProcessor(rules *rules.Rules) *ClaudeHookProcessor {
	return &ClaudeHookProcessor{
		rules: rules,
	}
}

func (c *ClaudeHookProcessor) CanHandle(input map[string]interface{}) bool {
	hookEvent, exists := input["hook_event_name"]
	if !exists {
		return false
	}

	switch hookEvent.(string) {
	case "PreToolUse", "UserPromptSubmit":
		return true
	default:
		return false
	}
}

func (c *ClaudeHookProcessor) Process(input map[string]interface{}) (string, error) {
	hookEvent := input["hook_event_name"].(string)

	switch hookEvent {
	case "PreToolUse":
		return c.processPreToolUse(input)
	case "UserPromptSubmit":
		return c.processUserPromptSubmit(input)
	default:
		if originalJSON, err := json.Marshal(input); err == nil {
			return string(originalJSON), nil
		}
		return "{}", nil
	}
}

func (c *ClaudeHookProcessor) processPreToolUse(input map[string]interface{}) (string, error) {
	toolName, _ := input["tool_name"].(string)
	toolInputRaw, _ := input["tool_input"].(map[string]interface{})

	// Check if this command should be auto-approved (e.g. safe SSH commands)
	if toolName == "Bash" {
		if command, ok := toolInputRaw["command"].(string); ok {
			if c.rules.IsLocalCommandSafe(command) {
				response := map[string]interface{}{
					"hookSpecificOutput": map[string]interface{}{
						"hookEventName":      "PreToolUse",
						"permissionDecision": "allow",
					},
				}
				responseJSON, err := json.Marshal(response)
				return string(responseJSON), err
			}
		}
	}

	// Check if this tool should be blocked
	shouldBlock, reason := c.shouldBlockTool(toolName, toolInputRaw)

	// Only intervene if we need to block
	// Otherwise, defer to default permission system by not including permissionDecision
	if shouldBlock {
		response := map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
		}
		responseJSON, err := json.Marshal(response)
		return string(responseJSON), err
	}

	// Pass through - let default permission system handle it
	response := map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName": "PreToolUse",
		},
	}

	responseJSON, err := json.Marshal(response)
	return string(responseJSON), err
}

func (c *ClaudeHookProcessor) processUserPromptSubmit(input map[string]interface{}) (string, error) {
	prompt, _ := input["prompt"].(string)
	return prompt, nil
}

func (c *ClaudeHookProcessor) shouldBlockTool(toolName string, toolInput map[string]interface{}) (bool, string) {
	switch toolName {
	case "Read":
		if filePath, ok := toolInput["file_path"].(string); ok {
			return c.rules.ShouldBlockFile(filePath)
		}

	case "Glob":
		if pattern, ok := toolInput["pattern"].(string); ok {
			for _, blockedPattern := range c.rules.FileBlocks {
				if contains(pattern, blockedPattern) {
					return true, "Pattern may expose sensitive files: " + pattern
				}
			}
		}

		// NOTE(khoa): Bash commands already go through Claude Code's permission
		// dialog, so the user can approve/deny them directly. No need to block here.
	}

	return false, ""
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsAnywhere(s, substr)))
}

func containsAnywhere(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
