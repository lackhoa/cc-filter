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
				return allowDecision()
			}
		}
	}

	// Check if this tool should be blocked (deny wins over auto-approve)
	if shouldBlock, reason := c.shouldBlockTool(toolName, toolInputRaw); shouldBlock {
		return denyDecision(reason)
	}

	// Auto-approve Read/Edit/Write for files under configured directories
	if filePath := extractFilePath(toolName, toolInputRaw); filePath != "" {
		if c.rules.IsUnderAutoApprovePath(filePath) {
			return allowDecision()
		}
	}

	// Pass through - let default permission system handle it
	return passThroughDecision()
}

// extractFilePath returns the file path for file tools (Read, Edit, Write,
// MultiEdit, NotebookEdit). Returns "" for tools that don't take a file path.
func extractFilePath(toolName string, input map[string]interface{}) string {
	switch toolName {
	case "Read", "Edit", "Write", "MultiEdit":
		if p, ok := input["file_path"].(string); ok {
			return p
		}
	case "NotebookEdit":
		if p, ok := input["notebook_path"].(string); ok {
			return p
		}
	}
	return ""
}

func allowDecision() (string, error) {
	response := map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":      "PreToolUse",
			"permissionDecision": "allow",
		},
	}
	responseJSON, err := json.Marshal(response)
	return string(responseJSON), err
}

func denyDecision(reason string) (string, error) {
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

func passThroughDecision() (string, error) {
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
	// NOTE(khoa): Bash commands already go through Claude Code's permission
	// dialog, so the user can approve/deny them directly. No need to block here.
	if filePath := extractFilePath(toolName, toolInput); filePath != "" {
		return c.rules.ShouldBlockFile(filePath)
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
