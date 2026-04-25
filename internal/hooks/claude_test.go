package hooks

import (
	"encoding/json"
	"strings"
	"testing"

	"cc-filter/internal/rules"
)

func testProcessor() *ClaudeHookProcessor {
	r := &rules.Rules{
		FileBlocks: []string{
			".env*", "*secret*", "*credential*", "*.key", "*.pem",
		},
	}
	return NewClaudeHookProcessor(r)
}

func decodeDecision(t *testing.T, raw string) (string, string) {
	t.Helper()
	var resp struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return resp.HookSpecificOutput.PermissionDecision, resp.HookSpecificOutput.PermissionDecisionReason
}

func TestPreToolUseBlocksSensitivePaths(t *testing.T) {
	c := testProcessor()

	tests := []struct {
		name      string
		toolName  string
		toolInput map[string]interface{}
		wantDeny  bool
	}{
		{
			name:      "Grep with path pointing at .env",
			toolName:  "Grep",
			toolInput: map[string]interface{}{"pattern": "PASSWORD", "path": "/home/user/project/.env"},
			wantDeny:  true,
		},
		{
			name:      "Grep recursing into a secrets dir",
			toolName:  "Grep",
			toolInput: map[string]interface{}{"pattern": "TOKEN", "path": "/home/user/eatlab-drive/secrets/"},
			wantDeny:  true,
		},
		{
			name:      "Grep with glob targeting .env files",
			toolName:  "Grep",
			toolInput: map[string]interface{}{"pattern": "API", "glob": ".env*"},
			wantDeny:  true,
		},
		{
			name:      "Grep with safe glob and safe path",
			toolName:  "Grep",
			toolInput: map[string]interface{}{"pattern": "TODO", "glob": "*.go"},
			wantDeny:  false,
		},
		{
			name:      "Glob never blocked — listing filenames is harmless",
			toolName:  "Glob",
			toolInput: map[string]interface{}{"pattern": "**/.env*"},
			wantDeny:  false,
		},
		{
			name:      "Read of .env still blocked",
			toolName:  "Read",
			toolInput: map[string]interface{}{"file_path": "/home/user/.env"},
			wantDeny:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]interface{}{
				"hook_event_name": "PreToolUse",
				"tool_name":       tt.toolName,
				"tool_input":      tt.toolInput,
			}
			out, err := c.Process(input)
			if err != nil {
				t.Fatalf("Process returned error: %v", err)
			}
			decision, reason := decodeDecision(t, out)
			gotDeny := decision == "deny"
			if gotDeny != tt.wantDeny {
				t.Fatalf("decision=%q reason=%q, wantDeny=%v", decision, reason, tt.wantDeny)
			}
			if gotDeny && !strings.Contains(reason, "Access denied") {
				t.Fatalf("deny reason missing expected prefix: %q", reason)
			}
		})
	}
}
