package hooks

import (
	"encoding/json"
	"testing"

	"cc-filter/internal/rules"
)

func testOpencodeProcessor() *OpencodeHookProcessor {
	r := &rules.Rules{
		FileBlocks: []string{
			".env*", "*secret*", "*credential*", "*.key", "*.pem",
		},
	}
	return NewOpencodeHookProcessor(r)
}

func decodeOpencodeDecision(t *testing.T, raw string) (string, string) {
	t.Helper()
	var resp struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return resp.Decision, resp.Reason
}

func TestOpencodeCanHandle(t *testing.T) {
	o := testOpencodeProcessor()

	if o.CanHandle(map[string]interface{}{"source": "opencode"}) != true {
		t.Fatal("should handle source=opencode")
	}
	// Claude payloads must NOT be handled here.
	if o.CanHandle(map[string]interface{}{"hook_event_name": "PreToolUse"}) != false {
		t.Fatal("must not handle Claude payloads")
	}
}

func TestOpencodeDenyList(t *testing.T) {
	o := testOpencodeProcessor()

	tests := []struct {
		name     string
		tool     string
		args     map[string]interface{}
		wantDeny bool
	}{
		{
			name:     "bash cat of .env is blocked",
			tool:     "bash",
			args:     map[string]interface{}{"command": "cat ~/.env"},
			wantDeny: true,
		},
		{
			name:     "bash printenv piped is blocked when it hits a secret file",
			tool:     "bash",
			args:     map[string]interface{}{"command": "grep TOKEN config/secrets.yml"},
			wantDeny: true,
		},
		{
			name:     "safe bash is allowed",
			tool:     "bash",
			args:     map[string]interface{}{"command": "git status"},
			wantDeny: false,
		},
		{
			name:     "read of .env is blocked",
			tool:     "read",
			args:     map[string]interface{}{"filePath": "/home/user/.env"},
			wantDeny: true,
		},
		{
			name:     "edit of a secrets file is blocked",
			tool:     "edit",
			args:     map[string]interface{}{"filePath": "/home/user/config/db-credentials.yml"},
			wantDeny: true,
		},
		{
			name:     "write of a normal file is allowed",
			tool:     "write",
			args:     map[string]interface{}{"filePath": "/home/user/project/main.go"},
			wantDeny: false,
		},
		{
			name:     "grep with path at a secrets dir is blocked",
			tool:     "grep",
			args:     map[string]interface{}{"pattern": "PASSWORD", "path": "/home/user/secrets/"},
			wantDeny: true,
		},
		{
			name:     "grep for the literal word secret in a normal file is allowed",
			tool:     "grep",
			args:     map[string]interface{}{"pattern": "secret", "path": "/home/user/project/notes.txt"},
			wantDeny: false,
		},
		{
			name:     "grep with include glob targeting .env is blocked",
			tool:     "grep",
			args:     map[string]interface{}{"pattern": "API", "path": ".", "include": ".env*"},
			wantDeny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]interface{}{
				"source": "opencode",
				"event":  "tool.before",
				"tool":   tt.tool,
				"args":   tt.args,
			}
			out, err := o.Process(input)
			if err != nil {
				t.Fatalf("Process returned error: %v", err)
			}
			decision, reason := decodeOpencodeDecision(t, out)
			gotDeny := decision == "deny"
			if gotDeny != tt.wantDeny {
				t.Fatalf("decision=%q reason=%q, wantDeny=%v", decision, reason, tt.wantDeny)
			}
			if gotDeny && reason == "" {
				t.Fatal("deny decision must carry a reason")
			}
			if !gotDeny && decision != "allow" {
				t.Fatalf("non-deny decision should be allow, got %q", decision)
			}
		})
	}
}
