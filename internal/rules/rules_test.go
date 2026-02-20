package rules

import (
	"testing"
)

func testRules() *Rules {
	return &Rules{
		FileBlocks: []string{
			".env", ".env.local", "secrets.json", "credentials.json",
			"*.key", "*.pem", "*secret*",
		},
	}
}

func TestShouldBlockFile(t *testing.T) {
	r := testRules()

	tests := []struct {
		path    string
		blocked bool
	}{
		{"/home/user/.env", true},
		{"/home/user/.env.local", true},
		{"config/secrets.json", true},
		{"my-secret-file.txt", true},    // matches *secret*
		{"server.pem", true},            // matches *.pem
		{"private.key", true},           // matches *.key
		{"/home/user/config.py", false},
		{"/home/user/main.go", false},
		{"README.md", false},
	}

	for _, tt := range tests {
		blocked, _ := r.ShouldBlockFile(tt.path)
		if blocked != tt.blocked {
			t.Errorf("ShouldBlockFile(%q) = %v, want %v", tt.path, blocked, tt.blocked)
		}
	}
}

func TestShouldBlockCommand(t *testing.T) {
	r := testRules()

	tests := []struct {
		cmd     string
		blocked bool
		desc    string
	}{
		// Should block: read verb + blocked file
		{"cat .env", true, "cat reading .env"},
		{"head .env", true, "head reading .env"},
		{"tail -f .env", true, "tail reading .env"},
		{"grep password .env", true, "grep on .env"},
		{"less secrets.json", true, "less reading secrets"},
		{"cat /home/user/.env.local", true, "cat with full path"},
		{"source .env", true, "source .env"},
		{"awk '{print}' credentials.json", true, "awk on credentials"},
		{"sed -n '1p' .env", true, "sed on .env"},

		// Should block: piped/chained commands with read verb
		{"echo hello | cat .env", true, "pipe into cat .env"},
		{"cd /tmp && cat .env", true, "chained with cat .env"},
		{"ls; cat .env", true, "semicolon then cat .env"},

		// Should NOT block: no read verb
		{"mv .env .env.backup", false, "mv doesn't read"},
		{"cp .env .env.bak", false, "cp doesn't read"},
		{"rm .env", false, "rm doesn't read"},
		{"ls .env", false, "ls doesn't read"},
		{"touch .env", false, "touch doesn't read"},
		{"chmod 600 .env", false, "chmod doesn't read"},

		// Should NOT block: read verb but no blocked file
		{"cat README.md", false, "cat on safe file"},
		{"grep TODO main.go", false, "grep on safe file"},
		{"head config.py", false, "head on safe file"},

		// Should NOT block: no read verb, no blocked file
		{"ls -la", false, "plain ls"},
		{"git status", false, "git command"},
		{"python main.py", false, "running python"},
	}

	for _, tt := range tests {
		blocked, reason := r.ShouldBlockCommand(tt.cmd)
		if blocked != tt.blocked {
			t.Errorf("[%s] ShouldBlockCommand(%q) = %v (reason: %s), want %v",
				tt.desc, tt.cmd, blocked, reason, tt.blocked)
		}
	}
}

func TestContainsBlockedPattern(t *testing.T) {
	r := testRules()

	tests := []struct {
		text    string
		blocked bool
	}{
		{".env", true},
		{"path/to/.env.local", true},
		{"my-secret-config", true},  // matches *secret*
		{"server.pem", true},        // matches *.pem
		{"normal-file.txt", false},
		{"main.go", false},
	}

	for _, tt := range tests {
		blocked, _ := r.containsBlockedPattern(tt.text)
		if blocked != tt.blocked {
			t.Errorf("containsBlockedPattern(%q) = %v, want %v", tt.text, blocked, tt.blocked)
		}
	}
}
