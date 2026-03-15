package rules

import (
	"testing"
)

func testRules() *Rules {
	return &Rules{
		FileBlocks: []string{
			".env", ".env.local", "secrets.json", "credentials.json",
			"*.key", "*.pem", "*secret*",
			"secrets", "secrets.*",
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

func safeCommandsRules() *Rules {
	return &Rules{
		SafeCommands: &SafeCommands{
			AllowedCommands:    []string{"ls", "df", "du", "ps", "uptime", "free", "whoami", "hostname", "docker ps", "docker stats", "docker compose ps", "docker compose ls", "ffprobe"},
			AllowedPipeTargets: []string{"head", "tail", "grep"},
		},
	}
}

func TestIsSSHCommandSafe(t *testing.T) {
	r := safeCommandsRules()

	tests := []struct {
		command string
		safe    bool
		desc    string
	}{
		// Safe: basic allowed commands
		{"ssh u6 ls", true, "simple ls"},
		{"ssh u6 ls -la /tmp", true, "ls with flags and path"},
		{"ssh u6 ls -la /home/user/project", true, "ls deep path"},
		{"ssh u6 df -h", true, "df with flags"},
		{"ssh u6 du -sh /home", true, "du with flags"},
		{"ssh u6 ps aux", true, "ps aux"},
		{"ssh u6 uptime", true, "uptime"},
		{"ssh u6 free -m", true, "free with flags"},
		{"ssh u6 whoami", true, "whoami"},
		{"ssh u6 hostname", true, "hostname"},
		{"ssh u6 ffprobe -v error video.mp4", true, "ffprobe"},

		// Safe: multi-word command prefixes
		{"ssh u6 docker ps", true, "docker ps"},
		{"ssh u6 docker ps -a", true, "docker ps with flags"},
		{"ssh u6 docker stats --no-stream", true, "docker stats"},
		{"ssh u6 docker compose ps", true, "docker compose ps"},
		{"ssh u6 docker compose ls", true, "docker compose ls"},

		// Safe: different server names
		{"ssh avo ls -la", true, "different server"},
		{"ssh 192.168.1.1 df -h", true, "IP address server"},
		{"ssh user@host ls", true, "user@host format"},

		// Safe: with allowed pipes
		{"ssh u6 ls -la | head", true, "pipe to head"},
		{"ssh u6 ls -la | tail -5", true, "pipe to tail with arg"},
		{"ssh u6 ls -la | grep foo", true, "pipe to grep"},
		{"ssh u6 docker ps | grep running", true, "docker ps piped to grep"},
		{"ssh u6 ls -la | head -20 | grep txt", true, "chained allowed pipes"},

		// Safe: quoted remote commands
		{`ssh u6 "ls -la /tmp"`, true, "double-quoted command"},
		{`ssh u6 'ls -la /tmp'`, true, "single-quoted command"},
		{`ssh u6 "docker ps -a"`, true, "quoted docker ps"},

		// Safe: boolean operators (&&, ||)
		{"ssh u6 ls -la && df -h", true, "two safe commands with &&"},
		{"ssh u6 ls && df && uptime", true, "three chained &&"},
		{"ssh u6 ls || df -h", true, "two safe commands with ||"},
		{"ssh u6 ls && df || uptime", true, "mixed && and ||"},
		{"ssh u6 ls -la | grep foo && df -h", true, "pipe + &&"},
		{"ssh u6 ls && docker ps | grep running", true, "&& + pipe"},

		// Unsafe: boolean with disallowed commands
		{"ssh u6 ls && rm -rf /", false, "&& with dangerous second command"},
		{"ssh u6 ls || bash", false, "|| with dangerous second command"},
		{"ssh u6 rm -rf / && ls", false, "&& with dangerous first command"},
		{"ssh u6 ls && cat /etc/passwd", false, "&& with cat"},

		// Unsafe: dangerous chars (shell injection)
		{"ssh u6 ls; rm -rf /", false, "semicolon injection"},
		{"ssh u6 ls & echo pwned", false, "background execution"},
		{"ssh u6 ls &", false, "trailing background &"},
		{"ssh u6 ls `whoami`", false, "backtick injection"},
		{"ssh u6 ls $(whoami)", false, "subshell injection"},
		{"ssh u6 ls > /etc/passwd", false, "redirect write"},
		{"ssh u6 ls >> /tmp/log", false, "redirect append"},
		{"ssh u6 cat < /etc/shadow", false, "redirect read"},

		// Unsafe: command not in whitelist
		{"ssh u6 cat /etc/passwd", false, "cat not allowed"},
		{"ssh u6 rm -rf /", false, "rm not allowed"},
		{"ssh u6 python script.py", false, "python not allowed"},
		{"ssh u6 bash -c 'echo hi'", false, "bash not allowed"},
		{"ssh u6 curl http://evil.com", false, "curl not allowed"},
		{"ssh u6 wget http://evil.com", false, "wget not allowed"},
		{"ssh u6 scp file user@host:/tmp", false, "scp not allowed"},
		{"ssh u6 docker exec -it foo bash", false, "docker exec not allowed"},
		{"ssh u6 docker run ubuntu", false, "docker run not allowed"},

		// Unsafe: disallowed pipe targets
		{"ssh u6 ls | bash", false, "pipe to bash"},
		{"ssh u6 ls | sh", false, "pipe to sh"},
		{"ssh u6 ls | python", false, "pipe to python"},
		{"ssh u6 ls | xargs rm", false, "pipe to xargs"},
		{"ssh u6 ls | tee /etc/passwd", false, "pipe to tee"},

		// Not SSH commands at all
		{"ls -la", false, "not ssh"},
		{"echo ssh u6 ls", false, "ssh not at start"},
		{"", false, "empty"},
		{"ssh", false, "ssh alone"},
		{"ssh u6", false, "ssh with no command"},

		// SSH with flags (not auto-approved for safety)
		{"ssh -t u6 ls", false, "ssh with -t flag"},
		{"ssh -p 22 u6 ls", false, "ssh with -p flag"},
		{"ssh -i keyfile u6 ls", false, "ssh with -i flag"},

		// Edge cases
		{"ssh u6  ls -la", true, "extra spaces"},
		{"ssh u6 ls||rm -rf /", false, "no-space double pipe with dangerous cmd"},
	}

	for _, tt := range tests {
		safe := r.IsSSHCommandSafe(tt.command)
		if safe != tt.safe {
			t.Errorf("[%s] IsSSHCommandSafe(%q) = %v, want %v", tt.desc, tt.command, safe, tt.safe)
		}
	}
}

func TestIsSSHCommandSafe_NilConfig(t *testing.T) {
	r := &Rules{SafeCommands: nil}
	if r.IsSSHCommandSafe("ssh u6 ls") {
		t.Error("should return false when SafeCommands is nil")
	}
}

func TestIsCommandSafe(t *testing.T) {
	r := safeCommandsRules()

	tests := []struct {
		command string
		safe    bool
		desc    string
	}{
		// Safe: basic allowed commands
		{"ls", true, "simple ls"},
		{"ls -la /tmp", true, "ls with flags and path"},
		{"df -h", true, "df with flags"},
		{"du -sh /home", true, "du with flags"},
		{"ps aux", true, "ps aux"},
		{"uptime", true, "uptime"},
		{"free -m", true, "free with flags"},
		{"whoami", true, "whoami"},
		{"hostname", true, "hostname"},
		{"docker ps", true, "docker ps"},
		{"docker ps -a", true, "docker ps with flags"},
		{"docker stats --no-stream", true, "docker stats"},
		{"docker compose ps", true, "docker compose ps"},
		{"docker compose ls", true, "docker compose ls"},

		// Safe: with pipes
		{"ls -la | head", true, "pipe to head"},
		{"ls -la | tail -5", true, "pipe to tail"},
		{"ls -la | grep foo", true, "pipe to grep"},
		{"docker ps | grep running", true, "docker ps piped"},
		{"ls -la | head -20 | grep txt", true, "chained pipes"},

		// Safe: boolean operators
		{"ls -la && df -h", true, "&& two safe commands"},
		{"ls && df && uptime", true, "&& three commands"},
		{"ls || df -h", true, "|| two safe commands"},
		{"ls && df || uptime", true, "mixed && ||"},
		{"ls -la | grep foo && df -h", true, "pipe + &&"},

		// Not auto-approved: needs permission prompt
		{"cat /etc/passwd", false, "cat needs permission"},
		{"rm -rf /", false, "rm needs permission"},
		{"python script.py", false, "python needs permission"},
		{"bash -c 'echo hi'", false, "bash needs permission"},
		{"curl http://evil.com", false, "curl needs permission"},

		// Unsafe: dangerous chars
		{"ls; rm -rf /", false, "semicolon with dangerous cmd"},
		{"ls; df", true, "semicolon with safe commands"},
		{"ls & echo pwned", false, "background with dangerous cmd"},
		{"ls & df", true, "background with safe commands"},
		{"ls `whoami`", false, "backtick injection"},
		{"ls $(whoami)", false, "subshell injection"},
		{"ls > /etc/passwd", false, "redirect write"},

		// Unsafe: boolean with disallowed commands
		{"ls && rm -rf /", false, "&& with dangerous cmd"},
		{"ls || bash", false, "|| with dangerous cmd"},

		// Unsafe: disallowed pipe targets
		{"ls | bash", false, "pipe to bash"},
		{"ls | python", false, "pipe to python"},
		{"ls | xargs rm", false, "pipe to xargs"},

		// Edge cases
		{"", false, "empty"},
		{"  ", false, "whitespace only"},
	}

	for _, tt := range tests {
		safe := r.IsCommandSafe(tt.command)
		if safe != tt.safe {
			t.Errorf("[%s] IsCommandSafe(%q) = %v, want %v", tt.desc, tt.command, safe, tt.safe)
		}
	}
}

func TestIsCommandSafe_NilConfig(t *testing.T) {
	r := &Rules{SafeCommands: nil}
	if r.IsCommandSafe("ls") {
		t.Error("should return false when SafeCommands is nil")
	}
}

func TestParseSSHCommand(t *testing.T) {
	tests := []struct {
		command   string
		server    string
		remoteCmd string
		desc      string
	}{
		{"ssh u6 ls -la", "u6", "ls -la", "basic"},
		{"ssh u6 docker ps -a", "u6", "docker ps -a", "multi-word command"},
		{`ssh u6 "ls -la /tmp"`, "u6", "ls -la /tmp", "quoted command"},
		{`ssh u6 'docker ps'`, "u6", "docker ps", "single-quoted"},
		{"ssh u6", "", "", "no remote command"},
		{"ssh -t u6 ls", "", "", "has ssh flags"},
		{"ssh", "", "", "just ssh"},
		{"", "", "", "empty"},
		{"ls -la", "", "", "not ssh"},
		{"ssh user@host df -h", "user@host", "df -h", "user@host format"},
	}

	for _, tt := range tests {
		server, remoteCmd := parseSSHCommand(tt.command)
		if server != tt.server || remoteCmd != tt.remoteCmd {
			t.Errorf("[%s] parseSSHCommand(%q) = (%q, %q), want (%q, %q)",
				tt.desc, tt.command, server, remoteCmd, tt.server, tt.remoteCmd)
		}
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		cmd    string
		count  int // expected token count, -1 means nil (unsafe)
		desc   string
	}{
		// Basic words
		{"ls", 1, "single word"},
		{"ls -la /tmp", 3, "words with flags"},
		{"docker compose ps", 3, "multi-word command"},

		// Operators
		{"ls && df", 3, "&&"},
		{"ls || df", 3, "||"},
		{"ls | grep foo", 4, "pipe"},
		{"ls && df || uptime", 5, "mixed operators"},

		// Quoting
		{`ls "my file"`, 2, "double-quoted word"},
		{`ls 'my file'`, 2, "single-quoted word"},

		// Operators (valid tokens, not unsafe)
		{"ls; df", 3, "semicolon"},
		{"ls & df", 3, "background &"},

		// Unsafe — returns nil
		{"ls `whoami`", -1, "backtick"},
		{"ls $(whoami)", -1, "subshell"},
		{"ls > file", -1, "redirect >"},
		{"ls >> file", -1, "redirect >>"},
		{"ls < file", -1, "redirect <"},
		{`ls "unclosed`, -1, "unclosed double quote"},
		{`ls 'unclosed`, -1, "unclosed single quote"},
		{"", 0, "empty"},
	}

	for _, tt := range tests {
		tokens := tokenize(tt.cmd)
		if tt.count == -1 {
			if tokens != nil {
				t.Errorf("[%s] tokenize(%q) = %v, want nil", tt.desc, tt.cmd, tokens)
			}
		} else {
			if len(tokens) != tt.count {
				t.Errorf("[%s] tokenize(%q) got %d tokens %v, want %d",
					tt.desc, tt.cmd, len(tokens), tokens, tt.count)
			}
		}
	}
}

func TestMergeSafeCommands(t *testing.T) {
	base := &SafeCommands{
		AllowedCommands:    []string{"ls", "df"},
		AllowedPipeTargets: []string{"head"},
	}
	override := &SafeCommands{
		AllowedCommands:    []string{"df", "du"},
		AllowedPipeTargets: []string{"head", "grep"},
	}

	merged := mergeSafeCommands(base, override)

	// Should have union: ls, df, du
	if len(merged.AllowedCommands) != 3 {
		t.Errorf("expected 3 commands, got %d: %v", len(merged.AllowedCommands), merged.AllowedCommands)
	}
	// Should have union: head, grep
	if len(merged.AllowedPipeTargets) != 2 {
		t.Errorf("expected 2 pipe targets, got %d: %v", len(merged.AllowedPipeTargets), merged.AllowedPipeTargets)
	}

	// Nil cases
	if mergeSafeCommands(nil, nil) != nil {
		t.Error("nil + nil should be nil")
	}
	if mergeSafeCommands(base, nil) != base {
		t.Error("base + nil should be base")
	}
	if mergeSafeCommands(nil, override) != override {
		t.Error("nil + override should be override")
	}
}

func TestShouldBlockFileWithSymlinkedPaths(t *testing.T) {
	r := testRules()

	tests := []struct {
		path    string
		blocked bool
		desc    string
	}{
		// "secrets" as a directory name in path (substring match)
		{"/c/Users/vodan/eatlab-drive/secrets/secrets.txt", true, "secrets dir on drive"},
		{"/c/Users/vodan/personal-drive/secrets/credentials.json", true, "personal-drive secrets"},
		{"C:\\Users\\vodan\\eatlab-drive\\secrets\\.env", true, "Windows backslash path"},

		// "secrets.*" glob matching against path segments
		{"/home/user/project/secrets.yml", true, "secrets.yml anywhere"},
		{"/home/user/project/secrets.json", true, "secrets.json anywhere"},

		// "*.key" and "*.pem" glob matching against path segments
		{"/home/user/.ssh/id_rsa.key", true, "key file in deep path"},
		{"/etc/ssl/server.pem", true, "pem file in deep path"},

		// Should NOT block
		{"/home/user/project/main.go", false, "normal go file"},
		{"/home/user/docs/secret-recipe.md", true, "matches *secret*"},
	}

	for _, tt := range tests {
		blocked, _ := r.ShouldBlockFile(tt.path)
		if blocked != tt.blocked {
			t.Errorf("[%s] ShouldBlockFile(%q) = %v, want %v", tt.desc, tt.path, blocked, tt.blocked)
		}
	}
}
