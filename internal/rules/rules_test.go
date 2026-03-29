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
		{"my-secret-file.txt", true}, // matches *secret*
		{"server.pem", true},         // matches *.pem
		{"private.key", true},        // matches *.key
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
		{"my-secret-config", true}, // matches *secret*
		{"server.pem", true},       // matches *.pem
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
			AllowedCommands:    []string{"ls", "df", "du", "ps", "uptime", "free", "whoami", "hostname", "docker ps", "docker stats", "docker compose ps", "docker compose ls", "ffprobe", "python *ralph_*"},
			LocalOnlyCommands:  []string{"git pull"},
			AllowedPipeTargets: []string{"head", "tail", "grep"},
		},
	}
}

func TestIsLocalCommandSafe_SSH(t *testing.T) {
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
		{"ssh u6 docker compose -p myproject ps", true, "docker compose -p flag"},
		{`ssh u6 "docker compose -p fd2-client-staging ps"`, true, "docker compose -p quoted"},
		{"ssh u6 docker compose -f docker-compose.prod.yml ps", true, "docker compose -f flag"},
		{"ssh u6 docker compose -p myproject -f prod.yml ps", true, "docker compose multiple global flags"},

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
		{"ssh u6 ls &", true, "trailing background & (safe cmd backgrounded is still safe)"},
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

		// Local-only commands: NOT safe via SSH
		{"ssh u6 git pull", false, "local-only git pull blocked via SSH"},
		{"ssh u6 git pull origin main", false, "local-only git pull with args blocked via SSH"},

		// Not SSH commands at all (these go through normal command checking)
		{"echo ssh u6 ls", false, "ssh not at start (echo not allowed)"},
		{"ssh", false, "ssh alone"},
		{"ssh u6", false, "ssh with no command"},

		// SSH with flags (not auto-approved for safety)
		{"ssh -t u6 ls", false, "ssh with -t flag"},
		{"ssh -p 22 u6 ls", false, "ssh with -p flag"},
		{"ssh -i keyfile u6 ls", false, "ssh with -i flag"},

		// Safe: redirects on the SSH process itself
		{`ssh apr "ls -la && df -h && uptime" 2>&1`, true, "quoted compound cmd with 2>&1"},
		{"ssh u6 ls 2>&1", true, "stderr to stdout"},
		{"ssh u6 ls 2>/dev/null", true, "stderr to /dev/null"},
		{"ssh u6 ls 2>&1 | grep foo", true, "stderr merge piped to grep"},

		// Unsafe: redirects that write to files
		{"ssh u6 ls > /tmp/out.txt", false, "redirect stdout to file"},
		{"ssh u6 ls 2>/tmp/err.log", false, "redirect stderr to file"},

		// Edge cases
		{"ssh u6  ls -la", true, "extra spaces"},
		{"ssh u6 ls||rm -rf /", false, "no-space double pipe with dangerous cmd"},
	}

	for _, tt := range tests {
		safe := r.IsLocalCommandSafe(tt.command)
		if safe != tt.safe {
			t.Errorf("[%s] IsLocalCommandSafe(%q) = %v, want %v", tt.desc, tt.command, safe, tt.safe)
		}
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
		{"docker compose -p myproject ps", true, "docker compose -p local"},
		{"docker compose -p myproject -f prod.yml ps", true, "docker compose multi flags local"},

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

		// Glob patterns in allowed_commands
		{"python ~/notes/scripts/ralph_query_db.py \"SELECT 1\"", true, "ralph script"},
		{"python ~/notes/scripts/ralph_query_db.py \"SELECT 1\" 2>&1 | head -30", true, "ralph script with pipe"},
		{"python C:/Users/vodan/notes/scripts/ralph_python.py -c \"print(1)\"", true, "ralph script windows path"},
		{"python script.py", false, "non-ralph python script"},
		{"python", false, "bare python"},

		// Local-only commands: safe locally
		{"git pull", true, "local-only git pull"},
		{"git pull origin main", true, "local-only git pull with args"},

		// Edge cases
		{"", false, "empty"},
		{"  ", false, "whitespace only"},
	}

	for _, tt := range tests {
		safe := r.IsLocalCommandSafe(tt.command)
		if safe != tt.safe {
			t.Errorf("[%s] IsCommandSafe(%q) = %v, want %v", tt.desc, tt.command, safe, tt.safe)
		}
	}
}

func TestIsCommandSafe_NilConfig(t *testing.T) {
	r := &Rules{SafeCommands: nil}
	if r.IsLocalCommandSafe("ls") {
		t.Error("should return false when SafeCommands is nil")
	}
}

func TestIsCommandSafe_Redirections(t *testing.T) {
	r := safeCommandsRules()

	tests := []struct {
		command string
		safe    bool
		desc    string
	}{
		// Safe redirections
		{"ls 2>&1", true, "stderr to stdout"},
		{"ls 2>&1 | grep foo", true, "stderr to stdout then pipe"},
		{"ls >/dev/null", true, "stdout to /dev/null"},
		{"ls 2>/dev/null", true, "stderr to /dev/null"},
		{"ls >/dev/null 2>&1", true, "both to /dev/null"},
		{"ls 2>/dev/null 1>&2", true, "fd duplication"},
		{"df -h 2>&1 | tail -5", true, "redirect + pipe + pipe target"},

		// Unsafe redirections
		{"ls > /tmp/out.txt", false, "write to file"},
		{"ls >> /tmp/out.txt", false, "append to file"},
		{"ls < /etc/passwd", false, "read redirect"},
		{"ls 2>/tmp/err.log", false, "stderr to file"},
		{"ls > /etc/passwd", false, "write to sensitive path"},
		{"ls >&/tmp/out.txt", false, "fd dup to non-digit"},
	}

	for _, tt := range tests {
		safe := r.IsLocalCommandSafe(tt.command)
		if safe != tt.safe {
			t.Errorf("[%s] IsCommandSafe(%q) = %v, want %v", tt.desc, tt.command, safe, tt.safe)
		}
	}
}

func fileReadRules() *Rules {
	return &Rules{
		SafeCommands: &SafeCommands{
			AllowedCommands:    []string{"ls", "df"},
			AllowedPipeTargets: []string{"head", "tail", "grep"},
			FileReadCommands:   []string{"cat", "tail", "head"},
			FileSearchCommands: []string{"grep"},
			AllowedFiles:       []string{"*.log"},
		},
	}
}

func TestIsCommandSafe_FileReadCommands(t *testing.T) {
	r := fileReadRules()

	tests := []struct {
		command string
		safe    bool
		desc    string
	}{
		// Safe: reading log files
		{"tail -f /var/log/app.log", true, "tail log file"},
		{"tail -100 /var/log/app.log", true, "tail with line count"},
		{"head -50 /var/log/app.log", true, "head log file"},
		{"cat /var/log/app.log", true, "cat log file"},
		{"grep ERROR /var/log/app.log", true, "grep log file"},
		{"grep -i error /var/log/app.log", true, "grep with flags"},
		{"grep error.occurred /var/log/app.log", true, "grep pattern with dot"},
		{"cat app.log", true, "cat log without path"},
		{"tail -f app.log 2>&1", true, "log with safe redirect"},

		// Safe: log file piped
		{"cat /var/log/app.log | grep ERROR", true, "cat log piped to grep"},
		{"tail -f /var/log/app.log | head -20", true, "tail log piped to head"},

		// Unsafe: reading non-log files
		{"cat /etc/passwd", false, "cat non-log file"},
		{"grep password /etc/shadow", false, "grep non-log file"},
		{"tail -f /var/data/output.txt", false, "tail non-log file"},
		{"head /home/user/config.py", false, "head non-log file"},

		// Unsafe: no file argument
		{"grep ERROR", false, "grep with no file"},
		{"cat", false, "cat with no file"},

		// Unsafe: mix of log and non-log files
		{"grep ERROR /var/log/app.log /etc/passwd", false, "grep with non-log arg that has /"},

		// Unsafe: cat/head/tail treat ALL non-flag args as files
		{"cat app.log passwd", false, "cat with sneaky extra file"},
		{"head app.log /etc/shadow", false, "head with non-log extra file"},
		{"tail app.log config.py", false, "tail with non-log extra file"},

		// Safe: grep's first non-flag arg is pattern, not a file
		{"grep passwd /var/log/auth.log", true, "grep pattern looks like filename"},
	}

	for _, tt := range tests {
		safe := r.IsLocalCommandSafe(tt.command)
		if safe != tt.safe {
			t.Errorf("[%s] IsCommandSafe(%q) = %v, want %v", tt.desc, tt.command, safe, tt.safe)
		}
	}
}

func blockedArgsRules() *Rules {
	return &Rules{
		SafeCommands: &SafeCommands{
			AllowedCommands:    []string{"find", "ls"},
			AllowedPipeTargets: []string{"head", "tail", "grep"},
			BlockedArgs: map[string][]string{
				"find": {"-exec", "-execdir", "-delete", "-ok", "-okdir"},
			},
		},
	}
}

func TestIsCommandSafe_BlockedArgs(t *testing.T) {
	r := blockedArgsRules()

	tests := []struct {
		command string
		safe    bool
		desc    string
	}{
		// Safe: find without dangerous args
		{"find . -name '*.py'", true, "find by name"},
		{"find /tmp -type f", true, "find by type"},
		{"find . -maxdepth 2 -name '*.log'", true, "find with maxdepth"},
		{"find . -name '*.py' -print", true, "find with print"},
		{"find . -name '*.py' | head", true, "find piped to head"},
		{"find . -name '*.py' | grep test", true, "find piped to grep"},

		// Unsafe: find with blocked args
		{"find . -exec rm {} ;", false, "find with -exec"},
		{"find . -name '*.tmp' -exec rm {} +", false, "find -exec with +"},
		{"find . -execdir mv {} /tmp ;", false, "find with -execdir"},
		{"find . -name '*.tmp' -delete", false, "find with -delete"},
		{"find . -ok rm {} ;", false, "find with -ok"},
		{"find . -okdir rm {} ;", false, "find with -okdir"},

		// Safe: ls is allowed and has no blocked args
		{"ls -la", true, "ls unaffected by blocked_args"},

		// Safe: blocked arg string in a non-blocked command
		{"ls -exec", true, "ls with -exec is fine (not blocked for ls)"},
	}

	for _, tt := range tests {
		safe := r.IsLocalCommandSafe(tt.command)
		if safe != tt.safe {
			t.Errorf("[%s] IsCommandSafe(%q) = %v, want %v", tt.desc, tt.command, safe, tt.safe)
		}
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
