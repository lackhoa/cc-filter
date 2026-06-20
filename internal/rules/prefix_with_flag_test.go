package rules

import (
	"testing"
)

func TestPrefixWithFlag(t *testing.T) {
	r := &Rules{
		SafeCommands: &SafeCommands{
			Prefixes:           []string{"crontab -l", "mkdir -p"},
			AllowedPipeTargets: []string{"head", "tail", "grep"},
		},
	}
	tests := []struct {
		cmd  string
		safe bool
		desc string
	}{
		// crontab -l: allowed
		{`crontab -l`, true, "plain crontab -l"},
		{`crontab -l 2>&1`, true, "crontab -l with stderr merge"},
		{`crontab -l | head`, true, "crontab -l piped"},
		{`ssh u6 crontab -l`, true, "ssh + crontab -l"},
		{`ssh u6 "crontab -l"`, true, "ssh + quoted crontab -l"},
		{`ssh u6 "crontab -l" 2>&1`, true, "ssh + quoted + 2>&1"},

		// crontab with other flags: NOT allowed
		{`crontab -r`, false, "crontab -r (remove) not allowed"},
		{`crontab -e`, false, "crontab -e (edit) not allowed"},
		{`crontab`, false, "bare crontab not allowed"},

		// crontab -l with extra flags: allowed (extra flags skipped)
		{`crontab -u root -l`, true, "crontab -u root -l allowed"},

		// mkdir -p: allowed
		{`mkdir -p /tmp/foo`, true, "mkdir -p with path"},
		{`mkdir /tmp/foo`, false, "mkdir without -p not allowed"},
	}
	for _, tt := range tests {
		got := r.IsLocalCommandSafe(tt.cmd)
		if got != tt.safe {
			t.Errorf("[%s] IsLocalCommandSafe(%q) = %v, want %v", tt.desc, tt.cmd, got, tt.safe)
		}
	}
}
