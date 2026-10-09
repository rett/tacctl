package console

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/tier"
)

func TestIsConsole(t *testing.T) {
	cases := map[string]bool{
		"tacctl-console":                true,
		"-tacctl-console":               true,
		"/usr/local/bin/tacctl-console": true,
		"tacctl":                        false,
		"-bash":                         false,
		"/usr/local/bin/tacctl":         false,
		"tacctl-console2":               false,
		"--tacctl-console":              false,
		"":                              false,
	}
	for argv0, want := range cases {
		if got := IsConsole(argv0); got != want {
			t.Errorf("IsConsole(%q) = %t, want %t", argv0, got, want)
		}
	}
}

func TestScrub(t *testing.T) {
	in := []string{
		"TERM=xterm", "LD_PRELOAD=/tmp/x.so", "HOME=/home/u", "TACCTL_SKIP_SUDO=1", "BASH_ENV=/tmp/e",
		"LC_ALL=C.UTF-8", "PATH=/tmp/evil:/usr/bin", "ENV=/tmp/e", "USER=u", "SSH_AUTH_SOCK=/tmp/a",
		"TACCTL_STATE_DIR=/tmp/s", "SHELL=/bin/sh", "LANG=C", "LOGNAME=u", "SSH_CONNECTION=a b c d",
		"SSH_CLIENT=192.0.2.9 5 22", "SSH_TTY=/dev/pts/3", "LD_LIBRARY_PATH=/tmp", "noequals", "TERM=vt100",
	}
	got := Scrub(in, "/usr/local/bin/tacctl-console", false)
	want := []string{
		"TERM=vt100", "HOME=/home/u", "LC_ALL=C.UTF-8", "USER=u", "LANG=C", "LOGNAME=u",
		"SSH_CONNECTION=a b c d", "SSH_CLIENT=192.0.2.9 5 22", "SSH_TTY=/dev/pts/3",
		"PATH=" + ConsolePath, "SHELL=/usr/local/bin/tacctl-console",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Scrub:\n got %q\nwant %q", got, want)
	}
	if again := Scrub(got, "/usr/local/bin/tacctl-console", false); !slices.Equal(again, got) {
		t.Errorf("Scrub is not idempotent: %q", again)
	}
	// The test knob keeps TACCTL_* and the PATH.
	kept := Scrub(in, "/c", true)
	for _, kv := range []string{"TACCTL_SKIP_SUDO=1", "TACCTL_STATE_DIR=/tmp/s", "PATH=/tmp/evil:/usr/bin", "SHELL=/c"} {
		if !slices.Contains(kept, kv) {
			t.Errorf("keepTest: %q missing from %q", kv, kept)
		}
	}
	for _, kv := range kept {
		if strings.HasPrefix(kv, "LD_") || strings.HasPrefix(kv, "BASH_ENV") || strings.HasPrefix(kv, "ENV=") {
			t.Errorf("keepTest kept %q", kv)
		}
	}
	if again := Scrub(kept, "/c", true); !slices.Equal(again, kept) {
		t.Errorf("Scrub(keepTest) is not idempotent: %q", again)
	}
}

func TestShellEnv(t *testing.T) {
	got := ShellEnv([]string{"TERM=x", "TACCTL_SKIP_SUDO=1", "SHELL=/usr/local/bin/tacctl-console", "PATH=/bin"}, "/bin/bash")
	want := []string{"TERM=x", "PATH=/bin", "SHELL=/bin/bash"}
	if !slices.Equal(got, want) {
		t.Errorf("ShellEnv = %q, want %q", got, want)
	}
}

func TestGuard(t *testing.T) {
	known := func(w string) bool { return slices.Contains([]string{"user", "device", "ssh", "log"}, w) }
	cases := []struct {
		line, first string
		ok          bool
	}{
		{"user list", "user", true},
		{"help device", "help", true},
		{"help", "help", true},
		{"ssh core-sw1", "ssh", true},
		{"'user' list", "user", true},
		// A metacharacter is part of a word: tacctl gets 'user "list;" id'.
		{"user list; id", "user", true},
		{"scp -t .", "scp", false},
		{"/usr/lib/openssh/sftp-server", "/usr/lib/openssh/sftp-server", false},
		{"rsync --server -vlogDtpre.iLsfxC . /tmp", "rsync", false},
		{"bash", "bash", false},
		{"sh -c id", "sh", false},
		{"system-shell", "system-shell", false},
		{"exit", "exit", false},
		{"quit", "quit", false},
		{"history", "history", false},
		{"", "", false},
		{"   ", "", false},
		{"user list\nbash", "user", false},
		{"user list\rbash", "user", false},
		{"user 'list", "user", false},
		{"user list\\", "user", false},
		{"_console-policy", "_console-policy", false},
		{"user " + strings.Repeat("x", 4100), "user", false},
	}
	for _, c := range cases {
		first, ok := Guard(c.line, known)
		if ok != c.ok || first != c.first {
			t.Errorf("Guard(%.40q) = %q, %t; want %q, %t", c.line, first, ok, c.first, c.ok)
		}
	}
	if _, ok := Guard("user list", nil); ok {
		t.Error("Guard without a command list let a command through")
	}
}

func TestSessionIDAndLogValues(t *testing.T) {
	id, err := NewSessionID(bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}))
	if err != nil || id != "deadbeef0102" || !ValidSessionID(id) {
		t.Fatalf("NewSessionID = %q, %v", id, err)
	}
	if _, err := NewSessionID(bytes.NewReader([]byte{1})); err == nil {
		t.Error("a short read gave an id")
	}
	for v, want := range map[string]string{"deadbeef0102": "deadbeef0102", "x y": "?", "": "?", "DEADBEEF0102": "?"} {
		if got := MarkerValue(v); got != want {
			t.Errorf("MarkerValue(%q) = %q, want %q", v, got, want)
		}
	}
	for v, want := range map[string]string{
		"": "-", "alice": "alice", "/dev/pts/3": "/dev/pts/3", "a b\nc=d": "a?b?c?d",
		strings.Repeat("a", 70): strings.Repeat("a", 64), "2001:db8::1": "2001:db8::1",
	} {
		if got := LogValue(v); got != want {
			t.Errorf("LogValue(%q) = %q, want %q", v, got, want)
		}
	}
	if ClientAddr("192.0.2.9 50000 22") != "192.0.2.9" || ClientAddr("") != "" {
		t.Error("ClientAddr")
	}
	s := Session{ID: "deadbeef0102", User: "carol", From: "192.0.2.9", TTY: "", Mode: ModeInteractive}
	for got, want := range map[string]string{
		s.StartLine():                           "console start session=deadbeef0102 user=carol from=192.0.2.9 tty=- mode=interactive",
		s.EndLine(ReasonIdle, 3, 0):             "console end session=deadbeef0102 user=carol reason=idle lines=3 status=0",
		s.DenyLine("scp"):                       "console DENY session=deadbeef0102 user=carol reason=command first=scp",
		s.DenyLine(""):                          "console DENY session=deadbeef0102 user=carol reason=command first=-",
		s.SystemShellDenyLine("readonly"):       "console system-shell DENY session=deadbeef0102 user=carol tier=readonly",
		s.SystemShellStartLine("/bin/bash"):     "console system-shell start session=deadbeef0102 user=carol tty=- shell=/bin/bash",
		s.SystemShellEndLine(0, 61*time.Second): "console system-shell end session=deadbeef0102 user=carol status=0 duration=61",
	} {
		if got != want {
			t.Errorf("log line\n got %q\nwant %q", got, want)
		}
	}
	if Seconds(-time.Second) != "0" {
		t.Error("a negative duration")
	}
}

func TestParseRemote(t *testing.T) {
	r, ok := ParseRemote("shell=console idle=5 system_shell=yes system_shell_path=/bin/zsh ssh_escape=yes agent=no tier=superuser list_max=12\n")
	want := Remote{Idle: 5 * time.Minute, SystemShell: true, SystemShellPath: "/bin/zsh", SSHEscape: true,
		Tier: tier.Superuser, ListMax: 12, SpaceCompletion: true, Known: true, TierRead: true}
	if !ok || r != want {
		t.Fatalf("ParseRemote = %+v, %t; want %+v", r, ok, want)
	}
	// Missing and malformed keys keep the defaults.
	r, ok = ParseRemote("idle=soon system_shell=maybe system_shell_path=bash tier=wizard list_max=0 agent=yes")
	d := DefaultRemote()
	d.Agent, d.Known = true, true
	if !ok || r != d {
		t.Errorf("malformed keys: %+v, want %+v", r, d)
	}
	// The space completion: on without the field (an older server), as the
	// field says otherwise; a malformed value keeps the default.
	for out, want := range map[string]bool{"idle=5": true, "space_completion=yes": true, "space_completion=no": false, "space_completion=off": true} {
		if r, _ := ParseRemote(out); r.SpaceCompletion != want {
			t.Errorf("ParseRemote(%q).SpaceCompletion = %t", out, r.SpaceCompletion)
		}
	}
	// The tier the shell lists for (D56): the gate's, else the tier field,
	// and none (read-only verbs only) when the answer was not read.
	for _, c := range []struct {
		out  string
		gate tier.Tier
		view tier.Tier
	}{
		{"tier=engineer gate=operator", tier.Operator, tier.Operator},
		{"tier=engineer", "", tier.Engineer},
		{"tier=operator gate=wizard", "", tier.Operator},
		{"gate=readonly", tier.Readonly, tier.Readonly},
		{"tier=unrestricted", "", tier.Unrestricted},
	} {
		r, ok := ParseRemote(c.out)
		if !ok || r.Gate != c.gate || r.View() != c.view {
			t.Errorf("ParseRemote(%q): gate %q view %q, want %q %q", c.out, r.Gate, r.View(), c.gate, c.view)
		}
	}
	if v := DefaultRemote().View(); v != tier.None {
		t.Errorf("the defaults' view = %q, want none", v)
	}
	// 'tier=none' is an answer (a disabled account); an answer without a
	// tier, or none at all, is not.
	for _, c := range []struct {
		out  string
		view tier.Tier
		read bool
	}{
		{"shell=system tier=none", tier.None, true},
		{"gate=none tier=operator", tier.None, true},
		{"tier=readonly", tier.Readonly, true},
		{"shell=console idle=30", tier.None, false},
		{"tier=wizard idle=30", tier.None, false},
		{"garbage", tier.None, false},
		{"", tier.None, false},
	} {
		r, _ := ParseRemote(c.out)
		if v, read := r.ViewRead(); v != c.view || read != c.read {
			t.Errorf("ParseRemote(%q).ViewRead() = %q, %t; want %q, %t", c.out, v, read, c.view, c.read)
		}
	}
	for _, out := range []string{"", "garbage", "sudo: a password is required"} {
		if r, ok := ParseRemote(out); ok || r != DefaultRemote() {
			t.Errorf("ParseRemote(%q) = %+v, %t", out, r, ok)
		}
	}
	if d := DefaultRemote(); d.Idle != 30*time.Minute || d.SystemShell || d.SSHEscape || d.ListMax != DefaultListMax || !d.SpaceCompletion {
		t.Errorf("defaults %+v", d)
	}
}

func TestForced(t *testing.T) {
	const cmd = "/usr/local/bin/tacctl-console"
	orig := func(v string) []string { return []string{"TERM=xterm", OriginalCommand + "=" + v} }
	for _, c := range []struct {
		argv, env, want []string
	}{
		// ForceCommand, no command: a login.
		{[]string{"tacctl-console", "-c", cmd}, []string{"TERM=xterm"}, []string{"tacctl-console"}},
		{[]string{"tacctl-console", "-c", "tacctl-console"}, nil, []string{"tacctl-console"}},
		// ForceCommand with the client's command, a subsystem, scp.
		{[]string{"tacctl-console", "-c", cmd}, orig("user list"), []string{"tacctl-console", "-c", "user list"}},
		{[]string{"tacctl-console", "-c", cmd}, orig("internal-sftp"), []string{"tacctl-console", "-c", "internal-sftp"}},
		{[]string{"tacctl-console", "-c", cmd}, orig(""), []string{"tacctl-console", "-c", ""}},
		// Anything else is left as it is.
		{[]string{"tacctl-console", "-c", "user list"}, orig("scp -t /"), []string{"tacctl-console", "-c", "user list"}},
		{[]string{"-tacctl-console"}, orig("x"), []string{"-tacctl-console"}},
		{[]string{"tacctl-console", "-c", cmd, "extra"}, nil, []string{"tacctl-console", "-c", cmd, "extra"}},
		{[]string{"tacctl-console", "-x", cmd}, nil, []string{"tacctl-console", "-x", cmd}},
	} {
		if got := Forced(c.argv, c.env, cmd); !slices.Equal(got, c.want) {
			t.Errorf("Forced(%q, %q) = %q, want %q", c.argv, c.env, got, c.want)
		}
	}
}
