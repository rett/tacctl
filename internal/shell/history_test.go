package shell

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct{ line, want string }{
		{"user list", "user list"},
		{"scope secret lab show", "scope secret lab show"},
		{"scope secret lab generate", "scope secret lab generate"},
		{"scope secret lab set x", "scope secret lab set …(redacted)"},
		{"scope secret lab set 'a b c'", "scope secret lab set …(redacted)"},
		{"scope secret set x", "scope secret set …(redacted)"},
		{"scope add lab --prefixes 10.0.0.0/8 --secret abc --default", "scope add lab --prefixes 10.0.0.0/8 --secret …(redacted)"},
		{"scope add lab --secret=abc", "scope add lab --secret=…(redacted)"},
		{"user add bob ops --hash $2b$12$abc", "user add bob ops --hash …(redacted)"},
		{"user passwd bob --hash=24326224", "user passwd bob --hash=…(redacted)"},
		{"user add bob ops --password pw", "user add bob ops --password …(redacted)"},
		{"store import /tmp/legacy.yaml", "store import …(redacted)"},
		{"store import", "store import"},
		{"device import devices.csv", "device import …(redacted)"},
		{"passwd", "passwd …(redacted)"},
		{"passwd oops-my-password", "passwd …(redacted)"},
		{"user show 'a b'", "user show 'a b'"},
		{"scope add 'my lab' --secret x", "scope add 'my lab' --secret …(redacted)"},
		// A line that does not tokenize is judged by its fields.
		{"scope secret lab set 'abc", "scope secret lab set …(redacted)"},
		{"  ", "  "},
		// a leading command is kept as typed and is no part of the verb
		{"tacctl user list", "tacctl user list"},
		{"tacctl passwd secret", "tacctl passwd …(redacted)"},
		{"sudo tacctl passwd secret", "sudo tacctl passwd …(redacted)"},
		{"/usr/local/bin/tacctl user add bob ops --hash x", "/usr/local/bin/tacctl user add bob ops --hash …(redacted)"},
		{"tacctl scope secret lab set x", "tacctl scope secret lab set …(redacted)"},
		{"tacctl", "tacctl"},
		{"sudo tacctl", "sudo tacctl"},
		// an email address is personal data: the flag's value and the word
		// of 'user email' are not kept
		{"user add bob ops --email bob@example.net", "user add bob ops --email …(redacted)"},
		{"user add bob ops --email=bob@example.net --hash x", "user add bob ops --email=…(redacted)"},
		{"user email bob alice@example.net", "user email bob …(redacted)"},
		{"user email bob alice@example.net extra", "user email bob …(redacted)"},
		{"user email alice@example.net", "user email …(redacted)"},
		{"user email alice@example.net bob@example.net", "user email …(redacted)"},
		{"tacctl user email bob carol@example.net", "tacctl user email bob …(redacted)"},
		{"user email bob", "user email bob"},
		{"user email bob clear", "user email bob clear"},
		{"user email", "user email"},
		// a word with an '@' in any other user verb is an address in the place of
		// a name; the line is kept up to it
		{"user remove alice@example.net", "user remove …(redacted)"},
		{"user show alice@example.net", "user show …(redacted)"},
		{"user rename bob alice@example.net", "user rename bob …(redacted)"},
		{"user move alice@example.net operator", "user move …(redacted)"},
		{"user move bob alice@example.net", "user move bob …(redacted)"},
		{"user scope bob add lab,alice@example.net", "user scope bob add …(redacted)"},
		{"user add zed alice@example.net", "user add zed …(redacted)"},
		{"user add alice@example.net operator --hash x", "user add …(redacted)"},
		{"user add zed operator --scopes alice@example.net", "user add zed operator --scopes …(redacted)"},
		{"user passwd alice@example.net --hash x", "user passwd …(redacted)"},
		{"user require-password-change bob alice@example.net", "user require-password-change bob …(redacted)"},
		{"user add zed ops --hash x --email alice@example.net", "user add zed ops --hash …(redacted)"},
		{"user show bob", "user show bob"},
		// the note of a kept snapshot is free text
		{"backup keep 20261030_010101_001 --note before the upgrade", "backup keep 20261030_010101_001 --note …(redacted)"},
		{"backup keep 20261030_010101_001 --note='the state of bob' --yes", "backup keep 20261030_010101_001 --note=…(redacted)"},
		{"backup keep 20261030_010101_001", "backup keep 20261030_010101_001"},
	}
	for _, c := range cases {
		if got := Redact(c.line); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestHistoryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "tacctl", "history")
	h := NewHistory(path, nil)
	h.Add("user list")
	h.Add("user list") // a repeat of the newest is not recorded
	h.Add("   ")
	h.Add("scope secret lab set hunter2")
	h.Add("user show a\nb")
	interrupted := true
	h.skip = func() bool { return interrupted }
	h.Add("group list")
	interrupted = false
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("history mode %v, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Errorf("history directory mode %v, want 0700", di.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	want := "user list\nscope secret lab set …(redacted)\nuser show a\\nb\n"
	if string(b) != want {
		t.Errorf("history file = %q, want %q", b, want)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Error("the secret reached the file")
	}
	if h.Len() != 3 || h.At(0) != `user show a\nb` || h.At(2) != "user list" {
		t.Errorf("entries = %q", h.Entries())
	}
	// A new session loads the file.
	h2 := NewHistory(path, nil)
	if got := h2.Entries(); len(got) != 3 || got[1] != "scope secret lab set …(redacted)" {
		t.Errorf("reloaded = %q", got)
	}
}

func TestHistoryKeepsTheNewest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	var lines []string
	for i := range HistoryMax + 5 {
		lines = append(lines, fmt.Sprintf("user show u%d", i))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewHistory(path, nil)
	if h.Len() != HistoryMax || h.At(HistoryMax-1) != "user show u5" {
		t.Fatalf("loaded %d, oldest %q", h.Len(), h.At(h.Len()-1))
	}
	h.Add("group list")
	b, _ := os.ReadFile(path)
	got := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(got) != HistoryMax || got[0] != "user show u6" || got[len(got)-1] != "group list" {
		t.Errorf("file has %d lines, first %q, last %q", len(got), got[0], got[len(got)-1])
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("rewritten history mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestHistoryWarnsOnce(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var warn bytes.Buffer
	h := NewHistory(filepath.Join(blocker, "history"), &warn)
	h.Add("user list")
	h.Add("group list")
	if n := strings.Count(warn.String(), "history not saved"); n != 1 {
		t.Errorf("warnings: %q", warn.String())
	}
	if h.Len() != 2 {
		t.Errorf("memory history lost lines: %d", h.Len())
	}
}

func TestEscapeEntry(t *testing.T) {
	if got := escapeEntry("a\nb\rc\td\x1be\x7f"); got != `a\nb\rc\td\x1be\x7f` {
		t.Errorf("escapeEntry = %q", got)
	}
}
