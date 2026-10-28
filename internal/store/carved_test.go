package store

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCarvedLineAndUsers(t *testing.T) {
	l := CarvedLine(CarvedPasswordChange, "tacacs", []string{"carol", "bob"})
	if l != "# tacctl-carved reason=password-change protocol=tacacs users=bob,carol" {
		t.Errorf("line: %q", l)
	}
	p := filepath.Join(t.TempDir(), "f.yaml")
	text := "# --- Users ---\n" + l + "\n" + CarvedLine(CarvedLockdown, "tacacs", []string{"dave"}) + "\nusers:\n  # bob\n  - name: bob # tacctl-carved reason=x protocol=y users=zed\n"
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range CarvedUsers(p) {
		got = append(got, c.Reason+":"+c.Protocol+":"+c.User)
	}
	if want := []string{"password-change:tacacs:bob", "password-change:tacacs:carol", "lockdown:tacacs:dave"}; !slices.Equal(got, want) {
		t.Errorf("users: %v, want %v", got, want)
	}
	if CarvedUsers(filepath.Join(t.TempDir(), "none")) != nil {
		t.Error("a file that is not there names users")
	}
}
