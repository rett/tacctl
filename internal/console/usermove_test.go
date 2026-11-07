package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// RenameUsers reads a file that holds user names with a period (0.2.20 and
// 0.2.21 allowed them; Load refuses them now), carries the system shell, the
// password cache and the ignored override to the new names in one write, and
// leaves the other users and settings as they are. The file it writes passes
// Load. A second run changes nothing.
func TestRenameUsersCarriesTheSettings(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "console.yaml", `version: 1
users: {alice.smith: enable, bob: disable}
settings:
  idle_timeout: 12
  system_shell_users: {alice.smith: 'enable:operator', bob: disable, carol.jones: disable}
  password_cache_users: {alice.smith: true, carol.jones: true}
`, 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("Load reads a name with a period")
	}
	renames := []UserRename{{"alice.smith", "alice_smith"}, {"carol.jones", "carol_jones"}, {"dave.x", "dave_x"}}
	moves, err := RenameUsers(p, renames)
	if err != nil {
		t.Fatal(err)
	}
	if !moves[0].ShellHad || !moves[0].ShellOn || !moves[0].CacheHad || !moves[1].ShellHad || moves[1].ShellOn || !moves[1].CacheHad || moves[2].Had() {
		t.Errorf("moves %+v", moves)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatalf("the file written is not read: %v", err)
	}
	if !f.SystemShellUsers["alice_smith"] || f.SystemShellUserTiers["alice_smith"] != tier.Operator || f.SystemShellUsers["carol_jones"] || len(f.SystemShellUsers) != 3 ||
		!f.PasswordCacheUsers["alice_smith"] || !f.PasswordCacheUsers["carol_jones"] || len(f.PasswordCacheUsers) != 2 ||
		!f.IgnoredUsers["alice_smith"] || f.IgnoredUsers["bob"] || len(f.IgnoredUsers) != 2 || f.Idle != 12 {
		t.Errorf("after: %+v", f)
	}
	if got, _ := os.ReadFile(p); strings.Contains(string(got), ".") && strings.Contains(string(got), "alice.smith") {
		t.Errorf("a name with a period is left:\n%s", got)
	}
	first, _ := os.ReadFile(p)
	if _, err := RenameUsers(p, renames); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(first) {
		t.Errorf("a second run changed the file:\n%s", again)
	}
}

// A file that is absent is not created, and a name with a period that is not
// among the renames is refused when the file is written, with the file as it
// was.
func TestRenameUsersEdges(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "none.yaml")
	if moves, err := RenameUsers(missing, []UserRename{{"a.b", "a_b"}}); err != nil || len(moves) != 1 || moves[0].Had() {
		t.Fatalf("absent file: %v %v", moves, err)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("the file was created")
	}
	text := "version: 1\nsettings:\n  password_cache_users: {alice.smith: true}\n"
	p := write(t, dir, "console.yaml", text, 0o600)
	if _, err := RenameUsers(p, []UserRename{{"carol.jones", "carol_jones"}}); err == nil || !strings.Contains(err.Error(), "invalid user name 'alice.smith'") {
		t.Errorf("an unrenamed name: %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != text {
		t.Errorf("the file changed:\n%s", got)
	}
}
