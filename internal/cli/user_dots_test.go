package cli

import (
	"os"
	"strings"
	"testing"
)

// A user name may hold single periods between letters, digits, '_' and '-'
// (names.ValidateUsername): it is added, shown, listed and removed, and
// written to the store as a plain key, or quoted where YAML would read it as
// a number.
func TestUserNamesWithPeriods(t *testing.T) {
	sb := newSandbox(t, true)
	for _, name := range []string{"alice.smith", "a.b-c_d", "1.5", "1_0.5", "1.2.3"} {
		sb.run("", []string{"user", "add", name, "operator", "--hash", testHash, "--scopes", "lab"})
		sb.expect(0, "[INFO] User '"+name+"' added (operator) with scopes: lab", "")
	}
	store := sb.store()
	for _, want := range []string{"\n  alice.smith:\n", "\n  a.b-c_d:\n", "\n  '1.5':\n", "\n  '1_0.5':\n", "\n  1.2.3:\n"} {
		if !strings.Contains(store, want) {
			t.Errorf("store lacks %q:\n%s", want, store)
		}
	}
	for _, name := range []string{"alice.smith", "1.5", "1_0.5"} {
		sb.run("", []string{"user", "show", name})
		sb.expect(0, "User:             "+name, "")
	}
	sb.run("", []string{"user", "list"})
	sb.expect(0, "alice.smith", "")
	sb.run("", []string{"config", "validate"})
	if sb.code != 0 {
		t.Errorf("config validate: %d\n%s%s", sb.code, sb.out.String(), sb.err.String())
	}
	sb.run("", []string{"user", "disable", "alice.smith"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "enable", "alice.smith"})
	sb.expect(0, "", "")
	sb.run("y\n", []string{"user", "remove", "alice.smith"})
	sb.expect(0, "", "")
	if strings.Contains(sb.store(), "alice.smith") {
		t.Errorf("alice.smith is still in the store:\n%s", sb.store())
	}
}

// The period rule is the shape rule: the bad shapes are refused by every
// command that takes a user name, with the new text, and change nothing.
func TestUserNamesWithBadPeriods(t *testing.T) {
	const want = "Username must contain only letters, numbers, underscores, hyphens, and periods (not first, not last, not two in a row)."
	sb := newSandbox(t, true)
	before := sb.store()
	for _, name := range []string{".alice", "alice.", "alice..smith", ".", ".."} {
		sb.run("", []string{"user", "add", name, "operator", "--hash", testHash})
		sb.expect(1, "", want)
		sb.run("", []string{"user", "show", name})
		sb.expect(1, "", want)
		sb.run("", []string{"user", "rename", "bob", name})
		sb.expect(1, "", want)
	}
	if sb.store() != before {
		t.Error("the store changed")
	}
	// Reserved names stay reserved, with or without a period beside them.
	sb.run("", []string{"user", "add", "root", "operator", "--hash", testHash})
	sb.expect(1, "", "Username 'root' is reserved")
	sb.run("", []string{"user", "add", "tacquito", "operator", "--hash", testHash})
	sb.expect(1, "", "Username 'tacquito' is reserved")
	sb.run("", []string{"user", "add", "Alice.Smith", "operator", "--hash", testHash})
	sb.expect(1, "", "Names are lower case: use 'alice.smith'.")
}

// A name with a period is no Linux account name, so a user that has an
// account (a UID in linux-uids) is not renamed to one, and no UID is
// assigned to one; a user with none is renamed.
func TestUserPeriodsAndLinuxAccounts(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-uids", "alice:80001\n", 0o600)
	before := sb.store()
	sb.run("", []string{"user", "rename", "alice", "alice.smith"})
	sb.expect(1, "", "'alice.smith' cannot be a Linux account name (a period is not allowed), and 'alice' has an account on hosts (or a UID in linux-uids) that the rename would remove. Nothing was changed.")
	if sb.store() != before {
		t.Error("the store changed")
	}
	if got := uidLines(sb); got != "alice:80001\n" {
		t.Errorf("linux-uids: %q", got)
	}
	sb.run("", []string{"user", "rename", "bob", "bob.jones"})
	sb.expect(0, "User renamed: bob -> bob.jones", "")
	sb.run("", []string{"config", "linux", "uid", "bob.jones", "80050"})
	sb.expect(1, "", "'bob.jones' has no Linux account: a period is not allowed in a Linux account name")
	sb.run("", []string{"config", "linux", "uid", "bob.jones"})
	sb.expect(1, "", "No UID assigned to 'bob.jones' yet.")
	if got := uidLines(sb); got != "alice:80001\n" {
		t.Errorf("linux-uids: %q", got)
	}
	// And back to a name that can be an account.
	sb.run("", []string{"user", "rename", "bob.jones", "bob"})
	sb.expect(0, "User renamed: bob.jones -> bob", "")
}

// uidLines are the entries of linux-uids, without its comment lines.
func uidLines(sb *sandbox) string {
	b, _ := os.ReadFile(sb.path("state/linux-uids"))
	var out strings.Builder
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out.WriteString(l)
		}
	}
	return out.String()
}
