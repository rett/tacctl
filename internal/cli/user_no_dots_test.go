package cli

import (
	"os"
	"strings"
	"testing"
)

// A user name is letters, digits, '_' and '-' (0.2.22): every user has an
// account on the tacctl server, and a name with a period cannot be a Linux
// account name. 0.2.20 and 0.2.21 allowed periods, so a store can still hold
// such a name; it is read, shown, listed, removed and renamed from.

const noDotsWant = "Username must contain only letters, numbers, underscores and hyphens (a period cannot be part of a Linux account name)."

// dottedSandbox is a sandbox whose store holds the user bob.jones (bob of the
// fixture) as 0.2.21 could write it.
func dottedSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  bob:", "  bob.jones:")
	return sb
}

// No command makes a name with a period: 'user add' and the new name of
// 'user rename' refuse it with the reason, whatever its shape, and change
// nothing.
func TestNewUserNamesHaveNoPeriods(t *testing.T) {
	sb := newSandbox(t, true)
	before := sb.store()
	for _, name := range []string{"alice.smith", "a.b-c_d", "1.5", "1.2.3", ".alice", "alice.", "alice..smith", ".", ".."} {
		sb.run("", []string{"user", "add", name, "operator", "--hash", testHash, "--scopes", "lab"})
		sb.expect(1, "", noDotsWant)
		sb.run("", []string{"user", "rename", "bob", name})
		sb.expect(1, "", noDotsWant)
	}
	for _, name := range []string{".alice", "alice..smith", "."} {
		sb.run("", []string{"user", "show", name})
		sb.expect(1, "", noDotsWant)
	}
	// A command that reads a user says there is none.
	sb.run("", []string{"user", "show", "alice.smith"})
	sb.expect(1, "", "User 'alice.smith' does not exist.")
	if sb.store() != before {
		t.Error("the store changed")
	}
	// The shape comes before the reserved names and the case rule.
	sb.run("", []string{"user", "add", "Alice.Smith", "operator", "--hash", testHash})
	sb.expect(1, "", noDotsWant)
	sb.run("", []string{"user", "add", "root", "operator", "--hash", testHash})
	sb.expect(1, "", "Username 'root' is reserved")
	// The names that are letters, digits, '_' and '-' still go.
	for _, name := range []string{"alice-smith", "a_b-c_d", "15", "j_smith2"} {
		sb.run("", []string{"user", "add", name, "operator", "--hash", testHash, "--scopes", "lab"})
		sb.expect(0, "[INFO] User '"+name+"' added (operator) with scopes: lab", "")
	}
}

// The password verbs take the rule for a name with a period: they refuse it
// with the reason. For a user that stands in the store they add the way out,
// and for a name that is not there they say only the rule.
func TestPasswordVerbsRefuseAPeriod(t *testing.T) {
	sb := dottedSandbox(t)
	before := sb.store()
	const rename = "rename it first: tacctl user rename bob.jones <new-name>"
	for _, args := range [][]string{
		{"user", "passwd", "bob.jones", "--hash", testHash},
		{"user", "require-password-change", "bob.jones"},
	} {
		sb.run("", args)
		sb.expect(1, "", noDotsWant)
		if !strings.Contains(plain(sb.err.String()), "[ERROR] "+rename+"\n") {
			t.Errorf("%v: no rename line:\n%s", args, sb.err.String())
		}
	}
	for _, args := range [][]string{
		{"user", "passwd", "ghost.name", "--hash", testHash},
		{"user", "require-password-change", "ghost.name"},
	} {
		sb.run("", args)
		sb.expect(1, "", noDotsWant)
		if strings.Contains(sb.err.String(), "rename it first") {
			t.Errorf("%v: a rename line for a user that is not there:\n%s", args, sb.err.String())
		}
	}
	sb.run("CorrectHorse99\n", []string{"passwd"}, "SUDO_USER=bob.jones")
	sb.expect(1, "", noDotsWant)
	if sb.store() != before {
		t.Error("the store changed")
	}
}

// 'config linux uid' reads the number of a user with a period (the ledger can
// hold one) and refuses to give it one: the user has no Linux account.
func TestLinuxUIDForADottedUser(t *testing.T) {
	sb := dottedSandbox(t)
	before := sb.store()
	sb.run("", []string{"config", "linux", "uid", "bob.jones"})
	sb.expect(1, "", "No UID assigned to 'bob.jones' yet.")
	sb.write("state/linux-uids", "bob.jones:80001\n", 0o600)
	sb.run("", []string{"config", "linux", "uid", "bob.jones"})
	sb.expect(0, "80001", "")
	sb.run("", []string{"config", "linux", "uid", "bob.jones", "80050"})
	sb.expect(1, "", "'bob.jones' has no Linux account: a period is not allowed in a Linux account name, so no host gets one and a UID would never be used. Nothing was changed.")
	if got := uidLines(sb); got != "bob.jones:80001\n" {
		t.Errorf("linux-uids: %q", got)
	}
	// a name with a bad shape is refused with the rule
	sb.run("", []string{"config", "linux", "uid", ".bob", "80050"})
	sb.expect(1, "", noDotsWant)
	if sb.store() != before {
		t.Error("the store changed")
	}
}

// A stored name with periods is shown by 'user verify' like any other, and
// the reserved names stay reserved around the lenient check: 'root.x' is a
// name that can stand and be removed, 'root' cannot be renamed to.
func TestDottedUserVerifyAndReservedNames(t *testing.T) {
	sb := dottedSandbox(t)
	sb.run("wrong-password\n", []string{"user", "verify", "bob.jones"})
	sb.expect(0, "bob.jones", "")
	sb.legacyStoreCase("  carol:", "  root.x:")
	sb.run("", []string{"user", "show", "root.x"})
	sb.expect(0, "User:             root.x", "")
	sb.run("", []string{"user", "rename", "root.x", "root"})
	sb.expect(1, "", "Username 'root' is reserved")
	sb.run("", []string{"user", "add", "root.y", "operator", "--hash", testHash})
	sb.expect(1, "", noDotsWant)
	sb.run("y\n", []string{"user", "remove", "root.x"})
	sb.expect(0, "", "")
}

// The rollback to 0.2.20, which reads a name with periods, is not held up by
// one; every other target is (TestRollbackRefusesDottedUsersCLI).
func TestRollbackTo0220IgnoresADottedUser(t *testing.T) {
	hs := rollbackState(t)
	hs.step("", "user", "add", "alice-smith", "operator", "--hash", testHash, "--scopes", "lab")
	hs.legacyStoreCase("  alice-smith:", "  alice.smith:")
	hs.run(hs.runner(), "rollback", "0.2.20")
	hs.expect(0, "Roll back to 0.2.20 (dry run)", "")
	if strings.Contains(hs.all(), "whose name has a period") {
		t.Errorf("0.2.20 was refused for the user:\n%s", hs.all())
	}
}

// A store a release before 0.2.22 wrote keeps loading: every store command
// runs with the user in it, the user is shown, listed, disabled, enabled,
// moved, given a scope and removed.
func TestDottedUserIsStillRead(t *testing.T) {
	sb := dottedSandbox(t)
	sb.run("", []string{"user", "list"})
	sb.expect(0, "bob.jones", "")
	sb.run("", []string{"user", "show", "bob.jones"})
	sb.expect(0, "User:             bob.jones", "")
	sb.run("", []string{"user", "disable", "bob.jones"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "enable", "bob.jones"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "scope", "bob.jones", "add", "dmz"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "move", "bob.jones", "readonly"})
	sb.expect(0, "", "")
	// another user is added and the store is written again with the dotted
	// user in it
	sb.run("", []string{"user", "add", "dave", "operator", "--hash", testHash, "--scopes", "lab"})
	sb.expect(0, "[INFO] User 'dave' added (operator) with scopes: lab", "")
	if !strings.Contains(sb.store(), "\n  bob.jones:\n") {
		t.Errorf("the store lost the user:\n%s", sb.store())
	}
	sb.run("y\n", []string{"user", "remove", "bob.jones"})
	sb.expect(0, "", "")
	if strings.Contains(sb.store(), "bob.jones") {
		t.Errorf("bob.jones is still in the store:\n%s", sb.store())
	}
}

// 'user rename' still runs from a name with a period, to a name that is
// letters, digits, '_' and '-': the UID follows it, and what the old name
// had is carried. The new name cannot have a period.
func TestDottedUserRenameFrom(t *testing.T) {
	sb := dottedSandbox(t)
	sb.write("state/linux-uids", "bob.jones:80001\n", 0o600)
	before := sb.store()
	sb.run("", []string{"user", "rename", "bob.jones", "bob.j"})
	sb.expect(1, "", noDotsWant)
	sb.run("", []string{"user", "rename", "bob.jones", "alice"})
	sb.expect(1, "", "User 'alice' already exists.")
	if sb.store() != before {
		t.Error("the store changed")
	}
	sb.run("", []string{"user", "rename", "bob.jones", "bob-jones"})
	sb.expect(0, "User renamed: bob.jones -> bob-jones", "")
	if s := sb.store(); !strings.Contains(s, "\n  bob-jones:\n") || strings.Contains(s, "bob.jones") {
		t.Errorf("the store:\n%s", s)
	}
	if got := uidLines(sb); got != "bob-jones:80001\n" {
		t.Errorf("linux-uids: %q", got)
	}
	sb.run("", []string{"config", "validate"})
	sb.expect(0, "", "")
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

// 'tacctl rollback' to any target is refused, nothing changed, while the
// store has a user with a period in its name (no release a rollback goes to
// reads one); once the user is renamed it plans again. The user is one a
// restored snapshot of 0.2.20 or 0.2.21 brings back.
func TestRollbackRefusesDottedUsersCLI(t *testing.T) {
	hs := rollbackState(t)
	hs.step("", "user", "add", "alice-smith", "operator", "--hash", testHash, "--scopes", "lab")
	hs.legacyStoreCase("  alice-smith:", "  alice.smith:")
	before := tree(t, hs.dir)
	for _, v := range []string{"0.2.3", "0.2.9", "0.2.16", "0.2.17", "0.2.18", "0.2.19"} {
		for _, args := range [][]string{{"rollback", v}, {"rollback", v, "--apply", "--yes"}} {
			hs.run(hs.runner(), args...)
			hs.expect(1, "", "The store has 1 user whose name has a period")
			if !strings.Contains(hs.all(), "  alice.smith   (tacctl user rename alice.smith <new-name>)") ||
				!strings.Contains(hs.all(), "Nothing was changed.") {
				t.Errorf("%v: %s", args, hs.all())
			}
			if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
				t.Errorf("%v changed %q", args, got)
			}
		}
	}
	hs.step("", "user", "rename", "alice.smith", "alice-smith")
	hs.run(hs.runner(), "rollback", "0.2.18")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
}
