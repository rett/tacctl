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

// 'tacctl rollback' to any target is refused, nothing changed, while the
// store has a user with a period in its name (no release a rollback goes to
// reads one); once the user is renamed it plans again.
func TestRollbackRefusesDottedUsersCLI(t *testing.T) {
	hs := rollbackState(t)
	hs.step("", "user", "add", "alice.smith", "operator", "--hash", testHash, "--scopes", "lab")
	before := tree(t, hs.dir)
	for _, v := range []string{"0.2.3", "0.2.9", "0.2.16", "0.2.17", "0.2.18"} {
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

// A user with an account on an enrolled host and no UID of its own in
// linux-uids is not renamed to a name with a period either: the hosts, not
// only the ledger, are what the rename would cost.
func TestUserRenameDottedAccountOnHostsNoUID(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	before := sb.store()
	sb.run("", []string{"user", "rename", "bob", "bob.jones"})
	sb.expect(1, "", "'bob.jones' cannot be a Linux account name (a period is not allowed), and 'bob' has an account on hosts (or a UID in linux-uids) that the rename would remove. Nothing was changed.")
	if sb.store() != before {
		t.Error("the store changed")
	}
	if got := uidLines(sb); got != "" {
		t.Errorf("linux-uids: %q", got)
	}
	// carol is in the scope lab too; bob is not in prod, so with only a prod
	// host enrolled he is renamed.
	sb.run("", []string{"user", "rename", "carol", "carol.lee"})
	sb.expect(1, "", "has an account on hosts")
	sb.write("state/linux-hosts", "web1|admin@web1.example.net||prod|192.0.2.1|\n", 0o600)
	sb.run("", []string{"user", "rename", "bob", "bob.jones"})
	sb.expect(0, "User renamed: bob -> bob.jones", "")
}

// The guard fails closed: a host registry that cannot be read leaves the
// hosts unknown, so the rename to a name with a period is refused with the
// read error and nothing changes; a rename to a name without one is not
// held up by it.
func TestUserRenameDottedRegistryUnreadable(t *testing.T) {
	sb := newSandbox(t, true)
	if err := os.MkdirAll(sb.path("state", "linux-hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := sb.store()
	sb.run("", []string{"user", "rename", "bob", "bob.jones"})
	sb.expect(1, "", "'bob.jones' has a period, so 'bob' would lose its account on every enrolled host, and the hosts that have it cannot be told: ")
	if !strings.Contains(plain(sb.err.String()), "linux-hosts") || !strings.Contains(plain(sb.err.String()), "Nothing was changed.") {
		t.Errorf("stderr %q", sb.err.String())
	}
	if sb.store() != before {
		t.Error("the store changed")
	}
	// A name with no period never needed the registry.
	sb.run("", []string{"user", "rename", "bob", "bobby"})
	sb.expect(0, "User renamed: bob -> bobby", "")
}
