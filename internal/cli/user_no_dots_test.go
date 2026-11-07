package cli

import (
	"strings"
	"testing"
)

// A user name is letters, digits, '_' and '-': every user has an account on
// the tacctl server, and a name with a period cannot be a Linux account name.
// 0.2.20 and 0.2.21 allowed periods; the upgrade renames such a user
// (internal/lifecycle/upgrade_dots.go), and no command makes or accepts one.

const noDotsWant = "Username must contain only letters, numbers, underscores and hyphens (a period cannot be part of a Linux account name)."

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
	if sb.store() != before {
		t.Error("the store changed")
	}
	// The shape comes before the reserved names and the case rule.
	sb.run("", []string{"user", "add", "Alice.Smith", "operator", "--hash", testHash})
	sb.expect(1, "", noDotsWant)
	sb.run("", []string{"user", "add", "root", "operator", "--hash", testHash})
	sb.expect(1, "", "Username 'root' is reserved")
	sb.run("", []string{"user", "rename", "bob", "root.x"})
	sb.expect(1, "", noDotsWant)
	sb.run("", []string{"user", "rename", "bob", "root"})
	sb.expect(1, "", "Username 'root' is reserved")
	// The names that are letters, digits, '_' and '-' still go.
	for _, name := range []string{"alice-smith", "a_b-c_d", "15", "j_smith2"} {
		sb.run("", []string{"user", "add", name, "operator", "--hash", testHash, "--scopes", "lab"})
		sb.expect(0, "[INFO] User '"+name+"' added (operator) with scopes: lab", "")
	}
}

// Every verb that takes a user name refuses one with a period with the same
// reason, whether the user exists or not, and changes nothing.
func TestEveryUserVerbRefusesAPeriod(t *testing.T) {
	sb := newSandbox(t, true)
	before := sb.store()
	for _, args := range [][]string{
		{"user", "show", "bob.jones"},
		{"user", "remove", "bob.jones"},
		{"user", "email", "bob.jones"},
		{"user", "email", "bob.jones", "bob@example.net"},
		{"user", "reports-limit", "bob.jones"},
		{"user", "passwd", "bob.jones", "--hash", testHash},
		{"user", "disable", "bob.jones"},
		{"user", "enable", "bob.jones"},
		{"user", "rename", "bob.jones", "bob-jones"},
		{"user", "move", "bob.jones", "readonly"},
		{"user", "verify", "bob.jones"},
		{"user", "require-password-change", "bob.jones"},
		{"user", "scope", "bob.jones", "list"},
		{"user", "scope", "bob.jones", "add", "lab"},
		{"config", "linux", "uid", "bob.jones"},
		{"config", "linux", "uid", "bob.jones", "80050"},
	} {
		sb.run("", args)
		sb.expect(1, "", noDotsWant)
		if strings.Contains(sb.err.String(), "rename it first") {
			t.Errorf("%v: a rename line:\n%s", args, sb.err.String())
		}
	}
	sb.run("CorrectHorse99\n", []string{"passwd"}, "SUDO_USER=bob.jones")
	sb.expect(1, "", noDotsWant)
	if sb.store() != before {
		t.Error("the store changed")
	}
	// A name that is not there, and has no period, is only absent.
	sb.run("", []string{"user", "show", "ghost"})
	sb.expect(1, "", "User 'ghost' does not exist.")
}

// A store a release before 0.2.22 wrote can still hold a name with a period
// until the upgrade renames it. No store write goes through with it in the
// store, and the message says the upgrade renames it; the user verbs do not
// take the name, so the way out is the upgrade.
func TestLeftoverDottedUserIsInvalidUntilTheUpgrade(t *testing.T) {
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  bob:", "  bob.jones:")
	before := sb.store()
	sb.run("", []string{"user", "disable", "bob.jones"})
	sb.expect(1, "", noDotsWant)
	const hint = "user 'bob.jones': invalid name (a period cannot be part of a Linux account name; 'tacctl upgrade' renames such a user)"
	sb.run("", []string{"user", "add", "dave", "operator", "--hash", testHash, "--scopes", "lab"})
	sb.expect(1, "", hint)
	if sb.store() != before {
		t.Error("the store changed")
	}
	sb.run("", []string{"config", "validate"})
	if sb.code != 1 || !strings.Contains(plain(sb.out.String()+sb.err.String()), hint) {
		t.Errorf("config validate: exit %d\n%s%s", sb.code, sb.out.String(), sb.err.String())
	}
}
