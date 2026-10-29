package lifecycle_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/lifecycle"
)

const dottedUpgradeStore = "version: 1\nusers:\n  alice.smith:\n    group: operator\n  bob:\n    group: operator\n  a.b-c_d:\n    group: operator\n"

// A user name with a period (0.2.20 and 0.2.21 allowed it) stops the upgrade
// before it changes anything: each such user is named with the command that
// renames it, and the run does not go on to the backends, the state or the
// files. Once the users are renamed it goes through.
func TestUpgradeRefusesDottedUsers(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, dottedUpgradeStore)
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs]\n")
	beforeOverrides := readFile(t, o.p.Overrides)
	if code := upgrade(o); code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, o.stdout, o.stderr)
	}
	errs := stripANSI(o.stderr.String())
	for _, want := range []string{
		"The store has 2 users whose name has a period, which user names no longer hold:",
		"  a.b-c_d   (tacctl user rename a.b-c_d <new-name>)",
		"  alice.smith   (tacctl user rename alice.smith <new-name>)",
		"Rename the users first, then run the upgrade again. Nothing was changed.",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	for _, p := range o.phases {
		if !strings.HasSuffix(p, " upgrade preflight") {
			t.Errorf("phase %q ran after the refusal", p)
		}
	}
	if strings.Contains(o.text(), "tacctl Upgrade") || slices.ContainsFunc(o.phases, func(p string) bool { return strings.Contains(p, "build") }) {
		t.Errorf("the upgrade went on:\n%s\n%v", o.text(), o.phases)
	}
	if got := readFile(t, o.p.StoreFile); got != dottedUpgradeStore {
		t.Errorf("the store changed:\n%s", got)
	}
	if got := readFile(t, o.p.Overrides); got != beforeOverrides {
		t.Errorf("tacctl.yaml changed:\n%s", got)
	}

	// A user renamed is not named again.
	o.write(o.p.StoreFile, strings.NewReplacer("alice.smith", "alice-smith", "a.b-c_d", "abcd").Replace(dottedUpgradeStore))
	if code := upgrade(o); code != 0 {
		t.Fatalf("after the rename: exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if strings.Contains(o.stderr.String(), "a period") {
		t.Errorf("stderr:\n%s", o.stderr)
	}
}

// The new command of an upgrade started by an older release (ReexecEnv=1) is
// where the gate refuses in practice: the installed command and the tacquito
// build are already replaced, so the refusal says that and what is left to
// do, and does not say that nothing was changed.
func TestUpgradeRefusesDottedUsersAfterTheReexec(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, dottedUpgradeStore)
	o.environ = append(o.environ, lifecycle.ReexecEnv+"=1")
	if code := upgrade(o); code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, o.stdout, o.stderr)
	}
	errs := stripANSI(o.stderr.String())
	for _, want := range []string{
		"The store has 2 users whose name has a period",
		"  alice.smith   (tacctl user rename alice.smith <new-name>)",
		"tacctl and the tacquito build were updated; the store, the configuration and the services were not.",
		"Rename the users, then run 'tacctl upgrade' again to finish.",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "Nothing was changed") {
		t.Errorf("says nothing was changed after the update:\n%s", errs)
	}
	if got := readFile(t, o.p.StoreFile); got != dottedUpgradeStore {
		t.Errorf("the store changed:\n%s", got)
	}
	// Renamed, the run goes on to the end.
	o.write(o.p.StoreFile, "version: 1\nusers:\n  alice-smith:\n    group: operator\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("after the rename: exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
}

// A store that cannot be read does not make the upgrade refuse for a name it
// cannot see: it warns and goes on; the store gate the backends run
// reports the file.
func TestUpgradeUnreadableStoreIsNotHeldUp(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, "version: [\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if !strings.Contains(o.text(), "store.yaml cannot be read, so a user name with a period was not looked for") ||
		strings.Contains(o.text(), "fix it first") {
		t.Errorf("no word about the store:\n%s", o.text())
	}
}
