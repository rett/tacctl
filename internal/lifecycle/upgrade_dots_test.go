package lifecycle_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/snapshot"
)

// dottedStorePrefix is what a store has before its users: the built-in
// groups and the scope the users are in.
const dottedStorePrefix = `version: 1
groups:
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
  operator: {priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}
scopes:
  site-a:
    prefixes: [192.0.2.0/24]
    secret: example-secret
filters:
  allow: []
  deny: []
`

// A store written by 0.2.20 or 0.2.21: users with a period in the name, with
// the things that follow a user name.
const dottedUpgradeStore = dottedStorePrefix + `users:
  alice.smith:
    group: operator
    scopes: [site-a]
    hash: null
    disabled: false
    password_changed: null
    email: alice@example.net
    password_change_required: true
  bob:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
  a.b-c_d:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
`

const dottedLedger = "# UIDs\nalice.smith:80001\nbob:80002\n"

const dottedConsole = `version: 1
users:
  alice.smith: enable
settings:
  system_shell_users:
    alice.smith: enable:operator
  password_cache_users:
    alice.smith: true
`

func snapshotIDs(o *ohost) []string { return snapshot.IDs(o.p.BackupDir) }

// The upgrade renames a user whose name has a period (alice.smith is
// alice_smith) with everything that follows the name: the store record, the
// UID line, the console settings. A snapshot comes first and is named; one
// line says each rename and a note says what to tell the people. A second
// run does nothing and takes no snapshot.
func TestUpgradeRenamesDottedUsers(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, dottedUpgradeStore)
	o.write(o.p.LinuxUIDs, dottedLedger)
	o.write(o.p.ConsoleFile, dottedConsole)
	if n := len(snapshotIDs(o)); n != 0 {
		t.Fatalf("%d snapshots before the upgrade", n)
	}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	ids := snapshotIDs(o)
	if len(ids) == 0 {
		t.Fatalf("no snapshot was taken\n%s", o.text())
	}
	text := o.text()
	for _, want := range []string{
		"Renaming 2 users whose name has a period",
		"snapshot " + ids[0] + " holds the state before the rename (tacctl backup restore " + ids[0] + ")",
		"renamed user a.b-c_d to a_b-c_d",
		"renamed user alice.smith to alice_smith (UID 80001 carried, console settings moved)",
		"Tell these users to log in with the new name",
		"never had a Linux account",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	// the snapshot is named before the renames are reported, and holds the
	// store as it was
	inOrder(t, text, "Renaming 2 users", "snapshot "+ids[0], "renamed user", "Tell these users", "Updating system files")
	if got := readFile(t, filepath.Join(o.p.BackupDir, ids[0], filepath.Base(o.p.StoreFile))); got != dottedUpgradeStore {
		t.Errorf("the snapshot's store is not the one before:\n%s", got)
	}

	// the store record moved whole
	st := readFile(t, o.p.StoreFile)
	for _, want := range []string{"alice_smith:", "a_b-c_d:", "email: alice@example.net", "password_change_required: true", "site-a", "bob:"} {
		if !strings.Contains(st, want) {
			t.Errorf("store lacks %q:\n%s", want, st)
		}
	}
	if strings.Contains(st, "alice.smith") || strings.Contains(st, "a.b-c_d") {
		t.Errorf("store still holds a name with a period:\n%s", st)
	}
	if got := readFile(t, o.p.LinuxUIDs); got != "# UIDs\nalice_smith:80001\nbob:80002\n" {
		t.Errorf("ledger:\n%s", got)
	}
	cons := readFile(t, o.p.ConsoleFile)
	if strings.Contains(cons, "alice.smith") || strings.Count(cons, "alice_smith") != 3 {
		t.Errorf("console.yaml:\n%s", cons)
	}
	// one audit line per rename, as 'user rename' writes it
	if got := strings.Join(o.audit, "\n"); !strings.Contains(got, "user rename from=alice.smith to=alice_smith uid=carried") ||
		!strings.Contains(got, "user rename from=a.b-c_d to=a_b-c_d uid=-") {
		t.Errorf("audit lines:\n%s", got)
	}

	// idempotent: nothing to do, no snapshot, no output about it
	after := readFile(t, o.p.StoreFile)
	if code := upgrade(o); code != 0 {
		t.Fatalf("second run: exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if got := snapshotIDs(o); !slices.Equal(got, ids) {
		t.Errorf("snapshots after the second run: %v, before %v", got, ids)
	}
	if strings.Contains(o.text(), "renamed user") || strings.Contains(o.text(), "Renaming") || strings.Contains(o.text(), "Tell these") {
		t.Errorf("second run:\n%s", o.text())
	}
	if got := readFile(t, o.p.StoreFile); got != after {
		t.Errorf("the store changed in the second run:\n%s", got)
	}
	if strings.Contains(strings.Join(o.audit, "\n"), "user rename") {
		t.Errorf("audit lines of the second run: %v", o.audit)
	}
}

// With no user whose name has a period nothing is done: no snapshot, no
// line, the store as it was.
func TestUpgradeWithoutDottedUsersTakesNoSnapshot(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	const clean = dottedStorePrefix + "users:\n  alice:\n    group: operator\n    scopes: []\n    hash: null\n    disabled: false\n    password_changed: null\n"
	o.write(o.p.StoreFile, clean)
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if ids := snapshotIDs(o); len(ids) != 0 {
		t.Errorf("snapshots: %v", ids)
	}
	if strings.Contains(o.text(), "Renaming") || strings.Contains(o.text(), "renamed user") {
		t.Errorf("output:\n%s", o.text())
	}
	if got := readFile(t, o.p.StoreFile); got != clean {
		t.Errorf("the store changed:\n%s", got)
	}
	// and an install with no store at all
	p := newOhost(t)
	p.cloned()
	if code := upgrade(p); code != 0 {
		t.Fatalf("no store: exit %d\n%s\n%s", code, p.stdout, p.stderr)
	}
}

// suffixes is the seam of the random suffix: the words in order, and a test
// failure when more are drawn than were given.
func suffixes(t *testing.T, words ...string) func() string {
	t.Helper()
	return func() string {
		if len(words) == 0 {
			t.Error("more suffixes were drawn than expected")
			return "zzzz"
		}
		w := words[0]
		words = words[1:]
		return w
	}
}

// A new name that is taken (a user of that name, a second name that becomes
// the same, a break-glass local user of the user's scopes) does not stop the
// upgrade: the user gets '_' and a random suffix, drawn again when the name
// with it is taken too. The first of two names that meet keeps the name
// without a suffix. The output says each pair and why; a second run does
// nothing.
func TestUpgradeDottedUserCollisionGetsASuffix(t *testing.T) {
	const store = dottedStorePrefix + `users:
  alice.smith:
    group: operator
    scopes: [site-a]
    hash: null
    disabled: false
    password_changed: null
  alice_smith:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
  carol.jones:
    group: operator
    scopes: [site-a]
    hash: null
    disabled: false
    password_changed: null
  dave.x:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
  dave_x:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
  dave_x_k3x9:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
  a.b_c:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
  a_b.c:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
`
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, store)
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs]\nbreakglass_scope:\n  site-a:\n    users: ['Carol_Jones:admin']\n")
	o.be.Conf.Reload()
	o.write(o.p.LinuxUIDs, dottedLedger)
	o.write(o.p.ConsoleFile, dottedConsole)
	// alice.smith, carol.jones, dave.x (k3x9 is taken, then m2p7), a_b.c
	o.nameSuffix = suffixes(t, "k3x9", "k3x9", "k3x9", "m2p7", "q8w1")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	text := o.text()
	for _, want := range []string{
		"Renaming 5 users whose name has a period",
		"renamed user alice.smith to alice_smith_k3x9 (UID 80001 carried, console settings moved, alice_smith was taken)",
		"renamed user carol.jones to carol_jones_k3x9 (carol_jones was taken)",
		"renamed user dave.x to dave_x_m2p7 (dave_x was taken)",
		"renamed user a.b_c to a_b_c\n",
		"renamed user a_b.c to a_b_c_q8w1 (a_b_c was taken)",
		"Tell these users to log in with the new name",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	st := readFile(t, o.p.StoreFile)
	for _, want := range []string{"alice_smith_k3x9:", "carol_jones_k3x9:", "dave_x_m2p7:", "a_b_c:", "a_b_c_q8w1:", "alice_smith:", "dave_x:", "dave_x_k3x9:"} {
		if !strings.Contains(st, want) {
			t.Errorf("store lacks %q:\n%s", want, st)
		}
	}
	for _, gone := range []string{"alice.smith:", "carol.jones:", "dave.x:", "a.b_c:", "a_b.c:"} {
		if strings.Contains(st, gone) {
			t.Errorf("store still holds %q:\n%s", gone, st)
		}
	}
	if got := readFile(t, o.p.LinuxUIDs); got != "# UIDs\nalice_smith_k3x9:80001\nbob:80002\n" {
		t.Errorf("ledger:\n%s", got)
	}
	if got := strings.Join(o.audit, "\n"); !strings.Contains(got, "user rename from=alice.smith to=alice_smith_k3x9 uid=carried") {
		t.Errorf("audit lines:\n%s", got)
	}

	// idempotent: no period is left, no draw, no snapshot
	ids := snapshotIDs(o)
	o.nameSuffix = suffixes(t)
	if code := upgrade(o); code != 0 {
		t.Fatalf("second run: exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if got := snapshotIDs(o); !slices.Equal(got, ids) {
		t.Errorf("snapshots after the second run: %v, before %v", got, ids)
	}
	if strings.Contains(o.text(), "renamed user") {
		t.Errorf("second run:\n%s", o.text())
	}
}

// A name that is not a user name even with the periods replaced stops the
// upgrade before anything is changed, and no user that could be renamed is:
// no command renames such a name, so the refusal names the key to edit. Once
// it is edited the upgrade goes through.
func TestUpgradeDottedUserInvalidNameChangesNothing(t *testing.T) {
	const store = dottedStorePrefix + `users:
  alice.smith:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
  x y.z:
    group: operator
    scopes: []
    hash: null
    disabled: false
    password_changed: null
`
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, store)
	o.write(o.p.LinuxUIDs, dottedLedger)
	o.write(o.p.ConsoleFile, dottedConsole)
	o.nameSuffix = suffixes(t)
	if code := upgrade(o); code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, o.stdout, o.stderr)
	}
	errs := stripANSI(o.stderr.String())
	for _, want := range []string{
		"1 user cannot be given a name:",
		"  x y.z -> x y_z: not a name a user can have",
		"No user was renamed. No command renames a name that is not a user name, so edit the key under 'users:' in " + o.p.StoreFile + ", then run the upgrade again.",
		"Nothing was changed.",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "alice.smith") {
		t.Errorf("a user that could be renamed is named:\n%s", errs)
	}
	for _, p := range o.phases {
		if !strings.HasSuffix(p, " upgrade preflight") {
			t.Errorf("phase %q ran after the refusal", p)
		}
	}
	if strings.Contains(o.text(), "tacctl Upgrade") {
		t.Errorf("the upgrade went on:\n%s", o.text())
	}
	if ids := snapshotIDs(o); len(ids) != 0 {
		t.Errorf("snapshots: %v", ids)
	}
	if got := readFile(t, o.p.StoreFile); got != store {
		t.Errorf("the store changed:\n%s", got)
	}
	if readFile(t, o.p.LinuxUIDs) != dottedLedger || readFile(t, o.p.ConsoleFile) != dottedConsole {
		t.Error("a file changed")
	}

	o.write(o.p.StoreFile, strings.ReplaceAll(store, "x y.z:", "x.z:"))
	o.nameSuffix = suffixes(t)
	if code := upgrade(o); code != 0 {
		t.Fatalf("after the edit: exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if !strings.Contains(o.text(), "renamed user alice.smith to alice_smith (") || !strings.Contains(o.text(), "renamed user x.z to x_z\n") {
		t.Errorf("output:\n%s", o.text())
	}
}

// The new command of an upgrade started by an older release (ReexecEnv=1) is
// where the refusal comes in practice: the installed command and the tacquito
// build are already replaced, so the refusal says that and does not say that
// nothing was changed.
func TestUpgradeDottedUserRefusalAfterTheReexec(t *testing.T) {
	const store = dottedStorePrefix + "users:\n  x y.z:\n    group: operator\n"
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, store)
	o.environ = append(o.environ, lifecycle.ReexecEnv+"=1")
	if code := upgrade(o); code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, o.stdout, o.stderr)
	}
	errs := stripANSI(o.stderr.String())
	for _, want := range []string{
		"1 user cannot be given a name:",
		"  x y.z -> x y_z: not a name a user can have",
		"tacctl and the tacquito build were updated; the store, the configuration and the services were not.",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "Nothing was changed") {
		t.Errorf("says nothing was changed after the update:\n%s", errs)
	}
	if got := readFile(t, o.p.StoreFile); got != store {
		t.Errorf("the store changed:\n%s", got)
	}
}

// A snapshot that cannot be made stops the rename: no user is renamed.
func TestUpgradeDottedUsersNeedTheSnapshot(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, dottedUpgradeStore)
	// a file where the snapshot directory goes
	if err := os.MkdirAll(filepath.Dir(o.p.BackupDir), 0o755); err != nil {
		t.Fatal(err)
	}
	o.write(o.p.BackupDir, "not a directory\n")
	if code := upgrade(o); code == 0 {
		t.Fatalf("exit 0\n%s\n%s", o.stdout, o.stderr)
	}
	if !strings.Contains(stripANSI(o.stderr.String()), "A snapshot could not be made, so no user was renamed") {
		t.Errorf("stderr:\n%s", o.stderr)
	}
	if got := readFile(t, o.p.StoreFile); got != dottedUpgradeStore {
		t.Errorf("the store changed:\n%s", got)
	}
}

// A store that cannot be read does not make the upgrade stop for a name it
// cannot see: it warns once and goes on; the store gate the backends run
// reports the file.
func TestUpgradeUnreadableStoreIsNotHeldUp(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, "version: [\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if n := strings.Count(o.text(), "store.yaml cannot be read, so a user name with a period was not looked for"); n != 1 || strings.Contains(o.text(), "fix it first") {
		t.Errorf("%d warnings:\n%s", n, o.text())
	}
}

// The plan: a name that two names with periods become (the first keeps it),
// a name that is not a user name, and the order of the renames.
func TestPlanDottedUsers(t *testing.T) {
	users := []lifecycle.DottedUser{{Name: "b.c"}, {Name: "a.b_c"}, {Name: "a_b.c"}, {Name: "zed"}, {Name: "x y.z"}, {Name: "q.r"}}
	plan := lifecycle.PlanDottedUsers(nil, users, suffixes(t, "aaaa"))
	var got []string
	for _, r := range plan.Renames {
		got = append(got, r.Old+">"+r.New)
	}
	if want := []string{"b.c>b_c", "a.b_c>a_b_c", "a_b.c>a_b_c_aaaa", "q.r>q_r"}; !slices.Equal(got, want) {
		t.Errorf("renames %v, want %v", got, want)
	}
	if len(plan.Clashes) != 1 || plan.Clashes[0] != "  x y.z -> x y_z: not a name a user can have" {
		t.Errorf("clashes %q", plan.Clashes)
	}
}

// A name too long for a Linux account with its suffix is cut before the
// suffix; a suffix already taken, a user's own new name, or a name a later
// user would get is drawn again.
func TestPlanDottedUsersSuffixShape(t *testing.T) {
	long := strings.Repeat("l", 30)
	users := []lifecycle.DottedUser{{Name: long + "_m"}, {Name: long + ".m"}, {Name: "a.b"}, {Name: "a_b"}, {Name: "c.d"}, {Name: "c_d"}, {Name: "c_d.wxyz"}}
	plan := lifecycle.PlanDottedUsers(nil, users, suffixes(t, "k3x9", "aaaa", "wxyz", "bbbb"))
	got := map[string]string{}
	for _, r := range plan.Renames {
		got[r.Old] = r.New
	}
	if len(plan.Clashes) != 0 {
		t.Fatalf("clashes %q", plan.Clashes)
	}
	if want := long[:27] + "_k3x9"; got[long+".m"] != want || len(want) != 32 {
		t.Errorf("long name %q, want %q", got[long+".m"], want)
	}
	if got["a.b"] != "a_b_aaaa" || got["c.d"] != "c_d_bbbb" {
		t.Errorf("renames %v", got)
	}
}

// A source that always answers the same cannot loop for ever: the user is a
// clash, and nothing is renamed.
func TestPlanDottedUsersNoFreeSuffix(t *testing.T) {
	users := []lifecycle.DottedUser{{Name: "a_b"}, {Name: "a_b_aaaa"}, {Name: "a.b"}}
	plan := lifecycle.PlanDottedUsers(nil, users, func() string { return "aaaa" })
	if len(plan.Clashes) != 1 || !strings.Contains(plan.Clashes[0], "a.b -> a_b: taken, and no free name with a suffix was found") {
		t.Errorf("clashes %q", plan.Clashes)
	}
}

// RandomSuffix is four lowercase letters or digits.
func TestRandomSuffixShape(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		w := lifecycle.RandomSuffix()
		if len(w) != 4 || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			t.Fatalf("suffix %q", w)
		}
		seen[w] = true
	}
	if len(seen) < 100 {
		t.Errorf("only %d different suffixes in 200 draws", len(seen))
	}
}

// console.yaml and the UID ledger are checked before the snapshot and before
// the store is written: the store is renamed first, and a file that fails
// after it is a half-done rename that a second upgrade (which looks at the
// store) would not see. A console.yaml that cannot be read, one that holds a
// name the rule refuses that is not a name with a period, and a ledger that
// cannot be read each stop the upgrade with nothing changed.
func TestUpgradeDottedUsersStopBeforeAnyWriteWhenAFileCannotFollow(t *testing.T) {
	for _, c := range []struct {
		name, want string
		arrange    func(o *ohost)
	}{
		{"console.yaml is not YAML", "console.yaml cannot take the renames", func(o *ohost) { o.write(o.p.ConsoleFile, "settings: [\n") }},
		{"console.yaml holds a name that is not a user name", "invalid user name 'x y'", func(o *ohost) {
			o.write(o.p.ConsoleFile, "version: 1\nsettings:\n  password_cache_users: {'x y': true}\n")
		}},
		{"the ledger cannot be read", "linux-uids cannot be moved", func(o *ohost) {
			if err := os.Remove(o.p.LinuxUIDs); err != nil {
				o.t.Fatal(err)
			}
			if err := os.Mkdir(o.p.LinuxUIDs, 0o700); err != nil {
				o.t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := newOhost(t)
			o.cloned()
			o.write(o.p.StoreFile, dottedUpgradeStore)
			o.write(o.p.LinuxUIDs, dottedLedger)
			o.write(o.p.ConsoleFile, dottedConsole)
			c.arrange(o)
			cons, _ := os.ReadFile(o.p.ConsoleFile)
			o.nameSuffix = suffixes(t)
			if code := upgrade(o); code != 1 {
				t.Fatalf("exit %d, want 1\n%s\n%s", code, o.stdout, o.stderr)
			}
			errs := stripANSI(o.stderr.String())
			for _, want := range []string{"The upgrade renames a user whose name has a period, but ", c.want, "Repair the file, then run the upgrade again. No user was renamed.", "Nothing was changed."} {
				if !strings.Contains(errs, want) {
					t.Errorf("stderr lacks %q:\n%s", want, errs)
				}
			}
			if strings.Contains(o.text(), "tacctl Upgrade") {
				t.Errorf("the upgrade went on:\n%s", o.text())
			}
			if ids := snapshotIDs(o); len(ids) != 0 {
				t.Errorf("snapshots: %v", ids)
			}
			if got := readFile(t, o.p.StoreFile); got != dottedUpgradeStore {
				t.Errorf("the store changed:\n%s", got)
			}
			if got, _ := os.ReadFile(o.p.ConsoleFile); string(got) != string(cons) {
				t.Errorf("console.yaml changed:\n%s", got)
			}
			if _, err := os.Stat(filepath.Join(o.p.StateDir, "upgrade-renames")); err == nil {
				t.Error("a journal was left")
			}
		})
	}
}

// A key with a period in console.yaml that no rename covers (a hand edit, the
// 'users' mapping, a user who is gone) is dropped with a line naming it and
// the file reads afterwards, whether or not the store has a user to rename.
// It is not renamed: the next user of that name would inherit its settings.
// A second upgrade does nothing.
func TestUpgradeDropsAConsoleKeyWithAPeriodNoRenameCovers(t *testing.T) {
	const cons = `version: 1
users:
  gone.user: enable
settings:
  password_cache_users:
    alice.smith: true
    gone.user: true
`
	for _, withStore := range []bool{true, false} {
		o := newOhost(t)
		o.cloned()
		store := dottedUpgradeStore
		if !withStore {
			store = dottedStorePrefix + "users:\n  bob:\n    group: operator\n    scopes: []\n    hash: null\n    disabled: false\n    password_changed: null\n"
		}
		o.write(o.p.StoreFile, store)
		o.write(o.p.LinuxUIDs, dottedLedger)
		o.write(o.p.ConsoleFile, cons)
		if code := upgrade(o); code != 0 {
			t.Fatalf("store %v: exit %d\n%s\n%s", withStore, code, o.stdout, o.stderr)
		}
		text := o.text() + stripANSI(o.stderr.String())
		if !strings.Contains(text, "dropped the console settings of 'gone.user'") {
			t.Errorf("store %v: no line names the dropped key:\n%s", withStore, text)
		}
		got := readFile(t, o.p.ConsoleFile)
		if strings.Contains(got, "gone") || strings.Contains(got, ".") && strings.Contains(got, "alice.smith") {
			t.Errorf("store %v: console.yaml:\n%s", withStore, got)
		}
		if withStore != strings.Contains(got, "alice_smith") {
			t.Errorf("store %v: alice_smith in console.yaml: %v\n%s", withStore, !withStore, got)
		}
		if withStore && !strings.Contains(text, "renamed user alice.smith to alice_smith (UID 80001 carried, console settings moved)") {
			t.Errorf("the rename is not reported:\n%s", text)
		}
		ids := snapshotIDs(o)
		if len(ids) == 0 {
			t.Errorf("store %v: no snapshot was taken before console.yaml changed", withStore)
		}
		// again: nothing
		if code := upgrade(o); code != 0 {
			t.Fatalf("second run: exit %d\n%s\n%s", code, o.stdout, o.stderr)
		}
		if strings.Contains(o.text()+stripANSI(o.stderr.String()), "dropped") || !slices.Equal(snapshotIDs(o), ids) {
			t.Errorf("store %v: the second run did something:\n%s", withStore, o.text())
		}
	}
}

// An upgrade that stops after the store was written and before the ledger and
// console.yaml follow (a crash, a power cut) leaves the user renamed in the
// store only. A second upgrade finishes the move for that user, with the same
// new name (a suffixed one too), reads nothing from the names, and the third
// does nothing.
func TestUpgradeFinishesARenameThatStoppedAfterTheStore(t *testing.T) {
	// alice_smith is a user already, so alice.smith gets the suffix k3x9
	store := strings.Replace(dottedUpgradeStore, "  bob:\n", "  alice_smith:\n    group: readonly\n    scopes: []\n    hash: null\n    disabled: false\n    password_changed: null\n  bob:\n", 1)
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, store)
	o.write(o.p.LinuxUIDs, dottedLedger)
	o.write(o.p.ConsoleFile, dottedConsole)
	o.nameSuffix = suffixes(t, "k3x9")
	o.afterStoreRename = func() error { return errors.New("simulated crash") }
	if code := upgrade(o); code == 0 {
		t.Fatalf("the simulated crash did not stop the upgrade\n%s\n%s", o.stdout, o.stderr)
	}
	st := readFile(t, o.p.StoreFile)
	if strings.Contains(st, "alice.smith") || !strings.Contains(st, "alice_smith_k3x9:") {
		t.Fatalf("the store after the crash:\n%s", st)
	}
	if readFile(t, o.p.LinuxUIDs) != dottedLedger || readFile(t, o.p.ConsoleFile) != dottedConsole {
		t.Fatal("the ledger or console.yaml followed before the crash")
	}
	// the store has no dotted user: a second upgrade used to find nothing here
	ids := snapshotIDs(o)
	o.afterStoreRename = nil
	o.nameSuffix = suffixes(t) // no draw: the journal has the name
	if code := upgrade(o); code != 0 {
		t.Fatalf("second run: exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	text := o.text()
	for _, want := range []string{
		"Finishing the rename of 2 users whose name had a period",
		"finished the rename of user alice.smith to alice_smith_k3x9 (UID 80001 carried, console settings moved, alice_smith was taken)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if got := readFile(t, o.p.LinuxUIDs); got != "# UIDs\nalice_smith_k3x9:80001\nbob:80002\n" {
		t.Errorf("ledger:\n%s", got)
	}
	cons := readFile(t, o.p.ConsoleFile)
	if strings.Contains(cons, "alice.smith") || strings.Count(cons, "alice_smith_k3x9") != 3 || strings.Contains(cons, "alice_smith:") {
		t.Errorf("console.yaml:\n%s", cons)
	}
	if _, err := os.Stat(filepath.Join(o.p.StateDir, "upgrade-renames")); err == nil {
		t.Error("the journal was not removed")
	}
	if got := readFile(t, o.p.StoreFile); got != st {
		t.Errorf("the second run changed the store:\n%s", got)
	}
	if len(snapshotIDs(o)) < len(ids) {
		t.Error("snapshots went missing")
	}
	// a third run has nothing to do
	after := snapshotIDs(o)
	if code := upgrade(o); code != 0 {
		t.Fatalf("third run: exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if strings.Contains(o.text(), "rename") || !slices.Equal(snapshotIDs(o), after) {
		t.Errorf("third run:\n%s", o.text())
	}
}

// A journal entry whose old name is still a store user was never written: the
// new plan covers it, and the entry does not move anything.
func TestUpgradeIgnoresAJournalEntryTheStoreNeverGot(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.StoreFile, dottedUpgradeStore)
	o.write(o.p.LinuxUIDs, dottedLedger)
	o.write(o.p.ConsoleFile, dottedConsole)
	o.write(filepath.Join(o.p.StateDir, "upgrade-renames"), "alice.smith bob\ngone.user gone_user\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if got := readFile(t, o.p.LinuxUIDs); got != "# UIDs\nalice_smith:80001\nbob:80002\n" {
		t.Errorf("ledger:\n%s", got)
	}
	if strings.Contains(o.text(), "finished the rename") {
		t.Errorf("a stale entry was finished:\n%s", o.text())
	}
}
