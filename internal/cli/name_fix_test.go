package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

// 'config validate --fix-names' (docs/plans/0.2.15-plan.md D226-D230): the
// report, then the rename of each name with upper case, one question each.

// nameFixLab is a sandbox with a name of every kind in the spelling of an
// earlier release: the device Core-SW1, the host Web1 alone in its own scope
// linux-Web1, the user Alice (with a line in the UID ledger) and the scopes
// Dmz and Prod-Inner.
func nameFixLab(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "add", "linux-web1", "--prefixes", "198.51.100.10/32", "--secret", "generate"})
	sb.expect(0, "", "")
	sb.legacyStoreCase("linux-web1", "linux-Web1")
	sb.legacyStoreCase("  alice:", "  Alice:")
	sb.legacyStoreCase("  dmz:", "  Dmz:")
	sb.legacyStoreCase(", dmz]", ", Dmz]")
	sb.legacyStoreCase("  prod-inner:", "  Prod-Inner:")
	sb.write("state/linux-uids", "Alice:80001\n", 0o600)
	sb.write("state/linux-hosts", "Web1|root@198.51.100.10||linux-Web1|192.0.2.1|\n", 0o600)
	sb.write("state/staging", "198.51.100.10/32|linux-Web1|host|Web1|2026-01-01\n", 0o600)
	sb.write("state/devices.yaml", "version: 1\ndevices:\n  Core-SW1:\n    address: 10.99.0.1\n    vendor: cisco\n", 0o600)
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	return sb
}

// upperCase lists what the report still names with upper case.
func upperCase(out string) []string {
	var left []string
	for _, l := range strings.Split(plain(out), "\n") {
		if strings.Contains(l, "has upper case in its name") {
			left = append(left, l)
		}
	}
	return left
}

// Every kind is renamed with -y: the device, the host (which carries its own
// scope, so the scope is not offered a second time), the user (whose ledger
// line moves) and the scopes. Each rename has its own undo point.
func TestFixNamesRenamesEveryKindWithYes(t *testing.T) {
	sb := nameFixLab(t)
	snaps := len(sb.snapshotDirs())
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	out := plain(sb.out.String())
	sb.expect(0, "Names: renamed 5, declined 0, not offered 0, failed 0.", "")
	// The report comes first, with the findings it lists.
	if i, j := strings.Index(out, "Configuration is valid."), strings.Index(out, "Device 'Core-SW1' renamed to 'core-sw1'."); i < 0 || j < i {
		t.Errorf("the report does not come first:\n%s", out)
	}
	for _, want := range []string{
		"Device 'Core-SW1' renamed to 'core-sw1'.",
		"Host 'Web1' renamed to 'web1'. Nothing was sent to the host.",
		"Scope renamed: linux-Web1 -> linux-web1",
		"User renamed: Alice -> alice",
		"UID 80001 follows the rename (linux-uids).",
		"Scope renamed: Dmz -> dmz",
		"Scope renamed: Prod-Inner -> prod-inner",
		"tacctl host sync --all",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	// Devices, hosts, users, then scopes.
	last := -1
	for _, w := range []string{"Device 'Core-SW1' renamed", "Host 'Web1' renamed", "User renamed: Alice", "Scope renamed: Dmz", "Scope renamed: Prod-Inner"} {
		if i := strings.Index(out[max(last, 0):], w); i < 0 {
			t.Errorf("%q is out of order:\n%s", w, out)
		} else {
			last += i + 1
		}
	}
	// The scope the host rename carried was renamed once.
	if n := strings.Count(out, "Scope renamed: linux-Web1"); n != 1 {
		t.Errorf("the host's scope was renamed %d times:\n%s", n, out)
	}
	if got := sb.registryText(); got != "web1|root@198.51.100.10||linux-web1|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	if got := sb.read("state/linux-uids"); got != "alice:80001\n" {
		t.Errorf("the ledger: %q", got)
	}
	if d := sb.devices(); strings.Contains(d, "Core-SW1") || !strings.Contains(d, "  core-sw1:") {
		t.Errorf("devices:\n%s", d)
	}
	for _, gone := range []string{"Alice", "Dmz", "Prod-Inner", "linux-Web1"} {
		if st := sb.store(); strings.Contains(st, gone) {
			t.Errorf("the store has %q:\n%s", gone, st)
		}
	}
	// device 1, host 2 (the host, then its scope), user 1, scopes 2.
	if n := len(sb.snapshotDirs()); n != snaps+6 {
		t.Errorf("%d snapshots, want %d", n, snaps+6)
	}
	// Nothing is left to say.
	if left := upperCase(sb.run("", []string{"config", "validate"})); len(left) != 0 {
		t.Errorf("names are left:\n%s", strings.Join(left, "\n"))
	}
	// A second run has nothing to offer.
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	sb.expect(0, "Names: renamed 0, declined 0, not offered 0, failed 0.", "")
	if strings.Contains(sb.printed(), "tacctl host sync --all") {
		t.Errorf("a sync was named without a renamed user:\n%s", sb.printed())
	}
}

// Typed answers: only y renames, anything else declines, and the counts say
// which. The questions go in order, one name each.
func TestFixNamesTypedAnswers(t *testing.T) {
	sb := nameFixLab(t)
	// Core-SW1 y, Web1 n, Alice y, Dmz n, Prod-Inner yes (not "y": declined)
	// and the scope linux-Web1, which the declined host leaves, y.
	sb.run("y\nn\ny\nn\nyes\ny\n", []string{"config", "validate", "--fix-names"})
	sb.expect(0, "Names: renamed 3, declined 3, not offered 0, failed 0.", "")
	if d := sb.devices(); !strings.Contains(d, "  core-sw1:") {
		t.Errorf("devices:\n%s", d)
	}
	if got := sb.registryText(); !strings.HasPrefix(got, "Web1|") || !strings.Contains(got, "|linux-web1|") {
		t.Errorf("registry %q", got)
	}
	st := sb.store()
	for _, want := range []string{"  alice:\n", "  Dmz:\n", "  Prod-Inner:\n", "  linux-web1:\n"} {
		if !strings.Contains(st, want) {
			t.Errorf("the store lacks %q:\n%s", want, st)
		}
	}
	// The questions are asked on the terminal only; the declined names are
	// what the report still lists.
	left := strings.Join(upperCase(sb.run("", []string{"config", "validate"})), "\n")
	for _, want := range []string{"host 'Web1'", "scope 'Dmz'", "scope 'Prod-Inner'"} {
		if !strings.Contains(left, want) {
			t.Errorf("%s is not left:\n%s", want, left)
		}
	}
	if strings.Contains(left, "user") || strings.Contains(left, "device") {
		t.Errorf("renamed names are left:\n%s", left)
	}
}

// Without -y, 'host rename' asks its own question about the host's scope
// after ours: the next answer is for it.
func TestFixNamesHostAsksItsOwnQuestions(t *testing.T) {
	sb := nameFixLab(t)
	// Core-SW1 y, Web1 y, its scope y, Alice n, Dmz n, Prod-Inner n.
	sb.run("y\ny\ny\nn\nn\nn\n", []string{"config", "validate", "--fix-names"})
	sb.expect(0, "Names: renamed 2, declined 3, not offered 0, failed 0.", "")
	if got := sb.registryText(); got != "web1|root@198.51.100.10||linux-web1|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	if st := sb.store(); strings.Contains(st, "linux-Web1") {
		t.Errorf("the host's scope was not renamed:\n%s", st)
	}
	// With the host's own question a no, the host keeps its scope, which is
	// then offered on its own, after the other scopes.
	sb = nameFixLab(t)
	sb.run("n\ny\nn\nn\nn\nn\ny\n", []string{"config", "validate", "--fix-names"})
	sb.expect(0, "Names: renamed 2, declined 4, not offered 0, failed 0.", "")
	if got := sb.registryText(); got != "web1|root@198.51.100.10||linux-web1|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	if n := strings.Count(plain(sb.out.String()), "Scope renamed: linux-Web1 -> linux-web1"); n != 1 {
		t.Errorf("the scope was renamed %d times", n)
	}
}

// A name whose lower-case spelling is another name's is not offered, and the
// run exits 1 even with -y: a script learns that names remain.
func TestFixNamesConflictIsNotOffered(t *testing.T) {
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  carol:", "  Carol:")
	sb.run("", []string{"user", "add", "carol", "readonly", "--hash", testHash})
	sb.expect(0, "", "")
	sb.write("state/linux-hosts", "Web1|root@198.51.100.10||lab|192.0.2.1|\nweb1|root@198.51.100.11||lab|192.0.2.1|\n", 0o600)
	before := sb.store()
	snaps := len(sb.snapshotDirs())
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	sb.expect(1, "Names: renamed 0, declined 0, not offered 2, failed 0.", "")
	out := plain(sb.out.String())
	for _, want := range []string{
		"'Carol' is not offered: 'carol' is taken; pick a name: tacctl user rename Carol <new>\n",
		"'Web1' is not offered: 'web1' is taken; pick a name: tacctl host rename Web1 <new>, or tacctl host forget <name> drops the stray registration\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if sb.store() != before || len(sb.snapshotDirs()) != snaps {
		t.Error("a name that is not offered changed something")
	}
	// Declining is not failing: only the decline exits 0.
	sb = nameFixLab(t)
	sb.run("n\nn\nn\nn\nn\n", []string{"config", "validate", "--fix-names"})
	sb.expect(0, "Names: renamed 0, declined 6, not offered 0, failed 0.", "")
}

// A rename its verb refuses is printed, counts as failed and the loop goes
// on: here the credentials file of the new scope name is already there.
func TestFixNamesRefusedRenameCountsAndGoesOn(t *testing.T) {
	sb := nameFixLab(t)
	sb.write("state/snmp/Dmz.yaml", "community: dmz-comm\n", 0o600)
	sb.write("state/snmp/dmz.yaml", "community: stray\n", 0o600)
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	sb.expect(1, "Names: renamed 4, declined 0, not offered 0, failed 1.",
		"SNMP credentials for a scope named 'dmz' are already on disk")
	// The rename after the refused one was made.
	st := sb.store()
	if !strings.Contains(st, "  Dmz:\n") || !strings.Contains(st, "  prod-inner:\n") || strings.Contains(st, "Prod-Inner") {
		t.Errorf("the store:\n%s", st)
	}
	if got := sb.registryText(); !strings.HasPrefix(got, "web1|") {
		t.Errorf("registry %q", got)
	}
}

// refuseHostScope makes the check of the scope a host rename carries pass at
// the offer and fail by the time the step runs (the credentials file of the
// new name appears once the host is renamed), which is the refusal D233 is
// about; at the offer the same file only makes the host keep its scope.
func refuseHostScope(sb *sandbox) {
	sb.hooks.hostRenameStep = func(step string) {
		if step == "pins" {
			sb.write("state/snmp/linux-Web1.yaml", "community: a\n", 0o600)
			sb.write("state/snmp/linux-web1.yaml", "community: b\n", 0o600)
		}
	}
}

// A host renamed whose carried scope is refused counts as renamed (D233): the
// scope is not offered again in the run, one line gives the command, and the
// run exits 1 with the scope under 'not offered'. The host verb typed on its
// own ends as it always did (TestHostRenameScopeStepFails).
func TestFixNamesHostScopeRefusedCountsAsRenamed(t *testing.T) {
	const line = "'linux-Web1' is not offered: its rename was refused with the host's (SNMP credentials for a scope named 'linux-web1' are already on disk: "
	const retry = "); retry: tacctl scope rename linux-Web1 linux-web1\n"
	sb := nameFixLab(t)
	refuseHostScope(sb)
	// Core-SW1 n, Web1 y, the host's own question about its scope y, Alice n,
	// Dmz n, Prod-Inner n.
	sb.run("n\ny\ny\nn\nn\nn\n", []string{"config", "validate", "--fix-names"})
	out := plain(sb.out.String())
	sb.expect(1, "Names: renamed 1, declined 4, not offered 1, failed 0.", "Host renamed. Scope 'linux-Web1' was NOT renamed: ")
	if !strings.Contains(out, "Host 'Web1' renamed to 'web1'.") {
		t.Errorf("the host was not renamed:\n%s", out)
	}
	if n := strings.Count(out, line); n != 1 || !strings.Contains(out, retry) {
		t.Errorf("the line for the scope (%d):\n%s", n, out)
	}
	if strings.Contains(out, "Rename scope 'linux-Web1'") {
		t.Errorf("the scope was offered:\n%s", out)
	}
	if got := sb.registryText(); got != "web1|root@198.51.100.10||linux-Web1|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	if !strings.Contains(sb.store(), "linux-Web1") {
		t.Errorf("the scope was renamed:\n%s", sb.store())
	}

	// With -y the same line once, the other renames made.
	sb = nameFixLab(t)
	refuseHostScope(sb)
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	out = plain(sb.out.String())
	sb.expect(1, "Names: renamed 5, declined 0, not offered 1, failed 0.", "")
	if n := strings.Count(out, line); n != 1 || !strings.Contains(out, retry) {
		t.Errorf("the line for the scope (%d):\n%s", n, out)
	}
	// Left out of this run only: the next run offers the scope again, and
	// once the file is gone it is renamed.
	sb.hooks.hostRenameStep = nil
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	sb.expect(1, "Names: renamed 0, declined 0, not offered 0, failed 1.", "are already on disk")
	if err := os.Remove(sb.path("state", "snmp", "linux-web1.yaml")); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	sb.expect(0, "Names: renamed 1, declined 0, not offered 0, failed 0.", "")
	if st := sb.store(); strings.Contains(st, "linux-Web1") {
		t.Errorf("the scope was not renamed:\n%s", st)
	}
}

// A scope a host rename leaves because other hosts use it is offered on its
// own and renamed (D234): the host counts as renamed and nothing is refused.
func TestFixNamesSharedScopeIsOfferedOnItsOwn(t *testing.T) {
	sb := nameFixLab(t)
	sb.write("state/linux-hosts", "Web1|root@198.51.100.10||linux-Web1|192.0.2.1|\nweb2|root@198.51.100.11||linux-Web1|192.0.2.1|\n", 0o600)
	sb.run("", []string{"config", "validate", "--fix-names", "-y"})
	out := plain(sb.out.String())
	sb.expect(0, "Names: renamed 6, declined 0, not offered 0, failed 0.", "")
	if strings.Contains(out, "is not offered") {
		t.Errorf("a name was not offered:\n%s", out)
	}
	if n := strings.Count(out, "Scope renamed: linux-Web1 -> linux-web1"); n != 1 {
		t.Errorf("the scope was renamed %d times:\n%s", n, out)
	}
}

// An engineer and an operator are refused before the report, and nothing is
// changed; a missing store is refused as everywhere else.
func TestFixNamesIsTheSuperusers(t *testing.T) {
	const denied = "'config validate --fix-names' renames devices, hosts, users and scopes, which is the superuser's."
	sb := engineerSandbox(t)
	sb.legacyStoreCase("  carol:", "  Carol:")
	before := sb.store()
	got := sb.asEngineer("y\ny\n", "config", "validate", "--fix-names", "-y")
	if sb.code != 1 || !strings.Contains(sb.stderr(), denied) || strings.Contains(got, "Configuration") || sb.store() != before {
		t.Errorf("engineer: %d %q %q", sb.code, got, sb.stderr())
	}

	op := newSandbox(t, true)
	op.legacyStoreCase("  carol:", "  Carol:")
	op.write("state/tacctl.yaml", "{}\n", 0o600)
	before = op.store()
	got = op.asUser("bob", "tac-operator", "config", "validate", "--fix-names", "-y")
	if op.code != 1 || !strings.Contains(op.stderr(), denied) || strings.Contains(got, "Configuration") || op.store() != before {
		t.Errorf("operator: %d %q %q", op.code, got, op.stderr())
	}
	if len(op.snapshotDirs()) != 0 {
		t.Error("a refusal took a snapshot")
	}

	// A server still on tacquito.yaml (read-only mode) has no store to
	// rename in.
	none := newSandbox(t, false)
	legacy, err := os.ReadFile("../../tests/fixtures/tacquito.minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	none.write("etc/tacquito.yaml", string(legacy), 0o600)
	none.run("", []string{"config", "validate", "--fix-names", "-y"})
	none.expect(1, "", store.NotInitialisedMsg)
	if strings.Contains(none.printed(), "Configuration is valid") {
		t.Errorf("a report was printed:\n%s", none.printed())
	}
}

// --fix-names asks and renames, so it does not go with --json, and -y goes
// with --fix-names only.
func TestFixNamesUsage(t *testing.T) {
	sb := nameFixLab(t)
	before := sb.store()
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"config", "validate", "--json", "--fix-names"}, "--fix-names asks questions and renames; it does not go with --json."},
		{[]string{"config", "validate", "--fix-names", "--json", "-y"}, "does not go with --json"},
		{[]string{"config", "validate", "-y"}, "-y goes with --fix-names."},
		{[]string{"config", "validate", "--fix-name"}, "Unknown option: '--fix-name'"},
	} {
		out := sb.run("y\n", c.args)
		if sb.code != 1 || out != "" || !strings.Contains(sb.stderr(), c.err) || !strings.Contains(sb.stderr(), "Usage: tacctl config validate [--json | --fix-names [-y]]") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", c.args, sb.code, out, sb.stderr())
		}
	}
	if sb.store() != before {
		t.Error("a usage error changed the store")
	}
}
