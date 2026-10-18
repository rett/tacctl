package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
)

// 'host rename' (docs/plans/0.2.14-plan.md D182-D186, D197-D201), on the
// sandbox of the hold tests: web1 (192.168.1.10), db1 and web2 are enrolled in
// scopes lab and prod, and the devices prod-sw and lab-sw are registered.

const (
	renameKey    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	renameRecord = `{"last_sync":{"at":"2026-10-01T00:00:00Z","by":"root","command":"sync","ok":true,"protocol":"1","created":[],"updated":[],"removed":[]}}` + "\n"
)

// seedPin gives the enrolled host name a pinned key and a recorded address in
// the device registry.
func (sb *sandbox) seedPin(name, addr string) {
	sb.t.Helper()
	f, err := devreg.Load(sb.path("state", "devices.yaml"))
	if err != nil {
		sb.t.Fatal(err)
	}
	f.SetHostKeys(name, []string{renameKey})
	f.SetHostAddress(name, addr, "2026-10-04 12:00")
	text, err := f.Text()
	if err != nil {
		sb.t.Fatal(err)
	}
	sb.write("state/devices.yaml", string(text), 0o600)
}

// seedKeyScan puts a host-key scan result in the seen cache under name.
func (sb *sandbox) seedKeyScan(name string) {
	sb.t.Helper()
	path := sb.path("var-lib", "devices-seen.json")
	s := devreg.NewSeen()
	s.RecordKeyScan(name, "192.168.1.10", 22, nil, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err := s.Save(path); err != nil {
		sb.t.Fatal(err)
	}
}

// registryHost is the registry as the test sees it.
func (sb *sandbox) registryText() string { return sb.read("state/linux-hosts") }

// pin is the device registry's record of the enrolled host name.
func (sb *sandbox) pin(name string) *devreg.HostPin {
	sb.t.Helper()
	f, err := devreg.Load(sb.path("state", "devices.yaml"))
	if err != nil {
		sb.t.Fatal(err)
	}
	return f.Host(name)
}

// fileExists reports whether a path under the sandbox is there.
func (sb *sandbox) fileExists(rel string) bool {
	_, err := os.Lstat(sb.path(rel))
	return err == nil
}

// stateOf is what a refusal must leave alone, in one string.
func (sb *sandbox) renameState() string {
	var b strings.Builder
	for _, rel := range []string{"state/linux-hosts", "state/devices.yaml", "state/staging", "state/tacctl.yaml", "state/store.yaml",
		"state/hosts/web1.json", "state/hosts/web7.json", "var-lib/devices-seen.json", "var-lib/ssh/known_hosts"} {
		b.WriteString(rel + ":" + readIn(sb.t, sb.dir, rel) + "\n")
	}
	return b.String() + strings.Join(sb.snapshotDirs(), ",")
}

// breakDeviceRegistryLock makes the device registry's lock file a directory:
// the registry can be read and not written.
func (sb *sandbox) breakDeviceRegistryLock() {
	sb.t.Helper()
	lock := sb.path("state", devreg.LockName)
	_ = os.Remove(lock)
	if err := os.Mkdir(lock, 0o700); err != nil {
		sb.t.Error(err)
	}
}

// printed is everything the last run printed, on either stream.
func (sb *sandbox) printed() string { return plain(sb.out.String()) + plain(sb.err.String()) }

// renameLab is hostLab with everything a host can carry under web1.
func renameLab(t *testing.T) *sandbox {
	sb := hostLab(t)
	sb.seedPin("web1", "192.168.1.10")
	sb.write("state/hosts/web1.json", renameRecord, 0o600)
	sb.write("state/staging", "192.0.2.9/32|lab|host|web1|2026-01-01\n192.0.2.8/32|lab|device|web1|2026-01-01\n192.0.2.7/32|lab|host|web2|2026-01-01\n", 0o600)
	sb.seedKeyScan("web1")
	return sb
}

func TestHostRenameCarriesEverythingTheHostHas(t *testing.T) {
	sb := renameLab(t)
	holdHost(t, sb, "web1", "locked out of sudo")
	snaps := len(sb.snapshotDirs())

	out := plain(sb.run("", []string{"host", "rename", "web1", "web7"}))
	sb.expect(0, "Host 'web1' renamed to 'web7'. Nothing was sent to the host.", "")
	if strings.Contains(out, "Rename it to") {
		t.Errorf("a scope was offered:\n%s", out)
	}

	// The registry line is renamed where it is.
	if got, want := sb.registryText(), strings.Replace(hostLines, "web1|", "web7|", 1); got != want {
		t.Errorf("registry %q, want %q", got, want)
	}
	// Pin, address and the generated known_hosts.
	if sb.pin("web1") != nil {
		t.Error("the pin stayed under the old name")
	}
	if p := sb.pin("web7"); p == nil || p.Address != "192.168.1.10" || len(p.Keys) != 1 {
		t.Errorf("pin %+v", p)
	}
	if kh := sb.read("var-lib/ssh/known_hosts"); !strings.Contains(kh, "web7") || strings.Contains(kh, "web1") {
		t.Errorf("known_hosts %q", kh)
	}
	// The record, the staging addresses of the host (and of nothing else).
	if sb.fileExists("state/hosts/web1.json") || sb.read("state/hosts/web7.json") != renameRecord {
		t.Error("the record did not move")
	}
	if got, want := sb.read("state/staging"), "192.0.2.9/32|lab|host|web7|2026-01-01\n192.0.2.8/32|lab|device|web1|2026-01-01\n192.0.2.7/32|lab|host|web2|2026-01-01\n"; got != want {
		t.Errorf("staging %q, want %q", got, want)
	}
	// The hold stays on the address and follows the name.
	if o := sb.overrides(); !strings.Contains(o, "breakglass_hold:\n  web7:\n    address: 192.168.1.10\n") || strings.Contains(o, "web1") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	if cfg := sb.renderedConfig(); !strings.Contains(cfg, "# break-glass held: 192.168.1.10 (device web7)") || strings.Contains(cfg, "device web1") {
		t.Errorf("the rendered file:\n%s", cfg)
	}
	// The key scan result moved with the name.
	if s, err := devreg.LoadSeen(sb.path("var-lib", "devices-seen.json")); err != nil || !s.HasKeyScanFor("web7") || s.HasKeyScanFor("web1") {
		t.Errorf("seen cache %+v %v", s, err)
	}
	// A snapshot of the state before; the audit line; nothing over ssh.
	// (carrying the hold takes one more, of the state after the rename)
	if n := len(sb.snapshotDirs()); n < snaps+1 {
		t.Errorf("%d snapshots, want more than %d", n, snaps)
	} else if first := sb.snapshotDirs()[snaps]; readIn(t, first, "linux-hosts") != hostLines {
		t.Errorf("the snapshot does not hold the registry from before: %q", readIn(t, first, "linux-hosts"))
	}
	if !sb.runner.CalledRegexp(`logger.* -p auth\.info host rename old=web1 new=web7 by=root`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	if sb.sshCalls() != 0 {
		t.Errorf("%d ssh calls", sb.sshCalls())
	}
	// The renamed host is held, listed, and its record is read under the new name.
	if got := plain(sb.run("", []string{"host", "list"})); !strings.Contains(got, "web7") || !strings.Contains(got, "BREAK-GLASS") || strings.Contains(got, "web1") {
		t.Errorf("host list:\n%s", got)
	}
	if got := plain(sb.run("", []string{"host", "show", "web7"})); !strings.Contains(got, "HELD since ") {
		t.Errorf("host show:\n%s", got)
	}
	if got := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(got, "web7") || strings.Contains(got, "ORPHAN") {
		t.Errorf("breakglass list:\n%s", got)
	}
}

// A rename that changes only the spelling to lower case is legal and is how
// a name from before, with upper case, is fixed; the host is not equal to a
// different host by it, and everything the host has follows.
func TestHostRenameSpellingOnly(t *testing.T) {
	sb := renameLab(t)
	holdHost(t, sb, "web1", "locked out of sudo")
	sb.legacyHostCase("web1", "Web1")
	sb.run("", []string{"host", "rename", "Web1", "web1"})
	sb.expect(0, "Host 'Web1' renamed to 'web1'.", "")
	if got, want := sb.registryText(), hostLines; got != want {
		t.Errorf("registry %q, want %q", got, want)
	}
	if p := sb.pin("web1"); p == nil || p.Name != "web1" || len(p.Keys) != 1 {
		t.Errorf("pin %+v", p)
	}
	if !sb.fileExists("state/hosts/web1.json") || sb.fileExists("state/hosts/Web1.json") {
		t.Error("the record did not move")
	}
	if !strings.Contains(sb.read("state/staging"), "|host|web1|") || strings.Contains(sb.read("state/staging"), "|host|Web1|") {
		t.Errorf("staging %q", sb.read("state/staging"))
	}
	if o := sb.overrides(); !strings.Contains(o, "  web1:\n    address: 192.168.1.10\n") || strings.Contains(o, "  Web1:") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	// The other way is refused, and so is the same name.
	sb.run("", []string{"host", "rename", "web1", "Web1"})
	sb.expect(1, "", "Names are lower case: use 'web1'. Nothing was changed.")
	sb.run("", []string{"host", "rename", "web1", "web1"})
	sb.expect(1, "", "'web1' already has that name.")
}

// Every refusal changes nothing and goes nowhere near ssh.
func TestHostRenameRefusals(t *testing.T) {
	sb := renameLab(t)
	// A hold recorded under a name no host has any more: an orphan.
	holdHost(t, sb, "web2", "x")
	sb.write("state/linux-hosts", hostLines[:strings.Index(hostLines, "web2|")], 0o600)
	before := sb.renameState()
	for _, c := range []struct {
		args []string
		err  string
	}{
		{nil, "Usage: tacctl host rename <old> <new> [-y]"},
		{[]string{"web1"}, "Usage: tacctl host rename"},
		{[]string{"web1", "a", "b"}, "Usage: tacctl host rename"},
		{[]string{"web1", "web7", "--bogus"}, "Unknown option: '--bogus'"},
		{[]string{"-z", "web1", "web7"}, "Unknown option: '-z'"},
		{[]string{"ghost", "web7"}, "No enrolled host named 'ghost'"},
		{[]string{"web1", "web1"}, "'web1' already has that name."},
		{[]string{"web1", "7web"}, "Invalid host name '7web'"},
		{[]string{"web1", "a.b"}, "Invalid host name 'a.b'"},
		{[]string{"web1", strings.Repeat("x", 27)}, "Invalid host name"},
		{[]string{"web1", "all"}, "'all' is a tacctl word and cannot name a host"},
		{[]string{"web1", "Scope"}, "'Scope' is a tacctl word"},
		{[]string{"web1", "switch2"}, "'switch2' is a generic name"},
		{[]string{"web1", "db1"}, "A host named 'db1' is already enrolled"},
		{[]string{"web1", "DB1"}, "'db1' is enrolled; names are not case-sensitive. Nothing was changed."},
		{[]string{"web1", "LAB-sw"}, "'lab-sw' is already registered as a device (192.168.1.1)"},
		// The hold of a host that is gone is not a new host's.
		{[]string{"web1", "web2"}, "A break-glass hold is recorded under the name 'web2' (192.168.1.12)"},
		{[]string{"web1", "web2", "--yes"}, "tacctl breakglass release web2'. Nothing was changed."},
		{[]string{"web1", "Web7"}, "Names are lower case: use 'web7'. Nothing was changed."},
	} {
		sb.run("y\n", append([]string{"host", "rename"}, c.args...))
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.err) {
			t.Errorf("%q: %d %q, want %q", c.args, sb.code, sb.stderr(), c.err)
		}
		if after := sb.renameState(); after != before {
			t.Errorf("%q changed something:\n%s\n%s", c.args, before, after)
		}
	}
	if sb.sshCalls() != 0 || sb.runner.Called("logger") && sb.runner.CalledRegexp(`host rename`) {
		t.Error("a refusal went on")
	}
}

// What an earlier host of the new name left is listed and replaced after a
// confirmation; declining changes nothing.
func TestHostRenameLeftovers(t *testing.T) {
	sb := renameLab(t)
	sb.seedPin("web7", "192.0.2.77")
	sb.write("state/hosts/web7.json", `{"last_sync":{"at":"1999","by":"x","command":"sync","ok":false,"protocol":"0","created":[],"updated":[],"removed":[]}}`+"\n", 0o600)
	sb.write("state/staging", sb.read("state/staging")+"192.0.2.66/32|prod|host|web7|2020-01-01\n", 0o600)
	before := sb.renameState()

	for _, stdin := range []string{"n\n", "", "yes please\n"} {
		sb.run(stdin, []string{"host", "rename", "web1", "web7"})
		sb.expect(1, "Nothing was changed.", "")
		for _, want := range []string{"has what an earlier host of that name left", "its pinned ssh keys and address in the device registry", "its record ", "1 staging address(es)"} {
			if !strings.Contains(sb.printed(), want) {
				t.Errorf("%q: the leftovers lack %q:\n%s", stdin, want, sb.printed())
			}
		}
		if after := sb.renameState(); after != before {
			t.Errorf("declining (%q) changed something:\n%s\n%s", stdin, before, after)
		}
	}

	sb.run("y\n", []string{"host", "rename", "web1", "web7"})
	sb.expect(0, "Host 'web1' renamed to 'web7'.", "")
	if p := sb.pin("web7"); p == nil || p.Address != "192.168.1.10" || sb.pin("web1") != nil {
		t.Errorf("pin %+v", p)
	}
	if sb.read("state/hosts/web7.json") != renameRecord {
		t.Errorf("record %q", sb.read("state/hosts/web7.json"))
	}
	if got, want := sb.read("state/staging"), "192.0.2.9/32|lab|host|web7|2026-01-01\n192.0.2.8/32|lab|device|web1|2026-01-01\n192.0.2.7/32|lab|host|web2|2026-01-01\n"; got != want {
		t.Errorf("staging %q, want %q", got, want)
	}

	// -y is --yes, and a question has the shape of the device questions.
	sb3 := renameLab(t)
	sb3.write("state/hosts/web7.json", "stale\n", 0o600)
	holdTTY(t, sb3, "n\n")
	sb3.run("", []string{"host", "rename", "web1", "web7"})
	sb3.tty = nil
	sb3.expect(1, "Nothing was changed.", "  Replace it? [y/N]: ")
	sb3.run("", []string{"host", "rename", "web1", "web7", "-y"})
	sb3.expect(0, "renamed to 'web7'", "")

	// --yes asks nothing; the old host has no record, so the stray one goes.
	sb2 := renameLab(t)
	_ = os.Remove(sb2.path("state/hosts/web1.json"))
	sb2.write("state/hosts/web7.json", "stale\n", 0o600)
	sb2.run("", []string{"host", "rename", "web1", "web7", "--yes"})
	sb2.expect(0, "renamed to 'web7'", "")
	if sb2.fileExists("state/hosts/web7.json") || sb2.fileExists("state/hosts/web1.json") {
		t.Error("a stray record stayed")
	}
}

// A hold under the new name is refused flat, with --yes too, and the hold of
// the host itself follows it.
func TestHostRenameAnotherHostsHoldIsNotReplaced(t *testing.T) {
	sb := hostLab(t)
	holdHost(t, sb, "web2", "x")
	sb.write("state/linux-hosts", "web1|root@192.168.1.10||lab|192.0.2.1|\n", 0o600)
	before := sb.renameState()
	sb.run("y\n", []string{"host", "rename", "web1", "web2", "--yes"})
	sb.expect(1, "", "Nothing was changed.")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
}

// A devices.yaml that cannot be written puts the registry line back, and
// says that nothing was changed.
func TestHostRenameDeviceRegistryFailureRestoresTheRegistry(t *testing.T) {
	sb := renameLab(t)
	// The registry's lock cannot be taken: its file is a directory.
	sb.breakDeviceRegistryLock()
	regBefore, staging := sb.registryText(), sb.read("state/staging")
	sb.run("", []string{"host", "rename", "web1", "web7"})
	sb.expect(1, "", "Host 'web1' was not renamed; nothing was changed.")
	if sb.registryText() != regBefore {
		t.Errorf("registry %q, want %q", sb.registryText(), regBefore)
	}
	if sb.pin("web1") == nil || !sb.fileExists("state/hosts/web1.json") || sb.read("state/staging") != staging {
		t.Error("something moved")
	}
	if sb.runner.CalledRegexp(`host rename`) {
		t.Error("a failed rename was logged")
	}
}

// If the registry line cannot be put back either, both states are named.
func TestHostRenameThatCannotBeUndoneNamesBothStates(t *testing.T) {
	sb := renameLab(t)
	sb.hooks.hostRenameStep = func(step string) {
		if step != "registry" {
			return
		}
		// Between the two writes: the device registry is out of reach, and a
		// host equal to the old name has been enrolled meanwhile.
		sb.breakDeviceRegistryLock()
		sb.write("state/linux-hosts", "web7|root@192.168.1.10||lab|192.0.2.1|\nWeb1|other||lab|s|\n", 0o600)
	}
	sb.run("", []string{"host", "rename", "web1", "web7"})
	if sb.code != 1 {
		t.Fatalf("exit %d", sb.code)
	}
	for _, want := range []string{"could not be put back", "The host registry names the host 'web7'; its pinned ssh keys and address are under 'web1'", "tacctl backup restore"} {
		if !strings.Contains(sb.stderr(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, sb.stderr())
		}
	}
}

// A failed step after the pins is a warning that names the leftover; the
// rename itself stands.
func TestHostRenameWarnsForWhatStayed(t *testing.T) {
	sb := renameLab(t)
	// The record cannot move: a directory of its new name with something in it.
	if err := os.MkdirAll(sb.path("state", "hosts", "web7.json", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Staging cannot be saved: its temporary file is a directory.
	if err := os.Mkdir(sb.path("state", "staging.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"host", "rename", "web1", "web7", "--yes"})
	sb.expect(0, "Host 'web1' renamed to 'web7'.", "")
	for _, want := range []string{"web7: its record (", "web7: its staging addresses still name 'web1' (192.0.2.9)"} {
		if !strings.Contains(sb.printed(), want) {
			t.Errorf("no warning %q:\n%s", want, sb.printed())
		}
	}
	if !strings.Contains(sb.registryText(), "web7|") || sb.pin("web7") == nil {
		t.Error("the rename did not stand")
	}
	if !sb.runner.CalledRegexp(`host rename old=web1 new=web7`) {
		t.Error("not logged")
	}
}

// A running rotation of the host refuses the rename without waiting.
func TestHostRenameRefusedWhileARotationRuns(t *testing.T) {
	sb := renameLab(t)
	unlock, err := hosts.LockHost(sb.path("state", "locks"), "web1")
	if err != nil {
		t.Fatal(err)
	}
	before := sb.renameState()
	sb.run("", []string{"host", "rename", "web1", "web7"})
	sb.expect(1, "", "Another rotation of 'web1' is running; nothing was changed.")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
	unlock()
	sb.run("", []string{"host", "rename", "web1", "web7"})
	sb.expect(0, "renamed to 'web7'", "")
}

// A snapshot that cannot be taken is a refusal too (see the knobs file).

// The host is renamed locally: a registry that is not there, and a registry
// edited meanwhile, are met without ssh.
func TestHostRenameNeedsAnEnrolledHost(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"host", "rename", "web1", "web7"})
	sb.expect(1, "", "No enrolled host named 'web1'")
	if sb.fileExists("state/linux-hosts") {
		t.Error("a registry was made")
	}
}
