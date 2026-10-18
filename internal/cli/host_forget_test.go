package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
)

// 'host forget' and the findings about duplicate and orphaned hosts
// (docs/plans/0.2.14-plan.md D187), on the sandbox of the rename tests: web1
// carries a pin, a record, two staging entries (one of kind host) and a
// host-key scan.

const (
	// stagingAfterWeb1 is the staging file without the host entry of web1.
	stagingAfterWeb1 = "192.0.2.8/32|lab|device|web1|2026-01-01\n192.0.2.7/32|lab|host|web2|2026-01-01\n"
	// withoutWeb1 is the registry of the lab without web1.
	withoutWeb1 = "db1|root@10.99.0.20||prod|192.0.2.1|\nweb2|root@web2.example.net||lab|192.0.2.1|\n"
)

func TestHostForgetDropsEverythingTheHostHas(t *testing.T) {
	sb := renameLab(t)
	snaps := len(sb.snapshotDirs())

	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "Host 'web1' forgotten. Nothing was sent to the host.", "")
	if got := sb.registryText(); got != withoutWeb1 {
		t.Errorf("registry %q, want %q", got, withoutWeb1)
	}
	if sb.pin("web1") != nil {
		t.Error("the pin stayed")
	}
	if kh := sb.read("var-lib/ssh/known_hosts"); strings.Contains(kh, "web1") {
		t.Errorf("known_hosts %q", kh)
	}
	if sb.fileExists("state/hosts/web1.json") {
		t.Error("the record stayed")
	}
	if got := sb.read("state/staging"); got != stagingAfterWeb1 {
		t.Errorf("staging %q, want %q", got, stagingAfterWeb1)
	}
	if s, err := devreg.LoadSeen(sb.path("var-lib", "devices-seen.json")); err != nil || s.HasKeyScanFor("web1") {
		t.Errorf("seen cache %+v %v", s, err)
	}
	// What it says: the host is untouched, the staging /32 is still the
	// scope's and how to drop it, the pieces it dropped.
	for _, want := range []string{"The host itself is not touched", "tacctl host unenroll", "its line in the host registry",
		"its pinned ssh keys, address and history", "its record ", "1 staging address(es): 192.0.2.9/32",
		"The scope 'lab' still answers 192.0.2.9/32. To drop it: tacctl scope prefixes lab remove 192.0.2.9/32"} {
		if !strings.Contains(sb.printed(), want) {
			t.Errorf("the output lacks %q:\n%s", want, sb.printed())
		}
	}
	// The other hosts keep theirs; a snapshot of the state before; the audit
	// line; nothing over ssh.
	if sb.pin("web2") == nil && sb.fileExists("state/hosts/web2.json") {
		t.Error("another host lost something")
	}
	if n := len(sb.snapshotDirs()); n < snaps+1 {
		t.Errorf("%d snapshots, want more than %d", n, snaps)
	} else if first := sb.snapshotDirs()[snaps]; readIn(t, first, "linux-hosts") != hostLines || !strings.Contains(readIn(t, first, "hosts/web1.json"), "last_sync") {
		t.Errorf("the snapshot does not hold the host from before: %q", readIn(t, first, "linux-hosts"))
	}
	if !sb.runner.CalledRegexp(`logger.* -p auth\.info host forget name=web1 by=root`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	if sb.sshCalls() != 0 {
		t.Errorf("%d ssh calls", sb.sshCalls())
	}
	// Gone is gone.
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(1, "", "No enrolled host or leftover named 'web1'")
}

// The confirmation names what goes; no answer is a no; --yes skips it.
func TestHostForgetConfirms(t *testing.T) {
	sb := renameLab(t)
	before := sb.renameState()
	for _, stdin := range []string{"n\n", "", "yes please\n", "\n"} {
		sb.run(stdin, []string{"host", "forget", "web1"})
		sb.expect(1, "Nothing was changed.", "")
		if want := "Forget the host 'web1' (root@192.168.1.10, scope lab). Dropped from this server:"; !strings.Contains(sb.printed(), want) {
			t.Errorf("%q: lacks %q:\n%s", stdin, want, sb.printed())
		}
		if after := sb.renameState(); after != before {
			t.Errorf("declining (%q) changed something:\n%s\n%s", stdin, before, after)
		}
	}
	sb.run("y\n", []string{"host", "forget", "web1"})
	sb.expect(0, "Host 'web1' forgotten.", "")
	if strings.Contains(sb.registryText(), "web1|") {
		t.Errorf("registry %q", sb.registryText())
	}
}

func TestHostForgetUsageAndUnknown(t *testing.T) {
	sb := renameLab(t)
	before := sb.renameState()
	for _, c := range []struct {
		args []string
		err  string
	}{
		{nil, "Usage: tacctl host forget <name> [--yes]"},
		{[]string{"a", "b"}, "Usage: tacctl host forget"},
		{[]string{"web1", "--force"}, "Unknown option: '--force'"},
		{[]string{"ghost", "--yes"}, "No enrolled host or leftover named 'ghost'"},
	} {
		sb.run("y\n", append([]string{"host", "forget"}, c.args...))
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.err) {
			t.Errorf("%q: %d %q, want %q", c.args, sb.code, sb.stderr(), c.err)
		}
	}
	if after := sb.renameState(); after != before {
		t.Errorf("a refusal changed something:\n%s\n%s", before, after)
	}
}

// A held host is refused with the way out; so is the hold of a name with no
// host.
func TestHostForgetRefusedForAHeldHost(t *testing.T) {
	sb := renameLab(t)
	holdHost(t, sb, "web1", "locked out of sudo")
	before := sb.renameState()
	sb.run("y\n", []string{"host", "forget", "web1", "--yes"})
	sb.expect(1, "", "release it first (tacctl breakglass release web1). Nothing was changed.")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
	sb.run("", []string{"breakglass", "release", "web1"})
	if sb.code != 0 {
		t.Fatalf("release: %d %q %q", sb.code, sb.out.String(), sb.stderr())
	}
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "forgotten", "")

	// A hold recorded under a name no host has: the leftovers are not
	// forgotten before it is released.
	sb = renameLab(t)
	holdHost(t, sb, "web2", "x")
	sb.write("state/linux-hosts", strings.Replace(hostLines, "web2|", "web3|", 1), 0o600)
	sb.write("state/hosts/web2.json", renameRecord, 0o600)
	sb.run("", []string{"host", "forget", "web2", "--yes"})
	sb.expect(1, "", "Release it first: tacctl breakglass release web2. Nothing was changed.")
	if !sb.fileExists("state/hosts/web2.json") {
		t.Error("the record went")
	}
}

// The registered spelling first; else the leftovers of exactly the spelling
// typed; else the one registered host equal to it ignoring case.
func TestHostForgetSpelling(t *testing.T) {
	// A stray 'Web1' is forgotten by 'web1' when it is the only one.
	sb := hostLab(t)
	sb.seedPin("web1", "192.168.1.10")
	sb.write("state/linux-hosts", strings.Replace(hostLines, "web1|", "Web1|", 1), 0o600)
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "Host 'Web1' forgotten.", "")
	if strings.Contains(sb.registryText(), "eb1|") || sb.pin("web1") != nil {
		t.Errorf("registry %q, pin %v", sb.registryText(), sb.pin("web1"))
	}

	// Two spellings registered: an inexact one names neither, the exact one
	// forgets only itself and leaves the pin they share.
	sb = renameLab(t)
	sb.write("state/linux-hosts", "Web1|root@192.168.1.10||lab|192.0.2.1|\nweb1|root@192.168.1.10||lab|192.0.2.1|\n", 0o600)
	sb.write("state/hosts/Web1.json", renameRecord, 0o600)
	before := sb.renameState()
	sb.run("y\n", []string{"host", "forget", "WEB1", "--yes"})
	sb.expect(1, "", "'WEB1' matches the hosts 'Web1', 'web1' ignoring case")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
	sb.run("", []string{"host", "forget", "Web1", "--yes"})
	sb.expect(0, "The pinned keys stay: the enrolled host 'web1' has the same name ignoring case.", "")
	if got := sb.registryText(); got != "web1|root@192.168.1.10||lab|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	if p := sb.pin("web1"); p == nil || len(p.Keys) != 1 {
		t.Errorf("the surviving host lost its pin: %+v", p)
	}
	if sb.fileExists("state/hosts/Web1.json") || !sb.fileExists("state/hosts/web1.json") {
		t.Error("the records")
	}
	if s, err := devreg.LoadSeen(sb.path("var-lib", "devices-seen.json")); err != nil || !s.HasKeyScanFor("web1") {
		t.Errorf("the scan result the surviving host shares went: %+v %v", s, err)
	}
}

// The repair for an orphan: pieces that no registry line has.
func TestHostForgetOrphan(t *testing.T) {
	sb := renameLab(t)
	sb.write("state/linux-hosts", withoutWeb1, 0o600)
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "Forget what remains of the host 'web1', which is not enrolled", "")
	if !strings.Contains(sb.printed(), "Host 'web1' forgotten.") || strings.Contains(sb.printed(), "its line in the host registry") {
		t.Errorf("output:\n%s", sb.printed())
	}
	if sb.registryText() != withoutWeb1 || sb.pin("web1") != nil || sb.fileExists("state/hosts/web1.json") || sb.read("state/staging") != stagingAfterWeb1 {
		t.Errorf("not everything went:\n%s", sb.renameState())
	}
	if s, err := devreg.LoadSeen(sb.path("var-lib", "devices-seen.json")); err != nil || s.HasKeyScanFor("web1") {
		t.Errorf("seen cache %+v %v", s, err)
	}
	if sb.sshCalls() != 0 {
		t.Error("ssh was used")
	}

	// Only one kind of piece is enough, and the spelling is the one typed:
	// a record 'web1.json' is not the registered 'Web1''s.
	sb = renameLab(t)
	sb.write("state/linux-hosts", strings.Replace(hostLines, "web1|", "Web1|", 1), 0o600)
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "Forget what remains of the host 'web1', which is not enrolled", "")
	if !strings.Contains(sb.registryText(), "Web1|") || sb.fileExists("state/hosts/web1.json") {
		t.Errorf("registry %q", sb.registryText())
	}
	if sb.pin("web1") == nil {
		t.Error("the registered host's pin went with the leftover record")
	}
}

// A host enrolled with --local is forgotten like another; nothing is run.
func TestHostForgetLocalHost(t *testing.T) {
	sb := hostLab(t)
	sb.write("state/linux-hosts", hostLines+"here|local||lab|192.0.2.1|\n", 0o600)
	sb.run("", []string{"host", "forget", "here", "--yes"})
	sb.expect(0, "Host 'here' forgotten.", "")
	if sb.registryText() != hostLines || sb.sshCalls() != 0 {
		t.Errorf("registry %q, %d ssh calls", sb.registryText(), sb.sshCalls())
	}
}

// A running rotation of the host refuses it without waiting.
func TestHostForgetRefusedWhileARotationRuns(t *testing.T) {
	sb := renameLab(t)
	unlock, err := hosts.LockHost(sb.path("state", "locks"), "web1")
	if err != nil {
		t.Fatal(err)
	}
	before := sb.renameState()
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(1, "", "Another rotation of 'web1' is running; nothing was changed.")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
	unlock()
}

// A failing step after the registry line is a warning that names the verb
// that finishes it.
func TestHostForgetWarnsForWhatStayed(t *testing.T) {
	sb := renameLab(t)
	// The record is a directory with something in it; staging cannot be saved.
	_ = os.Remove(sb.path("state", "hosts", "web1.json"))
	if err := os.MkdirAll(sb.path("state", "hosts", "web1.json", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sb.path("state", "staging.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "Host 'web1' forgotten.", "")
	for _, want := range []string{"web1: its record (", "Run: tacctl host forget web1", "web1: its staging addresses could not be dropped"} {
		if !strings.Contains(sb.printed(), want) {
			t.Errorf("no warning %q:\n%s", want, sb.printed())
		}
	}
	if strings.Contains(sb.registryText(), "web1|") {
		t.Error("the registry line stayed")
	}
}

// --- findings ----------------------------------------------------------------------

// findings runs 'config validate' and 'host list' and returns the lines of
// the Linux hosts area and the footer of the list.
func (sb *sandbox) findings(t *testing.T) (validate, list string) {
	t.Helper()
	validate = plain(sb.run("", []string{"config", "validate"})) + sb.stderr()
	list = plain(sb.run("", []string{"host", "list"})) + sb.stderr()
	return
}

func TestHostFindingsNoneInAHealthyLab(t *testing.T) {
	sb := renameLab(t)
	v, l := sb.findings(t)
	if strings.Contains(v, "one name ignoring case") || strings.Contains(v, "is not an enrolled host") || strings.Contains(l, "finding(s)") {
		t.Errorf("findings in a healthy lab:\n%s\n%s", v, l)
	}
}

func TestHostFindingsDuplicateNames(t *testing.T) {
	sb := renameLab(t)
	sb.write("state/linux-hosts", hostLines+"Web1|root@192.168.1.10||lab|192.0.2.1|\n", 0o600)
	v, l := sb.findings(t)
	for _, want := range []string{"Linux hosts:", "the hosts 'web1', 'Web1' are one name ignoring case and share one record of pinned keys",
		"tacctl host forget <name> drops the stray registration; tacctl host rename <name> <new> gives it a name of its own"} {
		if !strings.Contains(v, want) {
			t.Errorf("validate lacks %q:\n%s", want, v)
		}
	}
	if !strings.Contains(l, "1 finding(s): see tacctl config validate") {
		t.Errorf("host list:\n%s", l)
	}
	// The shared pin is not also two hosts at one address.
	if strings.Contains(v, "same recorded address") {
		t.Errorf("validate:\n%s", v)
	}
}

func TestHostFindingsHostNamedLikeADevice(t *testing.T) {
	sb := renameLab(t)
	sb.write("state/linux-hosts", hostLines+"lab-sw|root@192.0.2.60||lab|192.0.2.1|\n", 0o600)
	v, l := sb.findings(t)
	if want := "the host 'lab-sw' has the name of the device 'lab-sw' (192.168.1.1) (tacctl host rename lab-sw <new>)"; !strings.Contains(v, want) {
		t.Errorf("validate lacks %q:\n%s", want, v)
	}
	if !strings.Contains(l, "1 finding(s)") {
		t.Errorf("host list:\n%s", l)
	}
}

func TestHostFindingsSameRecordedAddress(t *testing.T) {
	sb := renameLab(t)
	sb.seedPin("db1", "192.168.1.10")
	v, l := sb.findings(t)
	if want := "the hosts 'web1', 'db1' have the same recorded address, 192.168.1.10 (tacctl host forget <name> drops a registration made twice)"; !strings.Contains(v, want) {
		t.Errorf("validate lacks %q:\n%s", want, v)
	}
	if !strings.Contains(l, "1 finding(s)") {
		t.Errorf("host list:\n%s", l)
	}
}

func TestHostFindingsOrphans(t *testing.T) {
	sb := renameLab(t)
	// ghost has all three; ghost2 only a record; the staging of the device
	// web1 is a device's, and web2's is enrolled.
	sb.seedPin("ghost", "192.0.2.33")
	sb.write("state/hosts/ghost.json", renameRecord, 0o600)
	sb.write("state/hosts/ghost2.json", renameRecord, 0o600)
	sb.write("state/staging", sb.read("state/staging")+"192.0.2.34/32|lab|host|ghost|2026-01-01\n192.0.2.35/32|lab|host|ghost|2026-01-01\n", 0o600)
	v, l := sb.findings(t)
	for _, want := range []string{
		"'ghost' is not an enrolled host but has pinned ssh keys or an address, a record, 2 staging address(es) (tacctl host forget ghost)",
		"'ghost2' is not an enrolled host but has a record (tacctl host forget ghost2)"} {
		if !strings.Contains(v, want) {
			t.Errorf("validate lacks %q:\n%s", want, v)
		}
	}
	if !strings.Contains(l, "2 finding(s): see tacctl config validate") {
		t.Errorf("host list:\n%s", l)
	}
	// And forgetting them ends the findings.
	for _, n := range []string{"ghost", "ghost2"} {
		sb.run("", []string{"host", "forget", n, "--yes"})
		sb.expect(0, "forgotten", "")
	}
	if v, l = sb.findings(t); strings.Contains(v, "is not an enrolled host") || strings.Contains(l, "finding(s)") {
		t.Errorf("after forgetting:\n%s\n%s", v, l)
	}
}

// Findings are read-only, and an empty registry still reports its orphans.
func TestHostFindingsAreReadOnlyAndShownWithNoHosts(t *testing.T) {
	sb := renameLab(t)
	sb.write("state/linux-hosts", "", 0o600)
	before := sb.renameState()
	v, l := sb.findings(t)
	if !strings.Contains(v, "'web1' is not an enrolled host but has") || !strings.Contains(l, "None. Enroll one with") || !strings.Contains(l, "2 finding(s)") {
		t.Errorf("validate:\n%s\nlist:\n%s", v, l)
	}
	if after := sb.renameState(); after != before {
		t.Errorf("a read changed something:\n%s\n%s", before, after)
	}
}

// An engineer lists the hosts of their scopes and is told nothing of the
// registrations of the others.
func TestHostFindingsNotShownToAnEngineer(t *testing.T) {
	sb := renameLab(t)
	sb.write("state/hosts/ghost.json", renameRecord, 0o600)
	sb.asEngineer("", "host", "list")
	if sb.code != 0 || strings.Contains(plain(sb.out.String())+sb.stderr(), "finding(s)") {
		t.Errorf("%d %q %q", sb.code, sb.out.String(), sb.stderr())
	}
}
