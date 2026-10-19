package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// 'host forget' and the findings about duplicate and orphaned hosts
// (docs/plans/0.2.14-plan.md D187), on the sandbox of the rename tests: web1
// carries a pin, a record, two staging entries (one of kind host) and a
// host-key scan.

const (
	// renameStaging is the staging file of renameLab.
	renameStaging = "192.0.2.9/32|lab|host|web1|2026-01-01\n192.0.2.8/32|lab|device|web1|2026-01-01\n192.0.2.7/32|lab|host|web2|2026-01-01\n"
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
		if want := "Forget the host 'web1' (root@192.168.1.10, scope lab). Would drop from this server:"; !strings.Contains(sb.printed(), want) {
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

// -y is --yes, and the question has the shape of the device questions.
func TestHostForgetShortYesAndPromptShape(t *testing.T) {
	sb := renameLab(t)
	holdTTY(t, sb, "n\n")
	sb.run("", []string{"host", "forget", "web1"})
	sb.tty = nil
	sb.expect(1, "Nothing was changed.", "  Forget it? [y/N]: ")
	sb.run("", []string{"host", "forget", "web1", "-y"})
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
		{nil, "Usage: tacctl host forget <name> [-y]"},
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

// A host enrolled with --local is forgotten like another, but nothing is run
// on this server, so its PAM setup and console accounts keep using the scope:
// the warning comes before the question, and the scope is not offered for
// removal.
func TestHostForgetLocalHost(t *testing.T) {
	sb := hostLab(t)
	// The only host of its scope, so that a hint to remove the scope would be
	// given for any other host.
	sb.write("state/linux-hosts", "here|local||lab|192.0.2.1|\n", 0o600)
	warn := "This is the registration of this server itself. Its PAM setup and console accounts still use scope 'lab'"
	way := "'tacctl host unenroll here' cleans this server properly"

	// Declined, the warning has been given and nothing has changed.
	sb.run("n\n", []string{"host", "forget", "here"})
	sb.expect(1, "Nothing was changed.", "")
	out := sb.printed()
	i, j := strings.Index(out, warn), strings.Index(out, "Forget it?")
	if i < 0 || j >= 0 && i > j || !strings.Contains(out, way) || !strings.Contains(out, "Forget it only when the line is a stray duplicate.") {
		t.Errorf("the warning is missing or after the question:\n%s", out)
	}
	if sb.registryText() != "here|local||lab|192.0.2.1|\n" {
		t.Errorf("declining changed the registry: %q", sb.registryText())
	}

	// With --yes the warning is still printed, then the line goes.
	sb.run("", []string{"host", "forget", "here", "--yes"})
	sb.expect(0, "Host 'here' forgotten.", "")
	out = sb.printed()
	if !strings.Contains(out, warn) || !strings.Contains(out, way) {
		t.Errorf("--yes hides the warning:\n%s", out)
	}
	for _, bad := range []string{"tacctl scope remove", "No enrolled host uses scope", "cleans a host that can be reached", "nothing is sent to it"} {
		if strings.Contains(out, bad) {
			t.Errorf("the output for this server's own host has %q:\n%s", bad, out)
		}
	}
	if sb.registryText() != "" || sb.sshCalls() != 0 {
		t.Errorf("registry %q, %d ssh calls", sb.registryText(), sb.sshCalls())
	}
	if sb.runner.CalledRegexp(`sshd|/etc/shells|systemctl`) {
		t.Errorf("something was run: %v", sb.runner.Argvs())
	}

	// Another host: no such warning, and the scope hint stays.
	sb = hostLab(t)
	sb.write("state/linux-hosts", "web1|root@192.168.1.10||lab|192.0.2.1|\n", 0o600)
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "Host 'web1' forgotten.", "")
	out = sb.printed()
	if strings.Contains(out, "this server itself") || !strings.Contains(out, "tacctl scope remove lab") || !strings.Contains(out, "'tacctl host unenroll' cleans a host that can be reached") {
		t.Errorf("output for another host:\n%s", out)
	}
}

// A pin that could not be removed is found again by its own spelling, which
// the hint names, whatever the registry's spelling was.
func TestHostForgetRetryHintNamesThePinsSpelling(t *testing.T) {
	sb := renameLab(t)
	// Registered as Web1; the pin, the record and the staging are web1's.
	sb.write("state/linux-hosts", strings.Replace(hostLines, "web1|", "Web1|", 1), 0o600)
	// The registry of the pins cannot be locked.
	_ = os.Remove(sb.path("state", devreg.LockName))
	if err := os.Mkdir(sb.path("state", devreg.LockName), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"host", "forget", "Web1", "--yes"})
	sb.expect(0, "Host 'Web1' forgotten.", "")
	if want := "Web1: its pinned ssh keys and address could not be removed"; !strings.Contains(sb.printed(), want) {
		t.Fatalf("no warning %q:\n%s", want, sb.printed())
	}
	if !strings.Contains(sb.printed(), "Run: tacctl host forget web1") || strings.Contains(sb.printed(), "Run: tacctl host forget Web1") {
		t.Errorf("the hint does not name the pin's spelling:\n%s", sb.printed())
	}
	if strings.Contains(sb.registryText(), "Web1|") || sb.pin("web1") == nil {
		t.Fatalf("registry %q, pin %+v", sb.registryText(), sb.pin("web1"))
	}

	// Running what the hint says finishes it.
	if err := os.Remove(sb.path("state", devreg.LockName)); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"host", "forget", "web1", "--yes"})
	sb.expect(0, "Host 'web1' forgotten.", "")
	if sb.pin("web1") != nil {
		t.Error("the pin stayed")
	}
	// And the registry spelling is not a name any more.
	sb.run("", []string{"host", "forget", "Web1", "--yes"})
	sb.expect(1, "", "No enrolled host or leftover named 'Web1'")
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

// sshWorks makes the script copy and run of the fake ssh succeed.
func sshWorks(sb *sandbox) {
	sb.script = func(r *fake.Runner) {
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" }, func(c execx.Cmd) (execx.Result, error) {
			if strings.Contains(strings.Join(c.Args, " "), "mktemp") {
				if c.Stdin != nil {
					_, _ = io.Copy(io.Discard, c.Stdin)
				}
				return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
			}
			return execx.Result{}, nil
		})
	}
}

// A routine 'host unenroll' of a host enrolled with --staging leaves no
// orphan: the host's staging entries go with it, and the /32 each added is
// still a prefix of the scope, which the output says how to drop.
func TestHostUnenrollDropsTheStagingEntries(t *testing.T) {
	sb := renameLab(t)
	sshWorks(sb)
	sb.run("", []string{"host", "unenroll", "web1"})
	sb.expect(0, "Host 'web1' unenrolled.", "")
	if got := sb.read("state/staging"); got != stagingAfterWeb1 {
		t.Errorf("staging %q, want %q", got, stagingAfterWeb1)
	}
	if want := "The scope 'lab' still answers 192.0.2.9/32. To drop it: tacctl scope prefixes lab remove 192.0.2.9/32"; !strings.Contains(sb.printed(), want) {
		t.Errorf("the output lacks %q:\n%s", want, sb.printed())
	}
	if strings.Contains(sb.printed(), "192.0.2.8/32") || strings.Contains(sb.printed(), "192.0.2.7/32") {
		t.Errorf("the staging of another kind or host is named:\n%s", sb.printed())
	}
	// The pins, the record and the staging are gone: nothing is left to find.
	if sb.pin("web1") != nil || sb.fileExists("state/hosts/web1.json") {
		t.Error("the pin or the record stayed")
	}
	v, l := sb.findings(t)
	if strings.Contains(v, "is not an enrolled host") || strings.Contains(l, "finding(s)") {
		t.Errorf("findings after a routine unenroll:\n%s\n%s", v, l)
	}

	// A host with no staging entry prints no such line.
	sb = renameLab(t)
	sshWorks(sb)
	sb.run("", []string{"host", "unenroll", "db1"})
	sb.expect(0, "Host 'db1' unenrolled.", "")
	if strings.Contains(sb.printed(), "still answers") || sb.read("state/staging") != renameStaging {
		t.Errorf("staging %q:\n%s", sb.read("state/staging"), sb.printed())
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
	// The mixed-case spelling is a Names finding as well, counted with it.
	if !strings.Contains(l, "2 finding(s): see tacctl config validate") {
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
	if want := "the hosts 'web1', 'db1' have the same recorded address and ssh port, 192.168.1.10:22 (tacctl host forget <name> drops a registration made twice)"; !strings.Contains(v, want) {
		t.Errorf("validate lacks %q:\n%s", want, v)
	}
	if !strings.Contains(l, "1 finding(s)") {
		t.Errorf("host list:\n%s", l)
	}
	js := hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"}))
	for _, n := range []string{"web1", "db1"} {
		if fs := js[n].Findings; len(fs) != 1 || !strings.Contains(fs[0].Text, "same recorded address and ssh port, 192.168.1.10:22") {
			t.Errorf("%s findings %+v", n, fs)
		}
	}
	if len(js["web2"].Findings) != 0 {
		t.Errorf("web2 findings %+v", js["web2"].Findings)
	}
}

// One address on another ssh port is another machine (hosts behind one NAT
// address), as 'host enroll' judges it.
func TestHostFindingsSameAddressOtherPortIsNoFinding(t *testing.T) {
	sb := renameLab(t)
	sb.seedPin("db1", "192.168.1.10")
	sb.write("state/linux-hosts", "web1|root@192.168.1.10|2201|lab|192.0.2.1|\ndb1|root@192.168.1.10|2202|prod|192.0.2.1|\nweb2|root@web2.example.net||lab|192.0.2.1|\n", 0o600)
	v, l := sb.findings(t)
	if strings.Contains(v, "same recorded address") || strings.Contains(l, "finding(s)") {
		t.Errorf("two ports are two machines:\n%s\n%s", v, l)
	}
	for n, h := range hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"})) {
		if len(h.Findings) != 0 {
			t.Errorf("%s findings %+v", n, h.Findings)
		}
	}

	// This server's own host has no port: it is the machine at its address on
	// every port, as for 'host enroll'.
	sb.seedPin("here", "192.168.1.10")
	sb.write("state/linux-hosts", "web1|root@192.168.1.10|2201|lab|192.0.2.1|\nhere|local||lab|192.0.2.1|\nweb2|root@web2.example.net||lab|192.0.2.1|\n", 0o600)
	v, _ = sb.findings(t)
	if want := "the hosts 'web1', 'here' have the same recorded address and ssh port, 192.168.1.10:2201"; !strings.Contains(v, want) {
		t.Errorf("validate lacks %q:\n%s", want, v)
	}

	// The same port is a finding, with the port in it; the default port is 22.
	sb.write("state/linux-hosts", "web1|root@192.168.1.10|2201|lab|192.0.2.1|\ndb1|root@192.168.1.10|2201|prod|192.0.2.1|\nweb2|root@web2.example.net||lab|192.0.2.1|\n", 0o600)
	v, _ = sb.findings(t)
	if want := "the hosts 'web1', 'db1' have the same recorded address and ssh port, 192.168.1.10:2201"; !strings.Contains(v, want) {
		t.Errorf("validate lacks %q:\n%s", want, v)
	}
	sb.write("state/linux-hosts", "web1|root@192.168.1.10|22|lab|192.0.2.1|\ndb1|root@192.168.1.10||prod|192.0.2.1|\nweb2|root@web2.example.net||lab|192.0.2.1|\n", 0o600)
	v, _ = sb.findings(t)
	if want := "have the same recorded address and ssh port, 192.168.1.10:22"; !strings.Contains(v, want) {
		t.Errorf("22 and no port are one port:\n%s", v)
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
