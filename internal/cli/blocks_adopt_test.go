package cli

// 'adopt' of the configuration blocks (0.2.7, B6), end to end against the
// fake device: a live read with the caller's login (the pull's transport,
// password source and wording), the draft in the editor, and the flow of
// edit after it. What the device's text holds is never stored, never
// printed, and never in a log line.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
)

const (
	adoptSNMPCmd   = "show configuration snmp | display set"
	adoptSystemCmd = "show configuration system | display set"
)

// adoptSNMPDevice is the device's snmp hierarchy: its identity, the scope's
// own community (set from the scope's settings), a poller, a community the
// login cannot read, a trap group and what no block takes.
const adoptSNMPDevice = `set snmp name jsw1.lab.example.net
set snmp location "Rack 4"
set snmp community lab-own-community authorization read-only
set snmp community lab-own-community clients 192.0.2.0/24
set snmp community poller-string authorization read-only
set snmp community poller-string clients 198.51.100.7/32
set snmp community poller-string clients 198.51.100.8/32
set snmp community /* SECRET-DATA */ authorization read-only
set snmp community /* SECRET-DATA */ clients 203.0.113.0/24
set snmp trap-group traps-string version v2
set snmp trap-group traps-string targets 198.51.100.20
set snmp v3 usm local-engine user v3user authentication-sha authentication-password "$9$abcdefgh"
`

const adoptSystemDevice = `set system host-name jsw1
set system domain-name lab.example.net
set system time-zone UTC
set system name-server 192.0.2.53
set system ntp server 192.0.2.123 prefer
set system ntp authentication-key 1 type md5 value "$9$ntpsecretvalue"
set system login message "Authorized use only.\n  *** keep out ***"
set system login user alice class super-user
set system login user alice authentication encrypted-password "$6$hashhashhashhash"
`

// adoptBox is a device box with a Junos device of scope lab, a scope
// community, fake editors and the answers of the device.
type adoptBox struct {
	*pullBox
	e *editBox
}

func newAdoptBox(t *testing.T) *adoptBox {
	t.Helper()
	b := newPullBox(t)
	b.sb.scopeSNMP("", "lab", "version", "v2c")
	b.sb.scopeSNMP("lab-own-community\n", "lab", "community", "--stdin")
	b.devices([3]string{"jsw1.lab.example.net", "192.168.1.20", "juniper"}, [3]string{"prod-j", "10.99.0.20", "juniper"},
		[3]string{"lab-ios", "192.168.1.30", "cisco"})
	a := &adoptBox{pullBox: b, e: newEditBoxOn(t, b.sb)}
	a.serve(adoptSNMPCmd, adoptSNMPDevice)
	a.serve(adoptSystemCmd, adoptSystemDevice)
	return a
}

// commands is how many commands the device was asked (over NETCONF).
func (a *adoptBox) commands() int {
	n := 0
	for _, c := range a.srv.Commands() {
		if c == "netconf:command" {
			n++
		}
	}
	return n
}

// serve makes the fake device answer cmd with text.
func (a *adoptBox) serve(cmd, text string) {
	a.t.Helper()
	if err := os.WriteFile(filepath.Join(a.dir, cmd+".out"), []byte(text), 0o644); err != nil {
		a.t.Fatal(err)
	}
}

// adopt runs 'scope block lab juniper adopt <device> <block>' as alice with
// the editor, answering the questions with stdin.
func (a *adoptBox) adopt(stdin, editor string, args ...string) string {
	a.t.Helper()
	return a.runAs(stdin, editor, append([]string{"scope", "block", "lab", "juniper", "adopt"}, args...)...)
}

func (a *adoptBox) runAs(stdin, editor string, args ...string) string {
	a.t.Helper()
	a.e.cmds = nil
	env := []string{"SUDO_USER=alice"}
	if editor != "" {
		env = append(env, "VISUAL="+editor)
	}
	return plain(a.sb.cfgRun(stdin, args, func(r *fake.Runner) {
		route(r)
		if editor != "" {
			r.OnFunc([]string{editor}, realRun)
		}
	}, env...))
}

// storedOutside lists the files under the sandbox (but the block store and
// the editor's recordings) that hold s.
func (a *adoptBox) storedOutside(s string) []string {
	var out []string
	_ = filepath.WalkDir(a.sb.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(a.sb.dir, p)
		if strings.HasPrefix(rel, "state/blocks/") || strings.HasPrefix(rel, "rec/") {
			return nil
		}
		if data, err := os.ReadFile(p); err == nil && strings.Contains(string(data), s) {
			out = append(out, rel)
		}
		return nil
	})
	return out
}

func TestAdoptSNMPDraftFlow(t *testing.T) {
	a := newAdoptBox(t)
	// prune the trap group, and keep the poller
	ed := a.e.editor("ed-prune", `grep -v 'trap-group' "$f" > "$f.new" && mv "$f.new" "$f"`)
	n := a.sb.snapshots()
	out := a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is set (") {
		t.Fatalf("adopt: %d\n%s%s", a.sb.code, out, a.sb.stderr())
	}
	// one login, one read of the hierarchy, nothing else
	if a.pw.asked != 1 || a.pw.accepted != 1 || a.pw.rejected != 0 {
		t.Errorf("password: asked %d accepted %d rejected %d", a.pw.asked, a.pw.accepted, a.pw.rejected)
	}
	if a.commands() != 1 {
		t.Errorf("commands served: %q", a.srv.Commands())
	}
	// the draft: what the grammar takes and tacctl does not render, with the
	// left-out lines per statement and no value
	seed := a.e.recorded("seed1")
	for _, want := range []string{
		"# adopted from jsw1.lab.example.net at ", "# Remove what this block should not own",
		"set snmp community poller-string authorization read-only\nset snmp community poller-string clients 198.51.100.7/32\nset snmp community poller-string clients 198.51.100.8/32\n",
		"set snmp trap-group traps-string version v2\nset snmp trap-group traps-string targets 198.51.100.20\n",
		"# left out: the string of this community is masked (the login lacks the secret permission), so it cannot be adopted: authorization read-only.",
		"# left out: the string of this community is masked (the login lacks the secret permission), so it cannot be adopted: clients 203.0.113.0/24.",
		"identity (snmp name, engine-id), never part of a block: 1 statement, not adopted",
	} {
		if !strings.Contains(seed, want) {
			t.Errorf("the draft lacks %q:\n%s", want, seed)
		}
	}
	for _, bad := range []string{"lab-own-community", "set snmp name", "abcdefgh", "v3user", "Rack 4"} {
		if strings.Contains(seed, bad) {
			t.Errorf("the draft holds %q:\n%s", bad, seed)
		}
	}
	// the block that was installed is the pruned draft
	stored := a.sb.read("state/blocks/lab/juniper/snmp")
	if !strings.Contains(stored, "set snmp community poller-string authorization read-only\n") || strings.Contains(stored, "trap-group") {
		t.Errorf("stored:\n%s", stored)
	}
	if a.sb.snapshots() != n+1 {
		t.Errorf("snapshots %d -> %d", n, a.sb.snapshots())
	}
	// the logs: the sensitive read and the write, names only
	log := strings.Join(a.sb.runner.Argvs(), "\n")
	if a.sb.logged("secret-read kind=block-adopt name=lab/juniper/snmp by=alice") != 1 || a.sb.logged("block-adopt name=lab/juniper/snmp bytes=") != 1 ||
		a.sb.logged("block adopt-read user=alice device=jsw1.lab.example.net transport=netconf result=ok") != 1 {
		t.Errorf("log:\n%s", log)
	}
	// nothing of the device's text is in the output, the log or any file
	// outside the block that was installed
	for _, s := range []string{"poller-string", "traps-string", "lab-own-community", "abcdefgh"} {
		noneOf(t, "output, error and log", out+a.sb.stderr()+log, s)
		if f := a.storedOutside(s); len(f) != 0 && s != "lab-own-community" {
			t.Errorf("%q is stored in %v", s, f)
		}
	}
	if l := a.e.leftover(); len(l) != 0 {
		t.Errorf("private directory left: %v", l)
	}
	// the title of the check says where the text came from
	if !strings.Contains(out, "the text adopted from jsw1.lab.example.net and edited") ||
		!strings.Contains(out, "Draft of the snmp block of scope 'lab' from jsw1.lab.example.net (read as alice over netconf; nothing of it is stored)") {
		t.Errorf("output:\n%s", out)
	}
}

func TestAdoptSNMPOverTheCommandLineWhenTheSettingSaysSo(t *testing.T) {
	a := newAdoptBox(t)
	a.sb.write("state/tacctl.yaml", "device:\n  config:\n    transport: ssh\n", 0o640)
	ed := a.e.editor("ed-noop", "true")
	out := a.adopt("n\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 0 || !strings.Contains(out, "read as alice over ssh") {
		t.Errorf("%d\n%s%s", a.sb.code, out, a.sb.stderr())
	}
	if a.sb.logged("block adopt-read user=alice device=jsw1.lab.example.net transport=ssh result=ok") != 1 {
		t.Errorf("log: %q", a.sb.runner.Argvs())
	}
}

func TestAdoptMergesBeneathTheExistingBlock(t *testing.T) {
	a := newAdoptBox(t)
	existing := "# the poller\nset snmp community poller-string authorization read-only\nset snmp community poller-string clients 198.51.100.7/32\n"
	a.sb.putBlock("lab", existing)
	ed := a.e.editor("ed-keep", "true")
	n := a.sb.snapshots()
	out := a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 0 {
		t.Fatalf("%d\n%s%s", a.sb.code, out, a.sb.stderr())
	}
	seed := a.e.recorded("seed1")
	if !strings.HasPrefix(seed, existing+"\n# adopted from jsw1.lab.example.net at ") {
		t.Errorf("the existing file is not first, whole:\n%s", seed)
	}
	// the poller's community differs from the file's: left in place and
	// counted; the trap group is new
	if !strings.Contains(seed, "in this block already with other statements: 1 object, left as they are (edit them in place).") ||
		!strings.Contains(seed, "set snmp trap-group traps-string version v2\n") {
		t.Errorf("the draft:\n%s", seed)
	}
	if strings.Count(seed, "set snmp community poller-string clients 198.51.100.8/32") != 0 {
		t.Errorf("a conflicting object was adopted:\n%s", seed)
	}
	got := a.sb.read("state/blocks/lab/juniper/snmp")
	if !strings.HasPrefix(got, existing) || !strings.Contains(got, "traps-string") {
		t.Errorf("stored:\n%s", got)
	}
	if a.sb.snapshots() != n+1 {
		t.Error("no snapshot")
	}
	// the draft pruned to nothing leaves the block as it was
	ed2 := a.e.editor("ed-prune-all", `grep -v '^set snmp' "$f" > "$f.new" && mv "$f.new" "$f"; printf '%s\n' "set snmp community poller-string authorization read-only" "set snmp community poller-string clients 198.51.100.7/32" >> "$f"`)
	a.sb.write("state/blocks/lab/juniper/snmp", existing, 0o600)
	before := existing
	out = a.adopt("y\n", ed2, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 0 || !strings.Contains(out, "No statement was adopted: the snmp block of scope 'lab' is as it was. Nothing was written.") {
		t.Errorf("%d\n%s%s", a.sb.code, out, a.sb.stderr())
	}
	if a.sb.read("state/blocks/lab/juniper/snmp") != before {
		t.Error("the block changed")
	}
}

func TestAdoptSystemDraft(t *testing.T) {
	a := newAdoptBox(t)
	ed := a.e.editor("ed-keep", "true")
	out := a.adopt("y\n", ed, "jsw1.lab.example.net", "system")
	if a.sb.code != 0 || !strings.Contains(out, "The system block of scope 'lab' is set (") {
		t.Fatalf("%d\n%s%s", a.sb.code, out, a.sb.stderr())
	}
	if a.commands() != 1 {
		t.Errorf("commands served: %q", a.srv.Commands())
	}
	seed := a.e.recorded("seed1")
	for _, want := range []string{
		"set system login message <<'EOF'\nAuthorized use only.\n  *** keep out ***\nEOF\n",
		"set system domain-name lab.example.net\n", "set system time-zone UTC\n", "set system name-server 192.0.2.53\n",
		"set system ntp server 192.0.2.123 prefer\n",
		"# left out: ntp authentication-key 1 holds the device's ciphertext, so its value cannot be adopted: type it in the block where the device lacks it.",
		"and the like): 3 statements, not adopted",
	} {
		if !strings.Contains(seed, want) {
			t.Errorf("the draft lacks %q:\n%s", want, seed)
		}
	}
	for _, bad := range []string{"ntpsecretvalue", "hashhashhash", "host-name", "alice"} {
		if strings.Contains(seed, bad) {
			t.Errorf("the draft holds %q:\n%s", bad, seed)
		}
	}
	log := strings.Join(a.sb.runner.Argvs(), "\n")
	noneOf(t, "output, error and log", out+a.sb.stderr()+log, "ntpsecretvalue", "Authorized use", "keep out", "hashhashhash")
	if a.sb.logged("secret-read kind=block-adopt name=lab/juniper/system by=alice") != 1 {
		t.Errorf("log:\n%s", log)
	}
	if got := a.sb.read("state/blocks/lab/juniper/system"); !strings.Contains(got, "set system login message <<'EOF'\n") {
		t.Errorf("stored:\n%s", got)
	}
}

func TestAdoptDeviceLevelIsTheDevicesExceptions(t *testing.T) {
	a := newAdoptBox(t)
	// the scope states the poller as the device has it, and a trap group the
	// device has differently
	a.sb.putBlock("lab", "set snmp community poller-string authorization read-only\nset snmp community poller-string clients 198.51.100.7/32\n"+
		"set snmp community poller-string clients 198.51.100.8/32\nset snmp trap-group traps-string version v1\n")
	ed := a.e.editor("ed-keep", "true")
	out := a.runAs("y\n", ed, "device", "block", "jsw1.lab.example.net", "adopt", "snmp")
	if a.sb.code != 0 || !strings.Contains(out, "The snmp block of device 'jsw1.lab.example.net' is set (") {
		t.Fatalf("%d\n%s%s", a.sb.code, out, a.sb.stderr())
	}
	seed := a.e.recorded("seed1")
	if strings.Contains(seed, "poller-string") {
		t.Errorf("an object the scope states identically is repeated:\n%s", seed)
	}
	if !strings.Contains(seed, "set snmp trap-group traps-string version v2\nset snmp trap-group traps-string targets 198.51.100.20\n") ||
		!strings.Contains(seed, "stated already, with the same statements, by this block or the scope's: 1 object, not repeated.") {
		t.Errorf("the device's exception is not whole:\n%s", seed)
	}
	if a.sb.logged("secret-read kind=block-adopt name=_devices/jsw1.lab.example.net/juniper/snmp by=alice") != 1 ||
		a.sb.logged("block-adopt name=_devices/jsw1.lab.example.net/juniper/snmp bytes=") != 1 {
		t.Errorf("log: %q", a.sb.runner.Argvs())
	}
	if got := a.sb.read("state/blocks/_devices/jsw1.lab.example.net/juniper/snmp"); !strings.Contains(got, "traps-string version v2") {
		t.Errorf("stored:\n%s", got)
	}
}

func TestAdoptNothingToAdoptOpensNoEditor(t *testing.T) {
	a := newAdoptBox(t)
	a.serve(adoptSNMPCmd, "set snmp name jsw1.lab.example.net\nset snmp community /* SECRET-DATA */ authorization read-only\nset snmp community $9$abcdefghijkl clients 203.0.113.0/24\n")
	ed := a.e.editor("ed-add", editSNMPAdd)
	n := a.sb.snapshots()
	out := a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 0 || a.e.ran() != 0 || !strings.Contains(out, "Nothing to adopt from jsw1.lab.example.net into the snmp block of scope 'lab'. Nothing was changed.") {
		t.Errorf("%d, ran %d\n%s%s", a.sb.code, a.e.ran(), out, a.sb.stderr())
	}
	for _, want := range []string{"left out: the string of this community is masked", "left out: this community 1 is shown only as the device's ciphertext, so its string cannot be adopted: clients 203.0.113.0/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	noneOf(t, "output", out, "abcdefghijkl")
	if a.sb.snapshots() != n {
		t.Error("a snapshot was taken")
	}
	// the read was still a reveal's, and is logged
	if a.sb.logged("secret-read kind=block-adopt name=lab/juniper/snmp by=alice") != 1 {
		t.Errorf("log: %q", a.sb.runner.Argvs())
	}
}

func TestAdoptRefusals(t *testing.T) {
	a := newAdoptBox(t)
	ed := a.e.editor("ed-keep", "true")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"scope", "block", "lab", "juniper", "adopt", "prod-j", "snmp"}, "Device 'prod-j' is in scope 'prod', not in scope 'lab'"},
		{[]string{"scope", "block", "lab", "juniper", "adopt", "lab-ios", "snmp"}, "'lab-ios' is not a Junos device"},
		{[]string{"scope", "block", "lab", "juniper", "adopt", "nosuch", "snmp"}, "Device 'nosuch' not found"},
		{[]string{"scope", "block", "lab", "juniper", "adopt", "jsw1.lab.example.net"}, "Usage: tacctl scope block lab juniper adopt <device> <block> [--yes]"},
		{[]string{"scope", "block", "lab", "juniper", "adopt", "jsw1.lab.example.net", "firewall"}, ""},
	} {
		a.runAs("y\n", ed, c.args...)
		if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), c.want) {
			t.Errorf("%v: %d %q", c.args, a.sb.code, a.sb.stderr())
		}
	}
	if a.e.ran() != 0 || a.pw.asked != 0 {
		t.Errorf("an editor ran or a password was asked for a refused adopt: %d %d", a.e.ran(), a.pw.asked)
	}
	// no terminal
	a.sb.terminal(false)
	a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), "adopt opens an editor and needs a terminal on standard input and output. Nothing was changed.") || a.pw.asked != 0 {
		t.Errorf("no terminal: %d %q (asked %d)", a.sb.code, a.sb.stderr(), a.pw.asked)
	}
	a.sb.terminal(true)
	// a block of the scope that has errors: no draft goes beneath it
	a.sb.putBlock("lab", "set snmp community broken authorization read-only\n")
	a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), "The snmp block of scope 'lab' has errors, so a draft cannot be put beneath it:") || a.pw.asked != 0 {
		t.Errorf("block with errors: %d %q", a.sb.code, a.sb.stderr())
	}
	// an enrolled host is not a device
	a.sb.write("state/linux-hosts", "web1|root@192.0.2.10||lab|192.0.2.1|\n", 0o600)
	a.runAs("y\n", ed, "scope", "block", "lab", "juniper", "adopt", "web1", "snmp")
	if a.sb.code != 1 {
		t.Errorf("host: %d %q", a.sb.code, a.sb.stderr())
	}
}

// A failing read is the pull's own failure, in its words; the cache is told.
func TestAdoptReadFailures(t *testing.T) {
	a := newAdoptBox(t)
	ed := a.e.editor("ed-keep", "true")
	a.pw.pw = "not-the-password"
	a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), "Cannot read jsw1.lab.example.net: authentication failed.") || a.pw.rejected != 1 || a.e.ran() != 0 {
		t.Errorf("wrong password: %d %q (rejected %d)", a.sb.code, a.sb.stderr(), a.pw.rejected)
	}
	noneOf(t, "stderr", a.sb.stderr(), "not-the-password")
	if a.sb.logged("block adopt-read user=alice device=jsw1.lab.example.net result=auth-failed") != 1 || a.sb.logged("secret-read kind=block-adopt") != 0 {
		t.Errorf("log: %q", a.sb.runner.Argvs())
	}
	// no host key pinned: the pull's refusal and its hint
	a.pw.pw = testPassword
	a.sb.write("state/devices.yaml", "version: 1\ndevices:\n  jsw1.lab.example.net:\n    address: 192.168.1.20\n    vendor: juniper\n", 0o600)
	a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), "Cannot read jsw1.lab.example.net: no host key is pinned for the device.") ||
		!strings.Contains(a.sb.stderr(), "Run: tacctl device hostkey jsw1.lab.example.net accept") {
		t.Errorf("unpinned: %d %q", a.sb.code, a.sb.stderr())
	}
	// no password to give
	a.devices([3]string{"jsw1.lab.example.net", "192.168.1.20", "juniper"})
	a.pw.err = errNoPassword
	a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), "cannot log in to jsw1.lab.example.net: a password is needed and no terminal or cached password is available") {
		t.Errorf("no password: %d %q", a.sb.code, a.sb.stderr())
	}
	// the device refuses the command
	a.pw.err = nil
	a.serve(adoptSNMPCmd, "error: permission denied\n")
	a.adopt("y\n", ed, "jsw1.lab.example.net", "snmp")
	if a.sb.code != 1 || !strings.Contains(a.sb.stderr(), "Cannot read jsw1.lab.example.net:") {
		t.Errorf("refused: %d %q", a.sb.code, a.sb.stderr())
	}
	if l := a.e.leftover(); len(l) != 0 {
		t.Errorf("private directory left: %v", l)
	}
	if a.e.ran() != 0 {
		t.Error("the editor ran for a failed read")
	}
}
