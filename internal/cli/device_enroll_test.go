package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/snmp"
)

// 'device enroll' (0.2.17 D261-D264, D269) end to end, in process, against
// the configure model of the fake Junos device (the apply box: it calls
// itself example-sw1), with ssh-keyscan scripted per address and a stub SNMP
// getter. Every address dials the one fake device.

const (
	enrollAddr  = "192.168.1.40"
	enrollAddr2 = "192.168.1.41"
)

// enrollBox is the apply box with ssh-keyscan answering per address.
type enrollBox struct {
	*applyBox
	// keys are what ssh-keyscan offers at each address (none: no answer).
	keys map[string][]devreg.HostKey
	// more adjusts the runner after the scan's script.
	more func(*fake.Runner)
}

func newEnrollBox(t *testing.T) *enrollBox {
	t.Helper()
	b := &enrollBox{applyBox: newApplyBox(t), keys: map[string][]devreg.HostKey{}}
	k := b.key()
	b.keys[enrollAddr], b.keys[enrollAddr2] = []devreg.HostKey{k}, []devreg.HostKey{k}
	b.script = func(r *fake.Runner) {
		r.OnFunc([]string{"ssh-keyscan"}, func(c execx.Cmd) (execx.Result, error) {
			addr := c.Args[len(c.Args)-1]
			return execx.Result{Stdout: keyscanOut(addr, b.keys[addr]...)}, nil
		})
		if b.more != nil {
			b.more(r)
		}
	}
	return b
}

// snmpSays makes the device at each address name itself and its vendor.
func (b *enrollBox) snmpSays(names map[string]string, ids map[string]snmp.Identity) {
	b.sb.snmp = &stubSNMP{names: names, ids: ids}
}

// enroll runs 'device enroll args' as alice: on a terminal with typed typed
// ahead, or with typed "-" no terminal. It returns the status, stdout and
// stderr.
func (b *enrollBox) enroll(typed string, args ...string) (int, string, string) {
	b.t.Helper()
	out, errb := &lockedBuf{}, &lockedBuf{}
	return b.wait(b.enrollStart(typed, out, errb, args...), out, errb)
}

// enrollStart starts 'device enroll args' as enroll does.
func (b *enrollBox) enrollStart(typed string, out, errb *lockedBuf, args ...string) chan int {
	b.t.Helper()
	cmd := append([]string{"device", "enroll"}, args...)
	if typed == "-" {
		return b.startCmd(nil, out, errb, cmd...)
	}
	master, slave := terminal(b.t)
	if _, err := master.WriteString(typed); err != nil {
		b.t.Fatal(err)
	}
	return b.startCmd(slave, out, errb, cmd...)
}

// entry is the registry's entry of name (ok false: none).
func (b *enrollBox) entry(name string) (devreg.Entry, bool) {
	b.t.Helper()
	_, res, err := b.invoke().deviceLoad()
	if err != nil {
		b.t.Fatal(err)
	}
	return res.Lookup(name, devreg.ScopeFilter{})
}

// snapshots is the number of snapshots taken so far.
func (b *enrollBox) snapshots() int { return len(snapshot.IDs(b.sb.path("state", "backups"))) }

// hostConfig makes the fake device's configuration name it host.
func (b *enrollBox) hostConfig(host string) {
	b.t.Helper()
	data, err := os.ReadFile(filepath.Join(b.dir, "config.set"))
	if err != nil {
		b.t.Fatal(err)
	}
	b.knob("config.set", strings.ReplaceAll(string(data), "set system host-name example-sw1", "set system host-name "+host))
}

// rowOf is the summary table's row of addr.
func rowOf(out, addr string) []string {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 7 && f[0] == addr {
			return f
		}
	}
	return nil
}

// linesOf are the audit lines of the run that start with prefix.
func linesOf(r *fake.Runner, prefix string) []string {
	var out []string
	for _, l := range auditLines(r) {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// The chain for one Junos device: the one key shown and accepted by the
// device's name, the registration with that key pinned, one password, the
// pull, the plan, the offer declined (exit 0); one snapshot, named on the
// end line; the acceptance's line before the registration's.
func TestEnrollJunosChain(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "Example-SW1"}, map[string]snmp.Identity{enrollAddr: idJunos})
	before := b.snapshots()
	code, out, errs := b.enroll("example-sw1\ny\nn\n", enrollAddr)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	fp := b.key().Fingerprint()
	for _, want := range []string{
		"  " + enrollAddr + " offers:\n    Will pin:  ED25519  " + fp + "\n    On the device: Junos: ",
		"Device 'example-sw1' registered: " + enrollAddr + ", juniper.", "Host key pinned (the key you accepted):",
		"The plan above leaves each secret as a marked line; to paste it: tacctl device config plan <name>.", "next: tacctl device config apply example-sw1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, want := range []string{
		"Compare the key with the console of " + enrollAddr + ". Type the device name (example-sw1) to accept it and register it, or press Enter to skip the device: ",
		"Register " + enrollAddr + " as 'example-sw1' (juniper, the device says so)? [y/N] ",
		"Run the apply review for example-sw1 now (the plan is checked on each device, then each is confirmed on its own)? [y/N] ",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing the question %q in\n%s", want, errs)
		}
	}
	if row := rowOf(out, enrollAddr); strings.Join(row, " ") != enrollAddr+" example-sw1 juniper accepted ok differs planned" {
		t.Errorf("row %q\n%s", row, out)
	}
	e, ok := b.entry("example-sw1")
	if !ok || e.Address != enrollAddr || e.Vendor != "juniper" || !slices.Equal(e.HostKeys, []string{b.srv.HostKey()}) {
		t.Errorf("entry %+v", e)
	}
	if rec, ok := b.records().Of("example-sw1"); !ok || rec.Result != devconf.ResultOK || rec.By != "alice" {
		t.Errorf("record %+v", rec)
	}
	if b.pw.asked != 1 {
		t.Errorf("password asked %d times", b.pw.asked)
	}
	if n := b.snapshots(); n != before+1 {
		t.Errorf("snapshots %d -> %d", before, n)
	}
	lines := auditLines(b.runner)
	hk := "device enroll hostkey user=alice addr=" + enrollAddr + " device=example-sw1 alg=ssh-ed25519 fp=" + fp + " result=accepted source=confirmed"
	iHK, iAdd := slices.Index(lines, hk), slices.Index(lines, "device add name=example-sw1 address="+enrollAddr+" vendor=juniper count=1 by=alice")
	if iHK < 0 || iAdd < 0 || iHK > iAdd {
		t.Errorf("the acceptance's line is not before the registration's: %d %d\n%s", iHK, iAdd, strings.Join(lines, "\n"))
	}
	if !hasAudit(b.runner, "auth.notice", hk) {
		t.Error("the acceptance's line is not at auth.notice")
	}
	if !hasAudit(b.runner, "auth.info", "device enroll user=alice addr="+enrollAddr+" device=example-sw1 vendor=juniper source=snmp result=planned") {
		t.Errorf("no enroll line:\n%s", strings.Join(lines, "\n"))
	}
	ids := snapshot.IDs(b.sb.path("state", "backups"))
	if l := auditLine(b.runner, "cmd end "); len(ids) == 0 || !strings.Contains(l, "cmd=\"device enroll\" result=ok status=0 ") || !strings.HasSuffix(l, " snapshot="+ids[0]) {
		t.Errorf("end line %q (snapshots %q)", l, ids)
	}
	if l := auditLine(b.runner, "cmd start "); !strings.Contains(l, `cmd="device enroll" args=`+enrollAddr) {
		t.Errorf("start line %q", l)
	}
	noSecrets(t, "the audit lines", strings.Join(lines, "\n"), testPassword, "lab-secret-0123456789abcdef")
}

// The offer taken: the apply review asks for the device's name, the change
// is applied in the attended form, with the run's one password.
func TestEnrollOfferRunsTheReview(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "example-sw1"}, map[string]snmp.Identity{enrollAddr: idJunos})
	// the scope has an SNMP community: the plan stage prints none of it, and
	// the review shows it marked
	const community = "fake-community-7c1d"
	b.sb.cfgRun(community+"\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, nil, "SUDO_USER=alice")
	if b.sb.code != 0 {
		t.Fatalf("community: %d %s", b.sb.code, b.sb.stderr())
	}
	code, out, errs := b.enroll("example-sw1\ny\ny\nexample-sw1\n", enrollAddr)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	noSecrets(t, "the run", out+errs, community, "lab-secret-0123456789abcdef")
	if strings.Contains(out+errs, "THIS OUTPUT HOLDS") || !strings.Contains(out, "<secret:") {
		t.Errorf("a secret's banner, or no marked secret in the review:\n%s", out)
	}
	if !strings.Contains(errs, "Type the device name to apply to example-sw1: ") {
		t.Errorf("no per-device question:\n%s", errs)
	}
	if row := rowOf(out, enrollAddr); len(row) != 7 || row[6] != "applied" {
		t.Errorf("row %q\n%s", row, out)
	}
	if b.pw.asked != 1 {
		t.Errorf("password asked %d times", b.pw.asked)
	}
	if l := applyLineOf(b.applyBox, "example-sw1"); !strings.HasSuffix(l, " mode=attended") {
		t.Errorf("apply line %q", l)
	}
	if auditLine(b.runner, "device config apply review user=alice device=example-sw1 ") == "" ||
		!strings.HasSuffix(auditLine(b.runner, "device config apply review user=alice device=example-sw1 "), " answer=approved mode=attended") {
		t.Errorf("no review line:\n%s", strings.Join(auditLines(b.runner), "\n"))
	}
	if auditLine(b.runner, "device enroll user=alice addr="+enrollAddr+" device=example-sw1 vendor=juniper source=snmp result=applied") == "" {
		t.Errorf("no enroll line:\n%s", strings.Join(auditLines(b.runner), "\n"))
	}
	// enrolled again once the device agrees with tacctl: nothing to apply,
	// so no review is offered, and the row says why
	b.run("device", "remove", "example-sw1", "--yes")
	code, out, errs = b.enroll("example-sw1\ny\n", enrollAddr, "--json")
	if code != 0 || strings.Contains(errs, "Run the apply review") || strings.Contains(errs, "not offered") ||
		!strings.Contains(errs, enrollAddr+": planned: nothing to apply: the plan has no change") {
		t.Fatalf("again: exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, `"plan":"ok","result":"planned","reason":"nothing to apply: the plan has no change"`) {
		t.Errorf("json:\n%s", out)
	}
}

// The offer taken and the device declined at the review: exit 1, the
// device's next step is the apply.
func TestEnrollOfferDeclined(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "example-sw1"}, map[string]snmp.Identity{enrollAddr: idJunos})
	before := b.committed()
	code, out, errs := b.enroll("example-sw1\ny\ny\nnot-it\n", enrollAddr)
	if code != 1 || b.committed() != before {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if row := rowOf(out, enrollAddr); len(row) != 7 || row[6] != "declined" {
		t.Errorf("row %q\n%s", row, out)
	}
	if !strings.Contains(out, enrollAddr+": next: tacctl device config apply example-sw1") {
		t.Errorf("no next step:\n%s", out)
	}
}

// The answers to the key's question, for one address registered as other:
// the name shown and typed back, Enter, the end of input, another text; the
// name asked for when SNMP gives none, checked by the rules (upper case, a
// generic name, a taken name). An accepted 'other' device is registered,
// asks no password and ends its chain (exit 0).
func TestEnrollKeyAnswers(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "pdu-a"}, nil)
	fp := b.key().Fingerprint()
	for _, c := range []struct {
		name, typed string
		result      string
		line        string
	}{
		{"enter", "\n", "skipped", "device=- alg=ssh-ed25519 fp=" + fp + " result=skipped source=confirmed"},
		{"end of input", "\x04", "skipped", "device=- alg=ssh-ed25519 fp=" + fp + " result=skipped source=confirmed"},
		{"not the name", "pdu-b\n", "refused", "device=pdu-a alg=ssh-ed25519 fp=" + fp + " result=refused source=confirmed"},
	} {
		code, out, errs := b.enroll(c.typed, enrollAddr, "--vendor", "other")
		if code != 1 || !strings.Contains(out, enrollAddr+": "+c.result+": ") {
			t.Errorf("%s: exit %d\n%s\n%s", c.name, code, out, errs)
		}
		if l := auditLine(b.runner, "device enroll hostkey "); l != "device enroll hostkey user=alice addr="+enrollAddr+" "+c.line {
			t.Errorf("%s: line %q", c.name, l)
		}
		if _, ok := b.entry("pdu-a"); ok || auditLine(b.runner, "device add ") != "" {
			t.Errorf("%s: registered", c.name)
		}
	}
	// the name typed when SNMP gives none: refused by the rules
	b.snmpSays(nil, nil)
	b.devices([3]string{"taken-sw", "192.168.1.20", "juniper"})
	for typed, why := range map[string]string{
		"Pdu-A\n":    "the name has upper case: names are lower case",
		"switch\n":   "the name is a generic name",
		"taken-sw\n": "the name is already registered",
	} {
		code, out, errs := b.enroll(typed, enrollAddr, "--vendor", "other")
		if code != 1 || !strings.Contains(out, enrollAddr+": refused: "+why) {
			t.Errorf("%q: exit %d\n%s\n%s", typed, code, out, errs)
		}
		// what was typed is never in the reason
		if strings.Contains(out, "refused: '") || strings.Contains(out, "refused: Invalid") {
			t.Errorf("%q: the reason echoes the answer:\n%s", typed, out)
		}
		if !strings.Contains(errs, "Type the name to register it as to accept it, or press Enter to skip the device: ") {
			t.Errorf("%q: question %q", typed, errs)
		}
	}
	// accepted: registered as other, no password, no pull, exit 0
	code, out, errs := b.enroll("pdu-a\ny\n", enrollAddr, "--vendor", "other")
	if code != 0 || !strings.Contains(out, enrollAddr+": registered as other: set the vendor with tacctl device vendor pdu-a <vendor> (or --from-device), then pull") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if row := rowOf(out, enrollAddr); strings.Join(row, " ") != enrollAddr+" pdu-a other accepted - - registered-other" {
		t.Errorf("row %q", row)
	}
	if e, ok := b.entry("pdu-a"); !ok || e.Vendor != "other" || len(e.HostKeys) != 1 {
		t.Errorf("entry %+v", e)
	}
	if b.pw.asked != 0 || auditLine(b.runner, "device config pull ") != "" {
		t.Errorf("a pull: asked %d", b.pw.asked)
	}
	if auditLine(b.runner, "device enroll user=alice addr="+enrollAddr+" device=pdu-a vendor=other source=given result=registered-other") == "" {
		t.Errorf("lines %q", auditLines(b.runner))
	}
	if !strings.Contains(b.sb.knownHosts(), strings.Fields(b.srv.HostKey())[1]) {
		t.Errorf("known_hosts:\n%s", b.sb.knownHosts())
	}
}

// Two addresses: each is asked on its own; the second's wrong answer refuses
// it and leaves the first registered, pulled and planned; one snapshot for
// the run.
func TestEnrollTwoAddressesOneRefused(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "example-sw1", enrollAddr2: "sw-two"},
		map[string]snmp.Identity{enrollAddr: idJunos, enrollAddr2: idJunos})
	before := b.snapshots()
	code, out, errs := b.enroll("example-sw1\ny\nsw-2\nn\n", enrollAddr, enrollAddr2)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if row := rowOf(out, enrollAddr); len(row) != 7 || row[6] != "planned" {
		t.Errorf("first %q\n%s", row, out)
	}
	if row := rowOf(out, enrollAddr2); strings.Join(row, " ") != enrollAddr2+" - - refused not-tried not-tried refused" ||
		!strings.Contains(out, enrollAddr2+": refused: the answer typed is not the device's name") {
		t.Errorf("second %q\n%s", row, out)
	}
	if _, ok := b.entry("sw-two"); ok {
		t.Error("the refused address was registered")
	}
	if n := b.snapshots(); n != before+1 {
		t.Errorf("snapshots %d -> %d", before, n)
	}
	// the offer declined: the chain ends at the plan
	if !strings.Contains(out, enrollAddr+": next: tacctl device config apply example-sw1") {
		t.Errorf("no next step:\n%s", out)
	}
}

// What is refused before any question: an address registered already, one
// no scope covers, a held one, one that offers no key. Nothing is
// registered, so no snapshot is taken; the run goes on past each.
func TestEnrollRefusedBeforeAnyQuestion(t *testing.T) {
	b := newEnrollBox(t)
	b.devices([3]string{"sw-known", "192.168.1.20", "juniper"})
	b.sb.write("state/tacctl.yaml", "breakglass_hold:\n  gone-sw:\n    address: 192.168.1.42\n    since: '2026-10-20T00:00:00Z'\n    by: alice\n    reason: lab test\n", 0o600)
	delete(b.keys, enrollAddr2)
	before := b.snapshots()
	code, out, errs := b.enroll("", "192.168.1.20", "198.51.100.9", "203.0.113.9", "192.168.1.42", enrollAddr2)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"192.168.1.20: refused: registered already as 'sw-known'", "192.168.1.20: next: tacctl device config pull sw-known",
		"198.51.100.9: refused: no scope's prefixes cover it", "203.0.113.9: refused: 'alice' has no access to scope 'dmz'",
		"192.168.1.42: refused: break-glass is held on gone-sw",
		enrollAddr2 + ": refused: no ssh host key could be read",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(errs, "Type the") || b.snapshots() != before || auditLine(b.runner, "device enroll hostkey") != "" {
		t.Errorf("asked or snapshot:\n%s", errs)
	}
	if n := b.runner.Count("ssh-keyscan"); n < 1 || n > 2 {
		t.Errorf("scanned %d times", n)
	}
}

// Without a terminal: refused before anything is scanned unless --host-key
// names the key of one address; --host-key, --vendor and --name are for one
// address; a key that does not match refuses the device; with them the chain
// runs to the plan (the configured name taken over), and says the apply
// review needs a terminal.
func TestEnrollWithoutATerminal(t *testing.T) {
	b := newEnrollBox(t)
	fp := b.key().Fingerprint()
	for _, args := range [][]string{
		{enrollAddr},
		{enrollAddr, enrollAddr2, "--host-key", fp},
		{"--discovered", "--name", "x"},
		{enrollAddr, "--vendor", "hp"},
		{enrollAddr, "--host-key", "nope"},
		{"--discovered", enrollAddr},
		{enrollAddr, "--name", "Upper"},
	} {
		code, out, errs := b.enroll("-", args...)
		if code != 2 || b.runner.Count("ssh-keyscan") != 0 || !strings.Contains(errs, "Usage: tacctl device enroll") {
			t.Errorf("%q: exit %d %q %q", args, code, out, errs)
		}
	}
	if _, _, errs := b.enroll("-", enrollAddr); !strings.Contains(errs, "No terminal to answer the host-key question on") {
		t.Errorf("no terminal: %q", errs)
	}
	// a key that does not match
	code, out, _ := b.enroll("-", enrollAddr, "--host-key", "SHA256:"+strings.Repeat("A", 43), "--vendor", "juniper", "--name", "lab-sw1")
	if code != 1 || !strings.Contains(out, enrollAddr+": refused: no host key it offers matches --host-key") {
		t.Errorf("mismatch: %d\n%s", code, out)
	}
	if l := auditLine(b.runner, "device enroll hostkey "); l != "device enroll hostkey user=alice addr="+enrollAddr+" device=lab-sw1 alg=- fp=- result=refused source=flag" {
		t.Errorf("line %q", l)
	}
	// no vendor read and none given: skipped with the 'device add' line, no
	// acceptance line
	code, out, _ = b.enroll("-", enrollAddr, "--host-key", fp, "--name", "lab-sw1")
	if code != 1 || !strings.Contains(out, enrollAddr+": skipped: the vendor could not be read") ||
		!strings.Contains(out, "next: tacctl device add lab-sw1 "+enrollAddr+" --vendor <vendor>") || auditLine(b.runner, "device enroll hostkey") != "" {
		t.Errorf("no vendor: %d\n%s", code, out)
	}
	// everything given: registered, pulled, renamed to the device's own name,
	// planned; the review is not offered
	code, out, errs := b.enroll("-", enrollAddr, "--host-key", fp, "--vendor", "juniper", "--name", "lab-sw1")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "Host key pinned (it matches --host-key):") || strings.Contains(out, "the key you accepted") ||
		!strings.Contains(errs, "The apply review needs a terminal; run: tacctl device config apply example-sw1") ||
		!strings.Contains(out, "renamed lab-sw1 -> example-sw1 (the device's configured name") {
		t.Errorf("out\n%s\nerr\n%s", out, errs)
	}
	if l := auditLine(b.runner, "device enroll hostkey "); l != "device enroll hostkey user=alice addr="+enrollAddr+" device=lab-sw1 alg=ssh-ed25519 fp="+fp+" result=accepted source=flag" {
		t.Errorf("line %q", l)
	}
	if auditLine(b.runner, "device enroll user=alice addr="+enrollAddr+" device=example-sw1 vendor=juniper source=given result=planned") == "" {
		t.Errorf("lines %q", auditLines(b.runner))
	}
}

// The vendor asked when the device names none: Enter skips it with the
// 'device add' line; 'other' registers it and ends its chain. A run of an
// 'other' device and a Junos one asks one password and pulls one device.
func TestEnrollVendorAsked(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "pdu1", enrollAddr2: "example-sw1"},
		map[string]snmp.Identity{enrollAddr: idUnknown, enrollAddr2: idJunos})
	code, out, errs := b.enroll("pdu1\n\n", enrollAddr)
	if code != 1 || !strings.Contains(out, enrollAddr+": skipped: the vendor could not be read") ||
		!strings.Contains(out, "next: tacctl device add pdu1 "+enrollAddr+" --vendor <vendor>") {
		t.Errorf("enter: %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Vendor of "+enrollAddr+" (cisco, juniper, wti or other; Enter skips the device): ") {
		t.Errorf("question %q", errs)
	}
	code, out, errs = b.enroll("pdu1\nother\ny\nexample-sw1\ny\nn\n", enrollAddr, enrollAddr2)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if row := rowOf(out, enrollAddr); strings.Join(row, " ") != enrollAddr+" pdu1 other accepted - - registered-other" {
		t.Errorf("other %q\n%s", row, out)
	}
	if row := rowOf(out, enrollAddr2); len(row) != 7 || row[6] != "planned" {
		t.Errorf("junos %q", row)
	}
	if !strings.Contains(errs, "Register "+enrollAddr+" as 'pdu1' (other, as answered)? [y/N] ") {
		t.Errorf("question %q", errs)
	}
	if b.pw.asked != 1 || len(linesOf(b.runner, "device config pull ")) != 1 {
		t.Errorf("asked %d, pulls %q", b.pw.asked, linesOf(b.runner, "device config pull "))
	}
	if auditLine(b.runner, "device enroll user=alice addr="+enrollAddr+" device=pdu1 vendor=other source=asked result=registered-other") == "" {
		t.Errorf("lines %q", auditLines(b.runner))
	}
}

// The name step: a name typed is replaced by the name the device is
// configured with, in the registry only; it is kept, with the reason and the
// line to run, when that name is taken, generic or not a valid name, or a
// hold stands on the device. A name read by SNMP is never compared.
func TestEnrollNameStep(t *testing.T) {
	// renamed: the registry, the record and the plan under the new name
	b := newEnrollBox(t)
	code, out, errs := b.enroll("lab-typed\njuniper\ny\nn\n", enrollAddr)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, enrollAddr+": renamed lab-typed -> example-sw1 (the device's configured name)") ||
		!strings.Contains(out, "example-sw1") {
		t.Errorf("out\n%s", out)
	}
	if _, ok := b.entry("lab-typed"); ok {
		t.Error("the typed name is still registered")
	}
	if _, ok := b.records().Of("example-sw1"); !ok {
		t.Error("no record under the new name")
	}
	if auditLine(b.runner, "device rename from=lab-typed to=example-sw1 count=1 reason=device-name by=alice") == "" {
		t.Errorf("lines %q", auditLines(b.runner))
	}
	if strings.Contains(strings.Join(b.srv.Commands(), "\n"), "host-name") {
		t.Errorf("written to the device: %q", b.srv.Commands())
	}

	for _, c := range []struct {
		name  string
		setup func(*enrollBox)
		kept  string
		line  string
	}{
		{"taken", func(b *enrollBox) { b.devices([3]string{"example-sw1", "192.168.1.20", "juniper"}) },
			"the device is configured as 'example-sw1', and the device 'example-sw1' has that name", "tacctl device rename lab-typed example-sw1"},
		{"generic", func(b *enrollBox) { b.hostConfig("switch") },
			"the device is configured as 'switch', and it is a generic name", "tacctl device rename lab-typed switch --allow-generic"},
		{"invalid", func(b *enrollBox) { b.hostConfig("sw#1") },
			"the device is configured as 'sw#1', and it is not a valid device name", ""},
		{"held", func(b *enrollBox) {
			b.sb.hooks.applyPullDone = func() {
				b.sb.write("state/tacctl.yaml", "breakglass_hold:\n  lab-typed:\n    address: "+enrollAddr+"\n    since: '2026-10-20T00:00:00Z'\n    by: alice\n    reason: lab test\n", 0o600)
			}
		}, "the device is configured as 'example-sw1', and break-glass is held on lab-typed", "tacctl device rename lab-typed example-sw1"},
	} {
		b := newEnrollBox(t)
		c.setup(b)
		code, out, errs := b.enroll("lab-typed\njuniper\ny\nn\n", enrollAddr)
		want := enrollAddr + ": kept lab-typed: " + c.kept + "\n"
		if c.line != "" {
			want = enrollAddr + ": kept lab-typed: " + c.kept + " (" + c.line + ")"
		}
		if !strings.Contains(out, want) {
			t.Errorf("%s: exit %d\n%s\n%s", c.name, code, out, errs)
		}
		if _, ok := b.entry("lab-typed"); !ok || auditLine(b.runner, "device rename ") != "" {
			t.Errorf("%s: renamed", c.name)
		}
	}

	// a name from SNMP is the device's own: not compared
	b = newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "core-a"}, map[string]snmp.Identity{enrollAddr: idJunos})
	code, out, errs = b.enroll("core-a\ny\nn\n", enrollAddr)
	if code != 0 || strings.Contains(out, "renamed") || strings.Contains(out, "kept") {
		t.Errorf("snmp name: %d\n%s\n%s", code, out, errs)
	}
	if _, ok := b.entry("core-a"); !ok {
		t.Error("core-a is not registered")
	}
}

// The configured name of each vendor's record: the first label, lower case;
// a WTI unit's generic Site ID is none.
func TestDeviceOwnName(t *testing.T) {
	parallel(t)
	for _, c := range []struct {
		rec    devconf.Record
		vendor string
		want   string
	}{
		{devconf.Record{Hostname: "Core-SW1.lab.example.net"}, "juniper", "core-sw1"},
		{devconf.Record{Hostname: "rtr1"}, "cisco", "rtr1"},
		{devconf.Record{}, "cisco", ""},
		{devconf.Record{Unit: &devconf.UnitFacts{SiteID: "PDU-Rack4"}}, "wti", "pdu-rack4"},
		{devconf.Record{Unit: &devconf.UnitFacts{SiteID: "wti"}}, "wti", ""},
		{devconf.Record{Hostname: "ignored"}, "wti", ""},
	} {
		if got := deviceOwnName(&c.rec, c.vendor, nil); got != c.want {
			t.Errorf("%+v %s: %q, want %q", c.rec, c.vendor, got, c.want)
		}
	}
}

// The key shown and pinned is the first in type order: ed25519 when it is
// offered, else the ECDSA key, else RSA, whatever order they come in.
func TestPinnedKeyTypeOrder(t *testing.T) {
	parallel(t)
	ed, ec, rsa := hkKey(t, "ed25519"), hkKey(t, "ecdsa"), hkKey(t, "rsa")
	for _, c := range []struct {
		offered []devreg.HostKey
		want    devreg.HostKey
	}{
		{[]devreg.HostKey{rsa, ec, ed}, ed},
		{[]devreg.HostKey{rsa, ec}, ec},
		{[]devreg.HostKey{rsa}, rsa},
	} {
		if got, ok := pinnedKey(c.offered); !ok || got != c.want {
			t.Errorf("%v: %v", c.offered, got)
		}
	}
	if _, ok := pinnedKey(nil); ok {
		t.Error("a key out of nothing")
	}
}

// Several offered keys: the one shown under 'Will pin' is pinned alone, the
// others are listed as offered and not pinned, then and in 'device add's
// report.
func TestEnrollPinsOneKey(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "pdu-a"}, nil)
	rsa := hkKey(t, "rsa")
	b.keys[enrollAddr] = []devreg.HostKey{rsa, b.key()}
	code, out, errs := b.enroll("pdu-a\ny\n", enrollAddr, "--vendor", "other")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "    Will pin:  ED25519  "+b.key().Fingerprint()+"\n    Also offered, not pinned (unverified):\n      RSA      "+rsa.Fingerprint()) ||
		!strings.Contains(out, "Also offered, not pinned (unverified); after checking them: tacctl device hostkey pdu-a accept") {
		t.Errorf("out\n%s", out)
	}
	if e, _ := b.entry("pdu-a"); !slices.Equal(e.HostKeys, []string{b.srv.HostKey()}) {
		t.Errorf("pinned %q", e.HostKeys)
	}
}

// --json: the pull's line and the plan's objects, then the object of the
// run, on standard output; the questions, the progress and the table on
// standard error; the review is not offered.
func TestEnrollJSON(t *testing.T) {
	b := newEnrollBox(t)
	fp := b.key().Fingerprint()
	code, out, errs := b.enroll("-", enrollAddr, "--host-key", fp, "--vendor", "juniper", "--name", "example-sw1", "--json")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var run struct {
		Login   string
		Devices []enrollJSON
		Apply   string
		Exit    int
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &run); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	d := run.Devices
	if run.Login != "own" || run.Apply != "not-offered" || run.Exit != 0 || len(d) != 1 || d[0].Name != "example-sw1" || d[0].Key != "flag" ||
		d[0].HostKey == nil || d[0].HostKey.Fingerprint != fp || d[0].HostKey.Type != "ssh-ed25519" || d[0].VendorSource != "given" ||
		!d[0].Registered || d[0].Pull != "ok" || d[0].Plan != "differs" || d[0].Result != "planned" {
		t.Errorf("%+v", run)
	}
	if !strings.HasPrefix(lines[0], `{"name":"example-sw1"`) || !strings.Contains(out, "needs-change") {
		t.Errorf("no pull or plan object:\n%s", out)
	}
	if strings.Contains(out, "ADDRESS") || strings.Contains(out, "Device 'example-sw1' registered") || !strings.Contains(errs, "ADDRESS") ||
		!strings.Contains(errs, "The apply review is not offered with --json; run: tacctl device config apply example-sw1") {
		t.Errorf("out\n%s\nerr\n%s", out, errs)
	}
}

// --discovered takes the unregistered addresses that authenticated, from the
// seen cache.
func TestEnrollDiscovered(t *testing.T) {
	b := newEnrollBox(t)
	b.devices([3]string{"sw-known", "192.168.1.20", "juniper"})
	seen := `{"first":"2026-10-01T00:00:00Z","last":"2026-10-02T00:00:00Z","count":3,"last_user":"alice","last_outcome":"pass","last_ok":"2026-10-02T00:00:00Z"}`
	b.sb.write("var-lib/devices-seen.json", `{"version":1,"sources":{},"hostkeys":{},"addresses":{`+
		`"`+enrollAddr+`":{"tacacs":`+seen+`},"192.168.1.20":{"tacacs":`+seen+`}}}`, 0o600)
	code, out, errs := b.enroll("pdu-a\nother\ny\n", "--discovered")
	if code != 0 || rowOf(out, enrollAddr) == nil || rowOf(out, "192.168.1.20") != nil {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Type the name to register it as") {
		t.Errorf("question %q", errs)
	}
}

// A Ctrl-C at the second address's question leaves the first registered
// (exit 130), with nothing pulled; the second is not tried.
func TestEnrollInterrupted(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "pdu-a", enrollAddr2: "pdu-b"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.ctx = ctx
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.enrollStart("pdu-a\nother\ny\n", out, errb, enrollAddr, enrollAddr2)
	waitLong(t, "the second question", func() bool { return strings.Contains(errb.String(), "Type the device name (pdu-b)") })
	cancel()
	status, o, e := b.wait(code, out, errb)
	if status != 130 || !strings.Contains(o, enrollAddr2+": not-tried: interrupted") || !strings.Contains(o, "Interrupted: the devices registered stay registered") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
	if _, ok := b.entry("pdu-a"); !ok {
		t.Error("the first device was not kept")
	}
	if b.pw.asked != 0 {
		t.Errorf("password asked %d", b.pw.asked)
	}
	if l := auditLine(b.runner, "cmd end "); !strings.Contains(l, "result=interrupted status=130") {
		t.Errorf("end %q", l)
	}
}

// audit.strict: an acceptance whose line logger did not write refuses the
// device before anything is pinned or registered.
func TestEnrollStrictAcceptanceLine(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "pdu-a"}, nil)
	b.sb.strictOn()
	b.more = func(r *fake.Runner) {
		r.When(func(c execx.Cmd) bool {
			return c.Name == "logger" && len(c.Args) == 5 && strings.HasPrefix(c.Args[4], "device enroll hostkey ")
		}, execx.Result{Code: 1, Stderr: []byte("busy\n")}, nil)
	}
	code, out, errs := b.enroll("pdu-a\ny\n", enrollAddr, "--vendor", "other")
	if code != 1 || !strings.Contains(out, enrollAddr+": refused: the acceptance's audit line was not written") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if _, ok := b.entry("pdu-a"); ok || strings.Contains(errs, "Register ") {
		t.Error("registered after an unwritten acceptance line")
	}
	// strict with logger down altogether: refused before anything is scanned
	b.more = func(r *fake.Runner) { r.Fail([]string{"logger"}, 1, "busy") }
	code, _, errs = b.enroll("pdu-a\ny\n", enrollAddr, "--vendor", "other")
	if code != 1 || b.runner.Count("ssh-keyscan") != 0 || !strings.Contains(errs, "audit.strict is set; nothing was changed") {
		t.Errorf("logger down: exit %d %q", code, errs)
	}
}

// --host-key at a terminal for a device that gives no name: the name is asked
// first, so the acceptance's line names the device; Enter at it skips the
// device with device=-.
func TestEnrollHostKeyAtATerminalAsksTheNameFirst(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(nil, nil)
	fp := b.key().Fingerprint()
	code, out, errs := b.enroll("lab-sw7\ny\n", enrollAddr, "--host-key", fp, "--vendor", "other")
	if code != 0 || !strings.Contains(errs, "The name to register "+enrollAddr+" as (Enter skips the device): ") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	lines := linesOf(b.runner, "device enroll hostkey ")
	if len(lines) != 1 || lines[0] != "device enroll hostkey user=alice addr="+enrollAddr+" device=lab-sw7 alg=ssh-ed25519 fp="+fp+" result=accepted source=flag" {
		t.Errorf("lines %q", lines)
	}
	all := auditLines(b.runner)
	if slices.Index(all, lines[0]) > slices.Index(all, "device add name=lab-sw7 address="+enrollAddr+" vendor=other count=1 by=alice") {
		t.Errorf("the acceptance's line is after the registration's:\n%s", strings.Join(all, "\n"))
	}
	b = newEnrollBox(t)
	b.snmpSays(nil, nil)
	code, out, _ = b.enroll("\n", enrollAddr, "--host-key", fp, "--vendor", "other")
	if code != 1 || !strings.Contains(out, enrollAddr+": skipped: no name was given") {
		t.Errorf("enter: %d\n%s", code, out)
	}
	if l := auditLine(b.runner, "device enroll hostkey "); l != "device enroll hostkey user=alice addr="+enrollAddr+" device=- alg=ssh-ed25519 fp="+fp+" result=skipped source=flag" {
		t.Errorf("line %q", l)
	}
}

// A name a device reports is shown made safe (a WTI Site ID is only trimmed
// by the reader), and the 'device rename' line is offered only for a name
// the registry would accept.
func TestRenameKeptIsSafe(t *testing.T) {
	parallel(t)
	own := deviceOwnName(&devconf.Record{Unit: &devconf.UnitFacts{SiteID: "PDU\x1b[2J"}}, "wti", nil)
	kept, hint := renameKept(own, "it is not a valid device name", "tacctl device rename pdu-a "+own)
	if strings.ContainsRune(kept+hint, 0x1b) || hint != "" || !strings.Contains(kept, "'pdu?[2j'") {
		t.Errorf("%q %q", kept, hint)
	}
	if _, hint := renameKept("core-a", "the device 'core-a' has that name", "tacctl device rename x core-a"); hint != "tacctl device rename x core-a" {
		t.Errorf("hint %q", hint)
	}
}

// A run that stops on an error after a registration still writes each
// address's line and prints the table with the registered device's next
// step, and exits with the error's status.
func TestEnrollErrorAfterARegistration(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "example-sw1", enrollAddr2: "sw-two"},
		map[string]snmp.Identity{enrollAddr: idJunos, enrollAddr2: idJunos})
	b.more = func(r *fake.Runner) {
		r.OnFunc([]string{"ssh-keyscan"}, func(c execx.Cmd) (execx.Result, error) {
			addr := c.Args[len(c.Args)-1]
			if addr == enrollAddr2 {
				// the registry becomes unreadable once the first is registered
				b.sb.write("state/devices.yaml", "devices: [unreadable\n", 0o600)
			}
			return execx.Result{Stdout: keyscanOut(addr, b.keys[addr]...)}, nil
		})
	}
	code, out, errs := b.enroll("example-sw1\ny\nsw-two\ny\n", enrollAddr, enrollAddr2)
	if code == 0 || code == 130 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if row := rowOf(out, enrollAddr); len(row) != 7 || row[6] != "registered" || !strings.Contains(out, enrollAddr+": next: tacctl device config pull example-sw1") {
		t.Errorf("row %q\n%s\n%s", row, out, errs)
	}
	if auditLine(b.runner, "device enroll user=alice addr="+enrollAddr+" device=example-sw1 vendor=juniper source=snmp result=registered") == "" {
		t.Errorf("lines %q", auditLines(b.runner))
	}
	if b.pw.asked != 0 {
		t.Errorf("password asked %d", b.pw.asked)
	}
}

// The end of input at a key's question ends the run: the addresses after it
// are not scanned or asked.
func TestEnrollEndOfInputEndsTheRun(t *testing.T) {
	b := newEnrollBox(t)
	b.snmpSays(map[string]string{enrollAddr: "pdu-a", enrollAddr2: "pdu-b"}, nil)
	code, out, errs := b.enroll("\x04", enrollAddr, enrollAddr2)
	if code != 1 || !strings.Contains(out, enrollAddr+": skipped: not accepted (no answer: the input ended)") ||
		!strings.Contains(out, enrollAddr2+": not-tried: the input ended at an earlier question") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if n := b.runner.Count("ssh-keyscan"); n != 1 || strings.Contains(errs, "pdu-b") {
		t.Errorf("scanned %d times; asked %q", n, errs)
	}
}
