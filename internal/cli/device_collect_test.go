package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'device collect' (D137) and 'device sync' end to end, in process, against
// the fake Junos device: an address nobody registered is logged in to once
// (alice's own login, or the device's local account), read with 'show
// version' and the pull's read command and nothing else, shown in one table
// and, with --register, registered through 'device add' with its first
// pull record.

// collectConfig is a device that already runs TACACS+ and has a class of
// tacctl's, NETCONF and a filter applied on lo0.
const collectConfig = `set system host-name sw-lab-5
set system domain-name lab.example.net
set system authentication-order tacplus
set system authentication-order password
set system tacplus-server 10.0.0.42 single-connection
set system tacplus-server 10.0.0.43 single-connection
set system login class EN-CLASS permissions view
set system login user admin class super-user
set system services ssh
set system services netconf ssh
set interfaces lo0 unit 0 family inet filter input MGMT-ACL
set snmp location "Lab rack 2"
set snmp description "Lab switch five"
`

// newCollectBox is the onboard box with collectConfig as the device.
func newCollectBox(t *testing.T) *pullBox {
	t.Helper()
	b := newOnboardBox(t)
	b.knob("config.set", collectConfig)
	return b
}

// collect runs 'device collect' as alice with ssh-keyscan answering the fake
// device's key, on a terminal with the lines of typed typed ahead; typed "-"
// is no terminal at all.
func (b *pullBox) collect(typed string, args ...string) string {
	b.t.Helper()
	key := b.key()
	b.sb.script = func(r *fake.Runner) {
		route(r)
		scan(onboardAddr, key)(r)
	}
	defer func() { b.sb.script, b.sb.tty = nil, nil }()
	b.sb.tty = nil
	if typed != "-" {
		holdTTY(b.t, b.sb, typed)
	}
	return plain(b.sb.run("", append([]string{"device", "collect"}, args...), "SUDO_USER=alice"))
}

// row is the fields of the table's line of an address.
func tableRow(out, addr string) []string {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 2 && f[0] == addr && f[1] != "offers:" {
			return f
		}
	}
	return nil
}

func TestCollectTable(t *testing.T) {
	b := newCollectBox(t)
	out := b.collect("-", onboardAddr, "--host-key", b.key().Fingerprint())
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{
		onboardAddr + " offers:", "matches --host-key.", "ADDRESS", "HOSTNAME", "MODEL", "RELEASE", "AUTH-ORDER", "SERVERS", "EN-CLASS",
		"NETCONF", "LO0-FILTER", "LEGACY", "RESULT", "tacctl device add sw-lab-5 " + onboardAddr + " --vendor juniper",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	row := tableRow(out, onboardAddr)
	want := []string{onboardAddr, "sw-lab-5", "ex4300-48mp", "25.4R1-S2.3", "tacplus,password", "tacplus:2", "yes", "yes", "MGMT-ACL", "-", "collected"}
	if strings.Join(row, " ") != strings.Join(want, " ") {
		t.Errorf("row %q\nwant %q", row, want)
	}
	// nothing was registered or recorded; the device was asked 'show
	// version' and the pull's read command, and nothing else
	if strings.Contains(b.sb.devices(), onboardAddr) {
		t.Errorf("registered:\n%s", b.sb.devices())
	}
	if _, ok := b.records().Of("sw-lab-5"); ok {
		t.Error("a record was kept")
	}
	for _, c := range b.srv.Commands() {
		if c != "show version" && c != "show version | no-more" && !strings.HasPrefix(c, "show configuration | display inheritance no-comments | display set") {
			t.Errorf("typed on the device: %q", c)
		}
	}
	if b.pw.asked != 1 || b.pw.accepted != 1 || b.pw.rejected != 0 {
		t.Errorf("password: asked %d accepted %d rejected %d", b.pw.asked, b.pw.accepted, b.pw.rejected)
	}
	noSecrets(t, "the output", out+b.sb.stderr(), localPassword, testPassword)
	al := b.auditLines("device collect")
	if len(al) != 1 || !strings.Contains(al[0], "device collect user=alice addr=192.168.1.31 login=own result=collected") {
		t.Errorf("audit %q", al)
	}
}

// --json is one object; the progress goes to standard error.
func TestCollectJSON(t *testing.T) {
	b := newCollectBox(t)
	out := b.collect("-", onboardAddr, "--host-key", b.key().Fingerprint(), "--json")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	var got struct {
		Login   string
		Devices []collectJSON
		Exit    int
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got.Login != "own" || len(got.Devices) != 1 {
		t.Fatalf("%+v", got)
	}
	d := got.Devices[0]
	if d.Address != onboardAddr || d.Result != "collected" || d.TacplusServers != 2 || !d.ENClass || !d.Netconf ||
		len(d.Lo0Filter) != 1 || d.Lo0Filter[0] != "MGMT-ACL" || len(d.HostKeys) != 1 || d.HostKeys[0] != b.key().Fingerprint() ||
		!strings.HasPrefix(d.Add, "tacctl device add sw-lab-5 "+onboardAddr) {
		t.Errorf("%+v", d)
	}
}

// --register runs the registration of 'device add' with the key shown, keeps
// the read as the first pull record and is answered by one question; the
// address is the normal flow's afterwards.
func TestCollectRegister(t *testing.T) {
	b := newCollectBox(t)
	out := b.collect("y\ny\n", onboardAddr, "--register")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	errText := b.sb.stderr()
	if !strings.Contains(errText, "Trust these keys and send the password of 'alice' (your tacctl password) to "+onboardAddr+"? [y/N]") ||
		!strings.Contains(errText, "Register 1 device(s), pinning the host keys shown: sw-lab-5 ("+onboardAddr+")? [y/N]") {
		t.Errorf("the questions: %q", errText)
	}
	for _, want := range []string{"Device 'sw-lab-5' registered: " + onboardAddr + ", juniper.", "its first pull record"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	_, res, err := b.invoke().deviceLoad()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := res.Lookup("sw-lab-5", devreg.ScopeFilter{})
	if !ok || e.Address != onboardAddr || e.Vendor != "juniper" || len(e.HostKeys) != 1 || e.HostKeys[0] != b.srv.HostKey() {
		t.Errorf("entry %+v", e)
	}
	rec, ok := b.records().Of("sw-lab-5")
	if !ok || rec.Pulled.IsZero() || rec.Login != "" || !rec.UserPulled || rec.By != "alice" || rec.Result != devconf.ResultOK ||
		rec.Model != "ex4300-48mp" || rec.Release != "25.4R1-S2.3" || rec.Hostname != "sw-lab-5.lab.example.net" {
		t.Errorf("record %+v", rec)
	}
	if secs, _ := b.invoke().configStore().Sections("sw-lab-5", "juniper"); !strings.Contains(strings.Join(secs["snmp"].Lines, "\n"), `set snmp location "Lab rack 2"`) {
		t.Errorf("sections %+v", secs)
	}
	al := b.auditLines("device collect")
	if len(al) != 1 || !strings.Contains(al[0], "device collect user=alice addr=192.168.1.31 login=own result=registered device=sw-lab-5") {
		t.Errorf("audit %q", al)
	}
	// the address is registered: refused, nothing sent
	n := b.srv.Attempts()
	b.collect("y\n", onboardAddr)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), onboardAddr+" is registered as 'sw-lab-5'") || b.srv.Attempts() != n {
		t.Errorf("again: %d %q (%d attempts)", b.sb.code, b.sb.stderr(), b.srv.Attempts()-n)
	}
}

// A local account: the one-shot password is never the cache's; the record
// says login=local; the first refusal ends the run.
func TestCollectLocalLogin(t *testing.T) {
	b := newCollectBox(t)
	out := b.collect("y\ny\n", onboardAddr, "--login", localAccount, "--register")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if !strings.Contains(b.sb.stderr(), "send the local password of 'admin' to "+onboardAddr+"? [y/N]") {
		t.Errorf("the question: %q", b.sb.stderr())
	}
	if b.pw.asked != 0 || b.pw.accepted != 0 || b.pw.rejected != 0 {
		t.Errorf("the cache's source was used: %+v", b.pw)
	}
	rec, ok := b.records().Of("sw-lab-5")
	if !ok || rec.Login != "local:admin" || rec.UserPulled || rec.By != "alice" {
		t.Errorf("record %+v", rec)
	}
	noSecrets(t, "the output", out+b.sb.stderr(), localPassword, testPassword)
	al := b.auditLines("device collect")
	if len(al) != 1 || !strings.Contains(al[0], "login=local:admin result=registered device=sw-lab-5") {
		t.Errorf("audit %q", al)
	}
	for _, l := range al {
		noSecrets(t, "the audit", l, localPassword, testPassword)
	}
}

// A refused password ends the run at that address and is the one attempt;
// a wrong password in a run of one address is no second try.
func TestCollectRefusedPassword(t *testing.T) {
	b := newCollectBox(t)
	b.pw.pw = "wrong-password"
	out := b.collect("-", onboardAddr, "--host-key", b.key().Fingerprint())
	if b.sb.code != 1 || b.srv.Attempts() != 1 {
		t.Fatalf("exit %d, %d attempts\n%s\n%s", b.sb.code, b.srv.Attempts(), out, b.sb.stderr())
	}
	if row := tableRow(out, onboardAddr); len(row) == 0 || row[len(row)-1] != "auth-failed" {
		t.Errorf("row %q\n%s", row, out)
	}
	if b.pw.rejected != 1 || b.pw.accepted != 0 {
		t.Errorf("password: %+v", b.pw)
	}
	if !strings.Contains(out, "the device refused the password") {
		t.Errorf("output:\n%s", out)
	}
}

// Without a terminal the identity is --host-key's (one address) or nothing;
// a declined question and a wrong key send nothing; a registered address, an
// address no scope answers and the registration without -y are refused.
func TestCollectRefusalsSendNothing(t *testing.T) {
	b := newCollectBox(t)
	fp := b.key().Fingerprint()
	// an address of the registry
	b.devices([3]string{"sw-known", "192.168.1.40", "juniper"})
	for _, c := range []struct {
		typed string
		args  []string
		code  int
		want  string
	}{
		{"-", []string{onboardAddr}, 2, "No terminal to answer the identity question on"},
		{"-", []string{onboardAddr, "192.168.1.32", "--host-key", fp}, 2, "--host-key names the key of ONE device"},
		{"-", []string{"--discovered", "--host-key", fp}, 2, "--host-key names the key of ONE device"},
		{"-", []string{onboardAddr, "--host-key", fp, "--register"}, 2, "--register without one needs -y"},
		{"-", []string{}, 2, "Name the addresses to collect from"},
		{"-", []string{onboardAddr, "--discovered", "--host-key", fp}, 2, "not both"},
		{"-", []string{"bad name", "--host-key", fp}, 2, ""},
		{"-", []string{onboardAddr, "--host-key", "SHA256:nope"}, 2, "Invalid --host-key"},
		{"-", []string{onboardAddr, "--host-key", fp, "--login", "bad name"}, 2, "--login takes the name of one of the device's local accounts"},
		{"n\n", []string{onboardAddr}, 1, "Not trusted. Nothing was sent."},
		{"", []string{onboardAddr, "--host-key", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, 1, "No host key 192.168.1.31 offers matches"},
		{"", []string{"198.51.100.9", "--host-key", fp}, 1, "No scope answers 198.51.100.9"},
		{"", []string{"192.168.1.40", "--host-key", fp}, 1, "192.168.1.40 is registered as 'sw-known'"},
	} {
		b.collect(c.typed, c.args...)
		if b.sb.code != c.code || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%v: exit %d %q (want %d %q)", c.args, b.sb.code, b.sb.stderr(), c.code, c.want)
		}
	}
	if b.srv.Attempts() != 0 || b.pw.asked != 0 {
		t.Errorf("a refusal sent a password (%d attempts, %d asked)", b.srv.Attempts(), b.pw.asked)
	}
}

// A host that is not Junos gets the password once, answers 'show version'
// with something else and is closed: listed, never registered, nothing more
// typed.
func TestCollectNotJunos(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prompt"), []byte("user@linux:~$ "), 0o644); err != nil {
		t.Fatal(err)
	}
	b := newPullBoxIn(t, dir)
	b.pw.pw = testPassword
	out := b.collect("-", onboardAddr, "--host-key", b.key().Fingerprint(), "--register", "-y")
	if b.sb.code != 1 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if row := tableRow(out, onboardAddr); len(row) == 0 || row[len(row)-1] != "not-junos" {
		t.Errorf("row %q\n%s", row, out)
	}
	if !strings.Contains(out, "not a Junos device") || strings.Contains(b.sb.devices(), onboardAddr) {
		t.Errorf("output:\n%s\n%s", out, b.sb.devices())
	}
	for _, c := range b.srv.Commands() {
		if c != "show version" && c != "show version | no-more" {
			t.Errorf("typed on a host that is not Junos: %q", c)
		}
	}
}

// Text a device reports never reaches the terminal as it is: control
// characters are shown as '?', a long name is cut.
func TestCollectSanitisesDeviceText(t *testing.T) {
	b := newCollectBox(t)
	b.knob("config.set", strings.Replace(collectConfig, `set system authentication-order tacplus`,
		"set system authentication-order tacplus\nset system authentication-order \x1b]0;pwned\x07", 1))
	out := b.collect("-", onboardAddr, "--host-key", b.key().Fingerprint())
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Errorf("a terminal escape reached the output: %q", out)
	}
	if !strings.Contains(out, "pwned") {
		t.Errorf("the device's word is not shown, made safe:\n%s", out)
	}
	if got := devText(strings.Repeat("a", 200)); len([]rune(got)) != maxDevText+3 {
		t.Errorf("devText: %d", len(got))
	}
	if got := devText("a\nb\x1b[2Jc"); got != "a?b?[2Jc" {
		t.Errorf("devText: %q", got)
	}
}
