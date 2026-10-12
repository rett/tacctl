package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// 'device config plan' of Cisco devices: the dialect is the one resolution
// of D113 (the setting, else the pull's version line), never the ssh flag;
// a record that does not say needs a pull; a RADIUS scope has its one
// syntax; and a device that lacks the server block is given it in its own
// dialect.

// planDropServer is the device's text without its TACACS+ server: the
// block of the modern syntax or the host line of IOS 12.x.
func planDropServer(text string) string {
	var out []string
	inBlock := false
	for _, l := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(l, "tacacs server ") || strings.HasPrefix(l, "radius server "):
			inBlock = true
			continue
		case inBlock && strings.HasPrefix(l, " "):
			continue
		case strings.HasPrefix(l, "tacacs-server host "):
			inBlock = false
			continue
		}
		inBlock = false
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// ciscoDevices writes the registry with one Cisco device, with or without
// the ssh flag and the setting.
func (b *pullBox) ciscoDevice(extra string) {
	b.t.Helper()
	b.sb.write("state/devices.yaml", "version: 1\nsettings:\n  stale_days: 30\ndevices:\n  lab-c:\n    address: 192.168.1.30\n    vendor: cisco\n"+
		extra+"    host_keys:\n    - "+b.srv.HostKey()+"\n", 0o600)
}

// planCiscoBox pulls a Cisco device whose text lacks its server block and
// returns the box. version is the line the device answers.
func planCiscoBox(t *testing.T, extra, version string) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.ciscoDevice(extra)
	b.serve("cisco", b.expected("lab-c"))
	b.version(version)
	// the first pull records the image (and so the syntax) the rendering
	// is made in; the device then runs the rendering without its server
	b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	b.serve("cisco", planDropServer(b.expected("lab-c")))
	b.version(version)
	b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("second pull: %d %s", b.sb.code, b.sb.stderr())
	}
	return b
}

func TestPlanCiscoModernAndIOS12DialectsComeFromTheImage(t *testing.T) {
	// legacy-ssh on a 15.x device: the ssh algorithms, and nothing of the
	// syntax: the modern block is what is typed
	b := planCiscoBox(t, "    legacy_ssh: true\n", ciscoVersionModern)
	out := b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("modern: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"!!!!! lab-c  192.168.1.30  scope lab  cisco (IOS-XE and IOS 15 syntax, TACACS+) !!!!!",
		"!!!!! PASTE FROM HERE: lab-c !!!!!\nconfigure terminal\n", "\nend\n!!!!! PASTE TO HERE: lab-c !!!!!\n", "tacacs server TACACS\n",
		" address ipv4 ", "write memory"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "tacacs-server host") {
		t.Errorf("a legacy-ssh device is given the IOS 12.x syntax:\n%s", out)
	}
	noSecrets(t, "stderr", b.sb.stderr(), testPassword)
	planGolden(t, "cisco-modern.out", out)

	// a 12.x image without the flag: the IOS 12.x lines
	b = planCiscoBox(t, "", ciscoVersion12)
	out = b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("ios12: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if !strings.Contains(out, "cisco (IOS 12.x syntax, TACACS+)") || !strings.Contains(out, "tacacs-server host ") ||
		strings.Contains(out, "tacacs server TACACS") {
		t.Errorf("ios12:\n%s", out)
	}
	planGolden(t, "cisco-ios12.out", out)

	// the explicit setting wins over the image, and the plan follows it
	b.run("device", "config-syntax", "lab-c", "modern")
	b.run("device", "config", "pull", "lab-c")
	out = b.run("device", "config", "plan", "lab-c")
	if !strings.Contains(out, "IOS-XE and IOS 15 syntax") {
		t.Errorf("setting modern:\n%s", out)
	}
}

func TestPlanCiscoNeedsAPullForItsSyntax(t *testing.T) {
	b := planCiscoBox(t, "", ciscoVersionModern)
	// a record of 0.2.4 says nothing of the image
	b.editRecord("lab-c", func(r *devconf.Record) { r.OS, r.Syntax = "", "" })
	out := b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 1 || strings.Contains(out, "configure terminal") ||
		!strings.Contains(b.sb.stderr(), "lab-c cannot be planned: needs pull (the image's configuration syntax is not known): tacctl device config pull lab-c (or --pull)") {
		t.Errorf("needs pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	// setting a syntax is the other way out
	b.run("device", "config-syntax", "lab-c", "ios12")
	out = b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "IOS 12.x syntax") {
		t.Errorf("set: %d\n%s", b.sb.code, out)
	}
}

func TestPlanCiscoRadiusScope(t *testing.T) {
	b := newPullBox(t)
	b.ciscoDevice("")
	b.sb.run("", []string{"scope", "vendor-attrs", "lab", "enable", "cisco,juniper"})
	b.sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\nlisteners:\n  radius:\n    auth: {network: udp, address: \"10.0.0.77:1645\", role: auth}\n", 0o600)
	b.sb.run("", []string{"scope", "auth-method", "lab", "radius"})
	if b.sb.code != 0 {
		t.Fatalf("auth-method: %d %s", b.sb.code, b.sb.stderr())
	}
	b.serve("cisco", b.expected("lab-c"))
	b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, b.sb.out.String(), b.sb.stderr())
	}
	b.serve("cisco", planDropServer(b.expected("lab-c")))
	b.run("device", "config", "pull", "lab-c")
	out := b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("plan: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"cisco (IOS-XE and IOS 15 syntax, RADIUS)", "radius server ", " address ipv4 10.0.0.77 auth-port 1645 acct-port 1813"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	planGolden(t, "cisco-radius.out", out)
}

// A secret a device lacks is typed in its line; --no-secrets leaves it as a
// marked comment and the audit line says which; neither reaches --json.
func TestPlanSecretsRules(t *testing.T) {
	b := planCiscoBox(t, "", ciscoVersionModern)
	const key = "lab-secret-0123456789abcdef"
	out := b.run("device", "config", "plan", "lab-c")
	if !strings.Contains(out, " key "+key) || !strings.Contains(out, "THIS OUTPUT HOLDS THE TACACS+ KEY OF SCOPE lab") {
		t.Errorf("the key is not typed where the device lacks it:\n%s", out)
	}
	if !strings.Contains(b.sb.stderr(), "lab-c: THIS OUTPUT HOLDS THE TACACS+ KEY OF SCOPE lab") {
		t.Errorf("the sensitivity line is not on standard error: %q", b.sb.stderr())
	}
	if al := b.auditLines("device config plan"); len(al) != 1 || !strings.Contains(al[0], "secrets=values") {
		t.Errorf("audit %q", al)
	}
	noSecrets(t, "audit", strings.Join(b.auditLines("device config plan"), "\n"), key)

	out = b.run("device", "config", "plan", "lab-c", "--no-secrets")
	if strings.Contains(out, key) || !strings.Contains(out, "VALUE NEEDED, then remove this mark: ") || !strings.Contains(out, "<SECRET>") {
		t.Errorf("--no-secrets:\n%s", out)
	}
	if al := b.auditLines("device config plan"); len(al) != 1 || !strings.Contains(al[0], "secrets=placeholders") {
		t.Errorf("audit %q", al)
	}
	if strings.Contains(b.sb.stderr(), "THIS OUTPUT HOLDS") {
		t.Errorf("a sensitivity line for an output with no value: %q", b.sb.stderr())
	}
	js := b.run("device", "config", "plan", "lab-c", "--json")
	noSecrets(t, "json", js, key)
	// files carry the value and are 0600
	f := b.sb.path("plan.txt")
	b.run("device", "config", "plan", "lab-c", "--out", f)
	st, err := os.Stat(f)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("file %v %v", st, err)
	}
	// --secrets with nothing lacking still re-types the secret statements
	out = b.run("device", "config", "plan", "lab-c", "--secrets")
	if !strings.Contains(out, " key "+key) {
		t.Errorf("--secrets:\n%s", out)
	}
}

// The check pull the after-steps ask for replaces the picture a back-out is
// computed from: the plan kept its back-out beside the record, and --backout
// prints that one, saying which pull it undoes (D111, point 3). With no plan
// kept there is nothing to print, said in one line (exit 0); --backout with
// --pull is refused.
func TestPlanBackoutSurvivesTheCheckPull(t *testing.T) {
	b := planCiscoBox(t, "", ciscoVersionModern)
	out := b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "PASTE FROM HERE: lab-c") {
		t.Fatalf("plan: %d\n%s", b.sb.code, out)
	}
	// the after-steps say it accurately
	if !strings.Contains(unwrapPlan(out), "tacctl keeps this plan's back-out: after the check pull has replaced the picture, the command still prints this plan's, and says which pull it undoes") {
		t.Errorf("the after-steps do not say the back-out is kept:\n%s", out)
	}
	// kept beside the record: 0600, the printed back-out and nothing else
	store := b.sb.path("var-lib", "device-config", "lab-c.backout")
	st, err := os.Stat(store)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the back-out was not kept: %v %v", st, err)
	}
	kept, _ := os.ReadFile(store)
	const key = "lab-secret-0123456789abcdef"
	noSecrets(t, "the kept back-out", string(kept), key, testPassword)
	// the one kept prints, whatever the record's pull is: it is what was
	// pasted. Its first comment line says the sections and the pull; while the
	// record's pull is the stamp nothing says a later pull replaced it.
	bo := b.run("device", "config", "plan", "lab-c", "--backout")
	if b.sb.code != 0 || !strings.Contains(bo, "!!!!! BACK-OUT FROM HERE: lab-c !!!!!") || strings.Contains(bo, "PASTE FROM HERE") ||
		!strings.Contains(bo, "\nno tacacs server TACACS\n") ||
		!strings.HasPrefix(bo, "! This back-out undoes the plan of aaa made from the pull of ") ||
		!strings.Contains(strings.SplitN(bo, "\n", 2)[0], "it is the one tacctl kept from that plan.") ||
		strings.Contains(bo, "a later pull replaced that picture") {
		t.Fatalf("backout: %d\n%s", b.sb.code, bo)
	}
	_, bo, _ = strings.Cut(bo, "\n")
	// the paste is made, and the check pull reads the device: the record now
	// shows the standard, the plan has nothing to paste
	b.serve("cisco", b.expected("lab-c"))
	b.run("device", "config", "pull", "lab-c")
	out = b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "CONSISTENT") || strings.Contains(out, "PASTE FROM HERE") {
		t.Errorf("consistent: %d\n%s", b.sb.code, out)
	}
	// ... and the back-out is the one the plan kept, with the pull it undoes
	got := b.run("device", "config", "plan", "lab-c", "--backout")
	if b.sb.code != 0 || !strings.HasPrefix(got, "! This back-out undoes the plan of aaa made from the pull of ") ||
		!strings.Contains(got, "a later pull replaced that picture") {
		t.Fatalf("after the check pull: %d\n%s", b.sb.code, got)
	}
	_, body, _ := strings.Cut(got, "\n")
	if normPlan(body) != normPlan(bo) {
		t.Errorf("the kept back-out is not the one the plan printed:\n--- kept\n%s\n--- printed\n%s", body, bo)
	}
	// planning again from the new pull (nothing to paste) keeps the old one
	b.run("device", "config", "plan", "lab-c", "--converge")
	if again, _ := os.ReadFile(store); string(again) != string(kept) {
		t.Error("a plan with nothing to paste replaced the kept back-out")
	}

	// --backout with --pull is a usage error: the pull is the baseline it
	// would replace
	b.run("device", "config", "plan", "lab-c", "--backout", "--pull")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--backout with --pull") {
		t.Errorf("--backout --pull: %d %q", b.sb.code, b.sb.stderr())
	}

	// no plan was kept: one line, exit 0, not an error
	if err := os.Remove(store); err != nil {
		t.Fatal(err)
	}
	out = b.run("device", "config", "plan", "lab-c", "--backout")
	if b.sb.code != 0 || strings.Contains(out, "BACK-OUT FROM HERE") ||
		!strings.Contains(out, "! lab-c: nothing to back out: no plan was made from an earlier pull of lab-c") {
		t.Errorf("no kept back-out: %d\n%s", b.sb.code, out)
	}
}

// A kept back-out goes with the record when it is forgotten (the store's own
// tests pin rename).
func TestPlanKeptBackoutFollowsTheRecord(t *testing.T) {
	b := planCiscoBox(t, "", ciscoVersionModern)
	b.run("device", "config", "plan", "lab-c")
	file := b.sb.path("var-lib", "device-config", "lab-c.backout")
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("no kept back-out: %v", err)
	}
	b.run("device", "config", "forget", "lab-c")
	if _, err := os.Stat(file); err == nil {
		t.Errorf("forgetting the record left the kept back-out (exit %d, %q)", b.sb.code, b.sb.stderr())
	}
	b.run("device", "config", "pull", "lab-c")
	b.run("device", "config", "plan", "lab-c")
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("no kept back-out after the second plan: %v", err)
	}
	b.run("device", "config", "forget", "--all")
	if _, err := os.Stat(file); err == nil {
		t.Errorf("forgetting every record left the kept back-out (exit %d, %q)", b.sb.code, b.sb.stderr())
	}
}

// --pull reads the devices first, with the pull's own password handling,
// then plans from what it read; a device it could not read cannot be
// planned.
func TestPlanPullReadsFirst(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-j2", "192.168.1.26", "juniper"})
	text := b.expected("lab-j")
	b.serve("juniper", text)
	// no pull has been made: --pull makes it
	out := b.run("device", "config", "plan", "lab-j", "--pull")
	if b.sb.code != 0 || !strings.Contains(out, "CONSISTENT: nothing to paste") {
		t.Fatalf("--pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if b.pw.asked != 1 || b.srv.Logins() != 1 {
		t.Errorf("asked %d logins %d", b.pw.asked, b.srv.Logins())
	}
	if _, ok := b.records().Of("lab-j"); !ok {
		t.Error("--pull recorded no pull")
	}
	// the progress is on standard error: standard output is the plan
	if strings.Contains(out, "ok via netconf") {
		t.Errorf("the pull's progress is in the plan:\n%s", out)
	}
	if !strings.Contains(b.sb.stderr(), "ok via netconf") {
		t.Errorf("stderr: %q", b.sb.stderr())
	}
	// a wrong password: the device cannot be planned, and the old pull is
	// not used for it
	b.pw.pw = "not-the-password"
	b.run("device", "config", "plan", "lab-j", "--pull")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "lab-j cannot be planned: the pull failed (authentication failed)") {
		t.Errorf("failed pull: %d %q", b.sb.code, b.sb.stderr())
	}
	b.pw.pw = testPassword
	// the pull's options are for --pull alone
	b.run("device", "config", "plan", "lab-j", "--timeout", "30")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--timeout is for --pull") {
		t.Errorf("timeout: %d %q", b.sb.code, b.sb.stderr())
	}
}
