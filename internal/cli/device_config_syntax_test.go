package cli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
)

// The Cisco configuration syntax as a fact of its own (D113 of
// docs/plans/0.2.5-plan.md): the setting and its verb, the pull that records
// the image, the one resolution the comparison and the walkthrough share, and
// the state of a device that needs a pull.

// expectedSyntax is expected for a Cisco device in the given syntax: what a
// device that runs that syntax and agrees with tacctl prints.
func (b *pullBox) expectedSyntax(name string, legacy bool) string {
	b.t.Helper()
	inv := b.invoke()
	_, res, err := inv.deviceLoad()
	if err != nil {
		b.t.Fatal(err)
	}
	e, ok := res.Lookup(name, devreg.ScopeFilter{})
	if !ok {
		b.t.Fatalf("no device %s", name)
	}
	// An explicit setting makes the render prepare that syntax.
	e.IOSSyntax = devconf.SyntaxModern
	if legacy {
		e.IOSSyntax = devconf.SyntaxIOS12
	}
	r := inv.newManagedRender(managedOptions{}, false)
	r.prepare([]devreg.Entry{e})
	secs, err := r.ExpectedAs(e, legacy)
	if err != nil {
		b.t.Fatal(err)
	}
	var out []string
	for _, s := range secs {
		out = append(out, s.Lines...)
	}
	return "Building configuration...\n\nCurrent configuration : 2000 bytes\n!\n" + strings.Join(out, "\n") + "\nend\n"
}

func (b *pullBox) cisco(name string, legacySSH bool) {
	b.t.Helper()
	b.devices([3]string{name, "192.168.1.30", "cisco"})
	if legacySSH {
		b.sb.dev("", "legacy-ssh", name, "enable")
	}
}

func TestIOSSyntaxVerbAndRows(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"}, [3]string{"lab-j", "192.168.1.20", "juniper"})
	sb := b.sb

	// No word prints the setting; before any pull there is nothing behind auto.
	out := sb.dev("", "ios-syntax", "lab-c")
	if sb.code != 0 || !strings.Contains(out, "auto (unknown until the device is pulled: tacctl device config pull lab-c)") {
		t.Errorf("show: %d %q", sb.code, out)
	}
	if strings.Contains(sb.devices(), "ios_syntax") {
		t.Errorf("a setting appeared by itself:\n%s", sb.devices())
	}
	// Set, read, show, JSON, clear.
	sb.dev("", "ios-syntax", "lab-c", "ios12")
	if sb.code != 0 || !strings.Contains(sb.devices(), "ios_syntax: ios12") {
		t.Fatalf("set: %d\n%s", sb.code, sb.devices())
	}
	if out := strings.TrimSpace(sb.dev("", "ios-syntax", "lab-c")); out != "ios12" {
		t.Errorf("read = %q", out)
	}
	if show := sb.dev("", "show", "lab-c"); !strings.Contains(show, "Config syntax: ios12\n") {
		t.Errorf("show:\n%s", show)
	}
	var j struct {
		IOSSyntax    string `json:"ios_syntax"`
		Syntax       string `json:"syntax"`
		SyntaxSource string `json:"syntax_source"`
		LegacySSH    bool   `json:"legacy_ssh"`
	}
	if err := json.Unmarshal([]byte(sb.dev("", "show", "lab-c", "--json")), &j); err != nil ||
		j.IOSSyntax != "ios12" || j.Syntax != "ios12" || j.SyntaxSource != "setting" || j.LegacySSH {
		t.Errorf("show --json: %+v %v", j, err)
	}
	sb.dev("", "ios-syntax", "lab-c", "modern")
	if !strings.Contains(sb.devices(), "ios_syntax: modern") {
		t.Errorf("modern:\n%s", sb.devices())
	}
	sb.dev("", "ios-syntax", "lab-c", "auto")
	if strings.Contains(sb.devices(), "ios_syntax") {
		t.Errorf("auto left the key:\n%s", sb.devices())
	}
	// A bad word, an unknown device, a vendor with no such setting.
	sb.dev("", "ios-syntax", "lab-c", "ios15")
	sb.expect(1, "", "Invalid configuration syntax 'ios15'. Use: auto, ios12, modern.")
	sb.dev("", "ios-syntax", "nosuch", "modern")
	sb.expect(1, "", "not found")
	sb.dev("", "ios-syntax", "lab-j", "ios12")
	sb.expect(1, "", "has vendor 'juniper'; the configuration syntax is a Cisco setting")
	sb.dev("", "ios-syntax")
	sb.expect(1, "", "Usage: tacctl device ios-syntax")
	// A Junos device's show has no such row; a Cisco device's has.
	if show := sb.dev("", "show", "lab-j"); strings.Contains(show, "Config syntax") {
		t.Errorf("a Junos device shows a syntax:\n%s", show)
	}
	// --legacy-ssh is the ssh algorithms and sets no syntax.
	sb.dev("", "legacy-ssh", "lab-c", "enable")
	if strings.Contains(sb.devices(), "ios_syntax") {
		t.Errorf("legacy-ssh set a syntax:\n%s", sb.devices())
	}
}

func TestDeviceAddIOSSyntax(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-c", "192.168.1.30", "--vendor", "cisco", "--ios-syntax", "modern", "--legacy-ssh", "--no-host-key")
	if sb.code != 0 || !strings.Contains(sb.devices(), "ios_syntax: modern") || !strings.Contains(sb.devices(), "legacy_ssh: true") {
		t.Fatalf("add: %d\n%s\n%s", sb.code, sb.devices(), sb.stderr())
	}
	sb.dev("", "add", "lab-d", "192.168.1.31", "--vendor", "cisco", "--ios-syntax", "auto", "--no-host-key")
	if sb.code != 0 || strings.Count(sb.devices(), "ios_syntax") != 1 {
		t.Errorf("auto is written:\n%s", sb.devices())
	}
	sb.dev("", "add", "lab-e", "192.168.1.32", "--vendor", "cisco", "--ios-syntax", "ios15", "--no-host-key")
	sb.expect(1, "", "Invalid configuration syntax 'ios15'")
	sb.dev("", "add", "lab-f", "192.168.1.33", "--ios-syntax", "ios12", "--no-host-key")
	sb.expect(1, "", "--ios-syntax is the Cisco configuration syntax; give --vendor cisco")
}

// The verb and the flag are ios-syntax (docs/plans/0.2.18-plan.md D273):
// the names before 0.2.18 are refused like any unknown word, and neither the
// usage nor completion names them.
func TestIOSSyntaxOldNamesAreGone(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"})
	sb := b.sb
	sb.dev("", "config-syntax", "lab-c", "ios12")
	sb.expect(1, "", "Unknown subcommand: 'config-syntax'")
	sb.dev("", "add", "lab-d", "192.168.1.31", "--vendor", "cisco", "--config-syntax", "modern", "--no-host-key")
	sb.expect(1, "", "Unknown option: '--config-syntax'")
	if strings.Contains(sb.devices(), "ios_syntax") || strings.Contains(sb.devices(), "lab-d") {
		t.Errorf("a refused line wrote the registry:\n%s", sb.devices())
	}
	if u := sb.dev("", "--help"); strings.Contains(u, "config-syntax") || !strings.Contains(u, "ios-syntax <name>") {
		t.Errorf("the usage:\n%s", u)
	}
	for _, words := range [][]string{{"device", ""}, {"device", "add", "x", "192.0.2.1", "--"}} {
		got, _ := completeWords(t, liveNames, words...)
		if slices.ContainsFunc(got, func(w string) bool { return strings.Contains(w, "config-syntax") }) {
			t.Errorf("%q offers the old name: %q", words, got)
		}
		if want := map[bool]string{true: "ios-syntax", false: "--ios-syntax"}[len(words) == 2]; !slices.Contains(got, want) {
			t.Errorf("%q lacks %q: %q", words, want, got)
		}
	}
}

// A pull records the image and compares in the syntax the image says,
// whatever the ssh flag: the two lab devices that need legacy-ssh and speak
// the modern syntax are ok, the 12.4 router in its own.
func TestPullRecordsImageAndSyntaxPerDialect(t *testing.T) {
	for _, tc := range []struct {
		name     string
		line     string
		legacy   bool // what the device runs
		wantSyn  string
		wantText string
	}{
		{"IOSv 15.6 with legacy-ssh", ciscoVersionModern, false, devconf.SyntaxModern, "tacacs server"},
		{"IOS-XE 16.7 with legacy-ssh", "Cisco IOS XE Software, Version 16.07.01", false, devconf.SyntaxModern, "tacacs server"},
		{"IOS 12.4 with legacy-ssh", ciscoVersion12, true, devconf.SyntaxIOS12, "tacacs-server host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newPullBox(t)
			b.cisco("lab-c", true)
			b.serve("cisco", b.expectedSyntax("lab-c", tc.legacy))
			b.version(tc.line)
			if !strings.Contains(b.expectedSyntax("lab-c", tc.legacy), tc.wantText) {
				t.Fatalf("the fixture is not in the %s syntax", tc.wantSyn)
			}
			out := b.run("device", "config", "pull", "lab-c", "--diff")
			if b.sb.code != 0 || !strings.Contains(out, "ok via ssh") || strings.Contains(out, "differs") {
				t.Fatalf("pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
			}
			rec, _ := b.records().Of("lab-c")
			if rec == nil || rec.OS != tc.line || rec.Syntax != tc.wantSyn || rec.Result != devconf.ResultOK {
				t.Fatalf("record %+v", rec)
			}
			if st := rec.Sections["aaa"].State; st != "ok" {
				t.Errorf("aaa is %q", st)
			}
			// What the list, the diff and show say agrees with the pull.
			if list := b.run("device", "config", "list"); !strings.Contains(list, " ok ") || strings.Contains(list, "needs pull") {
				t.Errorf("list:\n%s", list)
			}
			if diff := b.run("device", "config", "diff", "lab-c"); b.sb.code != 0 || strings.Contains(diff, "differs") {
				t.Errorf("diff: %d\n%s", b.sb.code, diff)
			}
			show := b.run("device", "show", "lab-c")
			if !strings.Contains(show, "Config syntax: auto ("+tc.wantSyn+", from the pull of ") || !strings.Contains(show, "Legacy ssh:   enabled") {
				t.Errorf("show:\n%s", show)
			}
			// The same ssh flag, the other syntax: a device is compared
			// in what it runs, so serving the other text differs.
			b.serve("cisco", b.expectedSyntax("lab-c", !tc.legacy))
			b.version(tc.line)
			out = b.run("device", "config", "pull", "lab-c")
			if !strings.Contains(out, "differs in aaa") {
				t.Errorf("the wrong syntax is not drift:\n%s", out)
			}
			// pull --json says which syntax it compared in.
			js := b.run("device", "config", "pull", "lab-c", "--json")
			var line pullJSON
			if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(js), "\n")[0]), &line); err != nil || line.Syntax != tc.wantSyn || line.SyntaxConflict || line.OS != tc.line {
				t.Errorf("json: %+v %v\n%s", line, err, js)
			}
		})
	}
}

// The setting wins over the version line (and is not what the record keeps:
// the record says what the device said), and a device that answers no
// version line is compared under a setting and refused without one.
func TestPullSettingAndMissingVersionLine(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", false)
	b.serve("cisco", b.expectedSyntax("lab-c", true))
	b.version(ciscoVersionModern)
	// An explicit ios12 is what the device is compared in, though it says 15.6.
	b.sb.dev("", "ios-syntax", "lab-c", "ios12")
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "ok via ssh") {
		t.Fatalf("set ios12: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.Syntax != devconf.SyntaxModern || rec.OS != ciscoVersionModern {
		t.Errorf("record %+v", rec)
	}
	b.sb.dev("", "ios-syntax", "lab-c", "modern")
	if out := b.run("device", "config", "pull", "lab-c"); !strings.Contains(out, "differs in aaa") {
		t.Errorf("modern against the 12.x text:\n%s", out)
	}

	// No version line: auto cannot be compared, and says what to do; a
	// setting is compared and the record keeps no image.
	b.sb.dev("", "ios-syntax", "lab-c", "auto")
	b.putRecord("lab-c", devconf.Record{})
	b.version("")
	out = b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 1 || !strings.Contains(out, "failed: the device's IOS version was not read") ||
		!strings.Contains(out, "tacctl device ios-syntax lab-c ios12|modern") {
		t.Errorf("no line, auto: %d\n%s", b.sb.code, out)
	}
	b.sb.dev("", "ios-syntax", "lab-c", "ios12")
	out = b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "ok via ssh") {
		t.Fatalf("no line, ios12: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.OS != "" || rec.Syntax != "" {
		t.Errorf("record %+v", rec)
	}
	// Back to auto with nothing on the record: the one-time pull is due.
	b.sb.dev("", "ios-syntax", "lab-c", "auto")
	if list := b.run("device", "config", "list"); !strings.Contains(list, "needs pull (syntax unknown)") {
		t.Errorf("list:\n%s", list)
	}

	// A line no row maps is not guessed modern: the pull is refused with the
	// hint, nothing is recorded, and the setting makes it comparable.
	const unmapped = "Cisco IOS Software, CSR1000V Software, Version 3.16.0S, RELEASE SOFTWARE"
	b.serve("cisco", b.expectedSyntax("lab-c", false))
	b.version(unmapped)
	out = b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 1 || !strings.Contains(out, `the device's version line "`+unmapped+`" is not an image tacctl maps`) ||
		!strings.Contains(out, "tacctl device ios-syntax lab-c ios12|modern") {
		t.Fatalf("unmapped line, auto: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.OS != "" || rec.Syntax != "" {
		t.Errorf("a refused pull was recorded: %+v", rec)
	}
	b.sb.dev("", "ios-syntax", "lab-c", "modern")
	out = b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "ok via ssh") || strings.Contains(out, "warning") {
		t.Fatalf("unmapped line, modern: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.OS != unmapped || rec.Syntax != "" {
		t.Errorf("record %+v: the line is kept and no syntax is derived", rec)
	}
	// Back at auto, the record's line is one nothing maps: the device needs
	// the setting, and 'show' says which line it was.
	b.sb.dev("", "ios-syntax", "lab-c", "auto")
	if list := b.run("device", "config", "list"); !strings.Contains(list, "needs pull (syntax unknown)") {
		t.Errorf("list:\n%s", list)
	}
	if show := b.run("device", "show", "lab-c"); !strings.Contains(show, `Config syntax: auto (unknown: the pull of `) ||
		!strings.Contains(show, `read "`+unmapped+`", which tacctl does not map to a syntax`) {
		t.Errorf("show:\n%s", show)
	}
}

// A record of 0.2.4 has no version line: neither guessed modern nor IOS 12.x.
// 'device config list' says it needs a pull, --stale selects it, the CONFIG
// column of 'device list' says 'pull', and a pull makes it known.
func TestRecordWithoutVersionLineNeedsPull(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", true)
	b.serve("cisco", b.expectedSyntax("lab-c", false))
	b.version(ciscoVersionModern)
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d\n%s", b.sb.code, out)
	}
	// Make it the record 0.2.4 wrote: the pull's sections, no os, no syntax.
	rec, _ := b.records().Of("lab-c")
	old := *rec
	old.OS, old.Syntax = "", ""
	b.putRecord("lab-c", old)

	list := b.run("device", "config", "list")
	if !strings.Contains(list, "needs pull (syntax unknown)") {
		t.Errorf("list:\n%s", list)
	}
	var row string
	for _, l := range strings.Split(list, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "lab-c") {
			row = l
		}
	}
	if !slicesContain(strings.Fields(row), "pull") {
		t.Errorf("no pull in the state column: %q", row)
	}
	if got := b.run("device", "config", "list", "--stale"); !strings.Contains(got, "lab-c") || strings.Contains(got, "None:") {
		t.Errorf("--stale:\n%s", got)
	}
	if got := b.run("device", "config", "list", "--never"); strings.Contains(got, "lab-c") {
		t.Errorf("--never selects it:\n%s", got)
	}
	var js []listJSON
	if err := json.Unmarshal([]byte(b.run("device", "config", "list", "--json")), &js); err != nil || len(js) != 1 || js[0].State != "pull" {
		t.Errorf("list --json: %+v %v", js, err)
	}
	if dl := b.run("device", "list"); !strings.Contains(dl, " pull ") {
		t.Errorf("device list:\n%s", dl)
	}
	diff := b.run("device", "config", "diff", "lab-c")
	if b.sb.code != 1 || !strings.Contains(diff, "needs pull (syntax unknown)") {
		t.Errorf("diff: %d\n%s", b.sb.code, diff)
	}
	// The selection of a stale pull takes it, and one pull makes it known.
	out = b.run("device", "config", "pull", "--stale")
	if b.sb.code != 0 || !strings.Contains(out, "lab-c  ok via ssh") {
		t.Fatalf("pull --stale: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.Syntax != devconf.SyntaxModern {
		t.Errorf("record %+v", rec)
	}
	if got := b.run("device", "config", "list", "--stale"); !strings.Contains(got, "None:") {
		t.Errorf("after the pull:\n%s", got)
	}
	// A RADIUS scope has one syntax: the old record is not stale.
	b.putRecord("lab-c", old)
	b.sb.cfgRun("", []string{"scope", "auth-method", "lab", "radius"}, route)
	if got := b.run("device", "config", "list", "--stale"); strings.Contains(got, "needs pull") {
		t.Errorf("a RADIUS scope needs a pull:\n%s", got)
	}
}

// The walkthrough takes the same resolution: the setting, else the pull's
// syntax, else the modern syntax with one line saying so; --legacy is the
// explicit IOS 12.x override.
func TestWalkthroughSyntaxResolution(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", true)
	const modern, legacy = "tacacs server TACACS", "tacacs-server host"
	const note = "# syntax: modern (no pull yet; set 'tacctl device ios-syntax lab-c ios12' for IOS 12.x, or pull the device once)"

	show := func(args ...string) string {
		t.Helper()
		return b.run(append([]string{"device", "config", "show", "lab-c"}, args...)...)
	}
	// No pull, auto: modern, with the line; legacy-ssh changes nothing.
	out := show()
	if !strings.Contains(out, modern) || strings.Contains(out, legacy) || strings.Count(out, "# syntax:") != 1 || !strings.Contains(out, note) {
		t.Errorf("no pull:\n%s", out)
	}
	// --legacy is the explicit override and says nothing.
	out = show("--legacy")
	if !strings.Contains(out, legacy) || strings.Contains(out, "# syntax:") {
		t.Errorf("--legacy:\n%s", out)
	}
	// The setting.
	b.sb.dev("", "ios-syntax", "lab-c", "ios12")
	out = show()
	if !strings.Contains(out, legacy) || strings.Contains(out, "# syntax:") {
		t.Errorf("ios12:\n%s", out)
	}
	b.sb.dev("", "ios-syntax", "lab-c", "modern")
	out = show()
	if !strings.Contains(out, modern) || strings.Contains(out, "# syntax:") {
		t.Errorf("modern:\n%s", out)
	}
	// The record's syntax, with the setting back at auto; a setting over it.
	b.sb.dev("", "ios-syntax", "lab-c", "auto")
	b.putRecord("lab-c", devconf.Record{Vendor: "cisco", Result: devconf.ResultOK, OS: ciscoVersion12, Syntax: devconf.SyntaxIOS12,
		Sections: map[string]devconf.SectionRecord{"aaa": {State: "ok"}}})
	out = show()
	if !strings.Contains(out, legacy) || strings.Contains(out, "# syntax:") {
		t.Errorf("record says ios12:\n%s", out)
	}
	b.sb.dev("", "ios-syntax", "lab-c", "modern")
	if out = show(); !strings.Contains(out, modern) || strings.Contains(out, legacy) {
		t.Errorf("setting over the record:\n%s", out)
	}
	b.sb.dev("", "ios-syntax", "lab-c", "auto")

	// 'config cisco --name' is the same walkthrough: the configuration is
	// the device's syntax on stdout, the note on stderr; without --name it
	// is the modern syntax, as before.
	b.putRecord("lab-c", devconf.Record{})
	plainOut := plain(b.sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "lab-c"}, route, "SUDO_USER=alice"))
	if !strings.Contains(plainOut, modern) || strings.Contains(plainOut, "# syntax:") || !strings.Contains(b.sb.stderr(), note) {
		t.Errorf("config cisco --name, no pull:\n%s\nstderr: %s", plainOut, b.sb.stderr())
	}
	b.putRecord("lab-c", devconf.Record{Vendor: "cisco", Result: devconf.ResultOK, OS: ciscoVersion12, Syntax: devconf.SyntaxIOS12,
		Sections: map[string]devconf.SectionRecord{"aaa": {State: "ok"}}})
	plainOut = plain(b.sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "lab-c"}, route, "SUDO_USER=alice"))
	if !strings.Contains(plainOut, legacy) || strings.Contains(b.sb.stderr(), "# syntax:") {
		t.Errorf("config cisco --name, ios12 record:\n%s\nstderr: %s", plainOut, b.sb.stderr())
	}
	plainOut = plain(b.sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, route, "SUDO_USER=alice"))
	if !strings.Contains(plainOut, modern) || strings.Contains(plainOut, legacy) {
		t.Errorf("config cisco without --name:\n%s", plainOut)
	}
	// A RADIUS scope has one syntax: an ios12 setting is not an --legacy
	// error there (what is refused is the backend, which is not enabled).
	b.sb.dev("", "ios-syntax", "lab-c", "ios12")
	b.sb.cfgRun("", []string{"scope", "auth-method", "lab", "radius"}, route)
	out = show()
	if strings.Contains(b.sb.stderr(), "--legacy") || strings.Contains(out, legacy) || strings.Contains(out, "# syntax:") {
		t.Errorf("RADIUS scope: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
}

// A device that was upgraded says another syntax than its record: it is
// compared in the one it says now, and the record is made again.
func TestPullFollowsAnUpgradedDevice(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", false)
	b.putRecord("lab-c", devconf.Record{Vendor: "cisco", Result: devconf.ResultOK, OS: ciscoVersion12, Syntax: devconf.SyntaxIOS12,
		Sections: map[string]devconf.SectionRecord{"aaa": {State: "ok"}}})
	b.serve("cisco", b.expectedSyntax("lab-c", false))
	b.version(ciscoVersionModern)
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "lab-c  ok via ssh") {
		t.Fatalf("pull: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.Syntax != devconf.SyntaxModern || rec.OS != ciscoVersionModern {
		t.Errorf("record %+v", rec)
	}
}
