package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devssh"
)

// Device facts: the release, model and serial number a pull records from the
// device itself, shown by 'device show' and 'device config list'.

const factsFixtures = "../../tests/fixtures/devconf/"

// factsFixture is a captured, sanitised output of tests/fixtures/devconf.
func factsFixture(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(factsFixtures, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// answer makes the fake device answer cmd with text ("" removes the file:
// the device does not know the command).
func (b *pullBox) answer(cmd, text string) {
	b.t.Helper()
	p := filepath.Join(b.dir, cmd+".out")
	if text == "" {
		_ = os.Remove(p)
		return
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

// deny makes the fake device refuse cmd with msg.
func (b *pullBox) deny(cmd, msg string) {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.dir, cmd+".err"), []byte(msg+"\n"), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

// The fake device answers the command with or without the '| no-more' that
// the command line is sent: NETCONF is sent the bare command.
const (
	junosChassisCmd = "show chassis hardware"
	junosVersionCmd = "show version"
)

func TestPullRecordsJunosFacts(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	// the release is the configuration's 'set version'; the model and the
	// serial number are the chassis row of one more command
	b.serve("juniper", "set version 25.4R1-S2.3\n"+b.expected("lab-j"))
	b.answer(junosChassisCmd, factsFixture(t, "juniper/facts-ex4300/show-chassis-hardware.txt"))

	out := b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "ok via netconf") {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	rec, _ := b.records().Of("lab-j")
	if rec == nil || rec.Release != "25.4R1-S2.3" || rec.Model != "EX4300-48MP" || rec.Serial != "FXYZ00000001" || rec.OS != "" {
		t.Fatalf("record %+v", rec)
	}
	// the facts are no part of the pull's output, its --json or its audit line
	b.noSerial("FXYZ00000001", "lab-j")

	show := b.run("device", "show", "lab-j")
	for _, want := range []string{"\n  Release:      25.4R1-S2.3\n", "\n  Model:        EX4300-48MP\n", "\n  Serial:       FXYZ00000001\n"} {
		if !strings.Contains(show, want) {
			t.Errorf("no %q in:\n%s", want, show)
		}
	}
	if i, j := strings.Index(show, "Configuration:"), strings.Index(show, "Release:"); i < 0 || j < i {
		t.Errorf("the facts follow the Configuration row:\n%s", show)
	}
	var one deviceJSON
	if err := json.Unmarshal([]byte(b.run("device", "show", "lab-j", "--json")), &one); err != nil {
		t.Fatal(err)
	}
	if one.Release != "25.4R1-S2.3" || one.Model != "EX4300-48MP" || one.Serial != "FXYZ00000001" {
		t.Errorf("show --json: %+v", one)
	}

	list := b.run("device", "config", "list")
	var head, row string
	for _, l := range strings.Split(list, "\n") {
		switch {
		case strings.Contains(l, "NAME") && strings.Contains(l, "RELEASE"):
			head = l
		case strings.HasPrefix(strings.TrimSpace(l), "lab-j"):
			row = l
		}
	}
	if head == "" || row == "" {
		t.Fatalf("config list:\n%s", list)
	}
	if at := strings.Index(head, "RELEASE"); len(row) < at+11 || row[at:at+11] != "25.4R1-S2.3" {
		t.Errorf("RELEASE column %d: %q under %q", at, row, head)
	}
	if strings.Index(head, "RELEASE") > strings.Index(head, "CONFIG") {
		t.Errorf("RELEASE is before CONFIG: %q", head)
	}
	var rows []listJSON
	if err := json.Unmarshal([]byte(b.run("device", "config", "list", "--json")), &rows); err != nil || len(rows) != 1 || rows[0].Release != "25.4R1-S2.3" {
		t.Errorf("config list --json: %v %+v", err, rows)
	}

	// A pull replaces the facts: a device that now answers none has none,
	// and a refused command is no failure of the pull.
	b.serve("juniper", b.expected("lab-j"))
	b.answer(junosChassisCmd, "")
	b.deny(junosVersionCmd, "error: permission denied")
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 || !strings.Contains(out, "ok via netconf") {
		t.Fatalf("pull with no facts: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	rec, _ = b.records().Of("lab-j")
	if rec == nil || rec.Result != "ok" || rec.Release != "" || rec.Model != "" || rec.Serial != "" {
		t.Errorf("record %+v", rec)
	}
	show = b.run("device", "show", "lab-j")
	for _, no := range []string{"Release:", "Model:", "Serial:"} {
		if strings.Contains(show, no) {
			t.Errorf("a %s row with nothing to show:\n%s", no, show)
		}
	}
	js := b.run("device", "show", "lab-j", "--json")
	for _, no := range []string{`"release"`, `"model"`, `"serial"`} {
		if strings.Contains(js, no) {
			t.Errorf("a %s field with nothing in it:\n%s", no, js)
		}
	}
}

// noSerial asserts that a pull of the device shows the serial number in none
// of its outputs: the text, --json and the audit line.
func (b *pullBox) noSerial(serial, name string) {
	b.t.Helper()
	for _, args := range [][]string{{"device", "config", "pull", name}, {"device", "config", "pull", name, "--json"}} {
		if out := b.run(args...); strings.Contains(out, serial) || strings.Contains(b.sb.stderr(), serial) {
			b.t.Errorf("%v shows the serial number:\n%s", args, out)
		}
	}
	for _, l := range b.auditLines("device config pull") {
		if strings.Contains(l, serial) {
			b.t.Errorf("audit line: %s", l)
		}
	}
}

// A device that is upgraded and not committed since states the old release
// in its configuration: the running release is 'show version”s.
func TestPullRecordsTheRunningJunosRelease(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", "set version 15.1R7\n"+b.expected("lab-j"))
	b.answer(junosVersionCmd, "Hostname: sw1\nModel: ex4300-48mp\nJunos: 21.4R3\n")
	b.answer(junosChassisCmd, factsFixture(t, "juniper/facts-ex4300/show-chassis-hardware.txt"))
	for _, tr := range []string{"netconf", "ssh"} {
		if out := b.run("device", "config", "pull", "lab-j", "--transport", tr); b.sb.code != 0 {
			t.Fatalf("%s: %d %q %q", tr, b.sb.code, out, b.sb.stderr())
		}
		rec, _ := b.records().Of("lab-j")
		if rec == nil || rec.Transport != tr || rec.Release != "21.4R3" || rec.Model != "EX4300-48MP" || rec.Serial != "FXYZ00000001" {
			t.Errorf("%s: record %+v", tr, rec)
		}
	}
	// show version answers none: the configuration's statement stands
	b.answer(junosVersionCmd, "")
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("%d %q %q", b.sb.code, out, b.sb.stderr())
	}
	if rec, _ := b.records().Of("lab-j"); rec == nil || rec.Release != "15.1R7" {
		t.Errorf("record %+v", rec)
	}
}

// A configuration with no 'set version' statement: the release is 'show
// version”s, over the command line too, and the model stays the chassis
// description.
func TestPullRecordsJunosFactsFromShowVersion(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	b.answer(junosChassisCmd, factsFixture(t, "juniper/facts-ex4300/show-chassis-hardware.txt"))
	b.answer(junosVersionCmd, factsFixture(t, "juniper/facts-ex4300/show-version.txt"))
	for _, tr := range []string{"netconf", "ssh"} {
		if out := b.run("device", "config", "pull", "lab-j", "--transport", tr); b.sb.code != 0 {
			t.Fatalf("%s: %d %q %q", tr, b.sb.code, out, b.sb.stderr())
		}
		rec, _ := b.records().Of("lab-j")
		if rec == nil || rec.Transport != tr || rec.Release != "25.4R1-S2.3" || rec.Model != "EX4300-48MP" || rec.Serial != "FXYZ00000001" {
			t.Errorf("%s: record %+v", tr, rec)
		}
	}
}

func TestPullRecordsCiscoFacts(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"})
	b.serve("cisco", b.expected("lab-c"))
	// the IOS-XE build prints its padded number first: the release is the
	// IOS line's
	b.version(strings.TrimRight(factsFixture(t, "ios-xe/facts-csr1000v/show-version-include-version.txt"), "\n"))
	b.answer("show inventory", factsFixture(t, "ios-xe/facts-csr1000v/show-inventory.txt"))
	if out := b.run("device", "config", "pull", "lab-c"); b.sb.code != 0 || !strings.Contains(out, "ok via ssh") {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	rec, _ := b.records().Of("lab-c")
	if rec == nil || rec.Release != "16.7.1" || rec.Model != "CSR1000V" || rec.Serial != "FXYZ0000002" ||
		rec.OS != "Cisco IOS XE Software, Version 16.07.01" {
		t.Fatalf("record %+v", rec)
	}
	b.noSerial("FXYZ0000002", "lab-c")
	if show := b.run("device", "show", "lab-c"); !strings.Contains(show, "\n  Release:      16.7.1\n") ||
		!strings.Contains(show, "\n  Model:        CSR1000V\n") || !strings.Contains(show, "\n  Serial:       FXYZ0000002\n") {
		t.Errorf("show:\n%s", show)
	}

	// An image that does not know 'show inventory' is pulled all the same,
	// and keeps its release.
	b.answer("show inventory", "")
	b.version(ciscoVersionModern)
	if out := b.run("device", "config", "pull", "lab-c"); b.sb.code != 0 || !strings.Contains(out, "ok via ssh") {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	rec, _ = b.records().Of("lab-c")
	if rec == nil || rec.Result != "ok" || rec.Release != "15.6(2)T" || rec.Model != "" || rec.Serial != "" {
		t.Errorf("record %+v", rec)
	}
	// a refusal in the CLI's own words
	b.answer("show inventory", "% Invalid input detected at '^' marker.\n")
	if b.run("device", "config", "pull", "lab-c"); b.sb.code != 0 {
		t.Fatalf("exit %d: %q", b.sb.code, b.sb.stderr())
	}
	if rec, _ = b.records().Of("lab-c"); rec == nil || rec.Release != "15.6(2)T" || rec.Model != "" || rec.Serial != "" {
		t.Errorf("record %+v", rec)
	}
}

// The NETCONF runner sends the command without the pipe that keeps the
// command line from paging.
type rpcCapture struct {
	devssh.NetconfSession
	bodies []string
}

func (r *rpcCapture) RPC(_ context.Context, body string) (string, error) {
	r.bodies = append(r.bodies, body)
	return `<rpc-reply><output>x</output></rpc-reply>`, nil
}

func TestNetconfRunnerSendsTheBareCommand(t *testing.T) {
	c := &rpcCapture{}
	r := netconfRunner{c}
	for _, cmd := range []string{"show chassis hardware | no-more", "show version", "show | compare | no-more x"} {
		if _, err := r.Run(context.Background(), cmd); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{devssh.CommandRPC("show chassis hardware"), devssh.CommandRPC("show version"), devssh.CommandRPC("show | compare | no-more x")}
	if strings.Join(c.bodies, "\n") != strings.Join(want, "\n") {
		t.Errorf("sent %q, want %q", c.bodies, want)
	}
}

// A fact command that never answers costs the pull the facts' own timeout,
// not the rest of the device's: the pull is ok, the sections are recorded
// and the facts are empty.
func TestHangingFactCommandDoesNotHoldThePull(t *testing.T) {
	hang := func(b *pullBox, cmds ...string) {
		for _, c := range cmds {
			if err := os.WriteFile(filepath.Join(b.dir, c+".hang"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	check := func(t *testing.T, b *pullBox, name string, args ...string) {
		t.Helper()
		b.sb.hooks.factsTimeout = time.Second
		start := time.Now()
		out := b.run(append([]string{"device", "config", "pull", name, "--timeout", "10"}, args...)...)
		took := time.Since(start)
		if b.sb.code != 0 || !strings.Contains(out, "ok via") {
			t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
		}
		if took >= 10*time.Second {
			t.Errorf("the pull took %s", took)
		}
		rec, _ := b.records().Of(name)
		if rec == nil || rec.Result != "ok" || rec.Model != "" || rec.Serial != "" || len(rec.Sections) == 0 {
			t.Fatalf("record %+v", rec)
		}
		if s, ok := rec.Sections["aaa"]; !ok || s.State != "ok" {
			t.Errorf("sections %+v", rec.Sections)
		}
	}
	t.Run("junos over netconf", func(t *testing.T) {
		b := newPullBox(t)
		b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
		b.serve("juniper", b.expected("lab-j"))
		hang(b, junosChassisCmd, junosVersionCmd)
		check(t, b, "lab-j", "--transport", "netconf")
		if rec, _ := b.records().Of("lab-j"); rec.Release != "" || rec.Transport != "netconf" {
			t.Errorf("record %+v", rec)
		}
	})
	t.Run("junos over ssh", func(t *testing.T) {
		b := newPullBox(t)
		b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
		b.serve("juniper", "set version 15.1R7\n"+b.expected("lab-j"))
		hang(b, junosChassisCmd+" | no-more", junosVersionCmd+" | no-more")
		check(t, b, "lab-j", "--transport", "ssh")
		// the release the configuration stated is not lost with the facts
		if rec, _ := b.records().Of("lab-j"); rec.Release != "15.1R7" || rec.Transport != "ssh" {
			t.Errorf("record %+v", rec)
		}
	})
	t.Run("cisco", func(t *testing.T) {
		b := newPullBox(t)
		b.devices([3]string{"lab-c", "192.168.1.30", "cisco"})
		b.serve("cisco", b.expected("lab-c"))
		hang(b, "show inventory")
		check(t, b, "lab-c")
		if rec, _ := b.records().Of("lab-c"); rec.Release != "15.6(2)T" {
			t.Errorf("record %+v", rec)
		}
	})
}

// The facts are the Configuration row's: shown to the operator tier and up,
// in no output of a read-only user.
func TestFactsFollowTheConfigurationRow(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/devices.yaml", "version: 1\nsettings:\n  stale_days: 30\ndevices:\n"+
		"  d-ok: {address: 192.168.1.1, vendor: cisco}\n"+
		"  d-old: {address: 192.168.1.2, vendor: cisco}\n"+
		"  d-wti: {address: 192.168.1.5, vendor: wti}\n", 0o600)
	sb.write("var-lib/devices-config.json", `{"version":1,"updated":"2026-10-09T12:00:00Z","devices":{
"d-ok":{"vendor":"cisco","transport":"ssh","pulled":"2026-10-09T12:00:00Z","by":"alice","result":"ok","secrets_visible":true,
  "os":"Cisco IOS Software, IOSv Software, Version 15.6(2)T","syntax":"modern","release":"15.6(2)T","model":"IOSv","serial":"FXYZ0000001",
  "sections":{"aaa":{"state":"ok"},"roles":{"state":"ok"}}},
"d-old":{"vendor":"cisco","transport":"ssh","pulled":"2026-10-09T12:00:00Z","by":"alice","result":"ok","secrets_visible":true,
  "os":"Cisco IOS Software, IOSv Software, Version 15.6(2)T","syntax":"modern","sections":{"aaa":{"state":"ok"}}},
"d-wti":{"vendor":"wti","transport":"ssh","pulled":"2026-10-09T12:00:00Z","by":"alice","result":"ok","secrets_visible":true,
  "os":"8.10","release":"8.10","unit":{"site_id":"x","other_sessions":0,"users_read":true},"sections":{"aaa":{"state":"ok"}}}}}`, 0o600)

	ro := sb.asUser("carol", "tac-readonly", "device", "show", "d-ok")
	for _, no := range []string{"Release", "Model", "Serial", "FXYZ0000001", "15.6(2)T"} {
		if sb.code != 0 || strings.Contains(ro, no) {
			t.Errorf("read-only show has %q: %d\n%s", no, sb.code, ro)
		}
	}
	for _, args := range [][]string{{"device", "show", "d-ok", "--json"}, {"device", "list", "--json"}} {
		if ro := sb.asUser("carol", "tac-readonly", args...); sb.code != 0 || strings.Contains(ro, "FXYZ0000001") || strings.Contains(ro, `"release"`) || strings.Contains(ro, `"serial"`) {
			t.Errorf("read-only %v: %d\n%s", args, sb.code, ro)
		}
	}

	op := sb.asUser("bob", "tac-operator", "device", "show", "d-ok")
	for _, want := range []string{"\n  Release:      15.6(2)T\n", "\n  Model:        IOSv\n", "\n  Serial:       FXYZ0000001\n"} {
		if !strings.Contains(op, want) {
			t.Errorf("operator show lacks %q:\n%s", want, op)
		}
	}
	// a record of an older release has none, and shows none
	if old := sb.asUser("bob", "tac-operator", "device", "show", "d-old"); strings.Contains(old, "Release:") || strings.Contains(old, "Serial:") || !strings.Contains(old, "Configuration:") {
		t.Errorf("record without facts:\n%s", old)
	}
	var devs []deviceJSON
	if err := json.Unmarshal([]byte(sb.asUser("bob", "tac-operator", "device", "list", "--json")), &devs); err != nil {
		t.Fatal(err)
	}
	got := map[string]deviceJSON{}
	for _, d := range devs {
		got[d.Name] = d
	}
	if d := got["d-ok"]; d.Release != "15.6(2)T" || d.Model != "IOSv" || d.Serial != "FXYZ0000001" {
		t.Errorf("d-ok: %+v", d)
	}
	if d := got["d-wti"]; d.Release != "8.10" || d.Model != "" || d.Serial != "" {
		t.Errorf("d-wti: %+v", d)
	}
	if d := got["d-old"]; d.Release != "" {
		t.Errorf("d-old: %+v", d)
	}

	// device config list: a RELEASE column, '-' where none was read
	list := sb.asUser("bob", "tac-operator", "device", "config", "list")
	cols := -1
	for _, l := range strings.Split(list, "\n") {
		if i := strings.Index(l, "RELEASE"); i >= 0 {
			cols = i
		}
	}
	if cols < 0 {
		t.Fatalf("no RELEASE column:\n%s", list)
	}
	want := map[string]string{"d-ok": "15.6(2)T", "d-old": "-", "d-wti": "8.10"}
	for _, l := range strings.Split(list, "\n") {
		f := strings.Fields(l)
		if len(f) > 4 && want[f[0]] != "" && len(l) > cols {
			if got := strings.Fields(l[cols:])[0]; got != want[f[0]] {
				t.Errorf("%s: RELEASE %q, want %q: %q", f[0], got, want[f[0]], l)
			}
			delete(want, f[0])
		}
	}
	if len(want) != 0 {
		t.Errorf("rows not found: %v\n%s", want, list)
	}
	var rows []listJSON
	if err := json.Unmarshal([]byte(sb.asUser("bob", "tac-operator", "device", "config", "list", "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	rel := map[string]string{}
	for _, r := range rows {
		rel[r.Name] = r.Release
	}
	if rel["d-ok"] != "15.6(2)T" || rel["d-wti"] != "8.10" || rel["d-old"] != "" {
		t.Errorf("config list --json: %v", rel)
	}
}

// The walkthrough of a registered Junos device follows its recorded release:
// before 16.1 the idle timeout is set on each login class.
func TestWalkthroughIdleTimeoutFollowsTheRecordedRelease(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", "set version 11.4R7.5\n"+b.expected("lab-j"))
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %q %q", out, b.sb.stderr())
	}
	out := b.run("device", "config", "show", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("show: %q %q", out, b.sb.stderr())
	}
	if strings.Contains(out, "\nset system login idle-timeout ") || !strings.Contains(out, " idle-timeout ") ||
		!strings.Contains(out, "This release has no 'system login idle-timeout'") {
		t.Errorf("an 11.4 device is not given the per-class form:\n%s", out)
	}

	// a newer release is given the global statement
	b.serve("juniper", "set version 25.4R1-S2.3\n"+b.expected("lab-j"))
	b.run("device", "config", "pull", "lab-j")
	out = b.run("device", "config", "show", "lab-j")
	if !strings.Contains(out, "\nset system login idle-timeout ") {
		t.Errorf("a 25.4 device lost the global statement:\n%s", out)
	}
}
