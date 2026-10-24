package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// applyCmd runs 'device config apply' as alice (a superuser) in the sandbox.
func (sb *sandbox) applyCmd(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, append([]string{"device", "config", "apply"}, args...), nil, "SUDO_USER=alice"))
}

// The arguments that need no device are refused with status 2 before a
// password is asked for or a device is dialled (D130, D134).
func TestApplyArgumentsAreCheckedFirst(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"sw-j", "--yes"}, "--yes answers the review only with --confirmed"},
		{[]string{"sw-j"}, "No terminal to confirm on"},
		{[]string{"sw-j", "--confirmed"}, "No terminal to confirm on"},
		{[]string{"sw-j", "--confirmed", "--yes", "--hold"}, "--hold asks a person"},
		{[]string{"sw-j", "--hold", "--json"}, "--hold asks on the terminal and --json keeps standard output to the objects"},
		{[]string{"sw-j", "--check", "--hold"}, "--hold, --pause and --no-canary are for an apply"},
		{[]string{"sw-j", "--check", "--pause", "5"}, "--hold, --pause and --no-canary are for an apply"},
		{[]string{"sw-j", "--exit-code"}, "--exit-code is for --check"},
		{[]string{"sw-j", "--check", "--max", "0"}, "--max takes a number of devices"},
		{[]string{"sw-j", "--check", "--pause", "-1"}, "--pause takes seconds"},
		{[]string{"sw-j", "--check", "--section", "breakglass"}, "never written"},
		{[]string{"sw-j", "--check", "--section", "bogus"}, "--section takes sections of"},
		{[]string{"--check"}, "Name the devices to apply"},
		{[]string{"sw-j", "--all", "--check"}, "not both"},
		{[]string{"sw-j", "--check", "--frob"}, "Unknown option: '--frob'"},
	} {
		sb.applyCmd("", c.args...)
		if sb.code != 2 || !strings.Contains(plain(sb.err.String()), c.want) {
			t.Errorf("%v: exit %d, stderr %q (want 2 with %q)", c.args, sb.code, sb.err.String(), c.want)
		}
	}
	if _, err := os.Stat(sb.path("var-lib", "devices-config.json")); err == nil {
		t.Error("a refused argument wrote a record")
	}
}

// A named Cisco device is a failed row with its reason, with no login and no
// password asked for; a lower tier is refused by the gate.
func TestApplyRefusesNonJunosAndLowerTiers(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-c", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "pdu-w", "192.168.1.7", "--vendor", "wti", "--no-host-key", "--no-lookup")
	out := sb.applyCmd("", "sw-c", "--check")
	if sb.code != 1 || !strings.Contains(out, "sw-c  failed: apply is not available for Cisco devices in this release") {
		t.Errorf("cisco: %d %q %q", sb.code, out, sb.err.String())
	}
	out = sb.applyCmd("", "pdu-w", "--check")
	if sb.code != 1 || !strings.Contains(out, "pdu-w  unsupported: apply is not available for WTI units") {
		t.Errorf("wti: %d %q", sb.code, out)
	}
	out = sb.applyCmd("", "--all", "--check", "--json")
	if sb.code != 0 || !strings.Contains(out, `"not_junos":["pdu-w","sw-c"]`) && !strings.Contains(out, `"not_junos":["sw-c","pdu-w"]`) {
		t.Errorf("selector: %d %q", sb.code, out)
	}
	sb.write("state/tacctl.yaml", "{}\n", 0o600)
	sb.asUser("bob", "tac-operator", "device", "config", "apply", "sw-c", "--check")
	if sb.code != 1 || !strings.Contains(sb.err.String(), "not permitted for the operator tier") {
		t.Errorf("operator: %d %q", sb.code, sb.err.String())
	}
	sb.asUser("bob", "tac-operator", "device", "config", "shapes")
	if sb.code != 1 || !strings.Contains(sb.err.String(), "not permitted for the operator tier") {
		t.Errorf("operator shapes: %d %q", sb.code, sb.err.String())
	}
}

// The apply part of a record: what it shows, in the row, the column and the
// JSON, and that it clones.
func TestAppliedRecordViews(t *testing.T) {
	at := time.Date(2026, 10, 13, 14, 12, 0, 0, time.UTC)
	applied := &devconf.Applied{At: at, By: "alice", Result: devconf.AppliedApplied, ID: "tacctl-x-3f2a", Kind: devconf.AppliedKindApply,
		Shape: "3f2a1b9c0d4e", Sections: []string{"aaa"}, Set: 3, Commit: &devconf.AppliedCommit{Seq: 0, Time: "t"}}
	if got := appliedCell(applied); got != "applied 2026-10-13 14:12" {
		t.Errorf("cell %q", got)
	}
	if got := applyBlock(applied); got != "applied 2026-10-13 14:12 by alice (tacctl-x-3f2a, shape 3f2a1b9c0d4e)" {
		t.Errorf("block %q", got)
	}
	pend := &devconf.Applied{Result: devconf.AppliedPending, Until: at, ID: "tacctl-y"}
	if got := appliedCell(pend); got != "PENDING 14:12" {
		t.Errorf("pending cell %q", got)
	}
	if got := plain(applyBlock(pend)); !strings.Contains(got, "PENDING until 14:12:00 (tacctl-y): do not type commit or commit check on the device") {
		t.Errorf("pending block %q", got)
	}
	if !pend.Pending() || applied.Pending() || (*devconf.Applied)(nil).Pending() {
		t.Error("Pending")
	}
	if appliedCell(nil) != "-" || applyBlock(nil) != "" {
		t.Error("nil record")
	}
	b, err := json.Marshal(appliedJSONOf(applied))
	if err != nil || !strings.Contains(string(b), `"result":"applied"`) || !strings.Contains(string(b), `"shape":"3f2a1b9c0d4e"`) {
		t.Errorf("json %s %v", b, err)
	}
	c := applied.Clone()
	c.Sections[0], c.Commit.Time = "snmp", "u"
	if applied.Sections[0] != "aaa" || applied.Commit.Time != "t" {
		t.Error("Clone shares")
	}
	// the record file round trip keeps the fields and nothing else
	recs := devconf.NewRecords()
	recs.Put("sw", devconf.Record{Vendor: "juniper", Applied: applied})
	st := devconf.Store{Records: filepath.Join(t.TempDir(), "r.json")}
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}
	back, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := back.Of("sw"); !ok || r.Applied == nil || r.Applied.ID != "tacctl-x-3f2a" || r.Applied.Commit == nil || r.Applied.Set != 3 {
		t.Errorf("round trip %+v", r)
	}
}

// --confirmed gates on the store, --max caps, and the skipped devices say why.
func TestApplySelectionGatesOnConfirmedShapes(t *testing.T) {
	dir := t.TempDir()
	shapes := devapply.OpenShapes(dir)
	d := plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events login"}}}
	hash, lines := plan.Shape(d)
	if err := shapes.Confirm(hash, lines, devapply.Confirmation{Device: "sw-0", At: time.Now(), By: "alice"}); err != nil {
		t.Fatal(err)
	}
	other := plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events change-log"}}}
	oh, _ := plan.Shape(other)
	mk := func(name, h string) *applyOutcome {
		return &applyOutcome{Name: name, Out: &devapply.Outcome{Exit: devapply.ExitChecked, Shape: h}, Delta: d, HasDelta: true}
	}
	a, b, c := mk("sw-a", hash), mk("sw-b", oh), mk("sw-c", hash)
	ctl := &applyCtl{aa: applyArgs{confirmed: true, max: 1}, run: &applyRun{shapes: shapes}, rows: []*applyOutcome{a, b, c}}
	groups := []*shapeGroup{{hash: hash, devices: []*applyOutcome{a, c}}, {hash: oh, devices: []*applyOutcome{b}}}
	got := ctl.selectApply(groups, nil)
	if len(got) != 1 || got[0] != a {
		t.Fatalf("selected %v", got)
	}
	if !strings.HasPrefix(b.Skipped, "unknown shape "+oh+": review and apply it by hand first") {
		t.Errorf("b: %q", b.Skipped)
	}
	if c.Skipped != "beyond --max 1: run it again for the rest" || a.ConfirmedOn != "sw-0" {
		t.Errorf("c: %q, a confirmed on %q", c.Skipped, a.ConfirmedOn)
	}
	if b.word() != "skipped" || summaryLine(map[string]int{"applied": 1, "skipped": 2}) != "1 applied, 2 skipped" {
		t.Errorf("words: %q", summaryLine(map[string]int{"applied": 1, "skipped": 2}))
	}
}

// The review groups by shape and by what it shows of each device: a device
// whose warnings or whose sections left out differ is its own heading, the
// statements whose per-device values differ are printed per device, a
// device whose plan refuses a section is not applied and is a failure, and
// the approval's audit line names the canary of each shape (none with
// --no-canary).
func TestApplyReviewGroupsByWhatItShows(t *testing.T) {
	sb := newSandbox(t, true)
	r := &fake.Runner{}
	r.On([]string{"logger"}, execx.Result{})
	var out bytes.Buffer
	a := app.New(nil, paths.NewEnv(append(append([]string(nil), sb.env...), "SUDO_USER=alice")), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out}, r)
	inv := &invocation{ctx: context.Background(), app: a, hooks: newTestHooks()}
	delta := func(loc string) plan.Delta {
		return plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{
			{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events login"},
			{Section: "snmp", Op: plan.OpSet, Text: "set snmp location \"" + loc + "\""}}}
	}
	var entries []devreg.Entry
	byName := map[string]*applyOutcome{}
	var rows []*applyOutcome
	mk := func(name string, d plan.Delta) *applyOutcome {
		h, _ := plan.Shape(d)
		o := &applyOutcome{Name: name, Out: &devapply.Outcome{Exit: devapply.ExitChecked, Shape: h}, Delta: d, HasDelta: true}
		entries = append(entries, devreg.Entry{Device: devreg.Device{Name: name}})
		byName[name] = o
		rows = append(rows, o)
		return o
	}
	da, db, dc, dd := delta("rack A"), delta("rack B"), delta("rack C"), delta("rack D")
	dc.Warnings = []string{"the pull is 9 days old"}
	dd.Skipped = []plan.Skip{{Section: "mgmt-acl", Kind: plan.KindRefused, Why: "the filter would refuse tacctl's own address"}}
	other := plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events change-log"}}}
	oa, ob, oc, od, oe := mk("sw-a", da), mk("sw-b", db), mk("sw-c", dc), mk("sw-d", dd), mk("sw-e", other)
	if oa.Out.Shape != ob.Out.Shape || oa.Out.Shape != oc.Out.Shape || oa.Out.Shape != od.Out.Shape || oa.Out.Shape == oe.Out.Shape {
		t.Fatalf("shapes %s %s %s %s %s", oa.Out.Shape, ob.Out.Shape, oc.Out.Shape, od.Out.Shape, oe.Out.Shape)
	}
	h := oa.Out.Shape
	for _, noCanary := range []bool{false, true} {
		out.Reset()
		for _, o := range rows {
			o.Skipped, o.Refused = "", ""
		}
		ctl := &applyCtl{inv: inv, user: "alice", aa: applyArgs{yes: true, max: 10, noCanary: noCanary},
			run: &applyRun{shapes: devapply.OpenShapes(t.TempDir()), minutes: 10}, rows: rows}
		groups := ctl.groupByShape(entries, byName)
		if len(groups) != 4 || len(groups[0].devices) != 2 || groups[0].devices[1] != ob || groups[1].devices[0] != oc || groups[2].devices[0] != od {
			t.Fatalf("groups %d: %+v", len(groups), groups)
		}
		apply := ctl.selectApply(groups, byName)
		if len(apply) != 4 || slices.Contains(apply, od) {
			t.Fatalf("applied %d, the refused device among them: %v", len(apply), slices.Contains(apply, od))
		}
		rv := ctl.review(groups, apply, false)
		if len(rv.approved) != len(apply) || rv.declined || rv.interrupted {
			t.Fatalf("not approved: %+v", rv)
		}
		ctl.audit(rv.approved)
		got := plain(out.String())
		for _, want := range []string{
			"Shape " + h + ", 2 devices (sw-a, sw-b), not confirmed yet; the same change as another heading, with other notes:\n  aaa\n    set system accounting events login\n  snmp\n    sw-a: set snmp location \"rack A\"\n    sw-b: set snmp location \"rack B\"\n",
			"Shape " + h + ", 1 device (sw-c), not confirmed yet; the same change as another heading, with other notes:\n",
			"  warning: the pull is 9 days old\n",
			"Shape " + h + ", 1 device (sw-d), not confirmed yet; the same change as another heading, with other notes:\n",
			"  not planned: mgmt-acl: the filter would refuse tacctl's own address\n",
			"  sw-d  failed: the plan refuses mgmt-acl (the filter would refuse tacctl's own address): nothing is applied to this device",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("no %q in:\n%s", want, got)
			}
		}
		if strings.Count(got, "warning: the pull is 9 days old") != 1 {
			t.Errorf("the warning is shown under another heading too:\n%s", got)
		}
		if od.word() != "failed" || !strings.HasPrefix(od.reason(), "the plan refuses mgmt-acl") {
			t.Errorf("refused device: %s %q", od.word(), od.reason())
		}
		canary := "sw-a,sw-e"
		if noCanary {
			canary = "none"
		}
		if line := "device config apply user=alice approved=4 shapes=" + h + "," + oe.Out.Shape + " canary=" + canary + " mode=scripted"; !hasAudit(r, "auth.notice", line) {
			t.Errorf("no audit line %q: %q", line, r.Argvs())
		}
	}
}

// 'shapes list' and 'seed' work from the store and the records alone: the
// listing says what is confirmed, seed asks once, files the shape as the
// person's word and refuses a device with nothing checked.
func TestShapesListAndSeed(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	run := func(stdin string, args ...string) string {
		return plain(sb.cfgRun(stdin, append([]string{"device", "config"}, args...), nil, "SUDO_USER=alice"))
	}
	if out := run("", "shapes"); sb.code != 0 || !strings.Contains(out, "None. A check or an apply") {
		t.Errorf("empty: %d %q", sb.code, out)
	}
	run("", "shapes", "seed", "sw-j", "-y")
	if sb.code != 1 || !strings.Contains(sb.err.String(), "has no check or apply on record that found a change") {
		t.Errorf("seed nothing: %d %q", sb.code, sb.err.String())
	}
	d := plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{
		{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events login"},
		{Section: "snmp", Op: plan.OpSet, Text: "set snmp location x"}}}
	hash, lines := plan.Shape(d)
	if err := devapply.OpenShapes(sb.path("var-lib", "device-apply")).Observe(hash, lines); err != nil {
		t.Fatal(err)
	}
	store := devconf.Store{Records: sb.path("var-lib", "devices-config.json"), Dir: sb.path("var-lib", "device-config")}
	recs := devconf.NewRecords()
	recs.Put("sw-j", devconf.Record{Vendor: "juniper", Address: "192.168.1.6",
		Applied: &devconf.Applied{Result: devconf.AppliedChecked, Shape: hash, Kind: devconf.AppliedKindCheck, At: time.Now(), By: "alice"}})
	if err := store.Save(recs); err != nil {
		t.Fatal(err)
	}
	out := run("", "shapes")
	if sb.code != 0 || !strings.Contains(out, hash) || !strings.Contains(out, " new ") {
		t.Errorf("list: %d %q", sb.code, out)
	}
	// declined: nothing is filed
	out = run("n\n", "shapes", "seed", "sw-j")
	if sb.code != 0 || !strings.Contains(out, "This is your word") || !strings.Contains(plain(sb.err.String()+out), "Nothing was changed") {
		t.Errorf("declined: %d %q %q", sb.code, out, sb.err.String())
	}
	if ok, _ := devapply.OpenShapes(sb.path("var-lib", "device-apply")).Confirmed(hash); ok {
		t.Error("a declined seed confirmed the shape")
	}
	run("y\n", "shapes", "seed", "sw-j")
	if sb.code != 0 {
		t.Fatalf("seed: %d %q", sb.code, sb.err.String())
	}
	m, _ := devapply.OpenShapes(sb.path("var-lib", "device-apply")).Load()
	if e := m[hash]; len(e.Confirmed) != 1 || !e.Confirmed[0].Seeded || e.Confirmed[0].Device != "sw-j" || e.Confirmed[0].By != "alice" {
		t.Errorf("entry %+v", e)
	}
	if !hasAudit(sb.runner, "auth.notice", "device config shapes seed user=alice device=sw-j shape="+hash) {
		t.Errorf("no audit line: %q", sb.runner.Argvs())
	}
	// again: already confirmed, nothing asked
	if out := run("", "shapes", "seed", "sw-j", "-y"); sb.code != 0 || !strings.Contains(out+sb.out.String(), "already") && !strings.Contains(plain(sb.err.String()), "confirmed on those devices already") {
		t.Errorf("again: %d %q %q", sb.code, out, sb.err.String())
	}
	if out := run("", "shapes", "list", "--show", hash[:5]); sb.code != 0 || !strings.Contains(out, "(seeded)") || !strings.Contains(out, "[aaa]") {
		t.Errorf("show: %d %q", sb.code, out)
	}
	run("", "shapes", "list", "--show", "zz")
	if sb.code != 1 {
		t.Errorf("show unknown: %d", sb.code)
	}
	// the store holds the lines with no value
	b, _ := os.ReadFile(sb.path("var-lib", "device-apply", "shapes.json"))
	if !strings.Contains(string(b), `set snmp location \u003cv\u003e`) {
		t.Errorf("the per-device value is not masked: %s", b)
	}
}

// reviewBox is the review of three checked devices, two of one shape and one
// of another, with stdin the lines typed (no terminal: the questions are not
// shown, the answers are read as typed).
type reviewBox struct {
	ctl    *applyCtl
	r      *fake.Runner
	out    *lockedBuf
	errb   *lockedBuf
	groups []*shapeGroup
	apply  []*applyOutcome
	devs   []*applyOutcome
}

func newReviewBox(t *testing.T, typed string, aa applyArgs) *reviewBox {
	t.Helper()
	sb := newSandbox(t, true)
	b := &reviewBox{r: &fake.Runner{}, out: &lockedBuf{}, errb: &lockedBuf{}}
	b.r.On([]string{"logger"}, execx.Result{})
	a := app.New(nil, paths.NewEnv(append(append([]string(nil), sb.env...), "SUDO_USER=alice")), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(typed), Stdout: b.out, Stderr: b.errb}, b.r)
	inv := &invocation{ctx: context.Background(), app: a, hooks: newTestHooks()}
	one := plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events login"}}}
	two := plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events change-log"}}}
	var entries []devreg.Entry
	byName := map[string]*applyOutcome{}
	for _, d := range []struct {
		name string
		d    plan.Delta
	}{{"sw-a", one}, {"sw-b", one}, {"sw-c", two}} {
		h, _ := plan.Shape(d.d)
		o := &applyOutcome{Name: d.name, Scope: "lab", Vendor: "juniper", Delta: d.d, HasDelta: true,
			Out: &devapply.Outcome{Exit: devapply.ExitChecked, Shape: h, Counts: devapply.Counts{Set: 1}}}
		entries = append(entries, devreg.Entry{Device: devreg.Device{Name: d.name}})
		byName[d.name] = o
		b.devs = append(b.devs, o)
	}
	if aa.max == 0 {
		aa.max = 10
	}
	b.ctl = &applyCtl{inv: inv, user: "alice", aa: aa, run: &applyRun{shapes: devapply.OpenShapes(t.TempDir()), minutes: 10}, rows: b.devs}
	b.groups = b.ctl.groupByShape(entries, byName)
	b.apply = b.ctl.selectApply(b.groups, byName)
	return b
}

// reviewed runs the review and, as run2 does, the approval line of the
// devices approved.
func (b *reviewBox) reviewed(asJSON bool) reviewResult {
	rv := b.ctl.review(b.groups, b.apply, asJSON)
	if len(rv.approved) > 0 && !rv.interrupted {
		b.ctl.audit(rv.approved)
	}
	return rv
}

// The review asks each device by its name, in the order of the apply: the
// name approves it, anything else (another case, Enter) declines it with no
// second try, the end of input declines it and every device after it. Each
// answer is a line of its own with mode=attended, the approval line names
// only the approved devices, and nothing typed reaches a line.
func TestApplyReviewAsksEachDeviceByName(t *testing.T) {
	for _, c := range []struct {
		name, typed    string
		approved       []string
		declined       map[string]string
		approval       string
		reviewQuestion int
	}{
		{"every name", "sw-a\nsw-b\nsw-c\n", []string{"sw-a", "sw-b", "sw-c"}, nil, "approved=3", 3},
		{"a wrong case and Enter", "sw-a\nSW-B\n\n", []string{"sw-a"},
			map[string]string{"sw-b": notApprovedWrong, "sw-c": notApprovedWrong}, "approved=1", 3},
		{"a count is no answer", "3\nsw-b\nsw-c\n", []string{"sw-b", "sw-c"},
			map[string]string{"sw-a": notApprovedWrong}, "approved=2", 3},
		{"the input ends", "sw-a\n", []string{"sw-a"},
			map[string]string{"sw-b": notApprovedEOF, "sw-c": notApprovedEOF}, "approved=1", 2},
		{"blanks around the name", "  sw-a \t\nsw-b\nsw-c\n", []string{"sw-a", "sw-b", "sw-c"}, nil, "approved=3", 3},
		{"a carriage return", "sw-a\r\nsw-b\nsw-c\n", []string{"sw-b", "sw-c"},
			map[string]string{"sw-a": notApprovedWrong}, "approved=2", 3},
		{"another device's name", "sw-b\nsw-b\nsw-c\n", []string{"sw-b", "sw-c"},
			map[string]string{"sw-a": notApprovedWrong}, "approved=2", 3},
		{"nothing typed", "", nil,
			map[string]string{"sw-a": notApprovedEOF, "sw-b": notApprovedEOF, "sw-c": notApprovedEOF}, "", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newReviewBox(t, c.typed, applyArgs{})
			rv := b.reviewed(false)
			var got []string
			for _, o := range rv.approved {
				got = append(got, o.Name)
			}
			if !slices.Equal(got, c.approved) || rv.declined != (len(c.declined) > 0) || rv.interrupted {
				t.Errorf("approved %v declined %v interrupted %v", got, rv.declined, rv.interrupted)
			}
			out := plain(b.out.String())
			for _, o := range b.devs {
				if why := c.declined[o.Name]; o.Skipped != why {
					t.Errorf("%s: skipped %q, want %q", o.Name, o.Skipped, why)
				} else if why != "" && !strings.Contains(out, "  "+o.Name+"  skipped: "+why+"\n") {
					t.Errorf("%s: no declined row in:\n%s", o.Name, out)
				}
			}
			// the device's line comes before its question, the devices in order
			if n := strings.Count(out, " (new), 1 set, 0 delete\n"); n != c.reviewQuestion {
				t.Errorf("%d device lines, want %d:\n%s", n, c.reviewQuestion, out)
			}
			if !strings.Contains(out, "Each device is applied only when its name is typed back.") ||
				strings.Index(out, "  sw-a  shape ") > strings.Index(out+"  sw-b  shape ", "  sw-b  shape ") {
				t.Errorf("the questions' text or order:\n%s", out)
			}
			lines := auditLines(b.r)
			for _, o := range b.devs {
				word := "approved"
				if c.declined[o.Name] != "" {
					word = "declined"
				}
				line := "device config apply review user=alice device=" + o.Name + " shape=" + o.Out.Shape + " answer=" + word + " mode=attended"
				if !hasAudit(b.r, "auth.notice", line) {
					t.Errorf("no line %q in %q", line, lines)
				}
			}
			approval := auditLine(b.r, "device config apply user=alice approved=")
			if c.approval == "" && approval != "" || c.approval != "" && (!strings.Contains(approval, c.approval+" ") || !strings.HasSuffix(approval, " mode=attended")) {
				t.Errorf("approval line %q, want %q", approval, c.approval)
			}
			for _, l := range lines {
				if strings.Contains(l, "SW-B") || strings.Contains(l, "answer=3") {
					t.Errorf("what was typed is in a line: %q", l)
				}
			}
		})
	}
}

// The approval line's canary is the first approved device of each shape: a
// declined first device does not make the next one skip the canary.
func TestApplyReviewCanaryIsTheFirstApproved(t *testing.T) {
	b := newReviewBox(t, "no\nsw-b\nsw-c\n", applyArgs{})
	rv := b.reviewed(false)
	if len(rv.approved) != 2 || rv.approved[0].Name != "sw-b" {
		t.Fatalf("approved %+v", rv.approved)
	}
	want := "device config apply user=alice approved=2 shapes=" + b.devs[1].Out.Shape + "," + b.devs[2].Out.Shape + " canary=sw-b,sw-c mode=attended"
	if !hasAudit(b.r, "auth.notice", want) {
		t.Errorf("no %q in %q", want, auditLines(b.r))
	}
}

// --max asks no question of a device beyond it; --json prints one review
// object per device asked (the review's text on standard error) with its
// mode.
func TestApplyReviewMaxAndJSON(t *testing.T) {
	b := newReviewBox(t, "sw-a\nnope\n", applyArgs{max: 2, pull: pullArgs{json: true}})
	if len(b.apply) != 2 || b.devs[2].Skipped == "" {
		t.Fatalf("--max 2 selected %d", len(b.apply))
	}
	rv := b.ctl.review(b.groups, b.apply, true)
	if len(rv.approved) != 1 || !rv.declined {
		t.Fatalf("%+v", rv)
	}
	var objs []applyJSON
	dec := json.NewDecoder(strings.NewReader(b.out.String()))
	for dec.More() {
		var j applyJSON
		if err := dec.Decode(&j); err != nil {
			t.Fatalf("%v in %s", err, b.out.String())
		}
		if j.Phase == "review" {
			objs = append(objs, j)
		}
	}
	if len(objs) != 2 || objs[0].Name != "sw-a" || objs[0].Status != "approved" || objs[0].Mode != "attended" ||
		objs[1].Name != "sw-b" || objs[1].Status != "declined" || objs[1].Reason != notApprovedWrong || objs[1].Shape == "" {
		t.Errorf("review objects %+v\n%s", objs, b.out.String())
	}
	if strings.Contains(b.out.String(), "nope") || !strings.Contains(b.errb.String(), "Shape ") {
		t.Errorf("stdout %s\nstderr %s", b.out.String(), b.errb.String())
	}
	if strings.Count(b.out.String(), `"name":"sw-c"`) != 1 || strings.Contains(b.out.String(), `"name":"sw-c","scope":"lab","vendor":"juniper","phase":"review"`) {
		t.Errorf("the device beyond --max was asked:\n%s", b.out.String())
	}
}

// --confirmed --yes asks nothing: every device is approved in the scripted
// form, each with its review line and object.
func TestApplyReviewScripted(t *testing.T) {
	b := newReviewBox(t, "", applyArgs{yes: true, confirmed: false, pull: pullArgs{json: true}})
	rv := b.reviewed(true)
	if len(rv.approved) != 3 || rv.declined {
		t.Fatalf("%+v", rv)
	}
	for _, o := range b.devs {
		if line := "device config apply review user=alice device=" + o.Name + " shape=" + o.Out.Shape + " answer=approved mode=scripted"; !hasAudit(b.r, "auth.notice", line) {
			t.Errorf("no %q in %q", line, auditLines(b.r))
		}
	}
	if l := auditLine(b.r, "device config apply user=alice approved=3 "); !strings.HasSuffix(l, " mode=scripted") {
		t.Errorf("approval %q", l)
	}
	if strings.Count(b.out.String(), `"phase":"review","status":"approved"`) != 3 || strings.Count(b.out.String(), `"mode":"scripted"`) != 3 ||
		strings.Contains(b.errb.String(), "Type the device name") {
		t.Errorf("stdout %s\nstderr %s", b.out.String(), b.errb.String())
	}
}

// A Ctrl-C while a question waits ends the review: nothing is approved, the
// devices not answered are skipped, no approval line is written.
func TestApplyReviewInterrupted(t *testing.T) {
	b := newReviewBox(t, "", applyArgs{})
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	inv := b.ctl.inv
	inv.app = app.New(nil, inv.app.Env, "/opt/x/dist/tacctl", 1000, app.Stdio{Stdin: pr, Stdout: b.out, Stderr: b.errb}, b.r)
	inv.ctx = ctx
	_, _ = pw.WriteString("sw-a\n")
	done := make(chan reviewResult, 1)
	go func() { done <- b.ctl.review(b.groups, b.apply, false) }()
	waitUntil(t, "the second question", func() bool { return strings.Contains(b.out.String(), "  sw-b  shape ") })
	cancel()
	var rv reviewResult
	select {
	case rv = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the review did not end at the Ctrl-C")
	}
	if !rv.interrupted || len(rv.approved) != 0 {
		t.Errorf("%+v", rv)
	}
	for _, o := range b.devs {
		if o.Skipped != notAppliedInterrupted {
			t.Errorf("%s: %q", o.Name, o.Skipped)
		}
	}
	if l := auditLine(b.r, "device config apply user=alice approved="); l != "" {
		t.Errorf("an approval line: %q", l)
	}
	// the answer given stays logged, and one line says nothing was applied
	if !hasAudit(b.r, "auth.notice", "device config apply review user=alice device=sw-a shape="+b.devs[0].Out.Shape+" answer=approved mode=attended") ||
		!hasAudit(b.r, "auth.notice", "device config apply review user=alice result=interrupted applied=0 mode=attended") ||
		auditLine(b.r, "device config apply review user=alice device=sw-b ") != "" {
		t.Errorf("lines %q", auditLines(b.r))
	}
}
