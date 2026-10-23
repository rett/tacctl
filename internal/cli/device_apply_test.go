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
		if !ctl.review(groups, apply, false) {
			t.Fatal("not approved")
		}
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
		if line := "device config apply user=alice approved=4 shapes=" + h + "," + oe.Out.Shape + " canary=" + canary; !hasAudit(r, "auth.notice", line) {
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
