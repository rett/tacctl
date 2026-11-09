package lifecycle

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// The rollback to 0.2.27 on the sandbox of rollback_test.go: this release
// changed no stored file 0.2.27 reads strictly, so the plan converts nothing,
// whatever 0.2.27 itself added to the state (the limits of the stored reports
// and the break-glass firewall included).

func plan0227(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0227
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The plan leaves every file, asks for no --yes, takes no snapshot and keeps
// what 0.2.27 has and the older targets drop: the limits of the stored reports
// (the two settings and the users' own), the users' email addresses, a pool of
// SNMPv3 users, a staging entry marked covered, the break-glass firewall (its
// setting, its rules file and its boot unit) and the per-tier drop-in, which
// 0.2.27 and this release write alike. It writes nothing.
func TestPlanRollback0227ConvertsNothing(t *testing.T) {
	s := poolState(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	rbStoreLimits(t, s, true)
	s.write(s.p.StateDir+"/staging", stagingKept+stagingCovered, 0o600)
	s.write(s.p.Overrides, "breakglass:\n  firewall: drop\nreports:\n  max_size: 20971520\n  max_count: 0\n", 0o600)
	s.in.Conf.Reload()
	s.write(s.p.FirewallRules, "table inet tacctl\n", 0o600)
	s.write(s.p.FirewallUnit, "[Unit]\n", 0o644)
	calls := 0
	s.in.RemoveFirewall = func() ([]string, error) { calls++; return []string{"the nftables table inet tacctl"}, nil }
	before := s.snapshotOf()
	p := plan0227(t, s)
	if p.Target != RollbackTarget0227 {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, w := range []string{s.p.Overrides + ": remove the keys 0.2.27 does not know", "nothing to remove (every key of tacctl.yaml is one 0.2.27 knows)",
		"leave every other file untouched", "are in formats 0.2.27 reads", "the pull records, the reports in the users' homes"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"remove device.", "remove server.", "remove breakglass", "remove reports", "firewall: remove", "email", "v3 user", "staging", "add scope", "0.2.3", "0.2.9", "report limits", "sudoers drop-in 0.2"} {
		if strings.Contains(strings.ToLower(st), not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	for _, step := range p.Steps {
		if step.Todo {
			t.Errorf("step %q does something", step.Title)
		}
	}
	if len(p.Keys()) != 0 || p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Notes) != 0 || len(p.Warnings) != 0 || p.FirewallTodo() ||
		len(p.todoSudoers()) != 0 || len(p.managedUsers) != 0 || len(p.EmailUsers()) != 0 || p.SNMPPoolDropped().Any() || len(p.ReportLimitUsers()) != 0 {
		t.Errorf("keys %q pending %v yes %v notes %q warnings %d sudoers %d managed %d email %q", p.Keys(), p.Pending(), p.NeedsYes(), p.Notes, len(p.Warnings), len(p.todoSudoers()), len(p.managedUsers), p.EmailUsers())
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the plan wrote a file")
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 || calls != 0 {
		t.Errorf("apply: %q %v (firewall removed %d times)", done, err, calls)
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the apply wrote a file")
	}
	if got := string(mustRead(t, s.p.TierSudoersFile)); got != tier.Sudoers() {
		t.Error("the per-tier drop-in was rewritten")
	}
	// the 0.2.26 target converts nothing either, and the 0.2.25 target, on the
	// same state, does convert (it is told apart)
	s.in.Target = RollbackTarget0226
	if r, err := PlanRollback(s.in); err != nil || len(r.Keys()) != 0 || r.PendingFiles() || r.NeedsYes() {
		t.Errorf("the 0.2.26 target converts something here: %v", err)
	}
	s.in.Target = RollbackTarget0225
	q, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Keys()) == 0 || !q.PendingFiles() || !q.NeedsYes() {
		t.Errorf("the 0.2.25 target converts nothing here: keys %q files %v yes %v", q.Keys(), q.PendingFiles(), q.NeedsYes())
	}
}

// With no limit set, nothing is different: the plan converts nothing and
// asks for nothing, and the second plan after the apply is the first.
func TestPlanRollback0227ConvertsNothingWithoutLimits(t *testing.T) {
	s := newRBSandbox(t)
	before := s.snapshotOf()
	p := plan0227(t, s)
	if len(p.Keys()) != 0 || p.PendingFiles() || p.NeedsYes() || len(p.Warnings) != 0 || len(p.ReportLimitUsers()) != 0 {
		t.Errorf("keys %q files %v yes %v warnings %d", p.Keys(), p.PendingFiles(), p.NeedsYes(), len(p.Warnings))
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 {
		t.Errorf("apply: %q %v", done, err)
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the apply wrote a file")
	}
	p = plan0227(t, s)
	if len(p.Keys()) != 0 || p.PendingFiles() {
		t.Error("the second plan has something to do")
	}
}

// The pull records' members, the reports in the homes (a PDF one included),
// the marker of the offer of the PDF tools and the limits of the stored reports
// are left alone, bytes and all: the plan and the apply write none of them.
func TestPlanRollback0227LeavesTheRecordsTheReportsAndTheLimits(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.ConfigRecords, `{"version": 1, "devices": {"sw1": {"address": "192.0.2.11", "vendor": "juniper", "serial": "SN000001",
 "members": [{"id": "0", "role": "master", "model": "EX4300-48T", "serial": "SN000001", "release": "21.4R3", "status": "present", "priority": 255, "components": []}]}}}
`, 0o600)
	report := filepath.Join(s.w, "home", "alice", "reports", "devices", "inventory-20261106.txt")
	s.write(report, "sw1  EX4300-48T  SN000001\n", 0o600)
	s.write(report+".meta", "{}\n", 0o600)
	pdf := filepath.Join(s.w, "home", "alice", "reports", "devices", "inventory-20261107.pdf")
	s.write(pdf, "%PDF-1.7\n", 0o600)
	s.write(pdf+".meta", "{\"format\": \"pdf\"}\n", 0o600)
	s.write(s.p.PDFOfferMarker, "tacctl 0.2.27 offered\n", 0o644)
	s.write(s.p.Overrides, rbConf+"reports:\n  max_count: 5\n", 0o640)
	s.reload()
	rbStoreLimits(t, s, false)
	was := s.snapshotOf()
	p := plan0227(t, s)
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(was, s.snapshotOf()) {
		t.Error("the rollback changed a pull record, a report, the PDF marker, tacctl.yaml or the store")
	}
	if got := string(mustRead(t, s.p.PDFOfferMarker)); got != "tacctl 0.2.27 offered\n" {
		t.Errorf("the PDF marker: %q", got)
	}
	if got := string(mustRead(t, s.p.StoreFile)); !strings.Contains(got, "reports_max_size") || !strings.Contains(got, "reports_max_count") {
		t.Errorf("the store lost a limit:\n%s", got)
	}
	if got := string(mustRead(t, s.p.Overrides)); !strings.Contains(got, "max_count: 5") {
		t.Errorf("tacctl.yaml lost the setting:\n%s", got)
	}
}

// --hosts is accepted and says nothing is done.
func TestPlanRollback0227WithHosts(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	p := plan0227(t, s)
	if st := stepText(p); !strings.Contains(st, "nothing to do for 0.2.27: this release changed nothing on the enrolled hosts") {
		t.Errorf("steps:\n%s", st)
	}
}

// A device whose apply is not settled refuses the target, as it does every
// other (the dry run too).
func TestPlanRollback0227RefusesAnUnsettledApply(t *testing.T) {
	s := newRBSandbox(t)
	s.in.Target = RollbackTarget0227
	s.write(s.p.ConfigRecords, `{"version": 1, "devices": {
 "sw1": {"address": "192.0.2.11", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "pending", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "via": "netconf"}}}}
`, 0o600)
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "sw1") {
		t.Errorf("an unsettled apply was not refused: %v", err)
	}
}

// What the plan promises of the 0.2.27 reader holds in its source: the
// tacctl.yaml schema and the user record validator know the limits of the
// stored reports (so nothing is removed), and the pull record decoder skips
// what it does not know. Skipped where git or the tag is absent (CI must fetch
// tags).
func TestRollback0227ReaderKnowsTheLimits(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.27 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.27^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.27 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	show := func(file string) string {
		res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.27:" + file}})
		if err != nil || res.Code != 0 {
			t.Fatalf("cannot read %s of the 0.2.27 tag: %v %s", file, err, res.Stderr)
		}
		return string(res.Stdout)
	}
	if !strings.Contains(show("internal/store/validate.go"), "name: ReportsMaxSizeKey") || !strings.Contains(show("internal/conf/schema.go"), "ReportsMaxSizeKey:") {
		t.Error("0.2.27 does not know the limits of the stored reports: the target would have to remove them")
	}
	if !strings.Contains(show("internal/devconf/store.go"), "json.Unmarshal(data, r)") {
		t.Error("the 0.2.27 record decoder is not a plain json.Unmarshal")
	}
}
