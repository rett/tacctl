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

// The rollback to 0.2.25 on the sandbox of rollback_test.go: this release's
// changes that 0.2.25 cannot read are the limits of the stored reports (two
// keys of tacctl.yaml and two fields of the user record); everything else it
// writes, the pull records' members and the reports in the homes included,
// 0.2.25 reads or never opens.

func plan0225(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0225
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// With no limit set the plan leaves every file, asks for no --yes, takes no
// snapshot and keeps what 0.2.25 has and the older targets drop: the users'
// email addresses, a pool of SNMPv3 users, a staging entry marked covered, the
// break-glass firewall (its setting, its rules file and its boot unit) and the
// per-tier drop-in. It writes nothing.
func TestPlanRollback0225ConvertsNothingWithoutLimits(t *testing.T) {
	s := poolState(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	rbStoreEmail(t, s)
	s.write(s.p.StateDir+"/staging", stagingKept+stagingCovered, 0o600)
	s.write(s.p.Overrides, "breakglass:\n  firewall: drop\n", 0o600)
	s.in.Conf.Reload()
	s.write(s.p.FirewallRules, "table inet tacctl\n", 0o600)
	s.write(s.p.FirewallUnit, "[Unit]\n", 0o644)
	calls := 0
	s.in.RemoveFirewall = func() ([]string, error) { calls++; return []string{"the nftables table inet tacctl"}, nil }
	before := s.snapshotOf()
	p := plan0225(t, s)
	if p.Target != RollbackTarget0225 {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, w := range []string{s.p.Overrides + ": remove the keys 0.2.25 does not know", "nothing to remove (every key of tacctl.yaml is one 0.2.25 knows)",
		"leave every other file untouched", "are in formats 0.2.25 reads", "the pull records, the reports in the users' homes"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"remove device.", "remove server.", "remove breakglass", "firewall: remove", "email", "v3 user", "staging", "add scope", "0.2.3", "0.2.9", "report limits"} {
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
		t.Errorf("keys %q pending %v yes %v notes %q warnings %d", p.Keys(), p.Pending(), p.NeedsYes(), p.Notes, len(p.Warnings))
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
}

// Both global settings and the users' own limits go: the plan lists the keys
// and the users with their values, converts two files (tacctl.yaml and the
// store), warns (--apply needs --yes) only for the users' data, and the apply
// removes them and nothing else, whatever else the files hold.
func TestPlanRollback0225RemovesTheReportLimits(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"reports:\n  max_size: 20971520\n  max_count: 0\nbreakglass:\n  firewall: drop\n", 0o640)
	s.reload()
	rbStoreLimits(t, s, true)
	before := s.snapshotOf()
	p := plan0225(t, s)
	if k := strings.Join(p.Keys(), " "); !strings.Contains(k, "reports.max_size") || !strings.Contains(k, "reports.max_count") || strings.Contains(k, "breakglass") || strings.Contains(k, "device.") {
		t.Errorf("keys %q", k)
	}
	st := stepText(p)
	for _, want := range []string{s.p.Overrides + ": remove the keys 0.2.25 does not know", "remove reports.max_size\n", "remove reports.max_count\n",
		"the limits of the stored reports are 0.2.26's", s.p.StoreFile + ": remove the limits of the stored reports 0.2.25 does not know",
		"remove the report limits of alice (max-size 20 MiB, max-count 50 reports)", "remove the report limits of carol (max-count no cap)"} {
		if !strings.Contains(st, want) {
			t.Errorf("steps lack %q:\n%s", want, st)
		}
	}
	if strings.Contains(st, "email") {
		t.Errorf("0.2.25 has the email address; the plan names it:\n%s", st)
	}
	if !p.PendingFiles() || !p.Pending() || !p.NeedsYes() {
		t.Errorf("files %v pending %v yes %v", p.PendingFiles(), p.Pending(), p.NeedsYes())
	}
	if w := warnText(p); !strings.Contains(w, limitsWarningTitle) || strings.Contains(w, "reports.max") {
		t.Errorf("warnings (only the users' data warns, not the settings):\n%s", w)
	}
	if after := s.snapshotOf(); !equalFiles(before, after) {
		t.Error("the plan wrote a file")
	}
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(done, "\n"); !strings.Contains(all, s.p.Overrides+": removed 2 keys") || !strings.Contains(all, s.p.StoreFile+": removed the report limits of 2 users") {
		t.Errorf("done:\n%s", all)
	}
	if got := string(mustRead(t, s.p.Overrides)); strings.Contains(got, "reports") || !strings.Contains(got, "firewall: drop") {
		t.Errorf("tacctl.yaml after:\n%s", got)
	}
	after := string(mustRead(t, s.p.StoreFile))
	if strings.Contains(after, "reports_max") || !strings.Contains(after, "email: bob@example.net") {
		t.Errorf("store after (the address stays, the limits go):\n%s", after)
	}
	// the second plan has nothing to do
	s.reload()
	p = plan0225(t, s)
	if p.PendingFiles() || p.NeedsYes() || len(p.Keys()) != 0 {
		t.Errorf("second plan: files %v yes %v keys %q", p.PendingFiles(), p.NeedsYes(), p.Keys())
	}
}

// The settings alone (no user has a limit) need no --yes, and convert only
// tacctl.yaml.
func TestPlanRollback0225TheSettingsAloneNeedNoYes(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"reports:\n  max_size: 1024\n", 0o640)
	s.reload()
	p := plan0225(t, s)
	if !p.PendingFiles() || p.NeedsYes() || len(p.Warnings) != 0 || strings.Join(p.Keys(), " ") == "" {
		t.Errorf("files %v yes %v warnings %d keys %q", p.PendingFiles(), p.NeedsYes(), len(p.Warnings), p.Keys())
	}
	if len(p.ReportLimitUsers()) != 0 {
		t.Error("a user has a limit")
	}
}

// The pull records' members and the report files are left alone, bytes and
// all: the plan and the apply write neither.
func TestPlanRollback0225LeavesTheRecordsAndTheReports(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.ConfigRecords, `{"version": 1, "devices": {"sw1": {"address": "192.0.2.11", "vendor": "juniper", "serial": "SN000001",
 "members": [{"id": "0", "role": "master", "model": "EX4300-48T", "serial": "SN000001", "release": "21.4R3", "status": "present", "priority": 255, "components": []}]}}}
`, 0o600)
	report := filepath.Join(s.w, "home", "alice", "reports", "devices", "inventory-20261106.txt")
	s.write(report, "sw1  EX4300-48T  SN000001\n", 0o600)
	s.write(report+".meta", "{}\n", 0o600)
	s.write(s.p.Overrides, rbConf+"reports:\n  max_count: 5\n", 0o640)
	s.reload()
	rbStoreLimits(t, s, false)
	files := func() map[string]string {
		all := s.snapshotOf()
		keep := map[string]string{}
		for path, text := range all {
			if path == s.p.ConfigRecords || strings.HasPrefix(path, filepath.Join(s.w, "home")) {
				keep[path] = text
			}
		}
		return keep
	}
	was := files()
	if len(was) != 3 {
		t.Fatalf("the fixture: %d files", len(was))
	}
	p := plan0225(t, s)
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(was, files()) {
		t.Error("the rollback changed a pull record or a report")
	}
	for _, step := range p.Steps {
		if strings.Contains(step.Title, s.p.ConfigRecords) && step.Todo {
			t.Errorf("a step converts the records: %q", step.Title)
		}
	}
}

// --hosts is accepted and says nothing is done.
func TestPlanRollback0225WithHosts(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	p := plan0225(t, s)
	if st := stepText(p); !strings.Contains(st, "nothing to do for 0.2.25: this release changed nothing on the enrolled hosts") {
		t.Errorf("steps:\n%s", st)
	}
}

// A device whose apply is not settled refuses the target, as it does every
// other (the dry run too).
func TestPlanRollback0225RefusesAnUnsettledApply(t *testing.T) {
	s := newRBSandbox(t)
	s.in.Target = RollbackTarget0225
	s.write(s.p.ConfigRecords, `{"version": 1, "devices": {
 "sw1": {"address": "192.0.2.11", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "pending", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "via": "netconf"}}}}
`, 0o600)
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "sw1") {
		t.Errorf("an unsettled apply was not refused: %v", err)
	}
}

// A store that cannot be read refuses the target: a limit that cannot be seen
// must not be hidden (rollback_reportlimits_test.go has it for every target).
func TestPlanRollback0225RefusesAnUnreadableStore(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.StoreFile, "version: 1\nusers: [\n", 0o600)
	s.in.Target = RollbackTarget0225
	if _, err := PlanRollback(s.in); err == nil {
		t.Error("planned")
	}
}

// What the plan promises of the 0.2.25 reader holds in its source: the pull
// record decoder ignores a key it does not know (a plain json.Unmarshal into
// the record, never DisallowUnknownFields), so the target leaves the records'
// 'members' alone, and the user record validator and the tacctl.yaml schema
// refuse a key they do not know, so the limits are removed. Skipped where
// git or the tag is absent (CI must fetch tags).
func TestRollback0225ReaderStrictnessIsAsThePlanSays(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.25 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.25^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.25 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	show := func(file string) string {
		res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.25:" + file}})
		if err != nil || res.Code != 0 {
			t.Fatalf("cannot read %s of the 0.2.25 tag: %v %s", file, err, res.Stderr)
		}
		return string(res.Stdout)
	}
	records := show("internal/devconf/store.go")
	if !strings.Contains(records, "json.Unmarshal(data, r)") || strings.Contains(records, "DisallowUnknownFields") {
		t.Error("the 0.2.25 record decoder is not a plain json.Unmarshal: the target may have to remove 'members'")
	}
	if v := show("internal/store/validate.go"); !strings.Contains(v, "unknown field '%s'") {
		t.Error("the 0.2.25 store validator no longer refuses an unknown user field: the limits need no removal")
	}
	if strings.Contains(show("internal/store/validate.go"), "reports_max") || strings.Contains(show("internal/conf/schema.go"), "reports.max") {
		t.Error("0.2.25 already knows the limits of the stored reports")
	}
}
