package lifecycle

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// The rollback to 0.2.29, the release before this one, on the sandbox of
// rollback_test.go: this release changed no stored file 0.2.29 reads strictly
// (it checks the name of a new user more strictly), so the plan converts
// nothing, whatever 0.2.28 and 0.2.29 added to the state (the console's file
// transfer settings included).

func plan0229(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0229
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The plan leaves every file, asks for no --yes, takes no snapshot and keeps
// what 0.2.29 has and the older targets drop: the console's file transfer
// settings, the limits of the stored reports, the users' email addresses, a
// pool of SNMPv3 users, a staging entry marked covered, the break-glass
// firewall and the per-tier drop-in, which 0.2.29 and this release write
// alike. It writes nothing.
func TestPlanRollback0229ConvertsNothing(t *testing.T) {
	s := poolState(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	ft := "  file_transfer:\n    tiers: [operator, superuser]\n    users: {bob: 'enable:readonly', carol: disable}\n    quota: {operator: 1G}\n"
	s.write(s.p.ConsoleFile, strings.Replace(rbConsole, "  space_completion: false\n", "  space_completion: false\n"+ft, 1), 0o600)
	rbStoreLimits(t, s, true)
	s.write(s.p.StateDir+"/staging", stagingKept+stagingCovered, 0o600)
	s.write(s.p.Overrides, "breakglass:\n  firewall: drop\nreports:\n  max_size: 20971520\n  max_count: 0\n", 0o600)
	s.in.Conf.Reload()
	s.write(s.p.FirewallRules, "table inet tacctl\n", 0o600)
	s.write(s.p.FirewallUnit, "[Unit]\n", 0o644)
	if !strings.Contains(string(mustRead(t, s.p.ConsoleFile)), "file_transfer") {
		t.Fatal("the fixture lacks the file transfer settings")
	}
	calls := 0
	s.in.RemoveFirewall = func() ([]string, error) { calls++; return []string{"the nftables table inet tacctl"}, nil }
	before := s.snapshotOf()
	p := plan0229(t, s)
	if p.Target != RollbackTarget0229 {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, w := range []string{s.p.Overrides + ": remove the keys 0.2.29 does not know", "nothing to remove (every key of tacctl.yaml is one 0.2.29 knows)",
		"leave every other file untouched", "are in formats 0.2.29 reads", "the pull records, the reports in the users' homes"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"remove device.", "remove server.", "remove breakglass", "remove reports", "remove settings", "file_transfer", "file transfer", "firewall: remove", "email", "v3 user", "staging", "add scope", "0.2.3", "0.2.9", "report limits", "sudoers drop-in 0.2", "take out the settings"} {
		if strings.Contains(strings.ToLower(st), not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	for _, step := range p.Steps {
		if step.Todo {
			t.Errorf("step %q does something", step.Title)
		}
	}
	if len(p.Keys()) != 0 || p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Notes) != 0 || len(p.Warnings) != 0 || p.FirewallTodo() || p.FileTransferRemoved() ||
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
	if !strings.Contains(string(mustRead(t, s.p.ConsoleFile)), "file_transfer") {
		t.Error("console.yaml lost the file transfer settings")
	}
	if got := string(mustRead(t, s.p.TierSudoersFile)); got != tier.Sudoers() {
		t.Error("the per-tier drop-in was rewritten")
	}
	// the 0.2.27 target, on the same state, does convert (it is told apart):
	// it takes the file transfer settings out
	s.in.Target = RollbackTarget0227
	q, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if !q.FileTransferRemoved() || !q.PendingFiles() || q.NeedsYes() {
		t.Errorf("the 0.2.27 target: file transfer removed %v files %v yes %v", q.FileTransferRemoved(), q.PendingFiles(), q.NeedsYes())
	}
}

// With nothing set, nothing is different: the plan converts nothing and
// asks for nothing, and the second plan after the apply is the first.
func TestPlanRollback0229ConvertsNothingOnAPlainState(t *testing.T) {
	s := newRBSandbox(t)
	before := s.snapshotOf()
	p := plan0229(t, s)
	if len(p.Keys()) != 0 || p.PendingFiles() || p.NeedsYes() || len(p.Warnings) != 0 || len(p.ReportLimitUsers()) != 0 {
		t.Errorf("keys %q files %v yes %v warnings %d", p.Keys(), p.PendingFiles(), p.NeedsYes(), len(p.Warnings))
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 {
		t.Errorf("apply: %q %v", done, err)
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the apply wrote a file")
	}
	p = plan0229(t, s)
	if len(p.Keys()) != 0 || p.PendingFiles() {
		t.Error("the second plan has something to do")
	}
}

// --hosts is accepted and says nothing is done.
func TestPlanRollback0229WithHosts(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	p := plan0229(t, s)
	if st := stepText(p); !strings.Contains(st, "nothing to do for 0.2.29: this release changed nothing on the enrolled hosts") {
		t.Errorf("steps:\n%s", st)
	}
}

// A device whose apply is not settled refuses the target, as it does every
// other (the dry run too).
func TestPlanRollback0229RefusesAnUnsettledApply(t *testing.T) {
	s := newRBSandbox(t)
	s.in.Target = RollbackTarget0229
	s.write(s.p.ConfigRecords, `{"version": 1, "devices": {
 "sw1": {"address": "192.0.2.11", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "pending", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "via": "netconf"}}}}
`, 0o600)
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "sw1") {
		t.Errorf("an unsettled apply was not refused: %v", err)
	}
}

// What the plan promises of the 0.2.29 reader holds in its source: the
// console.yaml reader knows settings.file_transfer (so nothing is removed).
// Skipped where git or the tag is absent (CI must fetch tags).
func TestRollback0229ReaderKnowsTheFileTransferSettings(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.29 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.29^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.29 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.29:internal/console/config.go"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.29 tag's console config: %v %s", err, res.Stderr)
	}
	if !strings.Contains(string(res.Stdout), `case "file_transfer":`) {
		t.Error("0.2.29's console.yaml reader does not know file_transfer: the target would have to remove it")
	}
}
