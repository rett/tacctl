package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// The rollback to 0.2.8 (D143 of docs/plans/0.2.9-rollout-plan.md) on the
// sandbox of rollback_test.go, which holds a state of 0.2.9: the two
// device.apply keys, this release's drop-ins, records of a pull and the
// apply state directory.

// rb028Records has an applied record, a record with the fields of a --login
// pull and a plain one.
const rb028Records = `{"version": 1, "devices": {
 "sw1": {"address": "10.99.0.1", "vendor": "cisco", "hostname": "sw1.example.net", "login": "local:admin", "user_pulled": true,
         "applied": {"at": "2026-10-13T10:00:00Z", "by": "alice", "result": "applied", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "shape": "0123abcd"}},
 "sw2": {"address": "10.99.0.2", "vendor": "juniper",
         "applied": {"at": "2026-10-13T11:00:00Z", "by": "alice", "result": "rolled-back", "id": "tacctl-20261013T110000Z-cd34", "kind": "apply", "reason": "verification failed"}},
 "sw3": {"address": "10.99.0.3", "vendor": "cisco"}
}}
`

func newRB028Sandbox(t *testing.T) *rbSandbox {
	t.Helper()
	s := newRBSandbox(t)
	s.write(s.p.ConfigRecords, rb028Records, 0o600)
	s.write(filepath.Join(s.p.ApplyDir, "shapes.json"), "{}\n", 0o600)
	s.write(filepath.Join(s.p.ApplyDir, "locks", "sw1.lock"), "", 0o600)
	s.in.Target = RollbackTarget028
	return s
}

func plan028(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget028
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The dry run lists every step and warning, and the plan writes nothing.
func TestPlanRollback028ListsEveryStep(t *testing.T) {
	s := newRB028Sandbox(t)
	before := s.snapshotOf()
	p := plan028(t, s)
	if p.Target != RollbackTarget028 {
		t.Errorf("target %q", p.Target)
	}
	if !reflect.DeepEqual(p.Keys(), []string{"device.apply.confirm_timeout", "device.apply.pause"}) {
		t.Errorf("keys %q", p.Keys())
	}
	st := stepText(p)
	for _, want := range []string{
		s.p.Overrides + ": remove the keys 0.2.8 does not know",
		"remove device.apply.confirm_timeout", "remove device.apply.pause",
		"put back the sudoers drop-ins 0.2.8 writes",
		"rewrite " + s.p.TierSudoersFile, "rewrite " + s.p.SudoersFile + " (the drop-in of group ops: 0.2.8's text",
		"leave what 0.2.9 wrote in " + s.p.VarLib,
		"leaves " + s.p.ConfigRecords + " (3 records",
		"2 records have an 'applied' part", "1 record has the 'login', 'user_pulled' or 'hostname' fields",
		"0.2.8 ignores the fields it does not know",
		"leaves " + s.p.ApplyDir + " (the state of 'device config apply': shapes.json; 1 device lock in locks/)",
		"leave every other file untouched",
	} {
		if !strings.Contains(st, want) {
			t.Errorf("steps lack %q:\n%s", want, st)
		}
	}
	// Nothing 0.2.3-specific: no console.yaml or devices.yaml conversion.
	for _, not := range []string{"console.yaml: write it the way", "remove the snmp map", "0.2.3"} {
		if strings.Contains(st, not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	if !p.Pending() || !p.PendingFiles() || !p.NeedsYes() || len(p.todoSudoers()) != 2 {
		t.Errorf("pending %v files %v yes %v sudoers %d", p.Pending(), p.PendingFiles(), p.NeedsYes(), len(p.todoSudoers()))
	}
	w := warnText(p)
	if !strings.Contains(w, "Settings 0.2.8 cannot use are dropped") || !strings.Contains(w, "device.apply.confirm_timeout=15, device.apply.pause=30") {
		t.Errorf("warnings:\n%s", w)
	}
	if n := strings.Join(p.Notes, "\n"); !strings.Contains(n, "restore it with 0.2.9") {
		t.Errorf("notes:\n%s", n)
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("planning wrote a file")
	}
	// --hosts is accepted and says there is nothing to do.
	s.in.WithHosts = true
	if st := stepText(plan028(t, s)); !strings.Contains(st, "the enrolled Linux hosts (--hosts)") || !strings.Contains(st, "no host is synced") {
		t.Errorf("--hosts:\n%s", st)
	}
}

// --apply removes the two keys and rewrites the drop-ins; every other file
// is byte-identical, and a second plan has nothing to do.
func TestApplyRollback028WritesKeysAndSudoers(t *testing.T) {
	s := newRB028Sandbox(t)
	before := s.snapshotOf()
	p := plan028(t, s)
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 3 || len(p.NotWritten()) != 0 {
		t.Errorf("done %q not written %q", done, p.NotWritten())
	}
	after := s.snapshotOf()
	if after[s.p.TierSudoersFile] != tier.Sudoers028() || after[s.p.SudoersFile] != tier.GroupSudoers028("ops") {
		t.Errorf("the drop-ins are not 0.2.8's text:\n%s\n%s", after[s.p.TierSudoersFile], after[s.p.SudoersFile])
	}
	for _, v := range []string{"device config apply *", "device onboard *", "device collect *"} {
		if strings.Contains(after[s.p.TierSudoersFile]+after[s.p.SudoersFile], v) {
			t.Errorf("the 0.2.8 text has %q", v)
		}
	}
	s.reload()
	if got := s.c.RollbackKeys028(); len(got) != 0 {
		t.Errorf("keys left: %q", got)
	}
	// 0.2.9's other keys are 0.2.8's too and stay.
	ov := after[s.p.Overrides]
	for _, kept := range []string{"max_concurrency: 16", "transport: ssh", "timeout: 120", "engineer_sudo:", "snmp_scope:"} {
		if !strings.Contains(ov, kept) {
			t.Errorf("tacctl.yaml lost %q:\n%s", kept, ov)
		}
	}
	// Nothing else changed: records, the apply state, console.yaml,
	// devices.yaml, store.yaml, credentials.
	for path, was := range before {
		if path == s.p.Overrides || path == s.p.TierSudoersFile || path == s.p.SudoersFile {
			continue
		}
		if after[path] != was {
			t.Errorf("%s changed", path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("%s appeared", path)
		}
	}
	// A second run finds nothing to convert.
	s.reload()
	p2 := plan028(t, s)
	if p2.Pending() || p2.NeedsYes() || len(p2.Notes) != 0 {
		t.Errorf("second plan: pending %v warnings %q", p2.Pending(), warnText(p2))
	}
	if st := stepText(p2); strings.Count(st, "is already the text 0.2.8 writes") != 2 || !strings.Contains(st, "nothing to remove (device.apply.confirm_timeout") {
		t.Errorf("second plan:\n%s", st)
	}
	if done, err := ApplyRollback(p2); err != nil || len(done) != 0 || !reflect.DeepEqual(after, s.snapshotOf()) {
		t.Errorf("second apply: %q %v", done, err)
	}
}

// An edited drop-in is left, with the step line; 0.2.3's and 0.2.8's own
// texts are not rewritten.
func TestRollback028LeavesEditedDropIns(t *testing.T) {
	s := newRB028Sandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers()+"# local addition\n", 0o640)
	s.write(s.p.SudoersFile, tier.GroupSudoers("ops")+"%ops ALL=(ALL) NOPASSWD: /usr/bin/id\n", 0o640)
	before := s.snapshotOf()
	p := plan028(t, s)
	if st := stepText(p); strings.Count(st, "it is not the text this release writes (edited, or another release's)") != 2 {
		t.Errorf("steps:\n%s", st)
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	after := s.snapshotOf()
	if after[s.p.TierSudoersFile] != before[s.p.TierSudoersFile] || after[s.p.SudoersFile] != before[s.p.SudoersFile] || len(s.ins) != 0 {
		t.Errorf("an edited drop-in was rewritten: %q", s.ins)
	}
	// The keys are still removed.
	if len(s.reloadKeys028()) != 0 {
		t.Error("the keys were not removed")
	}

	// A text of an earlier release is left too (0.2.8's own upgrade
	// rewrites it).
	s = newRB028Sandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers027(), 0o640)
	s.write(s.p.SudoersFile, tier.GroupSudoers027("ops"), 0o640)
	p = plan028(t, s)
	if len(p.todoSudoers()) != 0 {
		t.Errorf("an earlier text is rewritten:\n%s", stepText(p))
	}

	// The drop-ins of 0.2.8 itself: done, nothing installed.
	s = newRB028Sandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers028(), 0o640)
	s.write(s.p.SudoersFile, tier.GroupSudoers028("ops"), 0o640)
	p = plan028(t, s)
	if len(p.todoSudoers()) != 0 || strings.Count(stepText(p), "is already the text 0.2.8 writes") != 2 {
		t.Errorf("0.2.8's own text:\n%s", stepText(p))
	}

	// An installer that fails: reported, the keys still go.
	s = newRB028Sandbox(t)
	s.in.InstallSudoers = func(body, dst string) error { return errors.New("visudo validation failed") }
	p = plan028(t, s)
	done, err := ApplyRollback(p)
	if err != nil || len(done) != 1 || len(p.NotWritten()) != 2 || !strings.Contains(p.NotWritten()[0], "visudo validation failed") {
		t.Errorf("done %q not written %q %v", done, p.NotWritten(), err)
	}
}

func (s *rbSandbox) reloadKeys028() []string {
	s.reload()
	return s.c.RollbackKeys028()
}

// A record that says a confirmed commit is pending (or unknown) refuses the
// rollback, to 0.2.8 and to 0.2.3, in the dry run and --apply alike; the
// refusal names the device, the time and what settles it, and nothing is
// changed. A settled record does not.
func TestRollbackRefusesWhileAnApplyIsPending(t *testing.T) {
	for _, target := range []string{RollbackTarget028, RollbackTarget} {
		for _, result := range []string{"pending", "unknown"} {
			s := newRB028Sandbox(t)
			s.in.Target = target
			s.write(s.p.ConfigRecords, `{"version": 1, "devices": {
 "sw1": {"address": "10.99.0.1", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "`+result+`", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply"}},
 "sw2": {"address": "10.99.0.2", "vendor": "juniper", "applied": {"result": "applied"}}}}
`, 0o600)
			before := s.snapshotOf()
			_, err := PlanRollback(s.in)
			var ref *RollbackRefusal
			if !errors.As(err, &ref) {
				t.Fatalf("%s %s: %v", target, result, err)
			}
			text := strings.Join(ref.Lines, "\n")
			for _, want := range []string{"not settled on 1 device", "sw1: " + result, "tacctl-20261013T100000Z-ab12", "by alice",
				"tacctl device config apply sw1 --check", "tacctl device config forget sw1", "Nothing was changed."} {
				if !strings.Contains(text, want) {
					t.Errorf("%s %s: refusal lacks %q:\n%s", target, result, want, text)
				}
			}
			if strings.Contains(text, "sw2") {
				t.Errorf("a settled record is named:\n%s", text)
			}
			if result == "pending" && !strings.Contains(text, "until 2026-10-13") {
				t.Errorf("the pending window's end is not named:\n%s", text)
			}
			if !reflect.DeepEqual(before, s.snapshotOf()) {
				t.Error("a refusal wrote a file")
			}
		}
	}
	// A device with no record, or only settled ones: no refusal.
	s := newRB028Sandbox(t)
	if _, err := PlanRollback(s.in); err != nil {
		t.Errorf("settled records: %v", err)
	}
	// A records file that cannot be read cannot rule a window out.
	s.write(s.p.ConfigRecords, "{not json", 0o600)
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "a pending apply cannot be ruled out") {
		t.Errorf("unreadable records: %v", err)
	}
}

// 0.2.3 still works from this release, with the apply state listed.
func TestRollback023StillWorksFrom029(t *testing.T) {
	s := newRB028Sandbox(t)
	s.in.Target = RollbackTarget
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Target != RollbackTarget {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, want := range []string{"remove device.apply.confirm_timeout", "remove device.apply.pause", "leaves " + s.p.ApplyDir} {
		if !strings.Contains(st, want) {
			t.Errorf("steps lack %q:\n%s", want, st)
		}
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	if got := s.snapshotOf(); got[s.p.TierSudoersFile] != tier.Sudoers023() || got[s.p.SudoersFile] != tier.GroupSudoers023("ops") {
		t.Error("the drop-ins are not 0.2.3's text")
	}
	if p := old023Problems(t, s); len(p) != 0 {
		t.Errorf("a 0.2.3 reader refuses the converted state: %q", p)
	}
}

// Where the 0.2.8 tag is in the repository, the per-tier drop-in the
// rollback writes is the tag's golden file, byte for byte.
func TestRollback028WritesTheTagsDropIn(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.8 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.8^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.8 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.8:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.8 tag's golden file: %v %s", err, res.Stderr)
	}
	golden := res.Stdout
	s := newRB028Sandbox(t)
	p := plan028(t, s)
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.p.TierSudoersFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(golden) {
		t.Errorf("the per-tier drop-in after the rollback is not the 0.2.8 tag's golden file")
	}
}
