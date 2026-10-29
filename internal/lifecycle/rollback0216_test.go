package lifecycle

import (
	"reflect"
	"strings"
	"testing"
)

// The rollback to 0.2.16 (docs/plans/0.2.17-plan.md D257) on the sandbox of
// rollback_test.go: a 0.2.17 state is the 0.2.16 one with audit.strict.

func newRB0216Sandbox(t *testing.T, strict string) *rbSandbox {
	t.Helper()
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"audit:\n  strict: "+strict+"\n", 0o640)
	s.reload()
	s.in.Target = RollbackTarget0216
	return s
}

func plan0216(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0216
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The dry run lists the removal of audit.strict and leaves everything else;
// a true value needs --yes, a false one does not; the plan writes nothing.
func TestPlanRollback0216ListsTheKey(t *testing.T) {
	s := newRB0216Sandbox(t, "true")
	before := s.snapshotOf()
	p := plan0216(t, s)
	if p.Target != RollbackTarget0216 {
		t.Errorf("target %q", p.Target)
	}
	if got := p.Keys(); !reflect.DeepEqual(got, []string{"audit.strict"}) {
		t.Errorf("keys %q", got)
	}
	st := stepText(p)
	for _, w := range []string{
		s.p.Overrides + ": remove the keys 0.2.16 does not know", "remove audit.strict",
		"0.2.16's schema refuses it", "leave every other file untouched",
	} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"console.yaml: write it the way", "remove the snmp map", "0.2.3", "0.2.9"} {
		if strings.Contains(st, not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	if !p.Pending() || !p.PendingFiles() || !p.NeedsYes() || len(p.todoSudoers()) != 0 {
		t.Errorf("pending %v files %v yes %v sudoers %d", p.Pending(), p.PendingFiles(), p.NeedsYes(), len(p.todoSudoers()))
	}
	if w := warnText(p); !strings.Contains(w, "audit.strict is set and is dropped") || !strings.Contains(w, "0.2.16 has no such setting") {
		t.Errorf("warnings:\n%s", w)
	}
	if n := strings.Join(p.Notes, "\n"); !strings.Contains(n, "restore it with 0.2.18") {
		t.Errorf("notes:\n%s", n)
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("planning wrote a file")
	}
	s.in.WithHosts = true
	if st := stepText(plan0216(t, s)); !strings.Contains(st, "the enrolled Linux hosts (--hosts)") || !strings.Contains(st, "no host is synced") {
		t.Errorf("--hosts:\n%s", st)
	}

	f := newRB0216Sandbox(t, "false")
	pf := plan0216(t, f)
	if !pf.PendingFiles() || pf.NeedsYes() || len(pf.Warnings) != 0 {
		t.Errorf("false: files %v yes %v warnings %q", pf.PendingFiles(), pf.NeedsYes(), warnText(pf))
	}
}

// A state without the key has nothing to do.
func TestPlanRollback0216NothingToRemove(t *testing.T) {
	s := newRBSandbox(t)
	s.oldSyntaxKey()
	s.in.Target = RollbackTarget0216
	p := plan0216(t, s)
	if p.PendingFiles() || p.NeedsYes() || len(p.Keys()) != 0 {
		t.Errorf("files %v yes %v keys %q", p.PendingFiles(), p.NeedsYes(), p.Keys())
	}
	if st := stepText(p); !strings.Contains(st, "nothing to remove (audit.strict is not set and no emergency lockdown is recorded)") {
		t.Errorf("steps:\n%s", st)
	}
}

// --apply removes the key, the mapping it leaves empty and nothing else;
// a second plan has nothing to do.
func TestApplyRollback0216RemovesTheKey(t *testing.T) {
	s := newRB0216Sandbox(t, "true")
	before := s.snapshotOf()
	p := plan0216(t, s)
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 2 || !strings.Contains(done[0], "removed 1 key") || !strings.Contains(done[1], "wrote the configuration syntax of 1 device under config_syntax") || len(s.ins) != 0 {
		t.Errorf("done %q installed %q", done, s.ins)
	}
	after := s.snapshotOf()
	// devices.yaml: the syntax setting under config_syntax; its devices
	// read as they were.
	if dv := after[s.p.DevicesFile]; strings.Contains(dv, "ios_syntax") || !strings.Contains(dv, "    config_syntax: modern") {
		t.Errorf("devices.yaml:\n%s", dv)
	}
	for path, was := range before {
		if path == s.p.Overrides || path == s.p.DevicesFile {
			continue
		}
		if after[path] != was {
			t.Errorf("%s changed", path)
		}
	}
	ov := after[s.p.Overrides]
	if strings.Contains(ov, "audit") || strings.Contains(ov, "strict") {
		t.Errorf("tacctl.yaml still has the key:\n%s", ov)
	}
	for _, kept := range []string{"max_concurrency: 16", "pause: 30", "engineer_sudo:", "snmp_scope:", "cost: "} {
		if !strings.Contains(ov, kept) {
			t.Errorf("tacctl.yaml lost %q:\n%s", kept, ov)
		}
	}
	s.reload()
	if got := s.c.RollbackKeys0216(); len(got) != 0 {
		t.Errorf("keys left: %q", got)
	}
	if again := plan0216(t, s); again.PendingFiles() {
		t.Error("a second plan still has work")
	}
}

// The rollbacks to 0.2.9 and 0.2.3 drop the key too, say so when it was set,
// and do not describe it as another release's setting.
func TestOlderTargetsDropAuditStrict(t *testing.T) {
	for _, target := range []string{RollbackTarget029, RollbackTarget} {
		s := newRB0216Sandbox(t, "true")
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(filterAudit(p.Keys()), []string{"audit.strict"}) {
			t.Errorf("%s keys %q", target, p.Keys())
		}
		if w := warnText(p); !strings.Contains(w, "audit.strict is set and is dropped") || !strings.Contains(w, target+" has no such setting") {
			t.Errorf("%s warnings:\n%s", target, w)
		}
		if st := stepText(p); strings.Contains(st, "audit.strict  (no release") {
			t.Errorf("%s describes audit.strict as unknown to every release:\n%s", target, st)
		}
		if target == RollbackTarget029 && strings.Contains(warnText(p), "NETCONF") {
			t.Errorf("0.2.9 files audit.strict under the NETCONF setting:\n%s", warnText(p))
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatal(err)
		}
		s.reload()
		if got := filterAudit(s.c.RollbackKeys029()); len(got) != 0 {
			t.Errorf("%s: audit keys left: %q", target, got)
		}
	}
}

func filterAudit(keys []string) []string {
	var out []string
	for _, k := range keys {
		if strings.HasPrefix(k, "audit.") {
			out = append(out, k)
		}
	}
	return out
}

// CheckRollbackVersion takes 0.2.16 with or without a "v", and 0.2.10 to
// 0.2.15 and 0.2.22 (this release) are still not targets.
func TestCheckRollbackVersion0216(t *testing.T) {
	for _, ok := range []string{"0.2.16", "v0.2.16"} {
		if v, err := CheckRollbackVersion(ok); err != nil || v != "0.2.16" {
			t.Errorf("%s: %q %v", ok, v, err)
		}
	}
	for _, bad := range []string{"0.2.15", "0.2.10", "0.2.22", "0.2.160", "0.2.170"} {
		if _, err := CheckRollbackVersion(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}
