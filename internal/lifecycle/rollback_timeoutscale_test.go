package lifecycle

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
)

// The timing scale of 0.2.22 is a setting every older release lacks, in
// tacctl.yaml (the default of the whole server and a scope's) and in
// devices.yaml (a device's own). Every target removes all three, and says so.

var allRollbackTargets = []string{RollbackTarget0222, RollbackTarget0221, RollbackTarget0220, RollbackTarget0219, RollbackTarget0218, RollbackTarget0217,
	RollbackTarget0216, RollbackTarget029, RollbackTarget}

// targetsBefore0222 are the targets that lack the timing scale: all but 0.2.22,
// which has it.
var targetsBefore0222 = allRollbackTargets[1:]

// scaleState lays out a state with a scale at all three levels on top of the
// sandbox.
func scaleState(t *testing.T) *rbSandbox {
	t.Helper()
	s := newRBSandbox(t)
	s.write(s.p.Overrides, strings.Replace(rbConf, "    pause: 30\n", "    pause: 30\n  timeout_scale: 4\n", 1)+"timeout_scale_scope:\n  lab: 2\n", 0o640)
	devices := strings.Replace(rbDevices, "    vendor: cisco\n", "    vendor: cisco\n    timeout_scale: 3\n", 1)
	devices = strings.Replace(devices, "  lab-rtr2: {address: 192.0.2.7, vendor: juniper}", "  lab-rtr2: {address: 192.0.2.7, vendor: juniper, timeout_scale: 10}", 1)
	s.write(s.p.DevicesFile, devices, 0o600)
	s.reload()
	return s
}

func TestPlanRollbackEveryTargetRemovesTheTimeoutScale(t *testing.T) {
	for _, target := range targetsBefore0222 {
		t.Run(target, func(t *testing.T) {
			s := scaleState(t)
			s.in.Target = target
			before := s.snapshotOf()
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			keys := strings.Join(p.Keys(), " ")
			for _, k := range []string{"device.timeout_scale", "timeout_scale_scope.lab"} {
				if !strings.Contains(keys, k) {
					t.Errorf("keys %q lack %s", keys, k)
				}
			}
			st := stepText(p)
			for _, want := range []string{s.p.DevicesFile + ": remove the timeout scale of the devices",
				"remove the timeout_scale key of core-sw1 (3)", "remove the timeout_scale key of lab-rtr2 (10)",
				"unknown key 'timeout_scale'", "remove device.timeout_scale", "remove timeout_scale_scope.lab"} {
				if !strings.Contains(st, want) {
					t.Errorf("steps lack %q:\n%s", want, st)
				}
			}
			if !p.PendingFiles() || !p.Pending() {
				t.Error("the plan has nothing to do")
			}
			if notes := strings.Join(p.Notes, "\n"); !strings.Contains(notes, "The timing scale") || !strings.Contains(notes, "fixed timings again") {
				t.Errorf("notes:\n%s", notes)
			}
			// a note, never a warning: nothing here needs --yes
			if w := warnText(p); strings.Contains(w, "timing scale") || strings.Contains(w, "timeout_scale") {
				t.Errorf("a warning names the scale:\n%s", w)
			}
			if after := s.snapshotOf(); !equalFiles(before, after) {
				t.Error("the plan wrote a file")
			}
			if _, err := ApplyRollback(p); err != nil {
				t.Fatal(err)
			}
			if got := string(mustRead(t, s.p.DevicesFile)); strings.Contains(got, "timeout_scale") {
				t.Errorf("devices.yaml keeps the key:\n%s", got)
			}
			if got := string(mustRead(t, s.p.Overrides)); strings.Contains(got, "timeout_scale") {
				t.Errorf("tacctl.yaml keeps a key:\n%s", got)
			}
			f, err := devreg.Load(s.p.DevicesFile)
			if err != nil {
				t.Fatalf("devices.yaml does not load: %v", err)
			}
			if d := f.Find("core-sw1"); d == nil || d.Address != "10.99.0.1" || d.TimeoutScale != 0 {
				t.Errorf("core-sw1 after: %+v", d)
			}
			// the plan after the apply has nothing of the scale left
			s.reload()
			s.in.Target = target
			p2, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if st := stepText(p2); strings.Contains(st, "timeout scale of the devices") || strings.Contains(strings.Join(p2.Notes, "\n"), "timing scale") {
				t.Errorf("the second plan still has it:\n%s", st)
			}
		})
	}
}

// 0.2.22 has the timing scale: its target leaves it, in tacctl.yaml and in
// devices.yaml, and says nothing of it.
func TestPlanRollback0222KeepsTheTimeoutScale(t *testing.T) {
	s := scaleState(t)
	s.as0222()
	s.in.Target = RollbackTarget0222
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Keys()) != 0 || p.PendingFiles() || p.Pending() {
		t.Errorf("keys %q pending %v", p.Keys(), p.Pending())
	}
	if st := stepText(p) + strings.Join(p.Notes, "\n"); strings.Contains(st, "timeout scale of the devices") || strings.Contains(st, "timing scale") || strings.Contains(st, "remove device.") || strings.Contains(st, "remove timeout_scale") {
		t.Errorf("the plan removes something:\n%s", st)
	}
	before := s.snapshotOf()
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 0 || !equalFiles(before, s.snapshotOf()) {
		t.Errorf("the apply did something: %q", done)
	}
}

// A state that never had a scale gets no step, no note and no key: the plan
// of every target is as it was.
func TestPlanRollbackWithoutATimeoutScaleSaysNothingOfIt(t *testing.T) {
	for _, target := range allRollbackTargets {
		s := newRBSandbox(t)
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if st := stepText(p) + strings.Join(p.Notes, "\n"); strings.Contains(st, "timeout scale of the devices") || strings.Contains(st, "timing scale") || strings.Contains(st, "timeout_scale") {
			t.Errorf("%s: the plan names the scale:\n%s", target, st)
		}
	}
}

// Only the scale of a device goes: its other keys and the other devices are
// written as they were.
func TestApplyRollbackTimeoutScaleKeepsTheRest(t *testing.T) {
	s := scaleState(t)
	s.in.Target = RollbackTarget0221
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(done, "\n"), "removed the timeout scale of 2 devices") {
		t.Errorf("done: %q", done)
	}
	got := string(mustRead(t, s.p.DevicesFile))
	for _, want := range []string{"ios_syntax: modern", "location: Rack 4, DC1", "clients: [10.1.0.0/16, 10.2.0.0/16]", "oob-con1:"} {
		if !strings.Contains(got, want) {
			t.Errorf("devices.yaml lost %q:\n%s", want, got)
		}
	}
	if o := string(mustRead(t, s.p.Overrides)); !strings.Contains(o, "confirm_timeout: 15") || !strings.Contains(o, "bcrypt:") {
		t.Errorf("tacctl.yaml lost a key:\n%s", o)
	}
	// the families are the ones the tables list
	if !conf.Added0222Key("device.timeout_scale") {
		t.Error("conf.Added0222 does not list the scale")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func equalFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
