package lifecycle

import (
	"strings"
	"testing"
)

// The limits of the stored reports (0.2.26, reports.max_size and
// reports.max_count in tacctl.yaml) are keys every older release refuses, so
// every target but 0.2.26 itself removes them, the ones that read every other
// key included, and no target keeps another key with them.

// targetsBefore0226 are all the targets: every one is older than 0.2.26.
var targetsBefore0226 = append([]string{RollbackTarget0224, RollbackTarget0223}, allRollbackTargets...)

// reportKeysState is the sandbox with both limits set.
func reportKeysState(t *testing.T) *rbSandbox {
	t.Helper()
	s := newRBSandbox(t)
	s.oldSyntaxKey()
	s.write(s.p.Overrides, rbConf+"reports:\n  max_size: 20971520\n  max_count: 0\n", 0o640)
	s.reload()
	return s
}

func TestPlanRollbackEveryTargetRemovesTheReportLimits(t *testing.T) {
	for _, target := range targetsBefore0226 {
		t.Run(target, func(t *testing.T) {
			s := reportKeysState(t)
			s.in.Target = target
			before := s.snapshotOf()
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			keys := strings.Join(p.Keys(), " ")
			for _, k := range []string{"reports.max_size", "reports.max_count"} {
				if !strings.Contains(keys, k) {
					t.Errorf("keys %q lack %s", keys, k)
				}
			}
			st := stepText(p)
			for _, want := range []string{"remove reports.max_size\n", "remove reports.max_count\n"} {
				if !strings.Contains(st, want) {
					t.Errorf("steps lack %q:\n%s", want, st)
				}
			}
			// the targets with a plan of their own for the keys (0.2.16, 0.2.9
			// and 0.2.3) say it in their generic words
			switch target {
			case RollbackTarget0216, RollbackTarget029, RollbackTarget:
			default:
				if want := "the limits of the stored reports are 0.2.26's"; !strings.Contains(st, want) {
					t.Errorf("steps lack %q:\n%s", want, st)
				}
			}
			if !p.PendingFiles() || !p.Pending() {
				t.Error("the plan has nothing to do")
			}
			if w := warnText(p); strings.Contains(w, "reports") {
				t.Errorf("a warning names the limits (a setting of the file needs no --yes):\n%s", w)
			}
			if after := s.snapshotOf(); !equalFiles(before, after) {
				t.Error("the plan wrote a file")
			}
			if _, err := ApplyRollback(p); err != nil {
				t.Fatal(err)
			}
			if got := string(mustRead(t, s.p.Overrides)); strings.Contains(got, "reports") || strings.Contains(got, "max_size") {
				t.Errorf("tacctl.yaml keeps the limits:\n%s", got)
			}
			s.reload()
			s.in.Target = target
			p2, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if k := strings.Join(p2.Keys(), " "); strings.Contains(k, "reports") {
				t.Errorf("the second plan still removes %q", k)
			}
		})
	}
}

// Without the keys no target has a key to remove for them.
func TestPlanRollbackWithoutReportLimitsRemovesNoReportKey(t *testing.T) {
	for _, target := range targetsBefore0226 {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if strings.Contains(strings.Join(p.Keys(), " "), "reports") || strings.Contains(stepText(p), "remove reports") {
			t.Errorf("%s: the plan names the limits:\n%s", target, stepText(p))
		}
	}
}
