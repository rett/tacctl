package cli

// WP10.8a C-missing (4): what the shell lists comes from the sudo answer
// as the root side prints it, not from a view set by hand.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// viewFromAnswer is an invocation whose view was learned from answer, the
// line 'sudo -n tacctl _console-policy' prints.
func viewFromAnswer(t *testing.T, answer string) *invocation {
	t.Helper()
	inv, _, runner := shellTestInv(t)
	runner.OnFunc([]string{"sudo", "-n", testExe, "_console-policy"}, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte(answer)}, nil
	})
	inv.setView(shellRun{exe: testExe, mode: shellCommandMode}, true)
	return inv
}

// 'tier=engineer gate=operator' is an engineer the gate holds at the
// operator tier (an unreadable tacctl.yaml): Tab, a typed space and '?' list
// the operator's verbs. 'tier=none' (a disabled account) lists no verb.
func TestListsFollowTheParsedSudoAnswer(t *testing.T) {
	// The gate's tier, not the account's.
	inv := viewFromAnswer(t, "shell=console idle=30 tier=engineer gate=operator list_max=40\n")
	root := newRoot(inv)
	complete, fixed := inv.shellCompleter(root), inv.shellCompleterFixed(root)
	// Tab and '?' (the same candidates): the operator's device verbs, not the engineer's.
	got := words(complete([]string{"device"}, ""))
	if !slices.Contains(got, "check") || slices.Contains(got, "add") || slices.Contains(got, "import") {
		t.Errorf("Tab after 'device' for tier=engineer gate=operator: %q", got)
	}
	if top := words(complete(nil, "")); slices.Contains(top, "host") || slices.Contains(top, "store") || !slices.Contains(top, "log") {
		t.Errorf("Tab at the top for tier=engineer gate=operator: %q", top)
	}
	// A typed space completes only what the gate's tier may run.
	space := func(w []string, partial string) []string {
		var out []string
		for _, c := range fixed(w, partial) {
			if c.Fixed && !c.NoSpace && strings.HasPrefix(c.Word, partial) {
				out = append(out, c.Word)
			}
		}
		return out
	}
	if got := space([]string{"device"}, "ad"); got != nil {
		t.Errorf("space after 'device ad' for the gate's operator: %q", got)
	}
	if got := space([]string{"device"}, "che"); !slices.Equal(got, []string{"check"}) {
		t.Errorf("space after 'device che': %q", got)
	}
	// '?' after a verb typed by hand names the tier it needs.
	explain, _ := inv.shellExplain(root)([]string{"device", "add"})
	if !strings.Contains(explain, "Needs the engineer tier.") {
		t.Errorf("? after 'device add' for the gate's operator:\n%s", explain)
	}

	// The engineer itself (no gate field) lists the engineer's verbs.
	inv = viewFromAnswer(t, "shell=console idle=30 tier=engineer list_max=40\n")
	root = newRoot(inv)
	if got := words(inv.shellCompleter(root)([]string{"device"}, "")); !slices.Contains(got, "add") || !slices.Contains(got, "import") {
		t.Errorf("Tab after 'device' for an engineer: %q", got)
	}

	// tier=none: no verb on any path, only the shell's own words remain.
	inv = viewFromAnswer(t, "shell=system idle=30 tier=none list_max=40\n")
	root = newRoot(inv)
	complete, fixed = inv.shellCompleter(root), inv.shellCompleterFixed(root)
	if got := words(complete(nil, "")); len(got) != 0 {
		t.Errorf("Tab at the top for tier=none: %q", got)
	}
	if got := words(complete([]string{"user"}, "")); len(got) != 0 {
		t.Errorf("Tab after 'user' for tier=none: %q", got)
	}
	if got := space(nil, "us"); got != nil {
		t.Errorf("space after 'us' for tier=none: %q", got)
	}
	_ = fixed
	explain, _ = inv.shellExplain(root)([]string{"user", "list"})
	if strings.Contains(explain, "Next:") && !strings.Contains(explain, "Needs") {
		t.Errorf("? after 'user list' for tier=none offers a way in:\n%s", explain)
	}
}
