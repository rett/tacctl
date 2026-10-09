package tier

import (
	"context"
	"strings"
	"testing"
)

// WP10.2h, S2: the members of a group whose tier setting was lost are held at
// the operator tier; everyone else, the built-in superuser group's members
// included, keeps the tier the group gives.
func TestGateAmbiguousGroup(t *testing.T) {
	ctx := context.Background()
	lv := map[string]string{"ro": "1", "op": "7", "su": "15", "dave": "15"}
	ambiguous := func(user string) string {
		if user == "dave" {
			return "neteng"
		}
		return ""
	}
	for _, c := range []struct {
		user, groups string
		want         Tier
	}{
		{"dave", "tac-users", Operator}, {"su", "tac-users", Superuser}, {"op", "tac-users", Operator},
		{"ro", "tac-users", Readonly}, {"dave", "sudo", Unrestricted}, {"root", "", Unrestricted},
	} {
		g := newGate(c.user, c.groups, lv)
		g.gate.AmbiguousGroup = ambiguous
		if got := g.gate.Caller(ctx); got != c.want {
			t.Errorf("%s: %s, want %s", c.user, got, c.want)
		}
	}
	g := newGate("dave", "tac-users", lv)
	g.gate.AmbiguousGroup = ambiguous
	g.gate.ConfPath = "/etc/tacctl/tacctl.yaml"
	if err := g.gate.Enforce(ctx, "config", "validate"); err != nil {
		t.Errorf("config validate: %v %q", err, g.err.String())
	}
	if err := g.gate.Enforce(ctx, "group", "edit"); err != ErrDenied {
		t.Fatalf("group edit: %v", err)
	}
	for _, want := range []string{"'tacctl group edit' is not permitted: your group 'neteng'", "has no tier setting in /etc/tacctl/tacctl.yaml (it was lost)",
		"A superuser who is not a member sets it: tacctl group edit neteng tier <tier>."} {
		if !strings.Contains(g.err.String(), want) {
			t.Errorf("denial lacks %q: %q", want, g.err.String())
		}
	}
	if !g.run.Called("logger", "-t", "tacctl", "-p", "auth.warning", "tier DENY user=dave tier=operator reason=group-ambiguous cmd=group edit") {
		t.Errorf("not logged %q", g.run.Argvs())
	}
	// A global conf problem wins: its message and reason.
	g = newGate("dave", "tac-users", lv)
	g.gate.AmbiguousGroup = ambiguous
	g.gate.ConfProblem = func() string { return "oops" }
	g.gate.ConfPath = "/etc/tacctl/tacctl.yaml"
	if err := g.gate.Enforce(ctx, "group", "edit"); err != ErrDenied || !strings.Contains(g.err.String(), "cannot be read (oops)") {
		t.Errorf("conf problem first: %v %q", err, g.err.String())
	}
	// A superuser outside the group is never asked for more than the tier.
	g = newGate("su", "tac-users", lv)
	g.gate.AmbiguousGroup = ambiguous
	if err := g.gate.Enforce(ctx, "group", "edit"); err != nil {
		t.Errorf("su: %v %q", err, g.err.String())
	}
}
