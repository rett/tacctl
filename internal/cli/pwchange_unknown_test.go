package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/tier"
)

// lockedBy is the three answers: held, not held, unknown. Unknown holds a
// caller who is no superuser and never one who is, by the answer's tier or,
// without one, by the system's groups.
func TestLockedByThreeStates(t *testing.T) {
	yes := console.Remote{PasswordChange: true, Known: true}
	unknown := console.Remote{PasswordChangeUnknown: true, Known: true}
	for _, c := range []struct {
		name   string
		pol    console.Remote
		groups []string
		want   string // "", "held" or "unknown"
	}{
		{"held", yes, nil, "held"},
		{"known not held", console.Remote{Known: true, Tier: tier.Operator}, nil, ""},
		{"an answer of an older release", console.Remote{Known: true}, []string{"tac-users", "tac-operator"}, ""},
		{"unknown, an operator", unknown, []string{"tac-users", "tac-operator"}, "unknown"},
		{"unknown, no groups", unknown, nil, "unknown"},
		{"unknown, a superuser by the system's groups", unknown, []string{"tac-users", "tac-superuser"}, ""},
		{"unknown, a superuser by the answer", console.Remote{PasswordChangeUnknown: true, Known: true, Tier: tier.Superuser}, nil, ""},
		{"unknown, a superuser by the gate", console.Remote{PasswordChangeUnknown: true, Known: true, Gate: tier.Superuser}, nil, ""},
		{"held, a superuser by the answer", console.Remote{PasswordChange: true, Known: true, Tier: tier.Superuser}, nil, ""},
		{"no answer, an operator", unreadPolicy(), []string{"tac-users", "tac-operator"}, "unknown"},
		{"no answer, a superuser", unreadPolicy(), []string{"tac-users", "tac-superuser"}, ""},
		{"no answer, the defaults of an unread policy are not unknown by themselves", console.DefaultRemote(), nil, ""},
	} {
		l := lockedBy(c.pol, c.groups)
		got := ""
		switch {
		case l == nil:
		case l.unknown:
			got = "unknown"
		default:
			got = "held"
		}
		if got != c.want || (l != nil && !l.locked()) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A console session whose policy line cannot be read, or says it could not
// tell, runs nothing for a caller who is no superuser (it fails closed), and
// everything as usual for a superuser (a read error never locks one out) and
// for an answer that names no such field (a release that flags nobody).
func TestConsoleWithoutAPolicyAnswerHoldsTheCaller(t *testing.T) {
	run := func(groups, policy string) (*harness, error) {
		h, run := consoleHarness(t, "", groups, policy, "-c", "user list")
		err := run()
		return h, err
	}
	ran := func(h *harness) bool {
		for _, l := range lines(h.runner) {
			if strings.HasSuffix(l, " user list") {
				return true
			}
		}
		return false
	}
	// sudo fails: no answer
	for _, c := range []struct {
		name, groups, policy string
		held                 bool
	}{
		{"no answer, operator", "carol tac-users tac-operator", "", true},
		{"no answer, no groups", "", "", true},
		{"no answer, superuser", "carol tac-users tac-superuser", "", false},
		{"unknown, operator", "carol tac-users tac-operator", strings.TrimSpace(consoleTestPolicy) + " password_change=unknown\n", true},
		{"unknown, a tier of none (the store is unreadable)", "carol tac-users tac-operator", "idle=30 tier=none password_change=unknown\n", true},
		{"unknown, superuser by the groups", "carol tac-users tac-superuser", "idle=30 tier=none password_change=unknown\n", false},
		{"unknown, superuser by the answer", "carol tac-users", "idle=30 tier=superuser password_change=unknown\n", false},
		{"an older release's answer", "carol tac-users tac-operator", consoleTestPolicy, false},
		{"known not held", "carol tac-users tac-operator", "idle=30 tier=operator password_change=no\n", false},
		{"held", "carol tac-users tac-operator", "idle=30 tier=operator password_change=yes\n", true},
	} {
		h, err := run(c.groups, c.policy)
		if c.held {
			var x *ExitError
			if !errors.As(err, &x) || x.Code != 1 || ran(h) {
				t.Errorf("%s: err %v, ran %t, want refused with status 1\n%s", c.name, err, ran(h), h.err.String())
			}
			notice := "nothing runs here until it is made but 'passwd'"
			if !strings.Contains(c.policy, "password_change=yes") {
				notice = "It could not be read whether a password change is required of your account"
			}
			if !strings.Contains(h.err.String(), notice) {
				t.Errorf("%s: stderr %q lacks %q", c.name, h.err.String(), notice)
			}
		} else if err != nil || !ran(h) {
			t.Errorf("%s: err %v, ran %t, want the line to run\n%s", c.name, err, ran(h), h.err.String())
		}
	}
}

// With the store unreadable the tier gate gives every managed caller the tier
// none and refuses the policy line, so the console sees no answer: the
// operator is held, the superuser (known by the system's groups) is not.
func TestPolicyLineWithAnUnreadableStoreIsNoAnswer(t *testing.T) {
	sb := pwSandbox(t)
	sb.write("state/store.yaml", "this: is: not a store\n", 0o600)
	sb.cfgRun("", []string{"_console-policy"}, idAs("bob", "tac-users tac-operator"), "SUDO_USER=bob", "SUDO_UID=1003")
	if sb.code == 0 || sb.out.Len() != 0 {
		t.Errorf("an operator's policy line with an unreadable store: exit %d %q", sb.code, sb.out.String())
	}
	sb.cfgRun("", []string{"_console-policy"}, idAs("alice", "tac-users tac-superuser"), "SUDO_USER=alice", "SUDO_UID=1001")
	if sb.code == 0 {
		t.Errorf("a superuser's policy line with an unreadable store: exit %d", sb.code)
	}
}

// The command line's gate, for a caller the tier gate lets through while the
// model cannot be read: held unless a superuser, with the audit line naming
// the state; the words that run while a change is required still run.
func TestPasswordChangeGateWithAnUnreadableModel(t *testing.T) {
	gate := func(callerTier tier.Tier, args ...string) (*harness, *invocation, error) {
		h := newHarness(t, args, "SUDO_USER=bob")
		inv := &invocation{ctx: context.Background(), app: h.app, hooks: newTestHooks(), callerTier: callerTier,
			loaded: true, mErr: errors.New("store.yaml: cannot be read")}
		return h, inv, inv.passwordChangeGate()
	}
	for _, args := range [][]string{{"user", "list"}, {"status"}, {"device", "list"}} {
		h, _, err := gate(tier.Operator, args...)
		if err == nil || !strings.Contains(h.err.String(), "The store cannot be read, so it cannot be told whether a password change is required of 'bob'") {
			t.Errorf("%v: err %v stderr %q", args, err, h.err.String())
		}
		words := args[0]
		if len(args) > 1 {
			words += ` ` + args[1]
		}
		line := `password-change DENY user=bob tier=operator cmd="` + words + `" state=unknown`
		if args[0] == "status" {
			line = `password-change DENY user=bob tier=operator cmd=status state=unknown`
		}
		if !hasAudit(h.runner, "auth.warning", line) {
			t.Errorf("%v: no %q in %q", args, line, auditLines(h.runner))
		}
	}
	for _, args := range [][]string{{"passwd"}, {"version"}, {"help"}, {"_console-policy"}} {
		if _, _, err := gate(tier.Operator, args...); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	// a superuser is never held by a read error, and neither is root or an
	// unrestricted caller
	if _, _, err := gate(tier.Superuser, "user", "list"); err != nil {
		t.Errorf("superuser: %v", err)
	}
	if _, _, err := gate(tier.Unrestricted, "user", "list"); err != nil {
		t.Errorf("unrestricted: %v", err)
	}
	// a readable model is the two-state gate it was
	h := newHarness(t, []string{"user", "list"}, "SUDO_USER=bob")
	inv := &invocation{ctx: context.Background(), app: h.app, hooks: newTestHooks(), callerTier: tier.Operator, loaded: true, m: nil, mErr: nil}
	if err := inv.passwordChangeGate(); err == nil || !strings.Contains(h.err.String(), "cannot be told") {
		t.Errorf("a nil model without an error is unknown too: %v %q", err, h.err.String())
	}
}
