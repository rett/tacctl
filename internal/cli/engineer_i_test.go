package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/tier"
)

// WP10.2i: the fixes to the review of WP10.2h (docs/plans/0.2.3-plan.md
// §3a): B1 a built-in group other than superuser at priv-lvl 15 can be
// ambiguous, S1 the tier migration runs once, S2 a sync is never refused for
// an ambiguous group, S3/S4 a restricted caller's ssh, and the nits.

// B1, the reproduction of the review: the built-in operator group is given
// the engineer tier and priv-lvl 15, then tacctl.yaml is lost (or restored
// without its tier section). Its members must not be superusers: the gate
// holds them at the operator tier, a sync makes them operators, and a red
// line names the repair.
func TestBuiltinOperatorAt15WithALostTierIsAmbiguous(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	for _, a := range [][]string{{"group", "edit", "operator", "tier", "engineer"}, {"group", "edit", "operator", "priv-lvl", "15"}} {
		if sb.cfgRun("", a, nil); sb.code != 0 {
			t.Fatalf("%v: %d %q", a, sb.code, sb.stderr())
		}
	}
	if !strings.Contains(sb.read("state/tacctl.yaml"), "operator: engineer") {
		t.Fatalf("tacctl.yaml:\n%s", sb.read("state/tacctl.yaml"))
	}
	// Set: bob (operator) is an engineer, not a superuser.
	if got := sb.asUser("bob", "tac-superuser", "_console-policy"); !strings.Contains(got, " tier=engineer ") {
		t.Fatalf("bob with the setting: %q", got)
	}
	for _, c := range []struct {
		name string
		yaml *string
	}{{"removed", nil}, {"restored without tier", strPtr("backends:\n  enabled: [tacacs]\n")}} {
		t.Run(c.name, func(t *testing.T) {
			if c.yaml == nil {
				if err := os.Remove(sb.path("state", "tacctl.yaml")); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			} else {
				sb.write("state/tacctl.yaml", *c.yaml, 0o600)
			}
			if got := sb.asUser("bob", "tac-superuser", "_console-policy"); !strings.Contains(got, " tier=operator ") {
				t.Errorf("bob after the loss: %q", got)
			}
			sb.asUser("bob", "tac-superuser", "host", "sync", "authsrv")
			if sb.code != 1 || !strings.Contains(sb.stderr(), "your group 'operator' is at priv-lvl 15 or more and has no tier setting") {
				t.Errorf("host sync as bob: %d %q", sb.code, sb.stderr())
			}
			// The built-in superuser group is never ambiguous.
			if got := sb.asUser("alice", "tac-superuser", "_console-policy"); !strings.Contains(got, " tier=superuser ") {
				t.Errorf("alice: %q", got)
			}
			// A sync (root's) makes bob an operator and says why.
			sb.cfgRun("", []string{"config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "-o", sb.path("s.sh")}, nil)
			data := sb.read("s.sh")
			if sb.code != 0 || !strings.Contains(data, "bob:operator:") || strings.Contains(data, "bob:superuser") || !strings.Contains(data, "alice:superuser:") {
				t.Errorf("script users: %d\n%s", sb.code, head(data))
			}
			if !strings.Contains(sb.stderr(), "Group 'operator' (priv-lvl 15) has no tier setting in "+sb.path("state", "tacctl.yaml")+
				", so its members are synced as operators (no tac-superuser, no tac-engineer) until: tacctl group edit operator tier <tier>") {
				t.Errorf("no red line: %q", sb.stderr())
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// B1: raising a built-in group into the band records the tier it gets by it,
// as for any group, and lowering it takes that record away again; the
// built-in superuser keeps its own handling.
func TestBuiltinGroupRaisedTo15RecordsAndLowersItsTier(t *testing.T) {
	sb := newSandbox(t, true)
	out := plain(sb.cfgRun("", []string{"group", "edit", "operator", "priv-lvl", "15"}, nil))
	if sb.code != 0 || !strings.Contains(out, "tacctl tier: superuser (recorded") || !strings.Contains(sb.read("state/tacctl.yaml"), "operator: superuser") {
		t.Fatalf("raise: %d %q\n%s", sb.code, out, readOrEmpty(sb, "state/tacctl.yaml"))
	}
	out = plain(sb.cfgRun("", []string{"group", "edit", "operator", "priv-lvl", "7"}, nil))
	if sb.code != 0 || !strings.Contains(out, "tacctl tier: automatic again") || strings.Contains(readOrEmpty(sb, "state/tacctl.yaml"), "operator:") {
		t.Errorf("lower: %d %q\n%s", sb.code, out, readOrEmpty(sb, "state/tacctl.yaml"))
	}
	// An engineer setting chosen for it stays when it is lowered.
	sb.cfgRun("", []string{"group", "edit", "operator", "tier", "engineer"}, nil)
	sb.cfgRun("", []string{"group", "edit", "operator", "priv-lvl", "15"}, nil)
	sb.cfgRun("", []string{"group", "edit", "operator", "priv-lvl", "7"}, nil)
	if y := readOrEmpty(sb, "state/tacctl.yaml"); sb.code != 0 || !strings.Contains(y, "operator: engineer") {
		t.Errorf("engineer setting:\n%s", y)
	}
	// The superuser group at 15 is never given a record.
	sb.cfgRun("", []string{"group", "edit", "superuser", "priv-lvl", "15"}, nil)
	if y := readOrEmpty(sb, "state/tacctl.yaml"); strings.Contains(y, "superuser: superuser") {
		t.Errorf("superuser recorded:\n%s", y)
	}
}

// S2: a sync that takes rights away is not refused while a group is
// ambiguous: alice moved down while 'ops' has lost its setting still syncs
// this server (bash runs), with the red line for ops, and no refusal.
func TestLoweringSyncRunsWhileAGroupIsAmbiguous(t *testing.T) {
	hs := hostLowerSandbox(t)
	if hs.run(nil, "group", "add", "ops", "15", "OPS-CLASS"); hs.code != 0 {
		t.Fatalf("group add: %d %q", hs.code, hs.err.String())
	}
	hs.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs]\n", 0o600)
	r := hs.lowerRunner()
	hs.run(r, "user", "move", "alice", "readonly")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !r.Called("bash") || !strings.Contains(all, "syncing this server's accounts (authsrv).") ||
		strings.Contains(all, "accounts are not synced") || strings.Contains(all, "keeps the groups of the old tier") {
		t.Errorf("user move: exit %d, bash %v\n%s", hs.code, r.Called("bash"), all)
	}
	if !strings.Contains(all, "Group 'ops' (priv-lvl 15) has no tier setting in ") || !strings.Contains(all, "until: tacctl group edit ops tier <tier>") {
		t.Errorf("no red line for ops:\n%s", all)
	}
	if n := strings.Count(all, "Group 'ops'"); n != 1 {
		t.Errorf("the line was printed %d times:\n%s", n, all)
	}
}

// S1: store import pins only the groups it brought: neteng was in the store
// before the import and lost its setting, so it is still ambiguous after.
func TestStoreImportDoesNotRepinAGroupTheStoreHad(t *testing.T) {
	hs := hostLowerSandbox(t)
	if hs.run(nil, "group", "add", "neteng", "15", "EN-CLASS"); hs.code != 0 {
		t.Fatalf("group add: %d %q", hs.code, hs.err.String())
	}
	hs.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs]\n", 0o600)
	hs.stdin = "y\n"
	hs.run(hs.lowerRunner(), "store", "import", "--replace")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || strings.Contains(all, "tier recorded") || strings.Contains(hs.read("state/tacctl.yaml"), "neteng") {
		t.Errorf("store import: %d\n%s\n%s", hs.code, all, hs.read("state/tacctl.yaml"))
	}
}

// N2: user rename syncs this server's accounts, so the old account (and its
// tac-superuser) goes at once.
func TestUserRenameSyncsTheServer(t *testing.T) {
	hs := hostLowerSandbox(t)
	r := hs.lowerRunner()
	hs.run(r, "user", "rename", "alice", "alice2")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !r.Called("bash") || !strings.Contains(all, "syncing this server's accounts (authsrv).") {
		t.Errorf("user rename: exit %d, bash %v\n%s", hs.code, r.Called("bash"), all)
	}
	// A failed sync says what is left.
	hs = hostLowerSandbox(t)
	r = hs.lowerRunner()
	r.On([]string{"bash"}, execx.Result{Code: 1})
	hs.run(r, "user", "rename", "alice", "alice2")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || !strings.Contains(all, "'alice' keeps the groups of the old tier on this server until: tacctl host sync authsrv") {
		t.Errorf("user rename with a failing sync: exit %d\n%s", hs.code, all)
	}
}

// N6: a model that could not be read before the change leaves no tiers to
// compare, and the red line is printed anyway.
func TestLoweredWithNoTiersFromBeforeSaysWhatRemains(t *testing.T) {
	hs := hostLowerSandbox(t)
	h := newHarness(t, nil, hs.env...)
	inv := &invocation{ctx: context.Background(), app: h.app}
	w := &tierWatch{inv: inv, scope: "lab"}
	if err := w.lowered("'alice'", "'alice' keeps the groups of the old tier"); err != nil {
		t.Fatal(err)
	}
	if got := plain(h.err.String()); !strings.Contains(got, "'alice' keeps the groups of the old tier on this server until: tacctl host sync authsrv") {
		t.Errorf("stderr %q", got)
	}
	// An unreadable store at the start of a verb: watchServerTiers has
	// nothing to compare with.
	if err := os.WriteFile(hs.path("state", "store.yaml"), []byte("not: [a store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h = newHarness(t, nil, hs.env...)
	inv = &invocation{ctx: context.Background(), app: h.app}
	if w := inv.watchServerTiers(); w.before != nil {
		t.Errorf("tiers from an unreadable model: %v", w.before)
	}
}

// N4: a legacy install (no store) keeps no tier settings, so none can have
// been lost: its priv-lvl 15 groups are not ambiguous (0.2.2's rule stands
// until 'tacctl store import'), while the same groups in a store are.
func TestLegacyInstallHasNoAmbiguousGroups(t *testing.T) {
	hs := hostLowerSandbox(t)
	if hs.run(nil, "group", "add", "neteng", "15", "EN-CLASS"); hs.code != 0 {
		t.Fatalf("group add: %d %q", hs.code, hs.err.String())
	}
	hs.run(nil, "user", "move", "bob", "neteng")
	hs.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs]\n", 0o600)
	inv := func() *invocation {
		h := newHarness(t, nil, hs.env...)
		return &invocation{ctx: context.Background(), app: h.app}
	}
	if i := inv(); !i.hasTierSettings() || len(i.ambiguousGroups()) != 1 || i.userAmbiguousGroup("bob") != "neteng" || i.userTier("bob", "15") != tier.Operator {
		t.Fatalf("with a store: ambiguous %v, bob's group %q, tier %q", inv().ambiguousGroups(), inv().userAmbiguousGroup("bob"), inv().userTier("bob", "15"))
	}
	// The legacy model is read from tacquito.yaml, which carries neteng at 15.
	if err := os.Remove(hs.path("state", "store.yaml")); err != nil {
		t.Fatal(err)
	}
	i := inv()
	if m, err := i.model(); err != nil || m.Group("neteng") == nil {
		t.Fatalf("legacy model: %v %v", m, err)
	}
	if i.hasTierSettings() || len(i.ambiguousGroups()) != 0 || i.userAmbiguousGroup("bob") != "" || i.userTier("bob", "15") != tier.Superuser {
		t.Errorf("legacy: ambiguous %v, bob's group %q, tier %q", i.ambiguousGroups(), i.userAmbiguousGroup("bob"), i.userTier("bob", "15"))
	}
}

// N3: `console check` flags a tac-superuser member that is a tacctl account
// (its UID is in tacctl's range) whose tier is lower or that was removed; a
// local administrator added on purpose (a UID outside the range) is
// mentioned, informationally, and the check stays green.
func TestConsoleCheckLeavesLocalAdministratorsAlone(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	members := func(list string, extra ...func(*fake.Runner)) string {
		return sb.rootRun([]string{"console", "check"}, both(append([]func(*fake.Runner){sshdOK(link), passwdWith(link, "alice"), func(r *fake.Runner) {
			r.On([]string{"getent", "group", tier.SuperuserGroup}, execx.Result{Stdout: []byte("tac-superuser:x:80002:" + list + "\n")})
			r.On([]string{"getent", "passwd", "dave"}, execx.Result{Stdout: []byte("dave:x:1001:1001:Dave:/home/dave:/bin/bash\n")})
			r.On([]string{"getent", "passwd", "ghost"}, execx.Result{Stdout: []byte("ghost:x:80100:80000:ghost (TACACS+):/home/ghost:/bin/bash\n")})
		}}, extra...)...))
	}
	out := members("root,alice,dave")
	if sb.code != 0 || strings.Contains(out, "stale membership") ||
		!strings.Contains(out, "dave: in tac-superuser, not a tacctl account (a local administrator?); tacctl host sync authsrv takes it out of tacctl's groups") {
		t.Errorf("a local administrator: %d\n%s", sb.code, out)
	}
	// A removed tacctl account still in the group is a problem; dave still is not.
	out = members("root,alice,dave,ghost")
	if sb.code != 1 || !strings.Contains(out, "ghost is no tacctl user (removed?) but is still in tac-superuser here (stale membership; run: tacctl host sync authsrv)") ||
		strings.Contains(out, "dave is") {
		t.Errorf("a removed account: %d\n%s", sb.code, out)
	}
}

// N1: the address a host name resolved to is kept for the invocation: the
// check and the pin of ssh use the same one, not a second getent.
func TestResolveV4IsKeptForTheInvocation(t *testing.T) {
	hs := hostLowerSandbox(t)
	h := newHarness(t, nil, hs.env...)
	h.runner.Seq([]string{"getent", "ahostsv4", "web1.example.net"},
		execx.Result{Stdout: []byte("192.0.2.77 STREAM web1.example.net\n")},
		execx.Result{Stdout: []byte("192.0.2.99 STREAM web1.example.net\n")})
	inv := &invocation{ctx: context.Background(), app: h.app}
	if a, b := inv.resolveV4("web1.example.net"), inv.resolveV4("web1.example.net"); a != "192.0.2.77" || b != "192.0.2.77" {
		t.Errorf("resolved %q then %q", a, b)
	}
	if n := h.runner.Count("getent", "ahostsv4", "web1.example.net"); n != 1 {
		t.Errorf("getent ran %d times", n)
	}
	// A check that ran getent itself hands its answer over.
	inv.noteResolved("db1.example.net", "192.0.2.11")
	if got := inv.resolveV4("db1.example.net"); got != "192.0.2.11" || h.runner.Count("getent", "ahostsv4", "db1.example.net") != 0 {
		t.Errorf("noted address %q", got)
	}
	// A second resolution of the same name keeps the first answer.
	h = newHarness(t, nil, hs.env...)
	inv = &invocation{ctx: context.Background(), app: h.app}
	inv.noteResolved("web1.example.net", "192.0.2.77")
	h.runner.On([]string{"getent", "ahostsv4", "web1.example.net"}, execx.Result{Stdout: []byte("192.0.2.99 STREAM web1.example.net\n")})
	if got := inv.resolveV4("web1.example.net"); got != "192.0.2.77" {
		t.Errorf("a second resolution won: %q", got)
	}
}
