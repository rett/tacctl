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

// WP10.2h: the fixes to the review of WP10.2g (docs/plans/0.2.3-plan.md
// §3a): S1 the engineer drop-in sorts first, S2 a group at priv-lvl 15 has
// an explicit tier or is ambiguous, S3 every verb that lowers a tier syncs
// the server, and the nits.

// readOrEmpty is the file, or "" when the last key was removed and the file
// went with it.
func readOrEmpty(sb *sandbox, rel string) string {
	data, err := os.ReadFile(sb.path(rel))
	if err != nil {
		return ""
	}
	return string(data)
}

// asUser is a managed caller: SUDO_USER=user, a member of tac-users and
// groups.
func (sb *sandbox) asUser(user, groups string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun("", args, idAs(user, "tac-users "+groups), "SUDO_USER="+user))
}

// S2, the exact lockout sequence of the review: no tacctl.yaml, a managed
// superuser adds a group at priv-lvl 15 and then edits its tier. The group
// gets an explicit superuser setting, and nobody is capped.
func TestGroupAddAtPriv15RecordsItsTierWithoutLockout(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	if err := os.Remove(sb.path("state", "tacctl.yaml")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	out := sb.asUser("alice", "tac-superuser", "group", "add", "neteng", "15", "CLASS")
	if sb.code != 0 || !strings.Contains(out, "tacctl tier: superuser (recorded, as every group at priv-lvl 15 has one; change it with: tacctl group edit neteng tier <tier>).") {
		t.Fatalf("group add: %d %q %q", sb.code, out, sb.stderr())
	}
	if y := sb.read("state/tacctl.yaml"); !strings.Contains(y, "neteng: superuser") {
		t.Errorf("tacctl.yaml:\n%s", y)
	}
	// alice (the built-in superuser group) still has every verb.
	if got := sb.asUser("alice", "tac-superuser", "_console-policy"); !strings.Contains(got, " tier=superuser ") {
		t.Errorf("alice: %q", got)
	}
	sb.asUser("alice", "tac-superuser", "group", "edit", "neteng", "tier", "engineer")
	if sb.code != 0 || !strings.Contains(sb.read("state/tacctl.yaml"), "neteng: engineer") {
		t.Fatalf("group edit tier: %d %q", sb.code, sb.stderr())
	}
	// A group below 15 gets no setting, and --tier is kept as given.
	sb.asUser("alice", "tac-superuser", "group", "add", "helpdesk", "5", "HD-CLASS")
	sb.asUser("alice", "tac-superuser", "group", "add", "ops", "15", "OPS-CLASS", "--tier", "operator")
	y := sb.read("state/tacctl.yaml")
	if sb.code != 0 || strings.Contains(y, "helpdesk:") || !strings.Contains(y, "ops: operator") {
		t.Errorf("tier settings:\n%s", y)
	}
}

// ambiguousSandbox is a store with a group at priv-lvl 15 (neteng) that has
// a member (bob) and a tacctl.yaml that lost its setting: the text given.
// A nil text removes the file.
func ambiguousSandbox(t *testing.T, yaml *string) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	for _, a := range [][]string{{"group", "add", "neteng", "15", "ENG-CLASS"}, {"user", "move", "bob", "neteng"}} {
		if sb.cfgRun("", a, nil); sb.code != 0 {
			t.Fatalf("%v: %d %q", a, sb.code, sb.stderr())
		}
	}
	if yaml == nil {
		if err := os.Remove(sb.path("state", "tacctl.yaml")); err != nil {
			t.Fatal(err)
		}
	} else {
		sb.write("state/tacctl.yaml", *yaml, 0o600)
	}
	return sb
}

// S2: a group at priv-lvl 15 without a tier setting (the file is missing,
// empty, or an older one without `tier:`) is ambiguous: its members are held
// at the operator tier (the gate, and the accounts a sync makes), the syncs
// go ahead and name the group in one red line each, and everyone else (a
// member of the built-in superuser group) keeps every verb, the one that
// repairs the setting included.
func TestAmbiguousGroupHoldsItsMembersOnly(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		name string
		yaml *string
	}{
		{"missing", nil},
		{"empty", str("")},
		{"comment only", str("# nothing\n")},
		{"a backup restore without tier", str("backends:\n  enabled: [tacacs]\nhost:\n  default_method: tacplus\n")},
		{"tier lists other groups", str("tier:\n  operator: engineer\n")},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb := ambiguousSandbox(t, c.yaml)
			// bob is in neteng: capped at operator; the gate says why.
			if got := sb.asUser("bob", "tac-superuser", "_console-policy"); !strings.Contains(got, " tier=operator ") {
				t.Errorf("bob: %q", got)
			}
			sb.asUser("bob", "tac-superuser", "host", "sync", "authsrv")
			if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl host sync' is not permitted: your group 'neteng' is at priv-lvl 15 or more and has no tier setting in "+
				sb.path("state", "tacctl.yaml")+" (it was lost), so its members are held at the operator tier. A superuser who is not a member sets it: tacctl group edit neteng tier <tier>.") {
				t.Errorf("host sync as bob: %d %q", sb.code, sb.stderr())
			}
			// ... and a verb that only a superuser has is denied the same way.
			sb.asUser("bob", "tac-superuser", "group", "edit", "neteng", "tier", "superuser")
			if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted: your group 'neteng'") {
				t.Errorf("group edit as bob: %d %q", sb.code, sb.stderr())
			}
			// The syncs are not refused (one that takes rights away must
			// run): for root and for a superuser they go ahead, with one red
			// line naming the group and the repair.
			red := "Group 'neteng' (priv-lvl 15) has no tier setting in " + sb.path("state", "tacctl.yaml") +
				", so its members are synced as operators (no tac-superuser, no tac-engineer) until: tacctl group edit neteng tier <tier>"
			for _, who := range []string{"", "alice"} {
				bash := func(r *fake.Runner) { r.On([]string{"bash"}, execx.Result{}) }
				if who == "" {
					sb.cfgRun("", []string{"host", "sync", "authsrv"}, bash)
				} else {
					sb.cfgRun("", []string{"host", "sync", "authsrv"}, both(bash, idAs(who, "tac-users tac-superuser")), "SUDO_USER="+who)
				}
				if sb.code != 0 || strings.Count(sb.stderr(), red) != 1 {
					t.Errorf("host sync as %q: %d %q", who, sb.code, sb.stderr())
				}
			}
			// ... and the accounts it makes: bob (neteng, ambiguous) is an
			// operator, whatever his priv-lvl 15 says.
			sb.cfgRun("", []string{"config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "-o", sb.path("s.sh")}, nil)
			if data := sb.read("s.sh"); sb.code != 0 || !strings.Contains(data, "alice:superuser:") || !strings.Contains(data, "bob:operator:") || strings.Contains(data, "bob:superuser") {
				t.Errorf("script users: %d\n%s", sb.code, head(data))
			}
			if !strings.Contains(sb.stderr(), red) {
				t.Errorf("config linux script: %q", sb.stderr())
			}
			sb.cfgRun("", []string{"host", "enroll", "--local", "--scope", "lab"}, nil)
			if strings.Contains(sb.stderr(), "accounts are not synced") || !strings.Contains(sb.stderr(), red) {
				t.Errorf("host enroll: %d %q", sb.code, sb.stderr())
			}
			// A managed superuser who is not a member keeps working, and
			// repairs the setting.
			if got := sb.asUser("alice", "tac-superuser", "_console-policy"); !strings.Contains(got, " tier=superuser ") {
				t.Errorf("alice: %q", got)
			}
			for _, args := range [][]string{{"group", "list"}, {"group", "show", "neteng"}, {"user", "list"}, {"group", "add", "second", "15", "S-CLASS"}} {
				sb.asUser("alice", "tac-superuser", args...)
				if sb.code != 0 || strings.Contains(sb.stderr(), "not permitted") {
					t.Errorf("alice %v: %d %q", args, sb.code, sb.stderr())
				}
			}
			if show := sb.asUser("alice", "tac-superuser", "group", "show", "neteng"); !strings.Contains(show, "tacctl tier:       NOT SET") {
				t.Errorf("group show:\n%s", show)
			}
			sb.asUser("alice", "tac-superuser", "group", "edit", "neteng", "tier", "engineer")
			if sb.code != 0 {
				t.Fatalf("group edit tier as alice: %d %q", sb.code, sb.stderr())
			}
			if got := sb.asUser("bob", "tac-engineer", "_console-policy"); !strings.Contains(got, " tier=engineer ") {
				t.Errorf("bob after the repair: %q", got)
			}
			sb.cfgRun("", []string{"host", "sync", "authsrv"}, func(r *fake.Runner) {
				r.On([]string{"bash"}, execx.Result{})
			})
			if strings.Contains(sb.stderr(), "has no tier setting") {
				t.Errorf("host sync after the repair: %q", sb.stderr())
			}
		})
	}
}

// S2: the built-in groups and the groups below 15 are never ambiguous, with
// no tacctl.yaml at all: a default install is just a default install.
func TestNoAmbiguityWithoutCustomGroupsAt15(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	if err := os.Remove(sb.path("state", "tacctl.yaml")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	sb.cfgRun("", []string{"group", "add", "helpdesk", "14", "HD-CLASS"}, nil)
	if sb.code != 0 {
		t.Fatal(sb.stderr())
	}
	if got := sb.asUser("alice", "tac-superuser", "_console-policy"); !strings.Contains(got, " tier=superuser ") {
		t.Errorf("alice: %q", got)
	}
	sb.cfgRun("", []string{"host", "sync", "authsrv"}, func(r *fake.Runner) { r.On([]string{"bash"}, execx.Result{}) })
	if strings.Contains(sb.stderr(), "has no tier setting") || strings.Contains(sb.stderr(), "cannot be read") {
		t.Errorf("host sync: %q", sb.stderr())
	}
}

// S2: group edit priv-lvl keeps the invariant across 15: raised into the
// band a group gets superuser recorded; lowered out of it a superuser that
// only recorded the band goes, so the lower band decides again; a setting
// the operator chose (engineer) stays.
func TestGroupEditPrivLvlKeepsTheTierSetting(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"group", "add", "mid", "10", "MID-CLASS"}, nil)
	out := plain(sb.cfgRun("", []string{"group", "edit", "mid", "priv-lvl", "15"}, nil))
	if sb.code != 0 || !strings.Contains(out, "tacctl tier: superuser (recorded") || !strings.Contains(sb.read("state/tacctl.yaml"), "mid: superuser") {
		t.Fatalf("raise: %d %q\n%s", sb.code, out, sb.read("state/tacctl.yaml"))
	}
	out = plain(sb.cfgRun("", []string{"group", "edit", "mid", "priv-lvl", "9"}, nil))
	if sb.code != 0 || !strings.Contains(out, "tacctl tier: automatic again (the superuser setting recorded the priv-lvl band; priv-lvl 9 → operator).") ||
		strings.Contains(readOrEmpty(sb, "state/tacctl.yaml"), "mid:") {
		t.Fatalf("lower: %d %q\n%s", sb.code, out, readOrEmpty(sb, "state/tacctl.yaml"))
	}
	// An engineer setting is the operator's choice: it stays when the group is lowered or raised.
	sb.cfgRun("", []string{"group", "edit", "mid", "tier", "engineer"}, nil)
	sb.cfgRun("", []string{"group", "edit", "mid", "priv-lvl", "15"}, nil)
	sb.cfgRun("", []string{"group", "edit", "mid", "priv-lvl", "3"}, nil)
	if y := sb.read("state/tacctl.yaml"); sb.code != 0 || !strings.Contains(y, "mid: engineer") {
		t.Errorf("engineer setting:\n%s", y)
	}
	// tier auto on a group at 15 is recorded as superuser.
	sb.cfgRun("", []string{"group", "edit", "mid", "priv-lvl", "15"}, nil)
	out = plain(sb.cfgRun("", []string{"group", "edit", "mid", "tier", "auto"}, nil))
	if sb.code != 0 || !strings.Contains(out, "tacctl tier set to superuser (priv-lvl 15 is the superuser band") || !strings.Contains(sb.read("state/tacctl.yaml"), "mid: superuser") {
		t.Errorf("tier auto at 15: %d %q\n%s", sb.code, out, sb.read("state/tacctl.yaml"))
	}
	// Below 15 auto removes the setting.
	sb.cfgRun("", []string{"group", "edit", "mid", "priv-lvl", "4"}, nil)
	sb.cfgRun("", []string{"group", "edit", "mid", "tier", "operator"}, nil)
	out = plain(sb.cfgRun("", []string{"group", "edit", "mid", "tier", "auto"}, nil))
	if sb.code != 0 || !strings.Contains(out, "is automatic again") || strings.Contains(readOrEmpty(sb, "state/tacctl.yaml"), "mid:") {
		t.Errorf("tier auto below 15: %d %q\n%s", sb.code, out, readOrEmpty(sb, "state/tacctl.yaml"))
	}
}

// S2: `group show` words a tier that is not one: invalid, treated as readonly.
func TestGroupShowInvalidTierWording(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"group", "add", "mid", "10", "MID-CLASS"}, nil)
	sb.write("state/tacctl.yaml", "tier:\n  mid: Engineer\n", 0o600)
	out := plain(sb.cfgRun("", []string{"group", "show", "mid"}, nil))
	if sb.code != 0 || !strings.Contains(out, "readonly (invalid setting 'Engineer'; treated as readonly; fix: tacctl group edit mid tier <tier>)") ||
		strings.Contains(out, "(set;") {
		t.Errorf("group show: %d\n%s", sb.code, out)
	}
}

// S3: every verb that can take a tier or an account away syncs the server
// (the table of engineer_fixes_test.go has the others).
func TestMoreLoweringVerbsSyncTheServer(t *testing.T) {
	synced := "syncing this server's accounts (authsrv)."
	for _, c := range []struct {
		name  string
		setup func(*hostSandbox)
		args  []string
		stdin string
		sync  bool
		left  string
	}{
		// alice is a superuser (prod, lab), bob an operator (lab), carol readonly (lab, dmz).
		{name: "user disable", args: []string{"user", "disable", "bob"}, sync: true, left: "'bob' keeps the groups of the old tier"},
		{name: "user remove", args: []string{"user", "remove", "bob"}, stdin: "y\n", sync: true, left: "'bob' keeps the groups of the old tier"},
		{name: "user remove, cancelled", args: []string{"user", "remove", "bob"}, stdin: "n\n"},
		{name: "user scope remove the server's scope", args: []string{"user", "scope", "bob", "remove", "lab"}, sync: true, left: "'bob' keeps the groups of the old tier"},
		{name: "user scope replace without it", args: []string{"user", "scope", "bob", "replace", "prod"}, sync: true, left: "'bob' keeps the groups of the old tier"},
		{name: "user scope remove --all", args: []string{"user", "scope", "bob", "remove", "--all"}, stdin: "y\n", sync: true, left: "'bob' keeps the groups of the old tier"},
		{name: "user scope remove another scope", args: []string{"user", "scope", "carol", "remove", "dmz"}},
		{name: "user scope add", args: []string{"user", "scope", "bob", "add", "prod"}},
		{name: "user enable", args: []string{"user", "enable", "bob"}},
		{
			name: "group remove (it has no members)", args: []string{"group", "remove", "spare"}, stdin: "y\n",
			setup: func(hs *hostSandbox) {
				if hs.run(nil, "group", "add", "spare", "5", "SPARE-CLASS"); hs.code != 0 {
					hs.t.Fatalf("group add: %d %q", hs.code, hs.err.String())
				}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := hostLowerSandbox(t)
			if c.setup != nil {
				c.setup(hs)
			}
			hs.stdin = c.stdin
			r := hs.lowerRunner()
			hs.run(r, c.args...)
			all := plain(hs.out.String() + hs.err.String())
			if hs.code != 0 || strings.Contains(all, synced) != c.sync || r.Called("bash") != c.sync {
				t.Errorf("%v: exit %d, synced %v, want %v\n%s", c.args, hs.code, r.Called("bash"), c.sync, all)
			}
			if c.left == "" {
				return
			}
			// A sync that fails says what is left; the change stands.
			hs = hostLowerSandbox(t)
			hs.stdin = c.stdin
			r = hs.lowerRunner()
			r.On([]string{"bash"}, execx.Result{Code: 1})
			hs.run(r, c.args...)
			all = plain(hs.out.String() + hs.err.String())
			if hs.code != 1 || !strings.Contains(all, c.left+" on this server until: tacctl host sync authsrv") {
				t.Errorf("%v with a failing sync: exit %d\n%s", c.args, hs.code, all)
			}
		})
	}
}

// S3: store import, store rollback and backup restore replace the state
// wholesale, so they cannot say whose tier fell: when the server is enrolled
// they print the red line that names the sync.
func TestWholesaleVerbsNameTheServerSync(t *testing.T) {
	const left = "Users whose tier is lower now keep their old groups on this server until: tacctl host sync authsrv"
	hs := hostLowerSandbox(t)
	// The old-style file to import is the live tacquito.yaml the sandbox
	// rendered.
	imp := func(args ...string) string {
		hs.stdin = "y\n"
		hs.run(hs.lowerRunner(), append([]string{"store", "import"}, args...)...)
		return plain(hs.out.String() + hs.err.String())
	}
	all := imp("--replace")
	if hs.code != 0 || !strings.Contains(all, left) {
		t.Errorf("store import: %d\n%s", hs.code, all)
	}
	// --check changes nothing and says nothing.
	if all = imp("--check"); hs.code != 0 || strings.Contains(all, left) {
		t.Errorf("store import --check: %d\n%s", hs.code, all)
	}
	// Without an enrolled server there is nothing to say.
	hs.write("state/linux-hosts", "", 0o600)
	if all = imp("--replace"); strings.Contains(all, "keep their old groups") {
		t.Errorf("no server enrolled: %q", all)
	}
}

// S3: `console check` names every tac-superuser member that is a tacctl
// account and not a superuser-tier tacctl user, a removed user included, and
// never root.
func TestConsoleCheckFlagsRemovedSuperusers(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	out := sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice"), func(r *fake.Runner) {
		r.On([]string{"getent", "group", tier.SuperuserGroup}, execx.Result{Stdout: []byte("tac-superuser:x:80002:root,alice,ghost\n")})
		r.On([]string{"getent", "passwd", "ghost"}, execx.Result{Stdout: []byte("ghost:x:80100:80000:ghost (TACACS+):/home/ghost:/bin/bash\n")})
	}))
	if sb.code != 1 || !strings.Contains(out, "ghost is no tacctl user (removed?) but is still in tac-superuser here (stale membership; run: tacctl host sync authsrv)") {
		t.Errorf("removed superuser: %d\n%s", sb.code, out)
	}
	if strings.Contains(out, "root is") || strings.Contains(out, "root:") || strings.Contains(out, "alice is") {
		t.Errorf("named a member that is fine:\n%s", out)
	}
	// Only root and alice: nothing to flag.
	out = sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice"), func(r *fake.Runner) {
		r.On([]string{"getent", "group", tier.SuperuserGroup}, execx.Result{Stdout: []byte("tac-superuser:x:80002:root,alice\n")})
	}))
	if strings.Contains(out, "stale membership") {
		t.Errorf("flagged a fine group:\n%s", out)
	}
}

// S3: a model that cannot be read after a change still prints the red line.
func TestLoweredWithoutAModelSaysWhatRemains(t *testing.T) {
	hs := hostLowerSandbox(t)
	h := newHarness(t, nil, hs.env...)
	inv := &invocation{ctx: context.Background(), app: h.app}
	w := &tierWatch{inv: inv, scope: "lab", before: map[string]tier.Tier{"alice": tier.Superuser}}
	if err := os.WriteFile(hs.path("state", "store.yaml"), []byte("not: [a store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.lowered("'alice'", "'alice' keeps the groups of the old tier"); err != nil {
		t.Fatal(err)
	}
	if got := plain(h.err.String()); !strings.Contains(got, "'alice' keeps the groups of the old tier on this server until: tacctl host sync authsrv") {
		t.Errorf("stderr %q", got)
	}
}

// S1: `console install` moves an old engineer drop-in to its new name, and
// `console check` flags the old file and a name that sorts after the console's.
func TestConsoleInstallRenamesTheEngineerDropIn(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	engineer := sb.path("sshd_config.d", "00-tacctl-engineer.conf")
	old := sb.path("sshd_config.d", "tacctl-engineer.conf")
	sb.write("sshd_config.d/tacctl-engineer.conf", "Match Group tac-engineer\n    AllowTcpForwarding no\n", 0o644)
	out := sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice")))
	if sb.code != 1 || !strings.Contains(out, "the engineer tier's old sshd drop-in "+old+" is still there") {
		t.Errorf("check with the old file: %d\n%s", sb.code, out)
	}
	out = sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	if sb.code != 0 || !strings.Contains(out, "Installed: sshd drop-in "+engineer+" (engineer tier)") ||
		!strings.Contains(out, "Removed: sshd drop-in "+old+" (replaced by "+engineer+")") {
		t.Fatalf("install: %d\n%s", sb.code, out)
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("the old drop-in stayed")
	}
	if out = sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice"))); sb.code != 0 || strings.Contains(out, "old sshd drop-in") {
		t.Errorf("check after: %d\n%s", sb.code, out)
	}
	// 'console remove' with only the old file present moves it too.
	sb.write("sshd_config.d/tacctl-engineer.conf", "Match Group tac-engineer\n", 0o644)
	if err := os.Remove(engineer); err != nil {
		t.Fatal(err)
	}
	sb.rootRun([]string{"console", "remove"}, both(sshdOK(link), passwdWith(link)))
	if _, err := os.Stat(old); err == nil {
		t.Error("console remove left the old drop-in")
	}
	if _, err := os.Stat(engineer); err != nil {
		t.Errorf("console remove did not write the engineer drop-in under its new name: %v", err)
	}
}
