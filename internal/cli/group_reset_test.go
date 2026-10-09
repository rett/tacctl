package cli

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/testpty"
	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl group reset' (docs/plans/0.2.3-plan.md D51), end to end on the
// sandbox of native_test.go. The golden diffs are in testdata/reset (run
// with -update-reset to rewrite them, then read them).

// updateResetGoldens rewrites the goldens of the reset (go test -update-reset).
var updateResetGoldens = flag.Bool("update-reset", false, "rewrite internal/cli/testdata/reset")

// golden compares got with testdata/reset/<name>.golden.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "reset", name+".golden")
	if *updateResetGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test -update-reset writes it)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from %s:\n--- got\n%s\n--- want\n%s", name, path, got, want)
	}
}

// must runs args and fails the test unless they succeed.
func (sb *sandbox) must(args ...string) string {
	sb.t.Helper()
	out := sb.run("", args)
	if sb.code != 0 {
		sb.t.Fatalf("%v: exit %d\n%s%s", args, sb.code, out, sb.err.String())
	}
	return out
}

func (sb *sandbox) plainRun(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.run(stdin, args))
}

// state is what a reset may write: the store and tacctl.yaml.
func (sb *sandbox) state() string {
	sb.t.Helper()
	return sb.store() + "\n--\n" + sb.overrides()
}

func (sb *sandbox) snapshots() int { return len(sb.leftovers("backups/*")) }

// modifiers change each group away from its canonical state through the
// setters: an extra rule, a moved rule, a removed rule, another default
// action, priv-lvl, class, tier, WTI level, a Junos set and a privilege.
var resetModifiers = map[string][][]string{
	"readonly": {
		{"group", "commands", "add", "readonly", "configure", "--action", "permit"},
		{"group", "edit", "readonly", "priv-lvl", "5"},
		{"group", "edit", "readonly", "juniper-class", "RO2-CLASS"},
		{"group", "edit", "readonly", "tier", "operator"},
		{"group", "edit", "readonly", "wti-level", "user"},
		{"group", "junos", "readonly", "deny-configuration", "add", "^snmp"},
		{"group", "privilege", "add", "readonly", "show version"},
	},
	"operator": {
		{"group", "commands", "add", "operator", "configure", "--action", "permit"},
		{"group", "commands", "remove", "operator", "dir"},
		{"group", "commands", "add", "operator", "dir", "--before", "show"},
		{"group", "commands", "default", "operator", "permit"},
		{"group", "edit", "operator", "priv-lvl", "10"},
		{"group", "edit", "operator", "juniper-class", "NEW-CLASS"},
		{"group", "edit", "operator", "tier", "engineer"},
		{"group", "edit", "operator", "wti-level", "administrator"},
		{"group", "junos", "operator", "deny-commands", "add", "^foo"},
		{"group", "privilege", "add", "operator", "show version"},
	},
	"superuser": {
		{"group", "commands", "add", "superuser", "reload", "--action", "deny"},
		{"group", "edit", "superuser", "juniper-class", "SU2-CLASS"},
		{"group", "edit", "superuser", "tier", "engineer"},
		{"group", "edit", "superuser", "wti-level", "user"},
		{"group", "junos", "superuser", "deny-commands", "add", "^foo"},
		{"group", "privilege", "add", "superuser", "show version"},
	},
	"engineer": {
		{"group", "commands", "add", "engineer", "extra", "--action", "deny", "--match", "^(x)$"},
		{"group", "edit", "engineer", "priv-lvl", "14"},
		{"group", "edit", "engineer", "juniper-class", "OTHER-CLASS"},
		{"group", "edit", "engineer", "tier", "operator"},
		{"group", "edit", "engineer", "wti-level", "administrator"},
		{"group", "junos", "engineer", "deny-commands", "add", "^foo"},
		{"group", "junos", "engineer", "deny-configuration", "add", "^snmp"},
	},
}

func (sb *sandbox) modify(group string) {
	sb.t.Helper()
	if group == "engineer" {
		sb.must("group", "reset", "engineer", "--yes")
	}
	for _, args := range resetModifiers[group] {
		sb.must(args...)
	}
}

// engineer022 gives the sandbox an engineer group as 0.2.2's preset left it:
// EN-CLASS, tier engineer, WTI superuser, the fail-open Cisco rules and the
// two Junos sets of that release.
func (sb *sandbox) engineer022() {
	sb.t.Helper()
	sb.must("group", "add", "engineer", "15", "EN-CLASS", "--tier", "engineer", "--wti-level", "superuser")
	c := conf.Load(sb.path("state", "tacctl.yaml"), conf.DefaultBackends)
	dc, dcfg := policy.Engineer022Junos("")
	for _, err := range []error{
		policy.Write(c, "engineer", policy.Engineer022Commands()),
		policy.WriteJunosSet(c, "engineer", conf.JunosDenyCommands, []string{dc}),
		policy.WriteJunosSet(c, "engineer", conf.JunosDenyConfiguration, []string{dcfg}),
	} {
		if err != nil {
			sb.t.Fatal(err)
		}
	}
	if got := policy.Stale022Preset(conf.Load(sb.path("state", "tacctl.yaml"), conf.DefaultBackends)); len(got) != 3 {
		sb.t.Fatalf("the 0.2.2 state is not recognised: %q", got)
	}
}

func TestGroupResetGoldenDiffs(t *testing.T) {
	for _, g := range []string{"readonly", "operator", "superuser"} {
		t.Run(g, func(t *testing.T) {
			// Default: from the fresh install it is canonical already; from a
			// modified group the diff.
			sb := newSandbox(t, true)
			if out := sb.plainRun("", "group", "reset", g, "--dry-run"); sb.code != 0 || !strings.Contains(out, "is already canonical; nothing to change.") {
				t.Errorf("fresh: %d %q", sb.code, out)
			}
			// --preset from a fresh install: what the preset adds.
			golden(t, g+"_preset_fresh", sb.plainRun("", "group", "reset", g, "--preset", "--dry-run"))
			sb.modify(g)
			golden(t, g+"_modified", sb.plainRun("", "group", "reset", g, "--dry-run"))
			golden(t, g+"_preset_modified", sb.plainRun("", "group", "reset", g, "--preset", "--dry-run"))
		})
	}
	t.Run("engineer", func(t *testing.T) {
		sb := newSandbox(t, true)
		golden(t, "engineer_fresh", sb.plainRun("", "group", "reset", "engineer", "--dry-run"))
		// The same with --preset.
		if a, b := sb.plainRun("", "group", "reset", "engineer", "--dry-run"), sb.plainRun("", "group", "reset", "engineer", "--preset", "--dry-run"); strings.ReplaceAll(a, "canonical defaults", "") != strings.ReplaceAll(b, "canonical defaults", "") {
			t.Errorf("--preset changes the engineer's reset:\n%s\n%s", a, b)
		}
		sb.modify("engineer")
		golden(t, "engineer_modified", sb.plainRun("", "group", "reset", "engineer", "--dry-run"))
	})
	t.Run("engineer 0.2.2", func(t *testing.T) {
		sb := newSandbox(t, true)
		sb.engineer022()
		golden(t, "engineer_022", sb.plainRun("", "group", "reset", "engineer", "--dry-run"))
	})
}

// A group in its canonical state says so, exits 0 and never asks; applying a
// reset gets a group there, and a second one changes nothing and writes no
// snapshot or log line.
func TestGroupResetCanonicalAndIdempotent(t *testing.T) {
	for _, g := range []string{"readonly", "operator", "superuser", "engineer"} {
		for _, preset := range []bool{false, true} {
			flags := []string{"group", "reset", g}
			if preset {
				flags = append(flags, "--preset")
			}
			t.Run(strings.Join(flags[2:], " "), func(t *testing.T) {
				sb := newSandbox(t, true)
				fresh := newSandbox(t, true)
				if g == "engineer" {
					fresh.must("group", "reset", "engineer", "--yes")
				} else if preset {
					fresh.must("group", "reset", g, "--preset", "--yes")
				}
				sb.modify(g)
				if out := sb.plainRun("", append(slices.Clone(flags), "--dry-run")...); !strings.Contains(out, "Reset of group '"+g+"'") {
					t.Fatalf("modified, no diff:\n%s", out)
				}
				sb.must(append(slices.Clone(flags), "--yes")...)
				// The group reads as the fresh one does (shown by group show)
				// and nothing of it is left in tacctl.yaml but what canonical
				// means.
				if got, want := sb.plainRun("", "group", "show", g), fresh.plainRun("", "group", "show", g); got != want {
					t.Errorf("after the reset:\n%s\nfresh:\n%s", got, want)
				}
				if got, want := sb.plainRun("", "group", "commands", "list", g), fresh.plainRun("", "group", "commands", "list", g); got != want {
					t.Errorf("rules after the reset:\n%s\nfresh:\n%s", got, want)
				}
				if got, want := sb.plainRun("", "group", "privilege", "list", g), fresh.plainRun("", "group", "privilege", "list", g); got != want {
					t.Errorf("privileges after the reset:\n%s\nfresh:\n%s", got, want)
				}
				if got, want := sb.plainRun("", "group", "junos", g, "list"), fresh.plainRun("", "group", "junos", g, "list"); got != want {
					t.Errorf("junos after the reset:\n%s\nfresh:\n%s", got, want)
				}
				// Idempotent: no prompt (stdin is empty and not a terminal),
				// exit 0, nothing written, no snapshot, no audit line.
				state, snaps := sb.state(), sb.snapshots()
				for _, extra := range [][]string{nil, {"--yes"}, {"--dry-run"}} {
					out := sb.plainRun("", append(slices.Clone(flags), extra...)...)
					if sb.code != 0 || !strings.Contains(out, "Group '"+g+"' is already canonical; nothing to change.") || strings.Contains(out, "Reset of group") {
						t.Errorf("%v again: %d %q", extra, sb.code, out)
					}
					if sb.state() != state || sb.snapshots() != snaps || sb.runner.Called("logger") {
						t.Errorf("%v again changed something (snapshots %d -> %d, logger %v)", extra, snaps, sb.snapshots(), sb.runner.Called("logger"))
					}
				}
			})
		}
	}
}

// 'group reset engineer' is 'group preset roles --force' for that one group,
// from the 0.2.2 text and from a modified group.
func TestGroupResetEngineerEqualsPresetForce(t *testing.T) {
	for name, setup := range map[string]func(*sandbox){
		"0.2.2": (*sandbox).engineer022,
		// The preset keeps the priv-lvl of a group that exists (D20); the
		// reset sets it (item 57), so it is the one thing not modified here.
		"modified": func(sb *sandbox) {
			sb.must("group", "reset", "engineer", "--yes")
			for _, args := range resetModifiers["engineer"] {
				if !slices.Contains(args, "priv-lvl") {
					sb.must(args...)
				}
			}
		},
		"absent": func(*sandbox) {},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := newSandbox(t, true), newSandbox(t, true)
			setup(a)
			setup(b)
			a.must("group", "reset", "engineer", "--yes")
			b.run("y\n", []string{"group", "preset", "roles", "--force"})
			if b.code != 0 {
				t.Fatalf("preset: %d %s", b.code, b.err.String())
			}
			for _, args := range [][]string{{"group", "show", "engineer"}, {"group", "commands", "list", "engineer"},
				{"group", "junos", "engineer", "list"}, {"group", "privilege", "list", "engineer"}} {
				if x, y := a.plainRun("", args...), b.plainRun("", args...); x != y {
					t.Errorf("%v: reset\n%s\npreset --force\n%s", args, x, y)
				}
			}
			if got := policy.Stale022Preset(conf.Load(a.path("state", "tacctl.yaml"), conf.DefaultBackends)); len(got) != 0 {
				t.Errorf("still the 0.2.2 text: %q", got)
			}
			// The fail-open rules hold now: 'no aaa' is denied as a whole.
			if rules := a.plainRun("", "group", "commands", "list", "engineer"); !strings.Contains(rules, "^(aaa|logging|archive)( .*)?$") {
				t.Errorf("rules:\n%s", rules)
			}
			// The invariant: the engineer group has an explicit tier.
			if show := a.plainRun("", "group", "show", "engineer"); !strings.Contains(show, "tacctl tier:       engineer (set;") {
				t.Errorf("tier:\n%s", show)
			}
		})
	}
}

func TestGroupResetRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.must("group", "add", "helpdesk", "5", "HD-CLASS")
	sb.must("group", "commands", "add", "helpdesk", "show")
	state, snaps := sb.state(), sb.snapshots()
	for _, c := range []struct {
		name  string
		stdin string
		args  []string
		err   string
	}{
		{"custom group", "", []string{"group", "reset", "helpdesk", "--yes"},
			"[ERROR] Group 'helpdesk' is not a built-in or role group, so it has no canonical defaults; group commands reset helpdesk drops its command overrides."},
		{"custom group --preset", "", []string{"group", "reset", "helpdesk", "--preset", "--dry-run"},
			"Group 'helpdesk' is not a built-in or role group, so it has no canonical defaults"},
		{"missing group", "", []string{"group", "reset", "ghost", "--yes"}, "[ERROR] Group 'ghost' does not exist."},
		{"no group", "", []string{"group", "reset"}, "Usage: tacctl group reset <group> [--preset] [--only settings,commands,privileges,junos] [--dry-run] [--yes]"},
		{"two groups", "", []string{"group", "reset", "operator", "readonly"}, "Usage: tacctl group reset <group>"},
		{"unknown section", "", []string{"group", "reset", "operator", "--only", "settings,rules"}, "Unknown section 'rules' for --only. Use: settings, commands, privileges, junos"},
		{"empty section", "", []string{"group", "reset", "operator", "--only", "settings,"}, "Unknown section '' for --only."},
		{"unknown flag", "", []string{"group", "reset", "operator", "--force"}, "Usage: tacctl group reset <group>"},
		{"engineer to create without settings", "", []string{"group", "reset", "engineer", "--only", "commands", "--yes"},
			"Group 'engineer' does not exist yet; the reset creates it with its settings, so --only must include settings."},
	} {
		sb.run(c.stdin, c.args)
		if sb.code != 1 || !strings.Contains(plain(sb.err.String()), c.err) {
			t.Errorf("%s: exit %d, stderr %q", c.name, sb.code, plain(sb.err.String()))
		}
		if sb.state() != state || sb.snapshots() != snaps || sb.runner.Called("logger") {
			t.Errorf("%s changed something", c.name)
		}
	}

	// A modified group without a terminal and without --yes: the diff is
	// shown, nothing is changed, exit 1. A piped 'y' is not a confirmation.
	sb.must("group", "edit", "operator", "priv-lvl", "10")
	state, snaps = sb.state(), sb.snapshots()
	out := sb.plainRun("y\n", "group", "reset", "operator")
	if sb.code != 1 || !strings.Contains(out, "Cisco priv-lvl:  10 -> 7") ||
		!strings.Contains(plain(sb.err.String()), "No terminal to confirm on; nothing was changed. Review with --dry-run, then run again with --yes.") {
		t.Errorf("no terminal: %d\n%s\n%s", sb.code, out, sb.err.String())
	}
	if sb.state() != state || sb.snapshots() != snaps || sb.runner.Called("logger") {
		t.Error("no terminal: something changed")
	}
}

func TestGroupResetDryRunWritesNothing(t *testing.T) {
	sb := newSandbox(t, true)
	sb.modify("operator")
	storeBefore, yamlBefore := sb.store(), sb.overrides()
	live, snaps := sb.liveState(), sb.snapshots()
	for _, args := range [][]string{
		{"group", "reset", "operator", "--dry-run"},
		{"group", "reset", "operator", "--dry-run", "--yes"},
		{"group", "reset", "operator", "--preset", "--dry-run"},
		{"group", "reset", "engineer", "--dry-run"},
		{"group", "reset", "readonly", "--dry-run", "--only", "settings,junos"},
	} {
		out := sb.plainRun("", args...)
		if sb.code != 0 || !strings.Contains(out, "Dry run: nothing was written.") && !strings.Contains(out, "already canonical") {
			t.Errorf("%v: %d %q", args, sb.code, out)
		}
		if sb.store() != storeBefore || sb.overrides() != yamlBefore {
			t.Errorf("%v wrote the store or tacctl.yaml", args)
		}
		if sb.liveState() != live || sb.snapshots() != snaps || sb.runner.Called("logger") || sb.runner.Called("systemctl") {
			t.Errorf("%v wrote, took a snapshot or restarted something: %q", args, sb.runner.Argvs())
		}
	}
}

func TestGroupResetYesAppliesAndLogs(t *testing.T) {
	sb := newSandbox(t, true)
	sb.modify("operator")
	snaps := sb.snapshots()
	out := sb.plainRun("", "group", "reset", "operator", "--yes")
	if sb.code != 0 || !strings.Contains(out, "[INFO] Group 'operator' reset (settings, commands, privileges, junos).") ||
		!strings.Contains(out, "Review with: tacctl group show operator") {
		t.Fatalf("%d\n%s\n%s", sb.code, out, sb.err.String())
	}
	if sb.snapshots() != snaps+1 {
		t.Errorf("snapshots %d -> %d: the pre-change snapshot", snaps, sb.snapshots())
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "group reset name=operator sections=settings,commands,privileges,junos by=root") {
		t.Errorf("no audit line: %q", sb.runner.Argvs())
	}
	// The group, its users and its builtin flag are what they were.
	store := sb.store()
	if !strings.Contains(store, "operator: {priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}") || !strings.Contains(store, "group: operator") {
		t.Errorf("store:\n%s", store)
	}
	if strings.Contains(sb.overrides(), "operator") {
		t.Errorf("tacctl.yaml still holds the operator's settings:\n%s", sb.overrides())
	}
	// SUDO_USER names the user in the audit line.
	sb.modify("readonly")
	sb.cfgRun("", []string{"group", "reset", "readonly", "--yes", "--only", "commands"}, nil, "SUDO_USER=carol")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "group reset name=readonly sections=commands by=carol") {
		t.Errorf("audit line: %q", sb.runner.Argvs())
	}
}

// --only limits the reset to the sections named: the others are left as
// they were (a second, full dry run shows them still), the audit line lists
// the sections that changed.
func TestGroupResetOnlySections(t *testing.T) {
	all := []string{"settings", "commands", "privileges", "junos"}
	for _, only := range [][]string{{"settings"}, {"commands"}, {"privileges"}, {"junos"}, {"settings", "junos"}, {"junos", "commands"}} {
		t.Run(strings.Join(only, ","), func(t *testing.T) {
			sb := newSandbox(t, true)
			sb.modify("operator")
			// Another group's settings are never touched.
			sb.must("group", "edit", "readonly", "wti-level", "user")
			out := sb.plainRun("", "group", "reset", "operator", "--only", strings.Join(only, ","), "--dry-run")
			for _, s := range all {
				want := slices.Contains(only, s)
				if got := strings.Contains(out, "  "+s+"\n"); got != want {
					t.Errorf("--only %v: section %s shown %v\n%s", only, s, got, out)
				}
			}
			sb.must("group", "reset", "operator", "--only", strings.Join(only, ","), "--yes")
			want := slices.DeleteFunc(slices.Clone(all), func(s string) bool { return !slices.Contains(only, s) })
			if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "group reset name=operator sections="+strings.Join(want, ",")+" by=root") {
				t.Errorf("audit line: %q", sb.runner.Argvs())
			}
			rest := sb.plainRun("", "group", "reset", "operator", "--dry-run")
			for _, s := range all {
				unchanged := strings.Contains(rest, "  "+s+"\n    unchanged\n")
				if unchanged != slices.Contains(only, s) {
					t.Errorf("--only %v: afterwards section %s unchanged = %v\n%s", only, s, unchanged, rest)
				}
			}
			if out := sb.plainRun("", "group", "reset", "operator", "--only", strings.Join(only, ",")); !strings.Contains(out, "is already canonical ("+strings.Join(want, ", ")+"); nothing to change.") {
				t.Errorf("again: %q", out)
			}
			if show := sb.plainRun("", "group", "show", "readonly"); !strings.Contains(show, "User (set;") {
				t.Errorf("readonly:\n%s", show)
			}
		})
	}
}

// At a terminal the prompt is asked: n changes nothing, y applies.
func TestGroupResetPrompt(t *testing.T) {
	sb := newSandbox(t, true)
	sb.modify("operator")
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()
	sb.tty = slave
	state, snaps := sb.state(), sb.snapshots()
	for _, answer := range []string{"n\n", "\n", "no\n"} {
		if _, err := master.WriteString(answer); err != nil {
			t.Fatal(err)
		}
		out := sb.plainRun("", "group", "reset", "operator")
		if sb.code != 0 || !strings.Contains(out, "Reset of group 'operator'") || !strings.Contains(out, "[INFO] Aborted.") ||
			!strings.Contains(plain(sb.err.String()), "Apply these changes to group 'operator'? [y/N]: ") {
			t.Errorf("answer %q: %d\n%s\n%s", answer, sb.code, out, sb.err.String())
		}
		if sb.state() != state || sb.snapshots() != snaps || sb.runner.Called("logger") {
			t.Errorf("answer %q changed something", answer)
		}
	}
	if _, err := master.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	out := sb.plainRun("", "group", "reset", "operator")
	if sb.code != 0 || !strings.Contains(out, "[INFO] Group 'operator' reset (") || sb.state() == state {
		t.Errorf("y: %d\n%s\n%s", sb.code, out, sb.err.String())
	}
	if out := sb.plainRun("", "group", "reset", "operator"); !strings.Contains(out, "is already canonical") {
		t.Errorf("after: %q", out)
	}
}

// The lowered tier of a reset syncs this server's accounts (WP10.2f), like
// 'group edit tier'; a reset that lowers none does not.
func TestGroupResetLoweredTierSyncsTheServer(t *testing.T) {
	synced := "syncing this server's accounts (authsrv)."
	setup := func() *hostSandbox {
		hs := hostLowerSandbox(t)
		// A group called engineer at priv-lvl 15 with the superuser tier
		// recorded; bob in it is a superuser until the reset.
		for _, a := range [][]string{{"group", "add", "engineer", "15", "EN-CLASS"}, {"user", "move", "bob", "engineer"}} {
			if hs.run(nil, a...); hs.code != 0 {
				t.Fatalf("%v: %d %q", a, hs.code, hs.err.String())
			}
		}
		return hs
	}
	hs := setup()
	r := hs.lowerRunner()
	hs.run(r, "group", "reset", "engineer", "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, synced) || !r.Called("bash") || strings.Contains(all, "keep their old groups") {
		t.Errorf("reset: exit %d, synced %v\n%s", hs.code, r.Called("bash"), all)
	}
	// A failing sync says who is left; the reset stands.
	hs = setup()
	r = hs.lowerRunner()
	r.On([]string{"bash"}, execx.Result{Code: 1})
	hs.run(r, "group", "reset", "engineer", "--yes")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || !strings.Contains(all, "Members of 'engineer' keep their old groups on this server until: tacctl host sync authsrv") {
		t.Errorf("failing sync: exit %d\n%s", hs.code, all)
	}
	if show := plain(hs.run(nil, "group", "show", "engineer")); !strings.Contains(show, "tacctl tier:       engineer (set;") {
		t.Errorf("the reset did not stand:\n%s", show)
	}
	// operator: bob is in it and its tier stays: nothing to sync.
	hs = hostLowerSandbox(t)
	hs.run(nil, "group", "edit", "operator", "juniper-class", "NEW-CLASS")
	r = hs.lowerRunner()
	hs.run(r, "group", "reset", "operator", "--yes")
	if all = plain(hs.out.String() + hs.err.String()); hs.code != 0 || r.Called("bash") || strings.Contains(all, synced) {
		t.Errorf("no lowering: exit %d\n%s", hs.code, all)
	}
	// A priv-lvl reset that lowers the band: operator at 15 reset to 7.
	hs = hostLowerSandbox(t)
	hs.run(nil, "group", "edit", "operator", "priv-lvl", "15")
	hs.run(nil, "group", "edit", "operator", "tier", "superuser")
	r = hs.lowerRunner()
	hs.run(r, "group", "reset", "operator", "--yes")
	if all = plain(hs.out.String() + hs.err.String()); hs.code != 0 || !r.Called("bash") || !strings.Contains(all, synced) ||
		!strings.Contains(all, "the tier of its 1 user(s) falls from superuser to operator; this server's accounts are synced after the reset") {
		t.Errorf("operator at 15: exit %d\n%s", hs.code, all)
	}
}

// The lockout guard (D16): a group that ends with command rules does not
// leave a sibling at its priv-lvl without any; a group left without rules at
// its level is warned about.
func TestGroupResetLockoutGuard(t *testing.T) {
	sb := newSandbox(t, true)
	// noc has rules of its own (setting them seeds the groups at its level,
	// so helpdesk is added after).
	sb.must("group", "add", "noc", "7", "NOC-CLASS")
	sb.must("group", "commands", "default", "noc", "deny")
	sb.must("group", "add", "helpdesk", "7", "HD-CLASS")
	sb.must("group", "edit", "operator", "priv-lvl", "10")
	out := sb.plainRun("", "group", "reset", "operator", "--dry-run")
	if !strings.Contains(out, "Groups at priv-lvl 7 without command rules get a permit-* catchall, so that Cisco does not deny them every command: helpdesk\n") ||
		strings.Contains(out, "noc") {
		t.Errorf("dry run:\n%s", out)
	}
	if rules := sb.plainRun("", "group", "commands", "list", "helpdesk"); !strings.Contains(rules, "no commands") {
		t.Errorf("a dry run seeded helpdesk:\n%s", rules)
	}
	out = sb.plainRun("", "group", "reset", "operator", "--yes")
	if !strings.Contains(out, "[INFO] Auto-seeded permit-* catchall on sibling groups at priv-lvl 7: helpdesk") {
		t.Errorf("apply:\n%s", out)
	}
	if rules := sb.plainRun("", "group", "commands", "list", "helpdesk"); !strings.Contains(rules, "* (catchall)") || !strings.Contains(rules, "Default action: permit") {
		t.Errorf("helpdesk:\n%s", rules)
	}
	if rules := sb.plainRun("", "group", "commands", "list", "noc"); !strings.Contains(rules, "Default action: deny") {
		t.Errorf("noc was touched:\n%s", rules)
	}
	// Only settings are reset and the group has no rules of its own: the
	// level's authorization line would be left out.
	sb = newSandbox(t, true)
	sb.must("group", "add", "engineer", "10", "EN-CLASS")
	out = sb.plainRun("", "group", "reset", "engineer", "--only", "settings", "--dry-run")
	if !strings.Contains(out, "warning: group 'engineer' has no command rules at priv-lvl 15, so tacctl config cisco leaves 'aaa authorization commands 15' commented out; run: tacctl group commands default engineer permit") {
		t.Errorf("no warning:\n%s", out)
	}
}

// The warnings of the diff.
func TestGroupResetWarnings(t *testing.T) {
	sb := newSandbox(t, true)
	sb.must("group", "edit", "operator", "priv-lvl", "9")
	out := sb.plainRun("", "group", "reset", "operator", "--dry-run")
	if !strings.Contains(out, "warning: Cisco logins and the per-level authorization lines change; re-paste tacctl config cisco\n") ||
		strings.Contains(out, "re-paste tacctl config juniper") {
		t.Errorf("priv-lvl:\n%s", out)
	}
	sb.must("group", "edit", "operator", "juniper-class", "NEW-CLASS")
	out = sb.plainRun("", "group", "reset", "operator", "--dry-run")
	if !strings.Contains(out, "warning: the Junos template user of the class changes; re-paste tacctl config juniper Step 1\n") ||
		!strings.Contains(out, "Cisco priv-lvl:  9 -> 7\n") || !strings.Contains(out, "Juniper class:   NEW-CLASS -> OP-CLASS\n") {
		t.Errorf("class:\n%s", out)
	}
	// Only a class: no Cisco warning.
	sb.must("group", "reset", "operator", "--only", "settings", "--yes")
	sb.must("group", "edit", "operator", "juniper-class", "NEW-CLASS")
	out = sb.plainRun("", "group", "reset", "operator", "--dry-run")
	if strings.Contains(out, "re-paste tacctl config cisco") || !strings.Contains(out, "re-paste tacctl config juniper Step 1") {
		t.Errorf("class only:\n%s", out)
	}
}

// D48: a reset writes group state, so no Engineer row opens it; the gate, the
// shell's lists and the sudoers rules agree.
func TestGroupResetIsTheSuperusersAlone(t *testing.T) {
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer} {
		if tier.Permits(tr, "group", "reset") {
			t.Errorf("tier %s may run group reset", tr)
		}
	}
	if !tier.Permits(tier.Superuser, "group", "reset") {
		t.Error("the superuser may not run group reset")
	}
	// No row grants group reset (or every group verb) to a tier below the
	// superuser, whatever the second word: --dry-run is the gate's two words too.
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer} {
		if ruleAllows(tr, "group", "reset") {
			t.Errorf("a row of tier.Rules grants group reset to %s", tr)
		}
	}
	for _, r := range tier.Rules {
		if r.Cmd == "group" && (r.AnySub || r.Sub == "reset") && r.Tier != tier.Superuser {
			t.Errorf("a row opens group reset below the superuser: %+v", r)
		}
		if r.Cmd == "group" && r.Tier == tier.Engineer {
			t.Errorf("an Engineer row for group: %+v", r)
		}
		for _, s := range r.Sudoers {
			if strings.Contains(s, "group reset") {
				t.Errorf("a sudoers rule for group reset: %q in %+v", s, r)
			}
		}
	}
	// The engineer's run is refused by the gate and changes nothing.
	sb := engineerSandbox(t)
	before := watchedFiles(t, filepath.Join(sb.dir, "state"))
	for _, args := range [][]string{{"group", "reset", "operator", "--yes"}, {"group", "reset", "engineer", "--dry-run"},
		{"group", "reset", "engineer", "--preset", "--only", "settings", "--yes"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl group reset' is not permitted for the engineer tier.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if after := watchedFiles(t, filepath.Join(sb.dir, "state")); !reflect.DeepEqual(before, after) {
		t.Error("a refused reset changed the state")
	}

	// The shell and the console list it for the superuser only.
	for _, v := range viewCases {
		t.Run(v.name, func(t *testing.T) {
			inv, root := viewInv(t, v.view)
			listed := slices.Contains(words(inv.shellCompleter(root)([]string{"group"}, "")), "reset")
			if want := v.all; listed != want {
				t.Errorf("group reset listed %v for %s, want %v", listed, v.name, want)
			}
		})
	}
}

func TestGroupResetCompletion(t *testing.T) {
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"group", "reset", ""}, []string{"ops", "admins"}},
		{[]string{"group", "reset", "ops", ""}, []string{"--preset", "--only", "--dry-run", "--yes"}},
		{[]string{"group", "reset", "ops", "--only", ""}, []string{"settings", "commands", "privileges", "junos"}},
		{[]string{"group", "reset", "ops", "--only", "c"}, []string{"commands"}},
		{[]string{"group", "reset", "ops", "--only", "settings,"}, []string{"settings,commands", "settings,privileges", "settings,junos"}},
		{[]string{"group", "reset", "ops", "--preset", "--yes", ""}, []string{"--only", "--dry-run"}},
		{[]string{"group", "reset", "ops", "--p"}, []string{"--preset"}},
	} {
		got, _ := completeWords(t, liveNames, c.words...)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: offered %q, want %q", c.words, got, c.want)
		}
	}
}

func TestDiffSequences(t *testing.T) {
	for _, c := range []struct {
		name                 string
		have, want           []string
		removed, added, move []string
	}{
		{name: "equal", have: []string{"a", "b"}, want: []string{"a", "b"}},
		{name: "removed and added", have: []string{"a", "x", "b"}, want: []string{"a", "b", "y"}, removed: []string{"x"}, added: []string{"y"}},
		{name: "moved once", have: []string{"b", "a", "c"}, want: []string{"a", "b", "c"}, move: []string{"b"}},
		{name: "moved far", have: []string{"a", "b", "c", "d"}, want: []string{"b", "c", "d", "a"}, move: []string{"a"}},
		{name: "duplicates", have: []string{"a", "a", "b"}, want: []string{"a", "b"}, removed: []string{"a"}},
		{name: "from nothing", want: []string{"a"}, added: []string{"a"}},
		{name: "to nothing", have: []string{"a"}, removed: []string{"a"}},
	} {
		removed, added, moved := diffSequences(c.have, c.want)
		if !slices.Equal(removed, c.removed) || !slices.Equal(added, c.added) || !slices.Equal(moved, c.move) {
			t.Errorf("%s: removed %q added %q moved %q, want %q %q %q", c.name, removed, added, moved, c.removed, c.added, c.move)
		}
	}
}

func TestOnlySections(t *testing.T) {
	if got, problem := onlySections(""); problem != "" || !slices.Equal(got, resetSections) {
		t.Errorf("none: %q %q", got, problem)
	}
	if got, problem := onlySections("junos,settings,junos"); problem != "" || !slices.Equal(got, []string{"settings", "junos"}) {
		t.Errorf("two: %q %q", got, problem)
	}
	if _, problem := onlySections("all"); problem != "Unknown section 'all' for --only. Use: settings, commands, privileges, junos" {
		t.Errorf("all: %q", problem)
	}
}
