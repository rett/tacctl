package cli

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/testpty"
	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl group privilege reset' and 'tacctl group commands reset' (WP10.5h):
// 'group reset <group> --only privileges|commands' with the shipped default
// as the canonical state, for any group. The golden diffs are in
// testdata/reset (go test -update-reset rewrites them).

// sectionResetCases are the two verbs.
var sectionResetCases = []struct {
	section string // the section of 'group reset' it equals
	family  string
	prompt  string
	audit   string
}{
	{"privileges", "privilege", "Apply these changes to the privileges of group '%s'? [y/N]: ", "group privilege reset name=%s by=root"},
	{"commands", "commands", "Apply these changes to the command rules of group '%s'? [y/N]: ", "group commands reset name=%s by=root"},
}

func TestSectionResetGoldenDiffs(t *testing.T) {
	t.Run("privilege", func(t *testing.T) {
		sb := newSandbox(t, true)
		for _, g := range []string{"readonly", "operator", "superuser"} {
			if out := sb.plainRun("", "group", "privilege", "reset", g, "--dry-run"); sb.code != 0 ||
				!strings.Contains(out, "Group '"+g+"' is already canonical (privileges); nothing to change.") {
				t.Errorf("fresh %s: %d %q", g, sb.code, out)
			}
		}
		// A modified list: an entry added, a shipped one gone.
		sb.must("group", "privilege", "add", "operator", "show version,configure: router bgp")
		sb.must("group", "privilege", "remove", "operator", "clear counters")
		golden(t, "privilege_operator_modified", sb.plainRun("", "group", "privilege", "reset", "operator", "--dry-run"))
		// A built-in with the stored empty list 0.1.16's clear left.
		sb.must("group", "privilege", "remove", "readonly", "show running-config")
		if o := sb.overrides(); !strings.Contains(o, "readonly: []") {
			t.Fatalf("no stored empty list:\n%s", o)
		}
		golden(t, "privilege_readonly_stored_empty", sb.plainRun("", "group", "privilege", "reset", "readonly", "--dry-run"))
		// A custom group: no shipped list, the override goes.
		sb.must("group", "add", "helpdesk", "5", "HD-CLASS")
		sb.must("group", "privilege", "add", "helpdesk", "show clock,exec all: ping")
		golden(t, "privilege_custom_override", sb.plainRun("", "group", "privilege", "reset", "helpdesk", "--dry-run"))
	})
	t.Run("commands", func(t *testing.T) {
		sb := newSandbox(t, true)
		for _, g := range []string{"readonly", "operator", "superuser"} {
			if out := sb.plainRun("", "group", "commands", "reset", g, "--dry-run"); sb.code != 0 ||
				!strings.Contains(out, "Group '"+g+"' is already canonical (commands); nothing to change.") {
				t.Errorf("fresh %s: %d %q", g, sb.code, out)
			}
		}
		for _, args := range resetModifiers["operator"][:4] {
			sb.must(args...)
		}
		golden(t, "commands_operator_modified", sb.plainRun("", "group", "commands", "reset", "operator", "--dry-run"))
		// A custom group: the override goes, the group has no rules.
		sb.must("group", "add", "helpdesk", "5", "HD-CLASS")
		sb.must("group", "commands", "add", "helpdesk", "show")
		sb.must("group", "commands", "default", "helpdesk", "deny")
		golden(t, "commands_custom_override", sb.plainRun("", "group", "commands", "reset", "helpdesk", "--dry-run"))
		// The engineer is not built in: its reset removes the override, and
		// takes no --preset.
		sb.must("group", "reset", "engineer", "--yes")
		sb.must("group", "commands", "add", "engineer", "extra", "--action", "deny", "--match", "^(x)$")
		golden(t, "commands_engineer_override", sb.plainRun("", "group", "commands", "reset", "engineer", "--dry-run"))
	})
}

// The reset of a section equals 'group reset <group> --only <section>' for a
// built-in group: the same diff lines and the same state afterwards.
func TestSectionResetEqualsGroupResetOnly(t *testing.T) {
	// The lines of the section a diff prints, without the heading, the
	// warnings and the device lines only 'privilege reset' adds.
	body := func(out string) string {
		var keep []string
		for _, l := range strings.Split(out, "\n") {
			switch {
			case strings.HasPrefix(l, "Reset of"), strings.HasPrefix(l, "─"), strings.HasPrefix(l, "-"), strings.HasPrefix(l, "="),
				strings.Contains(l, "warning: devices keep"), strings.HasPrefix(strings.TrimSpace(l), "no privilege "),
				strings.HasPrefix(l, "[INFO]"), l == "":
			default:
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	for _, c := range sectionResetCases {
		for _, g := range []string{"readonly", "operator", "superuser"} {
			t.Run(c.section+"/"+g, func(t *testing.T) {
				mods := [][]string{{"group", "privilege", "add", g, "show version"}, {"group", "commands", "add", g, "reload", "--action", "deny"}}
				a, b := newSandbox(t, true), newSandbox(t, true)
				for _, sb := range []*sandbox{a, b} {
					for _, m := range mods {
						sb.must(m...)
					}
				}
				da := a.plainRun("", "group", c.family, "reset", g, "--dry-run")
				db := b.plainRun("", "group", "reset", g, "--only", c.section, "--dry-run")
				if body(da) != body(db) || !strings.Contains(da, "\n  "+c.section+"\n") {
					t.Errorf("diffs differ:\n--- section reset\n%s\n--- group reset\n%s", da, db)
				}
				a.must("group", c.family, "reset", g, "--yes")
				b.must("group", "reset", g, "--only", c.section, "--yes")
				if a.state() != b.state() {
					t.Errorf("states differ:\n--- section reset\n%s\n--- group reset\n%s", a.state(), b.state())
				}
				// The other section is as it was.
				other := "privilege"
				if c.family == "privilege" {
					other = "commands"
				}
				if out := a.plainRun("", "group", other, "reset", g, "--dry-run"); strings.Contains(out, "already canonical") {
					t.Errorf("the other section was reset too:\n%s", out)
				}
			})
		}
	}
}

func TestSectionResetRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.must("group", "add", "helpdesk", "5", "HD-CLASS")
	sb.must("group", "commands", "add", "helpdesk", "show")
	sb.must("group", "privilege", "add", "helpdesk", "show clock")
	state, snaps := sb.state(), sb.snapshots()
	for _, c := range sectionResetCases {
		usage := "Usage: tacctl group " + c.family + " reset <group> [--dry-run] [--yes]"
		for _, k := range []struct {
			name string
			args []string
			err  string
		}{
			{"missing group", []string{"ghost", "--yes"}, "[ERROR] Group 'ghost' does not exist."},
			{"no group", nil, usage},
			{"two groups", []string{"operator", "readonly"}, usage},
			{"--preset", []string{"operator", "--preset"}, usage},
			{"--only", []string{"operator", "--only", c.section}, usage},
		} {
			sb.run("", append([]string{"group", c.family, "reset"}, k.args...))
			if sb.code != 1 || !strings.Contains(sb.stderr(), k.err) {
				t.Errorf("%s %s: exit %d, stderr %q", c.family, k.name, sb.code, sb.stderr())
			}
		}
		// No terminal and no --yes: the diff is shown, nothing changes. A
		// piped 'y' is not a confirmation.
		out := sb.plainRun("y\n", "group", c.family, "reset", "helpdesk")
		if sb.code != 1 || !strings.Contains(out, "\n  "+c.section+"\n") ||
			!strings.Contains(sb.stderr(), "No terminal to confirm on; nothing was changed. Review with --dry-run, then run again with --yes.") {
			t.Errorf("%s no terminal: %d\n%s\n%s", c.family, sb.code, out, sb.stderr())
		}
	}
	if sb.state() != state || sb.snapshots() != snaps || sb.runner.Called("logger") {
		t.Error("a refusal changed something")
	}
}

// The removed 'clear' answers like any unknown subcommand.
func TestSectionResetClearIsGone(t *testing.T) {
	sb := newSandbox(t, true)
	state := sb.state()
	for _, c := range []struct{ family, usage string }{{"privilege", groupPrivilegeUsage()}, {"commands", groupCommandsUsage(sb.path("state", "tacctl.yaml"))}} {
		for _, args := range [][]string{{"group", c.family, "clear", "operator"}, {"group", c.family, "clear"}, {"group", c.family, "bogus", "operator"}} {
			out := sb.run("y\n", args)
			if sb.code != 1 || !strings.Contains(sb.stderr(), "Unknown subcommand: '"+args[2]+"'") || !strings.Contains(plain(out), "tacctl group "+c.family+" reset <group> [--dry-run] [--yes]") {
				t.Errorf("%v: exit %d, stderr %q\n%s", args, sb.code, sb.stderr(), out)
			}
			if strings.Contains(plain(out), " clear <group>") {
				t.Errorf("%v: the usage still names clear:\n%s", args, out)
			}
		}
	}
	if sb.state() != state {
		t.Error("changed something")
	}
}

func TestSectionResetDryRunWritesNothing(t *testing.T) {
	sb := newSandbox(t, true)
	sb.modify("operator")
	storeBefore, yamlBefore := sb.store(), sb.overrides()
	live, snaps := sb.liveState(), sb.snapshots()
	for _, c := range sectionResetCases {
		for _, args := range [][]string{
			{"group", c.family, "reset", "operator", "--dry-run"},
			{"group", c.family, "reset", "operator", "--dry-run", "--yes"},
			{"group", c.family, "reset", "readonly", "--dry-run"},
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
}

func TestSectionResetYesAppliesAndLogs(t *testing.T) {
	for _, c := range sectionResetCases {
		t.Run(c.family, func(t *testing.T) {
			sb := newSandbox(t, true)
			sb.modify("operator")
			sb.must("group", "add", "helpdesk", "5", "HD-CLASS")
			sb.must("group", "commands", "add", "helpdesk", "show")
			sb.must("group", "privilege", "add", "helpdesk", "show clock")
			snaps := sb.snapshots()
			out := sb.plainRun("", "group", c.family, "reset", "operator", "--yes")
			if sb.code != 0 || !strings.Contains(out, "[INFO] Group 'operator': the ") || !strings.Contains(out, "are back to the shipped default.") ||
				!strings.Contains(out, "Review with: tacctl group "+c.family+" list operator") {
				t.Fatalf("%d\n%s\n%s", sb.code, out, sb.err.String())
			}
			if sb.snapshots() != snaps+1 {
				t.Errorf("snapshots %d -> %d: the pre-change snapshot", snaps, sb.snapshots())
			}
			if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", strings.Replace(c.audit, "%s", "operator", 1)) {
				t.Errorf("no audit line: %q", sb.runner.Argvs())
			}
			// Idempotent: nothing to change, no snapshot, no log line.
			sb.runner.Reset()
			snaps = sb.snapshots()
			out = sb.plainRun("", "group", c.family, "reset", "operator", "--yes")
			if sb.code != 0 || !strings.Contains(out, "Group 'operator' is already canonical ("+c.section+"); nothing to change.") ||
				sb.snapshots() != snaps || sb.runner.Called("logger") {
				t.Errorf("again: %d %q", sb.code, out)
			}
			// The other section of operator is left as it was.
			other := "commands"
			if c.family == "commands" {
				other = "privileges"
			}
			if o := sb.overrides(); !strings.Contains(o, other+":") {
				t.Errorf("the %s of operator were dropped:\n%s", other, o)
			}
			// A custom group's override is removed, not stored empty.
			out = sb.plainRun("", "group", c.family, "reset", "helpdesk", "--yes")
			if sb.code != 0 || !strings.Contains(out, "the override of its ") || !strings.Contains(out, "none are shipped for it, so it has none.") {
				t.Fatalf("helpdesk: %d\n%s\n%s", sb.code, out, sb.err.String())
			}
			o := sb.overrides()
			if strings.Contains(o, "[]") || strings.Contains(o, "  helpdesk:") && strings.Contains(o, c.section+":\n  helpdesk") {
				t.Errorf("an empty override is stored:\n%s", o)
			}
			if c.section == "privileges" && strings.Contains(o, "show clock") || c.section == "commands" && strings.Contains(o, "helpdesk:") && strings.Contains(o, "name: show") {
				t.Errorf("the override is still there:\n%s", o)
			}
			if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", strings.Replace(c.audit, "%s", "helpdesk", 1)) {
				t.Errorf("no audit line for helpdesk: %q", sb.runner.Argvs())
			}
			// SUDO_USER names the user.
			sb.must("group", c.family, "reset", "operator", "--yes")
			sb.modify("readonly")
			sb.cfgRun("", []string{"group", c.family, "reset", "readonly", "--yes"}, nil, "SUDO_USER=carol")
			if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", strings.Replace(strings.Replace(c.audit, "%s", "readonly", 1), "by=root", "by=carol", 1)) {
				t.Errorf("audit line: %q", sb.runner.Argvs())
			}
		})
	}
}

// A group whose privileges override is the empty list 0.1.16 stored is
// shown as a change to the shipped default, and the reset removes it.
func TestPrivilegeResetStoredEmptyList(t *testing.T) {
	sb := newSandbox(t, true)
	sb.must("group", "privilege", "remove", "readonly", "show running-config")
	out := sb.plainRun("", "group", "privilege", "reset", "readonly", "--yes")
	if sb.code != 0 || !strings.Contains(out, "    + show running-config\n") {
		t.Fatalf("%d\n%s", sb.code, out)
	}
	if o := sb.overrides(); strings.Contains(o, "readonly") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	if list := sb.plainRun("", "group", "privilege", "list", "readonly"); !strings.Contains(list, "Source: default") {
		t.Errorf("list:\n%s", list)
	}
}

// Entries a reset removes are on the devices: the diff says how to take
// them off.
func TestPrivilegeResetDeviceLines(t *testing.T) {
	sb := newSandbox(t, true)
	sb.must("group", "privilege", "add", "operator", "show version,configure: router bgp,exec all: show ip")
	out := sb.plainRun("", "group", "privilege", "reset", "operator", "--dry-run")
	for _, want := range []string{
		"warning: devices keep the old 'privilege exec level 7 ...' lines until you re-paste tacctl config cisco and remove them (no privilege exec level 7 ...):\n",
		"      no privilege exec level 7 show version\n",
		"      no privilege configure level 7 router bgp\n",
		"      no privilege exec all level 7 show ip\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	// Nothing removed, nothing to remove from a device.
	sb.must("group", "privilege", "remove", "operator", "clear counters")
	sb.must("group", "privilege", "reset", "operator", "--yes")
	sb.must("group", "privilege", "remove", "operator", "clear counters")
	out = sb.plainRun("", "group", "privilege", "reset", "operator", "--dry-run")
	if strings.Contains(out, "devices keep") || !strings.Contains(out, "    + clear counters\n") {
		t.Errorf("added only:\n%s", out)
	}
}

// At a terminal the prompt is asked: n changes nothing, y applies.
func TestSectionResetPrompt(t *testing.T) {
	for _, c := range sectionResetCases {
		t.Run(c.family, func(t *testing.T) {
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
				out := sb.plainRun("", "group", c.family, "reset", "operator")
				if sb.code != 0 || !strings.Contains(out, "Reset of the ") || !strings.Contains(out, "[INFO] Aborted.") ||
					!strings.Contains(plain(sb.err.String()), strings.Replace(c.prompt, "%s", "operator", 1)) {
					t.Errorf("answer %q: %d\n%s\n%s", answer, sb.code, out, sb.err.String())
				}
				if sb.state() != state || sb.snapshots() != snaps || sb.runner.Called("logger") {
					t.Errorf("answer %q changed something", answer)
				}
			}
			if _, err := master.WriteString("y\n"); err != nil {
				t.Fatal(err)
			}
			out := sb.plainRun("", "group", c.family, "reset", "operator")
			if sb.code != 0 || !strings.Contains(out, "are back to the shipped default.") || sb.state() == state {
				t.Errorf("y: %d\n%s\n%s", sb.code, out, sb.err.String())
			}
			if out := sb.plainRun("", "group", c.family, "reset", "operator"); !strings.Contains(out, "already canonical") {
				t.Errorf("after: %q", out)
			}
		})
	}
}

// The lockout guard of the rules: the reset seeds a sibling without rules at
// the priv-lvl as 'group reset' does, and a group left without any warns.
func TestCommandsResetLockoutGuard(t *testing.T) {
	sb := newSandbox(t, true)
	sb.must("group", "commands", "add", "operator", "configure", "--action", "permit")
	sb.must("group", "add", "helpdesk", "7", "HD-CLASS")
	out := sb.plainRun("", "group", "commands", "reset", "operator", "--dry-run")
	want := "Groups at priv-lvl 7 without command rules get a permit-* catchall, so that Cisco does not deny them every command: helpdesk\n"
	if !strings.Contains(out, want) {
		t.Errorf("dry run:\n%s", out)
	}
	if rules := sb.plainRun("", "group", "commands", "list", "helpdesk"); !strings.Contains(rules, "no commands") {
		t.Errorf("a dry run seeded helpdesk:\n%s", rules)
	}
	out = sb.plainRun("", "group", "commands", "reset", "operator", "--yes")
	if !strings.Contains(out, "[INFO] Auto-seeded permit-* catchall on sibling groups at priv-lvl 7: helpdesk") {
		t.Errorf("apply:\n%s", out)
	}
	if rules := sb.plainRun("", "group", "commands", "list", "helpdesk"); !strings.Contains(rules, "Default action: permit") {
		t.Errorf("helpdesk:\n%s", rules)
	}
	// The same through group reset.
	sb2 := newSandbox(t, true)
	sb2.must("group", "commands", "add", "operator", "configure", "--action", "permit")
	sb2.must("group", "add", "helpdesk", "7", "HD-CLASS")
	if out2 := sb2.plainRun("", "group", "reset", "operator", "--only", "commands", "--dry-run"); !strings.Contains(out2, want) {
		t.Errorf("group reset:\n%s", out2)
	}
	// A custom group whose rules go has none: the level's authorization line
	// would be left out.
	sb3 := newSandbox(t, true)
	sb3.must("group", "add", "noc", "10", "NOC-CLASS")
	sb3.must("group", "commands", "add", "noc", "show")
	out = sb3.plainRun("", "group", "commands", "reset", "noc", "--dry-run")
	if !strings.Contains(out, "warning: group 'noc' has no command rules at priv-lvl 10, so tacctl config cisco leaves 'aaa authorization commands 10' commented out; run: tacctl group commands default noc permit") {
		t.Errorf("no warning:\n%s", out)
	}
}

// Both verbs write group state: no Engineer row, nothing below the
// superuser; the gate, the shell's lists and the sudoers rules agree.
func TestSectionResetIsTheSuperusersAlone(t *testing.T) {
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer} {
		for _, fam := range []string{"privilege", "commands"} {
			if tier.Permits(tr, "group", fam) || ruleAllows(tr, "group", fam) {
				t.Errorf("tier %s may run group %s", tr, fam)
			}
		}
	}
	for _, fam := range []string{"privilege", "commands"} {
		if !tier.Permits(tier.Superuser, "group", fam) {
			t.Errorf("the superuser may not run group %s", fam)
		}
	}
	for _, r := range tier.Rules {
		if r.Cmd == "group" && (r.AnySub || r.Sub == "privilege" || r.Sub == "commands") && r.Tier != tier.Superuser {
			t.Errorf("a row opens group privilege or commands below the superuser: %+v", r)
		}
		for _, s := range r.Sudoers {
			if strings.Contains(s, "group privilege") || strings.Contains(s, "group commands") {
				t.Errorf("a sudoers rule for a group privilege or commands verb: %q in %+v", s, r)
			}
		}
	}
	sb := engineerSandbox(t)
	before := watchedFiles(t, filepath.Join(sb.dir, "state"))
	for _, args := range [][]string{
		{"group", "privilege", "reset", "operator", "--yes"}, {"group", "privilege", "reset", "operator", "--dry-run"},
		{"group", "commands", "reset", "operator", "--yes"}, {"group", "commands", "reset", "operator", "--dry-run"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl group "+args[1]+"' is not permitted for the engineer tier.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if after := watchedFiles(t, filepath.Join(sb.dir, "state")); !reflect.DeepEqual(before, after) {
		t.Error("a refused reset changed the state")
	}
	// The shell lists the verbs of the families for the superuser only.
	for _, v := range viewCases {
		t.Run(v.name, func(t *testing.T) {
			inv, root := viewInv(t, v.view)
			for _, fam := range []string{"privilege", "commands"} {
				listed := slices.Contains(words(inv.shellCompleter(root)([]string{"group", fam}, "")), "reset")
				if listed != v.all {
					t.Errorf("group %s reset listed %v for %s, want %v", fam, listed, v.name, v.all)
				}
			}
		})
	}
}

func TestSectionResetCompletion(t *testing.T) {
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"group", "privilege", "reset", ""}, []string{"ops", "admins"}},
		{[]string{"group", "privilege", "reset", "ops", ""}, []string{"--dry-run", "--yes"}},
		{[]string{"group", "privilege", "reset", "ops", "--y"}, []string{"--yes"}},
		{[]string{"group", "commands", "reset", ""}, []string{"ops", "admins"}},
		{[]string{"group", "commands", "reset", "ops", ""}, []string{"--dry-run", "--yes"}},
		{[]string{"group", "commands", "reset", "ops", "--dry-run", ""}, []string{"--yes"}},
		{[]string{"group", "privilege", "re"}, []string{"remove", "reset"}},
		{[]string{"group", "commands", "re"}, []string{"remove", "reset"}},
		{[]string{"group", "privilege", "cl"}, nil},
		{[]string{"group", "commands", "cl"}, nil},
		{[]string{"group", "privilege", ""}, []string{"add", "list", "remove", "reset", "seed"}},
		{[]string{"group", "commands", ""}, []string{"add", "default", "list", "remove", "reset", "seed"}},
	} {
		got, _ := completeWords(t, liveNames, c.words...)
		if !reflect.DeepEqual(got, c.want) && (len(got) != 0 || len(c.want) != 0) {
			t.Errorf("%q: offered %q, want %q", c.words, got, c.want)
		}
	}
}
