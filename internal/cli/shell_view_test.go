package cli

// The shell and the console list what the caller's tier can run (D56).

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/shell"
	"github.com/rett/tacctl/internal/tier"
)

// viewCases are the views the lists are tested for: the tier the root side
// answered, the tier whose Rules decide, and whether everything is listed.
var viewCases = []struct {
	name string
	view tier.Tier
	eff  tier.Tier
	all  bool
}{
	{"readonly", tier.Readonly, tier.Readonly, false},
	{"operator", tier.Operator, tier.Operator, false},
	{"engineer", tier.Engineer, tier.Engineer, false},
	{"superuser", tier.Superuser, tier.Superuser, true},
	{"unrestricted", tier.Unrestricted, tier.Unrestricted, true},
	// A caller who cannot be classified (no answer yet, or none that can be
	// read) sees the read-only verbs only.
	{"unread", viewUnread, tier.Readonly, false},
	{"unknown", tier.Tier("wizard"), tier.Readonly, false},
	// A caller the root side answered has no tier (a disabled account) sees
	// no verb at all.
	{"none", tier.None, tier.None, false},
}

// ruleAllows is tier.Rules read directly (not through tier.Permits): the
// rows open to t, for the two words of the gate.
func ruleAllows(t tier.Tier, cmd, sub string) bool {
	for _, r := range tier.Rules {
		if tier.Covers(t, r) && r.Cmd == cmd && (r.AnySub || r.Sub == sub) {
			return true
		}
	}
	return false
}

func viewInv(t *testing.T, view tier.Tier) (*invocation, *cobra.Command) {
	t.Helper()
	inv, root, _ := shellTestInv(t)
	inv.view = func() tier.Tier { return view }
	return inv, root
}

func sortedWords(cs []shell.Candidate) []string {
	w := words(cs)
	sort.Strings(w)
	return w
}

func visibleChildren(c *cobra.Command) []string {
	var out []string
	for _, s := range c.Commands() {
		if !s.Hidden {
			out = append(out, s.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Every verb of the completion tree is listed for a tier if and only if
// tier.Rules let that tier run it: hidden-iff-denied, for every tier and
// every command. A new verb, a new row or a change of the lists that makes
// the two disagree fails here.
func TestViewHidesExactlyWhatTheTierDenies(t *testing.T) {
	for _, v := range viewCases {
		t.Run(v.name, func(t *testing.T) {
			inv, root := viewInv(t, v.view)
			complete := inv.shellCompleter(root)

			// The top level: a verb is listed when the tier may run it or
			// any of its sub-commands.
			var wantTop []string
			for _, r := range topRows() {
				if r.Name == "shell" || child(root, r.Name) == nil {
					continue
				}
				top := child(root, r.Name)
				ok := v.all || (noSudo[r.Name] && v.eff != tier.None) || ruleAllows(v.eff, r.Name, "")
				for _, s := range visibleChildren(top) {
					ok = ok || ruleAllows(v.eff, r.Name, s)
				}
				if ok {
					wantTop = append(wantTop, r.Name)
				}
			}
			sort.Strings(wantTop)
			if got := sortedWords(complete(nil, "")); !slices.Equal(got, wantTop) {
				t.Errorf("top level: listed %q, the rules allow %q", got, wantTop)
			}

			// Each sub-command level: the gate's two words decide; deeper
			// levels follow their second word.
			var walk func(c *cobra.Command, path []string)
			walk = func(c *cobra.Command, path []string) {
				subs := visibleChildren(c)
				if len(subs) == 0 {
					return
				}
				var want []string
				for _, s := range subs {
					ok := v.all
					switch {
					case ok:
					case len(path) == 1:
						ok = ruleAllows(v.eff, path[0], s)
					default:
						ok = ruleAllows(v.eff, path[0], path[1])
					}
					if ok {
						want = append(want, s)
					}
				}
				got := sortedWords(complete(path, ""))
				if !slices.Equal(got, want) {
					t.Errorf("%q: listed %q, the rules allow %q", strings.Join(path, " "), got, want)
				}
				for _, s := range subs {
					walk(child(c, s), append(slices.Clone(path), s))
				}
			}
			for _, r := range topRows() {
				if top := child(root, r.Name); top != nil && r.Name != "shell" {
					walk(top, []string{r.Name})
				}
			}
		})
	}
}

// The tree really exercises the rules: some verb is hidden from each lower
// tier and shown to the next, so the table above cannot pass by listing
// nothing or everything.
func TestViewDiffersByTier(t *testing.T) {
	has := func(view tier.Tier, w []string, want string) bool {
		inv, root := viewInv(t, view)
		return slices.Contains(words(inv.shellCompleter(root)(w, "")), want)
	}
	for _, c := range []struct {
		words      []string
		verb       string
		lowestTier tier.Tier
	}{
		{nil, "store", tier.Superuser},
		{nil, "config", tier.Operator},
		{nil, "host", tier.Engineer},
		{[]string{"user"}, "add", tier.Superuser},
		{[]string{"user"}, "list", tier.Readonly},
		{[]string{"group"}, "junos", tier.Superuser},
		{[]string{"log"}, "tail", tier.Operator},
		{[]string{"device"}, "add", tier.Engineer},
		{[]string{"scope"}, "secret", tier.Engineer},
		{[]string{"scope"}, "add", tier.Superuser},
		{[]string{"host"}, "default-method", tier.Superuser},
		{[]string{"host"}, "show", tier.Engineer},
	} {
		for _, v := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer, tier.Superuser} {
			want := tier.Rank(v) >= tier.Rank(c.lowestTier)
			if got := has(v, c.words, c.verb); got != want {
				t.Errorf("%v %s for %s: listed %v, want %v", c.words, c.verb, v, got, want)
			}
		}
	}
}

// A verb whose sub-verbs the code splits is listed at its two-word level.
func TestViewTwoWordVerbs(t *testing.T) {
	inv, root := viewInv(t, tier.Engineer)
	complete := inv.shellCompleter(root)
	for _, w := range []string{"secret", "show", "staging", "devices"} {
		if !slices.Contains(words(complete([]string{"scope"}, "")), w) {
			t.Errorf("scope %s is not listed for an engineer", w)
		}
	}
	// Its words after the verb are completed as for anyone.
	if got := words(complete([]string{"scope", "secret", "lab"}, "")); !slices.Contains(got, "show") {
		t.Errorf("scope secret <scope> %q lacks show", got)
	}
	// Beyond the two words nothing is hidden by the view: a hidden verb
	// offers nothing at all.
	inv, root = viewInv(t, tier.Operator)
	if got := inv.shellCompleter(root)([]string{"group", "junos"}, "-"); len(got) != 0 {
		t.Errorf("group junos offered %q to an operator", words(got))
	}
	if got := inv.shellCompleter(root)([]string{"user", "add", "x", "ops"}, "--"); len(got) != 0 {
		t.Errorf("user add offered %q to an operator", words(got))
	}
}

// A typed space completes fixed words only: the completer it asks never
// offers a hidden verb, so the space is inserted instead.
func TestViewSpaceCompletionSkipsHiddenVerbs(t *testing.T) {
	fixedFor := func(view tier.Tier, w []string, partial string) []string {
		inv, root := viewInv(t, view)
		var out []string
		for _, c := range inv.shellCompleterFixed(root)(w, partial) {
			if c.Fixed && !c.NoSpace && strings.HasPrefix(c.Word, partial) {
				out = append(out, c.Word)
			}
		}
		return out
	}
	for _, c := range []struct {
		view    tier.Tier
		words   []string
		partial string
		want    []string
	}{
		{tier.Readonly, nil, "sto", nil},
		{tier.Superuser, nil, "sto", []string{"store"}},
		{tier.Readonly, nil, "gr", []string{"group"}},
		{tier.Readonly, []string{"group"}, "ju", nil},
		{tier.Superuser, []string{"group"}, "ju", []string{"junos"}},
		{tier.Operator, []string{"user"}, "ad", nil},
		{tier.Readonly, []string{"user"}, "li", []string{"list"}},
		{viewUnread, []string{"user"}, "li", []string{"list"}},
		{viewUnread, []string{"user"}, "ad", nil},
		{tier.None, []string{"user"}, "li", nil},
		{tier.None, nil, "us", nil},
		{tier.Engineer, []string{"host"}, "en", nil},
		{tier.Engineer, []string{"host"}, "sh", []string{"show"}},
		{tier.Superuser, []string{"host"}, "en", []string{"enroll"}},
		{tier.Operator, []string{"host"}, "en", nil},
	} {
		if got := fixedFor(c.view, c.words, c.partial); !slices.Equal(got, c.want) {
			t.Errorf("%s %v %q: %q, want %q", c.view, c.words, c.partial, got, c.want)
		}
	}
}

// The top-level help lists only what the tier can run, and says so; a
// superuser and the unrestricted caller get the full help.
func TestViewTopHelp(t *testing.T) {
	topFor := func(view tier.Tier) string {
		inv, root := viewInv(t, view)
		got, ok := inv.shellHelp(root, false)(nil)
		if !ok {
			t.Fatal("no help")
		}
		return got
	}
	for _, v := range []tier.Tier{tier.Superuser, tier.Unrestricted} {
		if got := topFor(v); got != shellTop("0.2.1-test", false) {
			t.Errorf("%s: the top-level help is filtered:\n%s", v, got)
		}
	}
	ro := topFor(tier.Readonly)
	for _, want := range []string{"\n  status ", "\n  user <subcommand>", "\n  device <subcommand>", "\n  ssh <name|address>",
		"\n  hash <subcommand>", "\n  completion ", "\n  version ", "\n  shell ", "\n  backend <subcommand>",
		"Shown: the commands the readonly tier can run; help <command> describes all of a command's verbs and the tier each needs.\n",
		"\n  help user\n", "\n  help backend\n", "\nShell:\n  help [<command>]"} {
		if !strings.Contains(ro, want) {
			t.Errorf("readonly help lacks %q:\n%s", want, ro)
		}
	}
	for _, not := range []string{"  install ", "  upgrade ", "  uninstall ", "  store <subcommand>", "  config <subcommand>",
		"  console <subcommand>", "  host <subcommand>", "  log <subcommand>", "  backup <subcommand>", "help config", "Examples:",
		"user add jsmith", "--branch"} {
		if strings.Contains(ro, not) {
			t.Errorf("readonly help has %q:\n%s", not, ro)
		}
	}
	// The option rows of a hidden command go with it.
	if strings.Contains(ro, "-y, --yes") {
		t.Errorf("the options of a hidden command are listed:\n%s", ro)
	}
	op := topFor(tier.Operator)
	for _, want := range []string{"\n  config <subcommand>", "\n  log <subcommand>", "\n  backup <subcommand>", "\n  console <subcommand>", "help config"} {
		if !strings.Contains(op, want) {
			t.Errorf("operator help lacks %q", want)
		}
	}
	if strings.Contains(op, "  host <subcommand>") || strings.Contains(op, "Examples:") {
		t.Errorf("operator help lists what it cannot run:\n%s", op)
	}
	en := topFor(tier.Engineer)
	if !strings.Contains(en, "\n  host <subcommand>") || !strings.Contains(en, "\nExamples:\n  config cisco --scope prod\n") ||
		strings.Contains(en, "user add jsmith") || strings.Contains(en, "  install") {
		t.Errorf("engineer help:\n%s", en)
	}
	// Unclassified: the read-only list, as for the readonly tier.
	if strings.Replace(topFor(viewUnread), "the unread tier", "the readonly tier", 1) != ro && topFor(viewUnread) != ro {
		t.Errorf("unread:\n%s", topFor(viewUnread))
	}
	// A disabled account: no command, the shell's own words remain.
	none := topFor(tier.None)
	for _, want := range []string{"Shown: no command; this account has no tier", "\nShell:\n  help [<command>]"} {
		if !strings.Contains(none, want) {
			t.Errorf("none help lacks %q:\n%s", want, none)
		}
	}
	for _, not := range []string{"\n  user <subcommand>", "\n  status ", "\n  hash ", "\n  version ", "\n  passwd", "Examples:"} {
		if strings.Contains(none, not) {
			t.Errorf("none help has %q:\n%s", not, none)
		}
	}
}

// 'help <command>' describes every verb and ends with the tier each needs.
func TestViewFamilyHelp(t *testing.T) {
	helpFor := func(view tier.Tier, w ...string) string {
		inv, root := viewInv(t, view)
		got, ok := inv.shellHelp(root, false)(w)
		if !ok {
			t.Fatalf("help %q: none", w)
		}
		return got
	}
	for _, v := range []tier.Tier{tier.Readonly, tier.Engineer, tier.Superuser} {
		got := helpFor(v, "group")
		if !strings.HasPrefix(got, groupUsage()) {
			t.Errorf("%s: help group is not the complete usage", v)
		}
		for _, want := range []string{"\nTiers (the lowest tier that may run each group verb):\n",
			"\n  readonly   list, show\n", "\n  superuser  add, commands, edit, junos, preset, privilege, remove, reset\n"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: help group lacks %q:\n%s", v, want, got)
			}
		}
	}
	// A verb below the family is described by the family's block, tiers
	// included; a verb the tier cannot run is still described.
	if got := helpFor(tier.Readonly, "group", "junos"); !strings.Contains(got, "superuser  add,") {
		t.Errorf("help group junos:\n%s", got)
	}
	sc := helpFor(tier.Engineer, "scope")
	for _, want := range []string{"  engineer   devices, secret, show, snmp, staging\n", "  readonly   list\n",
		"scope secret: an engineer may run show for a scope of their own; set and generate need the superuser tier.",
		"An engineer's verbs reach only the devices, hosts and secrets of the scopes the engineer is a member of."} {
		if !strings.Contains(sc, want) {
			t.Errorf("help scope lacks %q:\n%s", want, sc)
		}
	}
	if h := helpFor(tier.Engineer, "host"); !strings.Contains(h, "host show: an engineer reads what tacctl recorded of a host; --check logs in to it and needs the superuser tier.") {
		t.Errorf("help host:\n%s", h)
	}
	if d := helpFor(tier.Engineer, "device"); !strings.Contains(d, "device import: an engineer imports from standard input only (device import -).") {
		t.Errorf("help device:\n%s", d)
	}
	// A command without sub-commands says its tier in one line.
	if got := helpFor(tier.Readonly, "ssh"); !strings.HasSuffix(got, "\nNeeds the readonly tier.\n") {
		t.Errorf("help ssh:\n%s", got)
	}
	// Outside the shell's view (the plain CLI, the tests of the usage) the
	// help is unchanged.
	inv, root, _ := shellTestInv(t)
	if got, _ := inv.shellHelp(root, false)([]string{"group"}); got != groupUsage() {
		t.Errorf("no view: help group is not the usage")
	}
}

// '?' on a verb typed by hand that the tier cannot run still shows its
// usage, and says which tier it needs.
func TestViewExplainNamesTheTier(t *testing.T) {
	explain := func(view tier.Tier, w ...string) string {
		inv, root := viewInv(t, view)
		got, _ := inv.shellExplain(root)(w)
		return got
	}
	if got := explain(tier.Readonly, "group", "junos"); !strings.Contains(got, "Usage:") || !strings.Contains(got, "Needs the superuser tier.\n") {
		t.Errorf("readonly, group junos:\n%s", got)
	}
	if got := explain(tier.Operator, "user", "add"); !strings.Contains(got, "Needs the superuser tier.\nNext: <username> <group>\n") {
		t.Errorf("operator, user add:\n%s", got)
	}
	if got := explain(tier.Superuser, "group", "junos"); strings.Contains(got, "Needs the") {
		t.Errorf("superuser, group junos:\n%s", got)
	}
	if got := explain(tier.Readonly, "device", "show", "x"); strings.Contains(got, "Needs the") {
		t.Errorf("readonly, device show:\n%s", got)
	}
}

// A shell started by a tac-users member asks the root side for the tier the
// gate enforces, once and only when a list or the help needs it; anyone else
// sees everything; an answer that cannot be read lists the read-only verbs.
func TestSetViewAsksThePolicy(t *testing.T) {
	policyRuns := func(h *harness) int { return h.runner.Count("sudo", "-n", testExe, "_console-policy") }
	newInv := func(answer string, fail bool) (*invocation, *harness) {
		h := newHarness(t, nil)
		switch {
		case fail:
			h.runner.Fail([]string{"sudo", "-n", testExe, "_console-policy"}, 1, "sudo: a password is required")
		default:
			h.runner.OnFunc([]string{"sudo", "-n", testExe, "_console-policy"}, func(execx.Cmd) (execx.Result, error) {
				return execx.Result{Stdout: []byte(answer)}, nil
			})
		}
		return &invocation{ctx: t.Context(), app: h.app}, h
	}

	inv, h := newInv("shell=console idle=30 tier=engineer gate=operator list_max=40\n", false)
	inv.setView(shellRun{exe: testExe}, true)
	if n := policyRuns(h); n != 0 {
		t.Errorf("asked before it was needed: %d", n)
	}
	for range 3 {
		if got := inv.view(); got != tier.Operator {
			t.Errorf("view = %q, want the gate's operator", got)
		}
	}
	if n := policyRuns(h); n != 1 {
		t.Errorf("policy asked %d times, want once", n)
	}

	inv, _ = newInv("shell=console idle=30 tier=superuser list_max=40\n", false)
	inv.setView(shellRun{exe: testExe}, true)
	if got := inv.view(); got != tier.Superuser {
		t.Errorf("without a gate field the view = %q, want tier=", got)
	}

	// With the console's marker the line carries it, as the console's does.
	inv, h = newInv("tier=readonly\n", false)
	inv.setView(shellRun{exe: testExe, extraEnv: []string{"TACCTL_CONSOLE=0123456789ab"}}, true)
	inv.view()
	if !h.runner.Called("sudo", "-n", "TACCTL_CONSOLE=0123456789ab", testExe, "_console-policy") {
		t.Errorf("calls %q", h.runner.Argvs())
	}

	// Not readable: the sudo failed, or the answer has no field.
	for _, c := range []struct {
		answer string
		fail   bool
	}{{"", true}, {"", false}, {"garbage\n", false}, {"shell=console idle=30\n", false}} {
		inv, _ = newInv(c.answer, c.fail)
		inv.setView(shellRun{exe: testExe}, true)
		if got := inv.view(); got != viewUnread {
			t.Errorf("answer %q (fail %v): view = %q, want unread", c.answer, c.fail, got)
		}
	}

	// An answer that says tier=none is the answer: a disabled account.
	inv, _ = newInv("shell=system idle=30 tier=none list_max=40\n", false)
	inv.setView(shellRun{exe: testExe}, true)
	if got := inv.view(); got != tier.None {
		t.Errorf("tier=none: view = %q, want none", got)
	}

	// Not a tac-users member: nothing to ask.
	inv, h = newInv("tier=readonly\n", false)
	inv.setView(shellRun{exe: testExe}, false)
	if got := inv.view(); got != tier.Unrestricted || policyRuns(h) != 0 {
		t.Errorf("unmanaged: view %q, asked %d", got, policyRuns(h))
	}

	// The console has its answer already.
	inv, h = newInv("tier=readonly\n", false)
	inv.setView(shellRun{exe: testExe, view: tier.Operator}, true)
	if got := inv.view(); got != tier.Operator || policyRuns(h) != 0 {
		t.Errorf("console: view %q, asked %d", got, policyRuns(h))
	}
}
