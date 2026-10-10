package cli

// What the tacctl shell and the login console list for the caller's tier
// (docs/plans/0.2.3-plan.md D56): Tab, '?', a typed space and the top-level
// 'help' name only the verbs and sub-commands that tier.Permits lets the
// caller's tier run. This is display only. The gate (tier.Gate.Enforce) and
// the sudoers drop-in stay the real check, and a verb typed by hand is still
// answered by them; the lists read the same tier.Rules, so they cannot
// drift (TestViewHidesExactlyWhatTheTierDenies walks the whole tree).
//
// The gate sees two words ('scope secret'), so a verb whose sub-verbs are
// split by code (scope secret show|set|generate, scope staging list|add,
// scope snmp show|set, host show [--check], device import -) shows at its
// two-word level, with a note in its family's help. A caller who cannot be classified (tier none, or the
// policy could not be read) sees the read-only verbs only, never more; the
// unrestricted caller and a superuser see everything. A caller the root side
// answered is 'none' (a disabled account) has no verb at all: the gate
// refuses every one, so the lists show none and the shell's own words
// (help, exit, quit) remain.
//
// The descriptions of the rows that are listed still name the verbs a tier
// cannot run (the 'user' row ends '(list, add, remove, passwd...)'): they
// are the usage's text, which stays complete (D56), not a list of what the
// caller may type; the lists of Tab and '?' are the ones that hide.

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// viewFn answers the tier the lists are for. It never blocks on the root
// side: until the answer is in (or when it could not be had) it answers
// viewUnread.
type viewFn func() tier.Tier

// viewUnread is the view of a caller whose tier is not known (yet): the
// read-only verbs are listed, never more. It is not a tier; tier.None is
// the root side's answer that the account has no tier.
const viewUnread tier.Tier = "unread"

// The lookup of a managed caller's tier in the plain shell: how long the
// root side may take, and how long after a failure the next Tab may try
// again.
const (
	viewTimeout = 3 * time.Second
	viewRetry   = 30 * time.Second
)

// viewOf is the tier whose Rules decide what is listed for t, and whether
// everything is listed. "" (no view) and the tiers that run anything list
// everything; the managed tiers below superuser list their own rows; none
// lists no verb; any other tier (unread) lists the read-only rows.
func viewOf(t tier.Tier) (eff tier.Tier, all bool) {
	switch t {
	case "", tier.Unrestricted, tier.Superuser:
		return t, true
	case tier.Readonly, tier.Operator, tier.Engineer, tier.None:
		return t, false
	}
	return tier.Readonly, false
}

// currentView is the tier of the lists now: eff and all as viewOf, and
// whether the shell has a view at all (false: no filtering, no tier notes).
func (inv *invocation) currentView() (eff tier.Tier, all, active bool) {
	if inv.view == nil {
		return "", true, false
	}
	eff, all = viewOf(inv.view())
	return eff, all, true
}

// viewShows reports whether the lists show the command at path (names
// below root). A top-level verb is shown when the tier may run it or any of
// its sub-commands; a sub-command by the gate's two words, and anything
// deeper with its second-level command. The words that run as the invoking
// user (completion, hash) are shown to all.
func viewShows(root *cobra.Command, eff tier.Tier, all bool, path []string) bool {
	if all || len(path) == 0 {
		return true
	}
	if eff == tier.None {
		return false
	}
	if noSudo[path[0]] {
		return true
	}
	if len(path) >= 2 {
		return tier.Permits(eff, path[0], path[1])
	}
	if tier.Permits(eff, path[0], "") {
		return true
	}
	top := child(root, path[0])
	if top == nil {
		return false
	}
	return slices.ContainsFunc(top.Commands(), func(c *cobra.Command) bool {
		return !c.Hidden && tier.Permits(eff, path[0], c.Name())
	})
}

// viewShowsWords is viewShows for the words of a typed example: the first
// two that name commands.
func viewShowsWords(root *cobra.Command, eff tier.Tier, all bool, words []string) bool {
	if len(words) == 0 {
		return true
	}
	path := []string{words[0]}
	if top := child(root, words[0]); top != nil && len(words) > 1 && child(top, words[1]) != nil {
		path = append(path, words[1])
	}
	return viewShows(root, eff, all, path)
}

// lowestTier is the lowest managed tier that may run 'cmd sub'.
func lowestTier(cmd, sub string) tier.Tier {
	for _, t := range tier.Managed {
		if tier.Permits(t, cmd, sub) {
			return t
		}
	}
	return tier.Superuser
}

// pathTier is lowestTier of a command path (the gate's two words).
func pathTier(path []string) tier.Tier {
	sub := ""
	if len(path) > 1 {
		sub = path[1]
	}
	return lowestTier(path[0], sub)
}

// familyTier is the lowest managed tier whose view lists the command at
// path: the lowest tier that may run it or any of its sub-commands.
func familyTier(root *cobra.Command, path []string) tier.Tier {
	for _, t := range tier.Managed {
		if viewShows(root, t, false, path) {
			return t
		}
	}
	return tier.Superuser
}

// tierNotes are the verbs whose sub-verbs the gate cannot tell apart (it
// sees two words); the family's help says what the code decides.
var tierNotes = map[string]string{
	"scope staging": "scope staging: an engineer may run list for a scope of their own; the other verbs need the superuser tier.",
	"scope secret":  "scope secret: an engineer may run show for a scope of their own; set and generate need the superuser tier.",
	"scope snmp":    "scope snmp: an engineer may read the settings of a scope of their own (show [--reveal], version, port, timeout, contact, clients list); every setter, clear and test needs the superuser tier.",
	"device snmp":   "device snmp: an engineer may read the settings of a device of their own scope (show [--reveal], version, port, timeout, clients list); every setter and clear needs the superuser tier.",
	"host show":     "host show: an engineer reads what tacctl recorded of a host; --check logs in to it and needs the superuser tier.",
	"device list":   "device list: the CONFIG column (and config of --json) is the operator tier's; a read-only user's list has none.",
	"device show":   "device show: the Configuration row (and config of --json) is the operator tier's; a read-only user's output has none.",
	"device import": "device import: an engineer imports from standard input only (device import -).",
	"device config": "device config: an operator may run list; show, pull and diff need the engineer tier (a device's walkthrough carries its scope's secret, and a pull logs in to the device as you), and an engineer gets the devices of their own scopes only; forget needs the superuser tier.",
}

// tierSection is the part of a family's help that names the tier each of
// its verbs needs: the lowest tier whose rows run it, grouped by tier, with
// the notes for the verbs the code splits further. "" for a command that is
// not in the tree.
func tierSection(root *cobra.Command, family string) string {
	fc := child(root, family)
	if fc == nil {
		return ""
	}
	var subs []string
	for _, c := range fc.Commands() {
		if !c.Hidden {
			subs = append(subs, c.Name())
		}
	}
	var b strings.Builder
	if len(subs) == 0 {
		return "\nNeeds the " + string(lowestTier(family, "")) + " tier.\n"
	}
	b.WriteString("\nTiers (the lowest tier that may run each " + family + " verb):\n")
	byTier := map[tier.Tier][]string{}
	for _, s := range subs {
		t := lowestTier(family, s)
		byTier[t] = append(byTier[t], s)
	}
	width := 0
	for _, t := range tier.Managed {
		width = max(width, len(t))
	}
	for _, t := range tier.Managed {
		if len(byTier[t]) > 0 {
			b.WriteString("  " + string(t) + strings.Repeat(" ", width-len(t)) + "  " + strings.Join(byTier[t], ", ") + "\n")
		}
	}
	for _, s := range subs {
		if n, ok := tierNotes[family+" "+s]; ok {
			b.WriteString("  " + n + "\n")
		}
	}
	if len(byTier[tier.Engineer]) > 0 {
		b.WriteString("  An engineer's verbs reach only the devices, hosts and secrets of the scopes the engineer is a member of.\n")
	}
	return b.String()
}

// withSection is a usage block followed by the tier section, one blank line
// between them (and the block alone when there is no section).
func withSection(block, section string) string {
	if section == "" {
		return block
	}
	return strings.TrimRight(block, "\n") + "\n" + section
}

// filterTop leaves out of the shell's top-level help (text, with the
// program's name already removed) the command rows, hint lines and examples
// that name a command the view does not show.
func filterTop(root *cobra.Command, eff tier.Tier, text string) string {
	lines := strings.Split(text, "\n")
	var out []string
	section, keep := "", true
	var held []string // the heading of an examples section until a line is kept
	for _, l := range lines {
		switch {
		case l == "Commands:":
			section = "commands"
		case strings.HasPrefix(l, "Type help <command> for detailed help"):
			section = "hint"
		case l == "Examples:":
			section, held = "examples", []string{"", l}
			// The blank line before the heading was already written.
			if n := len(out); n > 0 && out[n-1] == "" {
				out = out[:n-1]
			}
			continue
		case l == "":
			if section == "examples" && held != nil {
				held = nil
			}
			section = ""
		case section == "commands":
			if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") {
				name, _, _ := strings.Cut(strings.TrimSpace(l), " ")
				keep = name == "shell" || viewShows(root, eff, false, []string{name})
			}
			if !keep {
				continue
			}
		case section == "hint" || section == "examples":
			w := strings.Fields(l)
			if len(w) > 0 && w[0] == "help" {
				w = w[1:]
			}
			if strings.HasPrefix(l, "  ") && !viewShowsWords(root, eff, false, w) {
				continue
			}
			if held != nil {
				out = append(out, held...)
				held = nil
			}
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// viewNote is the sentence after the command list that says the list is
// the caller's.
func viewNote(eff tier.Tier) string {
	if eff == tier.None {
		return "Shown: no command; this account has no tier (it may be disabled), so every command is refused. help <command> describes a command and the tier it needs.\n"
	}
	return "Shown: the commands the " + string(eff) + " tier can run; help <command> describes all of a command's verbs and the tier each needs.\n"
}

// setView fixes the view of this shell run. A run with a view of its own
// (the console, whose policy answer already came) uses it; a caller who is
// not a tac-users member is unrestricted; a managed caller's tier is asked
// of the root side ('sudo -n _console-policy', as the console does) without
// ever holding the editor up. The interactive shell starts the question when
// it starts and lists the read-only verbs until the answer is in; after a
// failure (a timeout, a refusal, an answer that cannot be read) it asks
// again on a later use, no sooner than viewRetry after the failure. A run
// without a terminal (-c, a script) asks on first use and waits for the
// answer, but no longer than viewTimeout.
func (inv *invocation) setView(r shellRun, managed bool) {
	switch {
	case r.view != "":
		t := r.view
		inv.view = func() tier.Tier { return t }
	case !managed:
		inv.view = func() tier.Tier { return tier.Unrestricted }
	default:
		p := &policyView{
			ask:     func(ctx context.Context) (tier.Tier, bool) { return inv.policyTier(ctx, r.exe, r.extraEnv) },
			ctx:     inv.ctx,
			timeout: viewTimeout, retry: viewRetry, now: time.Now,
		}
		if r.mode == shellInteractive {
			p.start()
			inv.view = p.get
		} else {
			inv.view = p.wait
		}
	}
}

// policyView is the lookup of a managed caller's tier: ask runs in a
// goroutine of its own (bounded by timeout), and get answers at once.
type policyView struct {
	ask            func(ctx context.Context) (tier.Tier, bool)
	ctx            context.Context
	timeout, retry time.Duration
	now            func() time.Time

	mu     sync.Mutex
	t      tier.Tier
	known  bool
	busy   bool
	failed time.Time // when the last question failed (zero: none did)
	done   chan struct{}
}

// start begins a question unless one is under way or the answer is in.
func (p *policyView) start() {
	p.mu.Lock()
	if p.busy || p.known {
		p.mu.Unlock()
		return
	}
	p.busy = true
	done := make(chan struct{})
	p.done = done
	p.mu.Unlock()
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
		defer cancel()
		t, ok := p.ask(ctx)
		p.mu.Lock()
		p.busy = false
		if ok {
			p.t, p.known = t, true
		} else {
			p.failed = p.now()
		}
		p.mu.Unlock()
	}()
}

// get is the tier now: the answer once it is in, else viewUnread (and a new
// question when the last one failed viewRetry ago). It does not wait.
func (p *policyView) get() tier.Tier {
	p.mu.Lock()
	if p.known {
		t := p.t
		p.mu.Unlock()
		return t
	}
	retry := !p.busy && !p.failed.IsZero() && p.now().Sub(p.failed) >= p.retry
	p.mu.Unlock()
	if retry {
		p.start()
	}
	return viewUnread
}

// wait is get for a run without a terminal: the first use asks and waits.
func (p *policyView) wait() tier.Tier {
	p.mu.Lock()
	first := p.done == nil
	p.mu.Unlock()
	if first {
		p.start()
	}
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	<-done
	return p.get()
}

// policyTier asks the root side which tier the gate enforces for the
// caller; ok is false when it cannot be learned (the command failed or
// timed out, or the answer has no tier).
func (inv *invocation) policyTier(ctx context.Context, exe string, env []string) (tier.Tier, bool) {
	args := append(append([]string{"-n"}, env...), exe, "_console-policy")
	res, err := inv.app.Runner.Run(ctx, execx.Cmd{Name: "sudo", Args: args})
	if err != nil || res.Code != 0 {
		return "", false
	}
	pol, _ := console.ParseRemote(string(res.Stdout))
	return pol.ViewRead()
}
