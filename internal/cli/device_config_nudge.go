package cli

// The nudge and --apply of the registry setters (0.2.9, D130): a setter
// that changes what is rendered for a device says, in one line, that the
// device's configuration would now change, and 'location', 'description',
// 'address' and 'ios-syntax' take --apply to run 'device config apply'
// for that one device in the same process.
//
// The nudge reads the stored pull only: no login, no network, nothing kept
// (the plan is made as 'block check --against' makes it, dry). A device
// that was never pulled, whose pull is stale or failed, or that the planner
// cannot plan says nothing.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/tier"
)

// rendersField says whether a registry setter's field is an input of the
// rendered configuration: the location and the description feed the SNMP
// step, the address decides the scope (and so everything), the vendor the
// renderer. The host name, the port and legacy-ssh are not rendered; the
// name is not either.
func rendersField(field string) bool {
	switch field {
	case "location", "description", "address", "vendor", "config-syntax", "netconf":
		return true
	}
	return false
}

// nudgeRun is a dry planRun over entries: the plan is made from each
// device's last pull as 'device config plan' makes it, and nothing is kept.
func (inv *invocation) nudgeRun(entries []devreg.Entry) *planRun {
	r := inv.newManagedRender(managedOptions{}, inv.callerScopes().restricted)
	r.prepare(entries)
	staleDays := devreg.DefaultStaleDays
	if f, _, err := inv.deviceLoad(); err == nil && f.StaleDays > 0 {
		staleDays = f.StaleDays
	}
	return &planRun{inv: inv, render: r, store: inv.configStore(), user: inv.sudoUser(),
		now: inv.app.Knobs.Now(), stale: staleDays, failed: map[string]string{},
		wrap: plan.Wrapper{ConfirmMinutes: inv.confirmTimeout()}, dry: true}
}

// nudgeCandidate is whether the nudge may look at e at all: a registered
// device a scope covers, of a vendor that is read, with a pull.
func nudgeCandidate(recs *devconf.Records, e devreg.Entry) bool {
	if e.Source != devreg.SourceDevice || !e.Configured {
		return false
	}
	switch e.Vendor {
	case "cisco", "juniper", "wti":
	default:
		return false
	}
	rec, ok := recs.Of(e.Name)
	return ok && !rec.Pulled.IsZero()
}

// canApply is whether the caller may run 'device config apply' (the
// superuser's).
func (inv *invocation) canApply() bool {
	_, ok := inv.deviceConfigPermits("apply")
	return ok
}

// nudgeVerb is the command the nudge names for a device: the apply's check
// for a superuser and a Junos device, the plan for anyone else who may run
// it (apply is Junos-only and the superuser's).
func (inv *invocation) nudgeVerb(vendor string) string {
	if vendor == "juniper" && inv.canApply() {
		return "apply"
	}
	return "plan"
}

// configNudge prints the one line when the stored pull of device name,
// planned against what the registry says now, would change. It is silent on
// every error.
func (inv *invocation) configNudge(name string) {
	if !inv.configVisible() {
		return
	}
	if _, ok := inv.deviceConfigPermits("plan"); !ok {
		return
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return
	}
	e, err := inv.deviceFind(res, name)
	if err != nil || !nudgeCandidate(inv.configRecords(), e) {
		return
	}
	pd := inv.nudgeRun([]devreg.Entry{e}).planOne(e)
	if !pd.planned() || pd.d.Empty() {
		return
	}
	cmd := "tacctl device config " + inv.nudgeVerb(e.Vendor) + " " + e.Name
	if inv.nudgeVerb(e.Vendor) == "apply" {
		cmd += " --check"
	}
	inv.app.Out.Info("The configuration of " + e.Name + " would change: " + cmd)
}

// scopeNudge is configNudge for a scope-level change: one line when at least
// one device of the scope has a stored pull the planner would change. The
// work is bounded by the scope's devices and stops at the first that would;
// every error is silence.
func (inv *invocation) scopeNudge(scope string) {
	if scope == "" || !inv.configVisible() {
		return
	}
	if _, ok := inv.deviceConfigPermits("plan"); !ok {
		return
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return
	}
	recs := inv.configRecords()
	var entries []devreg.Entry
	for _, e := range res.Visible(inv.deviceFilter()) {
		if e.Scope == scope && nudgeCandidate(recs, e) {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return
	}
	run := inv.nudgeRun(entries)
	for _, e := range entries {
		pd := run.planOne(e)
		if !pd.planned() || pd.d.Empty() {
			continue
		}
		verb := "plan --scope " + scope
		if inv.canApply() {
			verb = "apply --scope " + scope + " --check"
		}
		inv.app.Out.Info("The configuration of devices in scope " + scope + " would change: tacctl device config " + verb)
		return
	}
}

// scopeWrites says whether a 'scope <verb> <args>' invocation writes what
// the devices of the scope are rendered from (the word after the verb is a
// writing one and has what it writes). It is read from the command line: a
// refused or unchanged write may still say so, which is true of the plan.
func scopeWrites(verb string, args []string) bool {
	if verb == "secret" {
		// '--stdin' may stand before the sub-command.
		args = slices.DeleteFunc(slices.Clone(args), func(w string) bool { return w == "--stdin" })
	}
	sub, n := arg(args, 1), len(args)
	switch verb {
	case "prefixes":
		return sub == "add" || sub == "remove" || sub == "move"
	case "secret":
		return sub == "set" || sub == "generate"
	case "mgmt-acl":
		switch sub {
		case "add", "remove", "clear":
			return true
		case "cisco-name", "juniper-name":
			return n > 2
		}
	case "snmp":
		switch sub {
		case "version", "community", "v3-user", "contact", "port", "timeout":
			return n > 2 || strings.Contains(strings.Join(args, " "), "--clear")
		case "clients":
			return arg(args, 2) == "add" || arg(args, 2) == "remove"
		case "clear":
			return true
		}
	case "block":
		// scope block <scope> <vendor> <verb>
		switch arg(args, 2) {
		case "set", "remove", "edit", "adopt":
			return true
		}
	case "protocols":
		return sub == "set" || sub == "clear"
	case "netconf":
		return sub == "enable" || sub == "disable" || sub == "leave"
	case "aaa-order", "exec-timeout", "tacacs-group", "radius-group", "auth-method":
		return n > 1
	}
	return false
}

// withScopeNudge runs a scope verb and, when it succeeded and wrote what the
// devices are rendered from, says whether the devices of the scope would
// change.
func (inv *invocation) withScopeNudge(verb string, run func([]string) error) func([]string) error {
	return func(args []string) error {
		err := run(args)
		if err == nil && scopeWrites(verb, args) {
			inv.scopeNudge(arg(args, 0))
		}
		return err
	}
}

// --- --apply ---------------------------------------------------------------------

// applyPreflight is everything 'device <setter> --apply' must know before it
// changes the registry: the caller may apply (the superuser's), logs in as
// themselves, the device is one that apply writes to, and there is a
// terminal for the review. A refusal is a usage error and nothing was
// changed.
func (inv *invocation) applyPreflight(e devreg.Entry) error {
	t, ok := inv.deviceConfigPermits("apply")
	if !ok {
		return inv.usageErr("--apply runs 'tacctl device config apply', which is for the " + string(tier.Superuser) + " tier; yours is " + string(t) + ". Nothing was changed.")
	}
	user, err := inv.configLogin("device config apply")
	if err != nil {
		return err
	}
	if m, err := inv.model(); err == nil && e.Configured {
		if msg := loginProblem(m, user, e.Scope); msg != "" {
			return inv.usageErr("--apply: " + msg + " Nothing was changed.")
		}
	}
	switch {
	case !e.Configured:
		return inv.usageErr("--apply: device '" + e.Name + "' is in no scope: no scope's prefixes cover its address, so there is nothing to apply. Nothing was changed.")
	case e.Vendor == "wti":
		return inv.usageErr("--apply: apply is not available for WTI units: a unit has no candidate configuration to check. Nothing was changed.")
	case e.Vendor != "juniper":
		return inv.usageErr("--apply: apply writes to Junos devices only in this release; '" + e.Name + "' has vendor '" + e.Vendor + "'. Nothing was changed.")
	}
	if _, held := inv.holdOf(e.Name, e.Address); held {
		return inv.usageErr("--apply: " + holdRefusal(e.Name) + ". Nothing was changed.")
	}
	if !inv.app.Prompter().Interactive() {
		return inv.usageErr("--apply: no terminal to confirm on: the review of an apply is answered by typing the device's name back, and --apply never skips it. Nothing was changed.")
	}
	return nil
}
