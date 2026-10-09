package cli

// 'tacctl rollback <version> [--apply] [--yes] [--hosts]' (docs/plans/
// 0.2.3-plan.md D50): prepare tacctl's state for the release before this
// one. The plan and the conversions of the files are internal/lifecycle's
// (rollback.go); this is the command around them: the arguments, what is
// printed, the snapshot, the re-render and the sync of the hosts.
//
// It is the superuser's alone (the tier table has no row for it, so the
// gate refuses every lower tier), and a dry run unless --apply is given.

import (
	"errors"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/ui"
)

func init() { registerFamily(rollbackCmd) }

const rollbackUsage = "Usage: tacctl rollback <version> [--apply] [--yes] [--hosts]"

// rollbackSpec is the arguments of 'rollback' (completion and parsing).
var rollbackSpec = Spec{
	Flags:   []Flag{{Names: []string{"--apply"}}, {Names: []string{"--yes"}}, {Names: []string{"--hosts"}}},
	MinArgs: 1, MaxArgs: 1,
	Args: []string{lifecycle.RollbackTarget},
}

func rollbackCmd(inv *invocation) *cobra.Command {
	c := verb("rollback <version> [--apply] [--yes] [--hosts]", "Prepare the state for an earlier release (a dry run unless --apply)")
	c.RunE = inv.native(noPreflight, inv.rollback)
	return c
}

// rollback is the command. Exit 0: the dry run was printed, or the rollback
// was applied; 1: refused or failed (what was changed is said); 2 is not
// used (the usage is exit 1, as every command's).
func (inv *invocation) rollback(args []string) error {
	a := inv.app
	p, err := Parse(rollbackSpec, args)
	if err != nil || len(p.Args) != 1 {
		return inv.usageErr(rollbackUsage)
	}
	apply, yes, withHosts := p.Has("--apply"), p.Has("--yes"), p.Has("--hosts")
	version, err := lifecycle.CheckRollbackVersion(p.Args[0])
	if err != nil {
		var ref *lifecycle.RollbackRefusal
		if errors.As(err, &ref) {
			return inv.usageErr(append(ref.Lines, "Nothing was changed.")...)
		}
		return err
	}
	// The gate lets only the superuser through; a restricted caller that got
	// here anyway (a changed table) syncs nothing.
	if f := inv.callerScopes(); f.restricted {
		return inv.usageErr("'tacctl rollback' is the superuser's. Nothing was changed.")
	}

	in, err := inv.rollbackInput(withHosts)
	if err != nil {
		return err
	}
	plan, err := lifecycle.PlanRollback(in)
	if err != nil {
		msgs := msgs(err)
		return inv.usageErr(append(msgs, "Nothing was changed.")...)
	}
	inv.printRollbackPlan(version, plan, apply, withHosts)

	if !apply {
		inv.echo("")
		inv.echo(ui.Bold + "This was a dry run: nothing was changed." + ui.NC)
		cmd := "tacctl rollback " + version + " --apply"
		if plan.NeedsYes() {
			cmd += " --yes"
		}
		if withHosts {
			cmd += " --hosts"
		}
		inv.echo("To convert the state: " + cmd)
		if plan.NeedsYes() {
			inv.echo("(--yes says you read the warnings above; --apply refuses without it.)")
		}
		if !withHosts {
			inv.echo("Add --hosts to take the engineers' sudo off the enrolled Linux hosts too.")
		}
		return nil
	}

	if plan.NeedsYes() && !yes {
		return inv.usageErr("The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed.")
	}

	inv.echo("")
	inv.echo(ui.Bold + "Applying." + ui.NC)
	hostNames := inv.rollbackHostNames(in, withHosts)
	// The snapshot is of the files the rollback converts; the syncs of the
	// hosts change none of them.
	if plan.Pending() {
		if err := inv.snapshotFirst(); err != nil {
			return err
		}
	}
	done, err := lifecycle.ApplyRollback(plan)
	for _, d := range done {
		a.Out.InfoE(d)
	}
	if err != nil {
		for _, m := range msgs(err) {
			a.Out.ErrorE(m)
		}
		return inv.usageErr("The rollback stopped. The files listed above are converted, the others are as they were (the snapshot holds the state before); run the same command again to finish: a file that is converted is not touched again.")
	}
	if len(done) == 0 {
		a.Out.InfoE("Nothing to convert: every file is one 0.2.2 can read.")
	}
	inv.loaded = false
	a.Conf().Reload()

	failed := false
	if in.HasStore {
		if err := inv.renderAfterRollback(); err != nil {
			a.Out.ErrorE("The re-render failed; the files are converted. Run 'tacctl config render --force' and look at 'tacctl config validate'.")
			failed = true
		}
	}
	if len(hostNames) > 0 {
		if !inv.syncRevoked(hostNames) {
			failed = true
		}
	}
	inv.rollbackNextSteps(version, withHosts, failed)
	a.Logger(inv.ctx, "auth.info", "rollback target="+version+" keys="+strconv.Itoa(len(plan.Keys()))+" hosts="+strconv.Itoa(len(hostNames))+" by="+inv.sudoUser())
	if failed {
		return exit(1)
	}
	return nil
}

// rollbackInput is what the plan reads: the settings, the model (or why it
// cannot be read), the hosts.
func (inv *invocation) rollbackInput(withHosts bool) (lifecycle.RollbackInput, error) {
	a := inv.app
	in := lifecycle.RollbackInput{Paths: a.Paths, Conf: a.Conf(), HasStore: isRegularFile(a.Paths.StoreFile), WithHosts: withHosts, Now: a.Knobs.Now}
	in.Model, in.ModelErr = inv.model()
	reg, err := inv.registry()
	if err != nil {
		return in, err
	}
	for _, e := range reg.Entries() {
		h := lifecycle.RollbackHost{Name: e.Name, Scope: e.Scope, Local: e.Target == hosts.Local}
		in.AllHosts = append(in.AllHosts, h)
		in.Hosts = append(in.Hosts, h)
	}
	return in, nil
}

// rollbackHostNames are the hosts --hosts syncs: every enrolled host but this
// server's own entry.
func (inv *invocation) rollbackHostNames(in lifecycle.RollbackInput, withHosts bool) []string {
	if !withHosts {
		return nil
	}
	var out []string
	for _, h := range in.Hosts {
		if !h.Local {
			out = append(out, h.Name)
		}
	}
	return out
}

// printRollbackPlan prints the steps, the warnings and the notes.
func (inv *invocation) printRollbackPlan(version string, plan *lifecycle.RollbackPlan, apply, withHosts bool) {
	inv.echo("")
	title := "Roll back to " + version
	if !apply {
		title += " (dry run)"
	}
	inv.echo(ui.Bold + title + ui.NC)
	inv.echo("")
	inv.echo("  --apply takes a snapshot of the state first (tacctl backup list), then does, in this order:")
	inv.echo("")
	for i, s := range plan.Steps {
		mark := "leaves"
		if s.Todo {
			mark = "does"
		}
		inv.echo("  " + strconv.Itoa(i+1) + ". " + s.Title + "   [" + mark + "]")
		for _, l := range s.Lines {
			inv.echo("       " + l)
		}
	}
	if len(plan.Warnings) > 0 {
		inv.echo("")
		inv.echo(ui.Red + "Warnings (--apply refuses without --yes while any applies)" + ui.NC)
		for i, w := range plan.Warnings {
			inv.echo("")
			inv.echo(ui.Red + "  " + strconv.Itoa(i+1) + ". " + w.Title + ui.NC)
			for _, l := range w.Lines {
				inv.echo("       " + l)
			}
		}
	}
	if len(plan.Notes) > 0 {
		inv.echo("")
		inv.echo(ui.Bold + "Notes" + ui.NC)
		for _, n := range plan.Notes {
			inv.echo("  " + n)
		}
	}
}

// renderAfterRollback is the re-render of the enabled backends from the
// store, through the path 'config render' takes (a backend whose files did
// not change is not restarted).
func (inv *invocation) renderAfterRollback() error {
	return inv.app.Backends().ConfigRender(inv.ctx, false)
}

// syncRevoked syncs the hosts with the script that revokes the engineers'
// sudo (TAC_REVOKE_ENGINEER=1), host by host through 'host sync', and says
// which failed. It reports whether every host synced.
func (inv *invocation) syncRevoked(names []string) bool {
	a := inv.app
	inv.revokeEngineer = true
	defer func() { inv.revokeEngineer = false }()
	inv.echo("")
	inv.echo(ui.Bold + "Taking the engineers' sudo off " + strconv.Itoa(len(names)) + " " + map[bool]string{true: "host", false: "hosts"}[len(names) == 1] + "." + ui.NC)
	var bad []string
	for _, n := range names {
		if inv.ctx.Err() != nil {
			bad = append(bad, n)
			continue
		}
		if err := inv.hostSync([]string{n}); err != nil {
			if !isExit(err) {
				inv.reportOnly(err)
			}
			bad = append(bad, n)
		}
	}
	if len(bad) > 0 {
		a.Out.ErrorE("Not synced: " + strings.Join(bad, ", ") + ". Their engineers may still have sudo there. Fix the cause (tacctl host show <name> --check) and run 'tacctl rollback " + lifecycle.RollbackTarget + " --apply --yes --hosts' again (the files are converted once; the hosts are synced again).")
		return false
	}
	return true
}

// rollbackNextSteps tells the operator what to do next, exactly.
func (inv *invocation) rollbackNextSteps(version string, withHosts, failed bool) {
	inv.echo("")
	if failed {
		inv.echo(ui.Red + "The rollback did not finish; fix what is reported above and run the command again before the next steps." + ui.NC)
		inv.echo("")
	}
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	if !withHosts {
		inv.echo("  3. The enrolled Linux hosts still have the engineers' sudo (the %tac-engineer line, membership of tac-engineer) and " + version + " does not remove it:")
		inv.echo("     'tacctl rollback " + version + " --apply --hosts' does that, before the upgrade, with this release.")
	}
	inv.echo("")
	inv.echo("Until the upgrade, do not run a command that writes the console's settings, the SNMP settings of a scope, a device location or an engineer sudo list:")
	inv.echo("it writes the 0.2.3 form again. If one did, run 'tacctl rollback " + version + " --apply' again (it converts what is left).")
	inv.echo("")
	inv.echo("Before upgrading, note the newest entry of 'tacctl backup list' (snapshots are taken before every change; the upgrade adds one only when it records a tier).")
	inv.echo("That entry is your way back: 'tacctl backup restore <id>' brings back that state and loses what changed since.")
}
