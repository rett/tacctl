package cli

// 'tacctl rollback <version> [--apply] [--yes] [--hosts]' (docs/plans/
// 0.2.3-plan.md D50, docs/plans/0.2.4-plan.md D73): prepare tacctl's state
// for the release before this one (0.2.3). The plan and the conversions of
// the files are internal/lifecycle's (rollback.go); this is the command
// around them: the arguments, what is printed, the snapshot and the
// sudoers installer.
//
// It is the superuser's alone (the tier table has no row for it, so the gate
// refuses every lower tier), and a dry run unless --apply is given.

import (
	"errors"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/tier"
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
	// here anyway (a changed table) changes nothing.
	if f := inv.callerScopes(); f.restricted {
		return inv.usageErr("'tacctl rollback' is the superuser's. Nothing was changed.")
	}

	in := lifecycle.RollbackInput{Paths: a.Paths, Conf: a.Conf(), HasStore: isRegularFile(a.Paths.StoreFile), WithHosts: withHosts,
		InstallSudoers: func(body, dst string) error {
			return tier.InstallSudoers(inv.ctx, a.Runner, a.Out.Stdout, a.Out.Stderr, body, dst)
		}}
	plan, err := lifecycle.PlanRollback(in)
	if err != nil {
		msgs := msgs(err)
		return inv.usageErr(append(msgs, "Nothing was changed.")...)
	}
	inv.printRollbackPlan(version, plan, apply)

	if !apply {
		inv.echo("")
		inv.echo(ui.Bold + "This was a dry run: nothing was changed." + ui.NC)
		cmd := "tacctl rollback " + version + " --apply"
		if plan.NeedsYes() {
			cmd += " --yes"
		}
		inv.echo("To convert the state: " + cmd)
		if plan.NeedsYes() {
			inv.echo("(--yes says you read the warnings above; --apply refuses without it.)")
		}
		return nil
	}

	if plan.NeedsYes() && !yes {
		return inv.usageErr("The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed.")
	}

	inv.echo("")
	inv.echo(ui.Bold + "Applying." + ui.NC)
	// The snapshot is of the files the rollback converts.
	if plan.PendingFiles() {
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
	for _, n := range plan.NotWritten() {
		a.Out.Warn("Not rewritten: " + n + " (the next 'tacctl config sudoers tiers install' or the upgrade to " + version + " writes it)")
	}
	if len(done) == 0 {
		a.Out.InfoE("Nothing to convert: every file is one " + version + " can read.")
	}
	inv.loaded = false
	a.Conf().Reload()

	inv.rollbackNextSteps(version)
	a.Logger(inv.ctx, "auth.info", "rollback target="+version+" keys="+strconv.Itoa(len(plan.Keys()))+" by="+inv.sudoUser())
	return nil
}

// printRollbackPlan prints the steps, the warnings and the notes.
func (inv *invocation) printRollbackPlan(version string, plan *lifecycle.RollbackPlan, apply bool) {
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

// rollbackNextSteps tells the operator what to do next, exactly.
func (inv *invocation) rollbackNextSteps(version string) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, do not run a command that writes the console's settings, a device's SNMP settings or the settings of 'device config pull':")
	inv.echo("it writes the 0.2.4 form again. If one did, run 'tacctl rollback " + version + " --apply' again (it converts what is left).")
	inv.echo("")
	inv.echo("The snapshot taken first (the newest entry of 'tacctl backup list') holds the 0.2.4 state. Restore it with 0.2.4 only: 'tacctl backup restore <id>' of this release brings that")
	inv.echo("state back and loses what changed since; " + version + "'s restore refuses a tacctl.yaml with a key it does not know.")
}
