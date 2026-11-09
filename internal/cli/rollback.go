package cli

// 'tacctl rollback <version> [--apply] [--yes] [--hosts]' (docs/plans/
// 0.2.3-plan.md D50, docs/plans/0.2.4-plan.md D73, docs/plans/
// 0.2.9-rollout-plan.md D143, docs/plans/0.2.10-plan.md): prepare tacctl's
// state for the release before this one (0.2.27), for 0.2.26, 0.2.25, 0.2.24, 0.2.23, 0.2.22, 0.2.21, 0.2.20, 0.2.19, 0.2.18, 0.2.17, 0.2.16, for 0.2.9 or for 0.2.3. The plan and the conversions of
// the files are internal/lifecycle's (rollback.go); this is the command
// around them: the arguments, what is printed, the snapshot and the
// sudoers installer.
//
// It is the superuser's alone (the tier table has no row for it, so the gate
// refuses every lower tier), and a dry run unless --apply is given.

import (
	"errors"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

func init() { registerFamily(rollbackCmd) }

const rollbackUsage = "Usage: tacctl rollback <version> [--apply] [--yes] [--hosts]"

// rollbackSpec is the arguments of 'rollback' (completion and parsing).
var rollbackSpec = Spec{
	Flags:   []Flag{{Names: []string{"--apply"}}, {Names: []string{"--yes"}}, {Names: []string{"--hosts"}}},
	MinArgs: 1, MaxArgs: 1,
	Args: []string{lifecycle.RollbackTarget0227 + "|" + lifecycle.RollbackTarget0226 + "|" + lifecycle.RollbackTarget0225 + "|" + lifecycle.RollbackTarget0224 + "|" + lifecycle.RollbackTarget0223 + "|" + lifecycle.RollbackTarget0222 + "|" + lifecycle.RollbackTarget0221 + "|" + lifecycle.RollbackTarget0220 + "|" + lifecycle.RollbackTarget0219 + "|" + lifecycle.RollbackTarget0218 + "|" + lifecycle.RollbackTarget0217 + "|" + lifecycle.RollbackTarget0216 + "|" + lifecycle.RollbackTarget029 + "|" + lifecycle.RollbackTarget},
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
		return inv.deniedUsage(reasonSuperuser, "'tacctl rollback' is the superuser's. Nothing was changed.")
	}

	in := lifecycle.RollbackInput{Paths: a.Paths, Conf: a.Conf(), HasStore: isRegularFile(a.Paths.StoreFile), WithHosts: withHosts, Target: version,
		InstallSudoers: func(body, dst string) error {
			return tier.InstallSudoers(inv.ctx, a.Runner, a.Out.Stdout, a.Out.Stderr, a.Paths.TempDir, body, dst)
		},
		RemoveFirewall: func() ([]string, error) { return inv.firewallEngine().Remove(inv.ctx) }}
	plan, err := lifecycle.PlanRollback(in)
	if err != nil {
		// A break-glass hold, a management ACL entry with services or an
		// apply that is not settled stands: the refusal says what to do
		// first and that nothing was changed.
		var held *lifecycle.RollbackRefusal
		if errors.As(err, &held) {
			return inv.usageErr(held.Lines...)
		}
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
	lineHead := "rollback target=" + version + " keys=" + strconv.Itoa(len(plan.Keys()))
	by := " by=" + inv.sudoUser()
	rollbackBase := lineHead + by
	// The snapshot is of the files the rollback converts. It is the record of
	// what the rollback drops, so the audit line names it (a state that
	// equals the newest snapshot takes none: that one is the record).
	snapID := ""
	if plan.PendingFiles() {
		id, err := inv.snapshotFirstID()
		if err != nil {
			inv.verbResult(audit.Notice, rollbackBase, "store")
			return err
		}
		if snapID = id; snapID == "" {
			if ids := inv.snapshotIDs(); len(ids) > 0 {
				snapID = ids[0]
			}
		}
	}
	// What the rollback drops from the store is recorded by the snapshot, and
	// the older release prunes backups/ by its own retention and knows no
	// KeepID: the snapshot is kept ('backup keep', a copy in backups-kept/
	// that no retention reaches) with a note that says what was dropped, never
	// who or what the addresses were. The line names it and the users (never
	// an address), before by=.
	emailUsers := plan.EmailUsers()
	pool := plan.SNMPPoolDropped()
	dropsPool := pool.Any()
	if len(emailUsers) > 0 || dropsPool {
		if snapID == "" {
			a.Out.ErrorE("Could not keep the snapshot of the state: there is none.")
			inv.verbResult(audit.Notice, rollbackBase, "store")
			return inv.usageErr("Nothing was converted.")
		}
		if snapshot.KeptPath(a.Paths.KeptDir, snapID) == "" {
			var dropped []string
			if len(emailUsers) > 0 {
				dropped = append(dropped, "dropped the email addresses of "+strconv.Itoa(len(emailUsers))+" "+plural(len(emailUsers), "user", "users"))
			}
			if dropsPool {
				dropped = append(dropped, snmpPoolNote(pool))
			}
			note := "rollback to " + version + ": " + strings.Join(dropped, "; ")
			if _, _, kerr := snapshot.Keep(a.Paths.BackupDir, a.Paths.KeptDir, snapID, inv.keptInfo(note)); kerr != nil {
				a.Out.ErrorE("Could not keep snapshot " + snapID + " in " + a.Paths.KeptDir + ": " + kerr.Error())
				inv.verbResult(audit.Notice, rollbackBase, "store")
				return inv.usageErr("Nothing was converted.")
			}
		}
		rollbackBase = lineHead + " kept=" + snapID
		if len(emailUsers) > 0 {
			rollbackBase += " email-users=" + namesList(emailUsers, 10)
		}
		if dropsPool {
			rollbackBase += " snmp-users=" + strconv.Itoa(pool.Users) + " snmp-levels=" + strconv.Itoa(pool.Levels) +
				" snmp-choices=" + strconv.Itoa(pool.Choices) + " snmp-devices=" + strconv.Itoa(pool.Orphans)
		}
		rollbackBase += by
	}
	// The users' own limits of the stored reports go with the snapshot, and the
	// line names the users (never more: the values are in the plan above).
	limitUsers := plan.ReportLimitUserNames()
	if len(limitUsers) > 0 {
		rollbackBase = strings.TrimSuffix(rollbackBase, by) + " limit-users=" + namesList(limitUsers, 10) + by
	}
	done, err := lifecycle.ApplyRollback(plan)
	for _, d := range done {
		a.Out.InfoE(d)
	}
	if err != nil {
		for _, m := range msgs(err) {
			a.Out.ErrorE(m)
		}
		inv.verbResult(audit.Notice, rollbackBase, "write")
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

	inv.rollbackNextSteps(version, plan.PendingFiles(), len(plan.Keys()) > 0, len(plan.ReportLimitUserNames()) > 0)
	if plan.FileTransferRemoved() {
		inv.rollbackFileTransferNote(version)
	}
	if plan.FirewallTodo() {
		inv.rollbackFirewallNote(version, plan)
	}
	if len(emailUsers) > 0 {
		inv.rollbackEmailNote(version, snapID, emailUsers)
	}
	if dropsPool {
		inv.rollbackSNMPPoolNote(version, snapID, plan)
	}
	if len(limitUsers) > 0 {
		inv.rollbackReportLimitUsersNote(version, snapID, plan)
	}
	inv.verbResult(audit.Info, rollbackBase, "")
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
	if plan.PendingFiles() {
		inv.echo("  --apply takes a snapshot of the state first (tacctl backup list), then does, in this order:")
	} else {
		inv.echo("  --apply converts no file of tacctl's own and takes no snapshot; the steps, in this order:")
	}
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

// rollbackNextSteps tells the operator what to do next, exactly; snapshot is
// whether the apply took one; keys and fields are whether it removed a key of
// tacctl.yaml and a field of the store (what the older release's restore
// refuses, in the note of the targets 0.2.25 and 0.2.24).
func (inv *invocation) rollbackNextSteps(version string, snapshot, keys, fields bool) {
	// every target older than 0.2.22 refuses the timing scale
	if lifecycle.RollbackUndoes(version, "0.2.22") {
		defer inv.rollbackTimeoutScaleNote(version)
	}
	// every target older than 0.2.26 keeps no limit of the stored reports
	if lifecycle.RollbackUndoes(version, "0.2.26") {
		defer inv.rollbackReportLimitsNote(version)
	}
	switch version {
	case lifecycle.RollbackTarget0227:
		inv.rollbackNextSteps0227(version, snapshot)
		return
	case lifecycle.RollbackTarget0226:
		inv.rollbackNextSteps0226(version, snapshot)
		return
	case lifecycle.RollbackTarget0225:
		inv.rollbackNextSteps0225(version, snapshot, keys, fields)
		return
	case lifecycle.RollbackTarget0224:
		inv.rollbackNextSteps0224(version, snapshot, keys, fields)
		return
	case lifecycle.RollbackTarget0223:
		inv.rollbackNextSteps0223(version, snapshot)
		return
	case lifecycle.RollbackTarget0222:
		inv.rollbackNextSteps0222(version, snapshot)
		return
	case lifecycle.RollbackTarget0221:
		inv.rollbackNextSteps0221(version, snapshot)
		return
	case lifecycle.RollbackTarget0220:
		inv.rollbackNextSteps0220(version)
		return
	case lifecycle.RollbackTarget0219:
		inv.rollbackNextSteps0219(version, snapshot)
		return
	case lifecycle.RollbackTarget0218:
		inv.rollbackNextSteps0218(version)
		return
	case lifecycle.RollbackTarget0217:
		inv.rollbackNextSteps0217(version)
		return
	case lifecycle.RollbackTarget0216:
		inv.rollbackNextSteps0216(version, snapshot)
		return
	case lifecycle.RollbackTarget029:
		inv.rollbackNextSteps029(version, snapshot)
		return
	}
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, do not run a command that writes the console's settings, a device's SNMP settings or configuration syntax, a scope's Cisco source interface or the settings of 'device config pull':")
	inv.echo("it writes the 0.2.5 form again. If one did, run 'tacctl rollback " + version + " --apply' again (it converts what is left).")
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore refuses a tacctl.yaml with a key it does not know.")
}

// rollbackFrom is the release this build is: the state a rollback leaves in
// its snapshot. It moves with each release (docs/releasing.md, The rollback
// target); TestRollbackFromIsTheReleaseOfTheChangelog compares it with the
// first release heading of CHANGELOG.md.
const rollbackFrom = "0.2.28"

// rollbackSnapshotNote says where the state before the rollback is, when the
// apply took a snapshot (it takes none when no file of tacctl's own is
// converted); tail ends the second sentence.
func (inv *invocation) rollbackSnapshotNote(snapshot bool, tail string) {
	if !snapshot {
		return
	}
	inv.echo("")
	inv.echo("The snapshot the rollback took first (the newest entry of 'tacctl backup list') holds the " + rollbackFrom + " state. Restore it with " + rollbackFrom + " only: 'tacctl backup restore <id>' of this release brings that")
	inv.echo("state back and loses what changed since" + tail)
}

// rollbackFirewallNote says, after a rollback that removed the break-glass
// firewall (every target but 0.2.27, 0.2.26, 0.2.25 and 0.2.24): what went and what stays, what a hold that stands
// gets from the older release, and that the setting command writes the key it
// refuses.
func (inv *invocation) rollbackFirewallNote(version string, plan *lifecycle.RollbackPlan) {
	p := inv.app.Paths
	inv.echo("")
	inv.echo("The break-glass firewall is removed: the nftables table inet tacctl, " + p.FirewallRules + " and the boot unit " + p.FirewallUnit + ". The nftables package stays installed; no other table of the ruleset was touched.")
	if holds := plan.FirewallHolds(); len(holds) > 0 {
		inv.echo("The hold of " + strings.Join(holds, ", ") + " stands, and " + version + " takes it as it is: its server completes the TCP handshake of the held address (it answers nothing), as before 0.2.24.")
	}
	inv.echo("Until the older release is installed, run no verb that changes the holds, their device or host names, the listeners or the setting ('tacctl breakglass hold|release', 'device address', 'device|host rename', 'device rename --replace', 'backup restore', 'server listen', 'config breakglass-firewall'): each writes the table, its rules file and the boot unit again, and the setting " + version + " refuses. If one was run, run 'tacctl rollback " + version + " --apply' again (it removes all of it).")
}

// rollbackEmailNote says, after a rollback that removed the users' email
// addresses (every target but 0.2.27, 0.2.26, 0.2.25, 0.2.24 and 0.2.23), where they are and how they come back, and that
// the commands that set one write the key again.
func (inv *invocation) rollbackEmailNote(version, snapID string, users []string) {
	n := len(users)
	inv.echo("")
	inv.echo("The email " + plural(n, "address", "addresses") + " of " + strconv.Itoa(n) + " " + plural(n, "user", "users") + " (" + strings.ReplaceAll(namesList(users, 10), ",", ", ") + ") " + plural(n, "was", "were") + " removed from the store; " + version + " does not know the key.")
	inv.echo(plural(n, "It is", "They are") + " in snapshot " + snapID + ", which is kept in " + inv.app.Paths.KeptDir + "/" + snapID + " (no retention reaches it; " + version + " prunes backups/ by its own):")
	inv.echo("once " + rollbackFrom + " is installed again, 'tacctl backup recover " + snapID + " --only email' puts " + plural(n, "it", "them") + " back; 'tacctl backup unkeep " + snapID + "' removes the kept copy after that.")
	inv.echo("Until then, do not run 'tacctl user email' or 'tacctl user add --email': they write the key again, which " + version + " refuses.")
	inv.echo("If one did, run 'tacctl rollback " + version + " --apply --yes' again (it removes it).")
}

// snmpPoolNote is what the note of the kept snapshot says was dropped from the
// SNMP credential files: counts only ("dropped 2 SNMPv3 users in 2 levels; the
// choice of 1 device of another level's user; the credentials of 1 device
// without an snmp: entry").
func snmpPoolNote(d lifecycle.SNMPPoolDrop) string {
	var parts []string
	if d.Users > 0 {
		parts = append(parts, strconv.Itoa(d.Users)+" SNMPv3 "+plural(d.Users, "user", "users")+" in "+strconv.Itoa(d.Levels)+" "+plural(d.Levels, "level", "levels"))
	}
	if d.Choices > 0 {
		parts = append(parts, "the choice of "+strconv.Itoa(d.Choices)+" "+plural(d.Choices, "device", "devices")+" of another level's SNMPv3 user")
	}
	if d.Orphans > 0 {
		parts = append(parts, "the SNMP credentials of "+strconv.Itoa(d.Orphans)+" "+plural(d.Orphans, "device", "devices")+" without an snmp: entry")
	}
	return "dropped " + strings.Join(parts, "; ")
}

// rollbackSNMPPoolNote says, after a rollback that dropped SNMPv3 users (or a
// device's credentials or choice) from the credential files, where they are
// and how they come back, and that every command that saves a credential file
// writes version 2 again (a second or non-default user and the like).
func (inv *invocation) rollbackSNMPPoolNote(version, snapID string, plan *lifecycle.RollbackPlan) {
	d := plan.SNMPPoolDropped()
	inv.echo("")
	if d.Users > 0 {
		inv.echo(strconv.Itoa(d.Users) + " SNMPv3 " + plural(d.Users, "user was", "users were") + " dropped from the credential files of " + strconv.Itoa(d.Levels) + " " + plural(d.Levels, "level", "levels") + " (" + strings.Join(plan.SNMPPoolLevels(), ", ") + "); " + version + " reads one v3 user for each level and the default user of each stays.")
	}
	if d.Orphans > 0 {
		inv.echo(strconv.Itoa(d.Orphans) + " " + plural(d.Orphans, "device's", "devices'") + " credentials file (" + strings.Join(plan.SNMPPoolOrphans(), ", ") + ") was removed: the device has no snmp: entry, and " + version + " ignores such a file.")
	}
	if d.Choices > 0 {
		inv.echo(strconv.Itoa(d.Choices) + " " + plural(d.Choices, "device's", "devices'") + " choice of a user of another level was dropped too.")
	}
	inv.echo("What was dropped is in snapshot " + snapID + ", which is kept in " + inv.app.Paths.KeptDir + "/" + snapID + " (no retention reaches it; " + version + " prunes backups/ by its own):")
	inv.echo("once " + rollbackFrom + " is installed again, 'tacctl backup recover " + snapID + " --only snmp-users' puts it back; 'tacctl backup unkeep " + snapID + "' removes the kept copy after that.")
	inv.echo("Until then, do not give a level a second or a non-default SNMPv3 user ('v3-user add'), a default that names another level's user ('v3-user default <user>' on a device), or a device with no snmp: entry a user of its own: such a file is written in version 2 again, which " + version + " refuses. A community, and one v3 user that is the default, are saved in version 1 and are fine (for a device, once it has an snmp: entry).")
	inv.echo("If one did, run 'tacctl rollback " + version + " --apply --yes' again (it writes version 1).")
}

// rollbackReportLimitUsersNote says, after a rollback that removed the users'
// own limits of the stored reports (every target older than 0.2.26), whose they
// were, where the snapshot is and how they are set again.
func (inv *invocation) rollbackReportLimitUsersNote(version, snapID string, plan *lifecycle.RollbackPlan) {
	users := plan.ReportLimitUsers()
	n := len(users)
	inv.echo("")
	inv.echo("The own limits of the stored reports were removed from the store for " + strconv.Itoa(n) + " " + plural(n, "user", "users") + "; " + version + " does not know the keys:")
	for _, u := range users {
		inv.echo("  " + u)
	}
	inv.echo("They are also in snapshot " + snapID + "; once " + rollbackFrom + " is installed again, 'tacctl user reports-limit <user> max-size|max-count <value>' sets them again.")
}

// rollbackReportLimitsNote says, after a rollback to a release before 0.2.26,
// that the reports stay where they are and what writes a limit again.
func (inv *invocation) rollbackReportLimitsNote(version string) {
	inv.echo("")
	inv.echo("The reports in the users' homes stay: they are the users' own files, and " + version + " has no 'device reports' verbs to list or remove them.")
	inv.echo("Until the upgrade, do not run 'tacctl config reports max-size', 'config reports max-count' or 'tacctl user reports-limit': they write a limit again, which " + version + " refuses.")
	inv.echo("If one did, run 'tacctl rollback " + version + " --apply' again (it removes it; with --yes while a user has a limit of their own).")
}

// rollbackTimeoutScaleNote says, after a rollback to a release before 0.2.22, that the commands of the
// timing scale write what the older release refuses until it is installed.
func (inv *invocation) rollbackTimeoutScaleNote(version string) {
	inv.echo("")
	inv.echo("Until the upgrade, do not run 'tacctl device timeout-scale', 'tacctl scope timeout-scale' or 'tacctl config devices timeout-scale': they write the timing scale again, which " + version + " refuses.")
	inv.echo("If one did, run 'tacctl rollback " + version + " --apply' again (it removes it).")
}

// rollbackFileTransferNote says, after a rollback that removed the console's
// file transfer settings (0.2.28), that the commands that set them write what
// the older release refuses until it is installed.
func (inv *invocation) rollbackFileTransferNote(version string) {
	inv.echo("")
	inv.echo("Until the upgrade, do not run 'tacctl console file-transfer' with a tier, a user, a quota or a rate to set: it writes the file transfer settings again, which " + version + " refuses (its console falls back to the defaults and 'console' commands that write fail).")
	inv.echo("If one did, run 'tacctl rollback " + version + " --apply' again (it removes them).")
}

// rollbackNextSteps0227 is the next steps of the rollback to 0.2.27: the
// upgrade of the tag. 0.2.27 reads every file this release writes but the
// file transfer settings of console.yaml, so the rollback converted nothing
// else and leaves no other command to avoid: the limits of the stored reports
// and the reports in the users' homes (the PDF ones too) stay, 0.2.27 has
// them. snapshot is whether it took the snapshot, which it does only for those
// settings; the note says why 0.2.27 cannot restore it.
func (inv *invocation) rollbackNextSteps0227(version string, snapshot bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore puts back a console.yaml with a setting it does not know.")
}

// rollbackNextSteps0226 is the next steps of the rollback to 0.2.26: those of
// 0.2.27, which reads the same files (0.2.26 reads every file 0.2.27 and this
// release write but the file transfer settings).
func (inv *invocation) rollbackNextSteps0226(version string, snapshot bool) {
	inv.rollbackNextSteps0227(version, snapshot)
}

// rollbackNextSteps0225 is the next steps of the rollback to 0.2.25: the
// upgrade of the tag. 0.2.25 reads every file 0.2.26, 0.2.27 and this release write but the
// limits of the stored reports (rollbackReportLimitsNote, printed after these
// steps, says that the reports stay in the users' homes and what to avoid), so
// the rollback converted a file only when a limit was set; snapshot is whether
// it took the snapshot then, and the note says why 0.2.25 cannot restore it.
func (inv *invocation) rollbackNextSteps0225(version string, snapshot, keys, fields bool) {
	inv.rollbackNextStepsAfter0224(version, snapshot, keys, fields)
}

// rollbackNextSteps0224 is the next steps of the rollback to 0.2.24: those of
// 0.2.25, which reads the same files.
func (inv *invocation) rollbackNextSteps0224(version string, snapshot, keys, fields bool) {
	inv.rollbackNextStepsAfter0224(version, snapshot, keys, fields)
}

// rollbackNextStepsAfter0224 is the next steps of the targets that read the
// same files, 0.2.25 and 0.2.24: the upgrade of the tag and, when the apply
// took a snapshot (a limit of the stored reports was removed), where the state
// of this release is and why the older release cannot restore it: keys says
// that a key of tacctl.yaml was removed (the settings of the limits), fields
// that a field of the store was (a user's own limits), and the note names what
// the older release's restore refuses for the case it is.
func (inv *invocation) rollbackNextStepsAfter0224(version string, snapshot, keys, fields bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	tail := "a tacctl.yaml with a key it does not know"
	switch {
	case fields && keys:
		tail += " and a store.yaml with a field it does not know"
	case fields:
		tail = "a store.yaml with a field it does not know"
	}
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore refuses "+tail+".")
}

// rollbackNextSteps0223 is the next steps of the rollback to 0.2.23: the
// upgrade of the tag. 0.2.23 reads every file 0.2.24 and this release write
// but breakglass.firewall, so the rollback converted no file of tacctl's own
// (it put back 0.2.23's per-tier sudoers drop-in, without 'log failures *')
// and leaves no command to avoid. When the key was set the apply took a
// snapshot (PendingFiles is true for the key), and snapshot makes this print
// the snapshot note, whose tail says why 0.2.23 cannot restore it: its
// tacctl.yaml has the key. The firewall note (rollbackFirewallNote) does not
// replace the snapshot note.
func (inv *invocation) rollbackNextSteps0223(version string, snapshot bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore refuses a tacctl.yaml with a key it does not know.")
}

// rollbackNextSteps0222 is the next steps of the rollback to 0.2.22: the
// upgrade of the tag. 0.2.22 reads every file but the store's email
// addresses (rollbackEmailNote), so there is no command to avoid until the
// upgrade but the two that set one.
func (inv *invocation) rollbackNextSteps0222(version string, snapshot bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.rollbackSnapshotNote(snapshot, ".")
}

// rollbackNextSteps0221 is the next steps of the rollback to 0.2.21: the
// upgrade of the tag, and the one command that writes again what the rollback
// took out (the server name, which 0.2.21 refuses).
func (inv *invocation) rollbackNextSteps0221(version string, snapshot bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, do not run 'tacctl server name <label>': it writes the key " + version + " refuses. If it did, run 'tacctl rollback " + version + " --apply' again (it removes it).")
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore refuses a snapshot with a key it does not know.")
}

// rollbackNextSteps0220 is the next steps of the rollback to 0.2.20: the
// upgrade of the tag. The users have the scope of this server's own login in
// their own scopes now; a user added or given new scopes before the upgrade
// gets it only by hand.
func (inv *invocation) rollbackNextSteps0220(version string) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, a user added or given other scopes logs in to this server only once the scope of its login is in the user's scopes: run 'tacctl rollback " + version + " --apply --yes' again (it adds it; its plan warns of the users it adds, so it needs --yes).")
}

// rollbackNextSteps0219 is the next steps of the rollback to 0.2.19: the
// upgrade of the tag, and the commands that write again what the rollback
// took out (0.2.20's keys, which 0.2.19 refuses) until it.
func (inv *invocation) rollbackNextSteps0219(version string, snapshot bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, do not run 'tacctl scope mgmt-acl <scope> mode strict', 'tacctl user add', 'tacctl user passwd <name>' or 'tacctl user require-password-change' (the first two require a password change by default),")
	inv.echo("'tacctl console color', 'tacctl console list-max', 'tacctl console system-shell user' or 'tacctl console password-cache on': they write the keys " + version + " refuses. If one did, run 'tacctl rollback " + version + " --apply' again (it converts what is left).")
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore refuses a snapshot with a key it does not know.")
}

// rollbackNextSteps0218 is the next steps of the rollback to 0.2.18, which
// converts the per-tier drop-in and a partial lockdown record at most: the
// upgrade of the tag, and what must not run until it.
func (inv *invocation) rollbackNextSteps0218(version string) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, do not run 'tacctl emergency lockdown': it writes the record " + version + " refuses. If one did, run 'tacctl rollback " + version + " --apply' again (it is refused while a lockdown locks a group).")
}

// rollbackNextSteps0217 is the next steps of the rollback to 0.2.17, which
// converts the per-tier drop-in and the syntax key: the upgrade of the tag.
func (inv *invocation) rollbackNextSteps0217(version string) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.rollbackSyntaxKeyNote(version)
}

// rollbackSyntaxKeyNote says, after the rollback to a release that reads
// the configuration syntax under config_syntax only (0.2.17, 0.2.16, 0.2.9),
// that a change of devices.yaml before the upgrade writes ios_syntax again.
func (inv *invocation) rollbackSyntaxKeyNote(version string) {
	inv.echo("")
	inv.echo("Until the upgrade, do not run a command that changes the device registry (" + inv.app.Paths.DevicesFile + "): it writes the configuration syntax under ios_syntax again,")
	inv.echo("which " + version + " refuses. If one did, run 'tacctl rollback " + version + " --apply' again (it converts what is left).")
}

// rollbackNextSteps0216 is the next steps of the rollback to 0.2.16: the
// upgrade of the tag is the documented way, and what must not run until it.
// 0.2.16's schema refuses audit.strict, so the key is removed here, and it
// must not be set again before the older release is installed.
func (inv *invocation) rollbackNextSteps0216(version string, snapshot bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, do not add the 'audit' setting (audit.strict) to " + inv.app.Paths.Overrides + " again: " + version + " does not know the key, and its 'config validate' reports it.")
	inv.echo("If it was, run 'tacctl rollback " + version + " --apply' again (it converts what is left).")
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore refuses a tacctl.yaml with a key it does not know.")
	inv.rollbackSyntaxKeyNote(version)
}

// rollbackNextSteps029 is the next steps of the rollback to 0.2.9: the
// upgrade of the tag is the documented way, and what must not run until it.
func (inv *invocation) rollbackNextSteps029(version string, snapshot bool) {
	inv.echo("")
	inv.echo(ui.Bold + "Next steps" + ui.NC)
	inv.echo("  1. Install " + version + " with the upgrade (see Upgrading in the README), which switches the clone in " + inv.app.Paths.Deploy + " to the tag, builds it and re-executes it:")
	inv.echo("       tacctl upgrade --branch " + version)
	inv.echo("  2. Check it: tacctl status; tacctl config validate")
	inv.echo("")
	inv.echo("Until the upgrade, do not run 'tacctl scope netconf', 'tacctl device netconf', 'tacctl config devices apply-transport' or 'tacctl device config apply --transport':")
	inv.echo("they write the NETCONF service setting and the transport setting again. If one did, run 'tacctl rollback " + version + " --apply' again (it converts what is left).")
	inv.rollbackSnapshotNote(snapshot, "; "+version+"'s restore refuses a tacctl.yaml with a key it does not know.")
	inv.rollbackSyntaxKeyNote(version)
}
