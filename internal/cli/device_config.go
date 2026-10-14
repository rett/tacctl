package cli

// 'device config': show, pull, diff, list and forget. 'show <name>' is a
// registered device's data, then the vendor walkthrough 'tacctl config
// <vendor> --scope <its scope> --name <name>' prints, built by the same
// in-process code (configDevice) with the device's own values in the SNMP
// step. 'pull' and 'diff' read the devices' configuration and compare the
// managed sections with what tacctl renders (device_config_pull.go,
// device_config_diff.go); 'list' and 'forget' are device_config_list.go.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// deviceConfigSpecs are the arguments of each 'device config' verb, for the
// parser and for completion (device.go's spec lookup).
var deviceConfigSpecs = func() map[string]Spec {
	selectors := []Flag{
		{Names: []string{"--all"}, Alone: true},
		{Names: []string{"--scope"}, Value: true, Kind: KindScopes},
		{Names: []string{"--vendor"}, Value: true, Kind: "cisco|juniper|wti"},
		{Names: []string{"--stale"}},
	}
	read := []Flag{
		{Names: []string{"--transport"}, Value: true, Kind: "auto|netconf|ssh"},
		{Names: []string{"--concurrency"}, Value: true},
		{Names: []string{"--timeout"}, Value: true},
		{Names: []string{"--max-failures"}, Value: true},
		{Names: []string{"--server"}, Value: true},
		{Names: []string{"--source"}, Value: true},
		// the one-shot local login (0.2.9, D136): superusers, one device
		{Names: []string{"--login"}, Value: true},
	}
	join := func(groups ...[]Flag) []Flag {
		var out []Flag
		for _, g := range groups {
			out = append(out, g...)
		}
		return out
	}
	return map[string]Spec{
		"show": {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices}, Flags: []Flag{
			{Names: []string{"--protocol"}, Value: true, Kind: "tacacs|radius"},
			{Names: []string{"--legacy"}},
			{Names: []string{"--server"}, Value: true},
			{Names: []string{"--source"}, Value: true}}},
		"pull": {MaxArgs: -1, Args: []string{KindDevices + KindList},
			Flags: join(selectors, read, []Flag{{Names: []string{"--diff"}}, flagJSON})},
		"diff": {MaxArgs: -1, Args: []string{KindDevices + KindList},
			Flags: join(selectors, read, []Flag{{Names: []string{"--pull"}},
				{Names: []string{"--section"}, Value: true, Kind: strings.Join(devconf.SectionNames, "|") + KindList},
				flagJSON, {Names: []string{"--exit-code"}}})},
		"plan": {MaxArgs: -1, Args: []string{KindDevices + KindList},
			Flags: join(selectors, read, []Flag{{Names: []string{"--pull"}},
				{Names: []string{"--section"}, Value: true, Kind: strings.Join(planSections, "|") + KindList},
				{Names: []string{"--converge"}}, {Names: []string{"--secrets"}}, {Names: []string{"--no-secrets"}},
				{Names: []string{"--plain"}}, {Names: []string{"--backout"}}, flagJSON,
				{Names: []string{"--out"}, Value: true, Kind: KindFile}, {Names: []string{"--out-dir"}, Value: true, Kind: KindFile},
				{Names: []string{"--force"}}, {Names: []string{"--from"}, Value: true}, {Names: []string{"--exit-code"}},
				{Names: []string{"--restore-point"}, Value: true, Optional: true, Kind: "flash:|bootflash:|disk0:|usbflash0:|harddisk:"}})},
		"list": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--stale"}}, {Names: []string{"--never"}}, {Names: []string{"--failed"}},
			{Names: []string{"--differs"}}, {Names: []string{"--transport"}, Value: true, Kind: "netconf|ssh|none"},
			{Names: []string{"--scope"}, Value: true, Kind: KindScopes}, {Names: []string{"--vendor"}, Value: true, Kind: "cisco|juniper|wti"},
			flagJSON}},
		"forget": {MaxArgs: -1, Args: []string{KindDevices + KindList}, Flags: []Flag{{Names: []string{"--all"}, Alone: true}}},
		// 'apply' (0.2.9, D130): the selection and the read options of a
		// pull, minus the transport (the apply is the Junos command line).
		"apply": {MaxArgs: -1, Args: []string{KindDevices + KindList},
			Flags: join(selectors, []Flag{
				{Names: []string{"--concurrency"}, Value: true}, {Names: []string{"--timeout"}, Value: true},
				{Names: []string{"--max-failures"}, Value: true}, {Names: []string{"--server"}, Value: true},
				{Names: []string{"--source"}, Value: true},
				{Names: []string{"--check"}}, {Names: []string{"--confirmed"}},
				{Names: []string{"--max"}, Value: true}, {Names: []string{"--pause"}, Value: true},
				{Names: []string{"--hold"}}, {Names: []string{"--no-canary"}},
				{Names: []string{"--section"}, Value: true, Kind: strings.Join(planSections, "|") + KindList},
				flagJSON, {Names: []string{"--exit-code"}}, flagYes})},
		// 'shapes' (0.2.9, D135): 'list' (the default) and 'seed'.
		"shapes": {MaxArgs: -1, Args: []string{"list|seed", KindDevices + KindList}, Flags: []Flag{
			{Names: []string{"--show"}, Value: true, Only: "list", Kind: KindShapes},
			{Names: []string{"--json"}, Only: "list"}, {Names: []string{"-y", "--yes"}, Only: "seed"}}},
	}
}()

// deviceConfigVerbs are the 'device config' verbs in the order of device.go's
// rows.
var deviceConfigWords = []string{"show", "pull", "diff", "plan", "apply", "shapes", "list", "forget"}

// deviceConfigUse is the usage of a 'device config' verb after
// 'tacctl device config ' (” for none).
func deviceConfigUse(sub string) string {
	for _, v := range deviceVerbs {
		if f := strings.Fields(v[0]); len(f) > 1 && f[0] == "config" && f[1] == sub {
			return strings.TrimPrefix(v[0], "config ")
		}
	}
	return sub
}

// deviceConfigParse parses a 'device config' verb's arguments with its spec;
// a bad one is the error line and the verb's usage, exit 2 (argErr).
func (inv *invocation) deviceConfigParse(sub string, args []string) (Parsed, error) {
	p, err := Parse(deviceConfigSpecs[sub], args)
	if err == nil {
		return p, nil
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return p, inv.argErr(msg, "Usage: tacctl device config "+deviceConfigUse(sub))
}

// argErr is a wrong argument of the verbs that read the devices: the lines,
// and exit status 2, the status of a verb that checks its own arguments (a
// refusal of a name, a tier or a login is 1; so is a device that failed).
func (inv *invocation) argErr(msgs ...string) error {
	for _, m := range msgs {
		inv.app.Out.ErrorE(m)
	}
	return exit(batch.ExitUsage)
}

// deviceConfigNeeds is the lowest tier of each verb. The gate sees the two
// words 'device config' (its rows let an operator through for 'list' and an
// engineer for the rest); the verb holds each to its own tier, as 'scope
// snmp' does.
var deviceConfigNeeds = map[string]tier.Tier{
	"list": tier.Operator, "show": tier.Engineer, "pull": tier.Engineer, "diff": tier.Engineer, "plan": tier.Engineer,
	"forget": tier.Superuser,
	// 'apply' (0.2.9, D130, D141) changes a device and 'shapes' (with its
	// 'list' and 'seed') files what was confirmed: the superuser's. No
	// sudoers row names them, so sudo refuses a lower tier before the verb
	// runs, and the verb asks again.
	"apply": tier.Superuser, "shapes": tier.Superuser,
}

// tierPermits is whether tier t may run a verb that needs tier need.
func tierPermits(t, need tier.Tier) bool {
	return t == tier.Unrestricted || t == tier.Superuser || (tier.Rank(t) >= 0 && tier.Rank(t) >= tier.Rank(need))
}

// deviceConfigPermits is the caller's tier and whether it may run the verb.
func (inv *invocation) deviceConfigPermits(sub string) (tier.Tier, bool) {
	t := inv.tierGate().Caller(inv.ctx)
	return t, tierPermits(t, deviceConfigNeeds[sub])
}

// deviceConfigAllowed is nil when the caller's tier may run the verb; the
// refusal is the gate's, printed and logged.
func (inv *invocation) deviceConfigAllowed(sub string) error {
	return inv.deviceVerbAllowed("device config", sub, deviceConfigNeeds[sub])
}

// deviceVerbAllowed holds a verb of a 'device' family whose gate row is
// wider than the verb to its own tier: nil when the caller's tier is at least
// need.
func (inv *invocation) deviceVerbAllowed(family, sub string, need tier.Tier) error {
	g := inv.tierGate()
	t := g.Caller(inv.ctx)
	if tierPermits(t, need) {
		return nil
	}
	user := inv.sudoUser()
	inv.app.Logger(inv.ctx, "auth.warning", "tier DENY user="+user+" tier="+string(t)+" cmd="+family+" "+sub)
	if t == tier.None {
		inv.app.Out.ErrorE("'" + g.SudoUser + "' has no active tacctl user, so tacctl access is denied.")
	} else {
		inv.app.Out.ErrorE("'tacctl " + family + " " + sub + "' is not permitted for the " + string(t) + " tier.")
	}
	return tier.ErrDenied
}

// deviceConfigOptKey is the key of a verb's option lines in deviceOptions.
func deviceConfigOptKey(sub string) string { return "config " + sub }

// deviceConfigUsage is the usage of 'device config'.
func deviceConfigUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Device Configuration" + ui.NC + "\n\nUsage: tacctl device config <subcommand> [arguments]\n\nSubcommands:\n")
	for _, w := range deviceConfigWords {
		use := deviceConfigUse(w)
		short := ""
		for _, v := range deviceVerbs {
			if f := strings.Fields(v[0]); len(f) > 1 && f[0] == "config" && f[1] == w {
				short = v[1]
			}
		}
		b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 4) + short + "\n")
		for _, o := range deviceOptions[deviceConfigOptKey(w)] {
			fmt.Fprintf(&b, "      %-34s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
'show' prints what is registered for the device, then the walkthrough for its
vendor (cisco, juniper or wti) and the scope that covers its address, exactly
as 'tacctl config <vendor> --scope <scope> --name <name>' prints it, with the
device's location, description and name filling the SNMP step. A device whose
vendor is 'other', an enrolled Linux host and a device no scope's prefixes
cover have none. A Cisco device is walked through in its configuration syntax:
the setting of 'tacctl device config-syntax' (ios12 or modern), else the one
the last pull read from its version line, else the modern syntax with a line
that says so; --legacy is the IOS 12.x syntax whatever that is.

'pull' logs in to the devices as you (your username and your tacctl password,
asked for once, never stored or logged), reads each one's configuration over
NETCONF where it answers (Junos) or the ssh command line, and keeps the managed
sections (aaa, roles, mgmt-acl, snmp, netconf, breakglass, and system for a
scope that has a system block) with the state of their comparison with what
tacctl renders for that device. A secret is compared by presence only and no
secret value is kept or printed (a login message is kept as its size and a
digest, never as text). A device
needs a pinned host key ('tacctl device hostkey <name> accept'); its scope
must be one of yours. At most device.config.max_concurrency devices are read
at once (--concurrency lowers it, never raises it). Ctrl-C stops starting new
devices; a second one cuts the running ones off. Exit status: 0 every device
read, 1 a device failed (or was refused), 2 wrong arguments, 130 interrupted.
A Cisco device is read with 'show version | include Version' as well: the
image's version line is kept on the record with the configuration syntax it
says (12.x is ios12; 15.2 to 15.9, 16.x, 17.x and IOS-XE are modern; any other
image, such as 11.x, 15.0, 15.1, an ASA or IOS XR, is unknown and is not guessed:
the pull is refused and nothing is recorded), and the device is compared in that
syntax unless 'device config-syntax' says otherwise; a setting that the image
contradicts wins and is shown.
A WTI console server is read as its menus show it, over ssh: its command menu
must be version 8.10 and its pages (never a prompt, never a save) give aaa,
mgmt-acl, snmp and breakglass. A login whose WTI level cannot configure the
unit is 'denied' and a menu of another version 'unsupported'; both are failed
pulls, and the line of a unit says how many other sessions it has.

'diff' compares the last pull with what tacctl renders now, section by
section: '-' is a statement tacctl renders that the device lacks, '+' one the
device has in a managed hierarchy that tacctl does not render, '!' a
reordering, '?' a secret the login could not see. --pull reads first.
--exit-code makes a difference exit 2.

'plan' prints, for each device, what to paste to make it match what tacctl
renders, from the last pull; it reads no device unless --pull reads them
first, and writes to none ever. The output is the report in plain words (each
irregularity, how serious it is, and what the paste does about it), then ONE
region between 'PASTE FROM HERE' and 'PASTE TO HERE' that is safe to paste
whole (on Junos it ends at 'commit confirmed', so the paste makes no permanent
change; on IOS at 'end'), then the check, the one line to type yourself
afterwards ('commit' or 'write memory'; it is never in the region) and the
back-out, all comments. A statement that is an extra is reported with the
line that removes it and left alone; --converge makes the region that removes
the old servers and the like for a device that has nothing else to paste (the
plan after the paste and the verifying pull; a device with a first region gets
that region and one line that says to plan again after it): never beside a
first region, never a server or group a statement that stays names, never the
other protocol's, never a named command list. A section
that cannot be pasted safely (a statement a group owns, a login class that
cannot commit it, the Cisco lock-out guards) is left out and the report says
why; on a Cisco device the standard's command authorization is held back until
the server is proven to the device, and the report says so. A device that was
never pulled, was pulled more than stale-days ago, whose last pull failed or
whose Cisco syntax is not known cannot be planned (exit 1). With several
devices a cover page comes first. --plain is the statements of one device
alone (for 'load set'; with --out-dir one .set file each); --json is one
object per device, secret values elided; --backout prints the back-out region
alone (every plan with changes keeps its back-out beside the record, so after
the check pull --backout prints that one, and says which pull it undoes;
--backout with --pull is refused); --out and --out-dir write 0600 files, as
the user who ran sudo, into a directory that user may write without a
supplementary group (--out-dir adds COVER.txt and each plan's back-out). A secret the device lacks is typed in its line, and a
secret it has is neither printed nor changed unless --secrets; --no-secrets
leaves each as a marked line to fill in. --from <address> is where you are
logged in from: the cleanup never removes it. --restore-point (a Cisco IOS or
IOS-XE device only; not with --plain or --backout) puts a block of its own
before the region, between 'RESTORE POINT FROM HERE' and 'RESTORE POINT TO
HERE': one 'copy running-config <fs>tacctl-<device>-<time>.cfg' on the file
system named (--restore-point=disk0:) or, bare, 'archive config' where the last
pull read an 'archive' with a 'path' (a bare flag with none is refused). It is
a file, not a timer: the back-out names 'configure replace <file> force' as
its alternative to the 'no' lines. Not lab-tested. Exit status: 0 the outputs were
made, 1 a device cannot be planned, 2 wrong arguments (or, with --exit-code,
a device needs a change), 130 interrupted.
A WTI console server has nothing to paste: its plan is a numbered checklist of
menu steps for you to type (the keys to the item, its label, what to enter and
the value the pull showed), in an order that cannot take away the way in before
the step that needs it, and one <iptables> block for the IP tables list, which
is the only line of the output that is not a comment, replaces every entry and
is presented, never applied. The unit has no commit-confirm: the plan names the
sessions to keep open, the check to make after the save (ESC out of /N) and, in
--backout, the steps with the old values and the old list. A secret step names
the command that shows the value (--secrets types it); a list that would not
fit, that does not permit the tacctl server or that --from is not in is left
out and the rest is planned. --plain, and --section roles or system, are
refused for a unit; --converge offers the read/write community and the other
protocol's switch only.

'apply' (superusers; Junos devices) types what 'plan' would paste into the
devices itself, as you (the password is asked for once). Each device is
checked first: tacctl reads it, loads the plan in an exclusive configure
session, runs the device's own 'commit check' and discards the candidate;
--check stops there and commits nothing. The devices that need a change are
then shown grouped by shape (the same change under one heading, every secret
elided) and ONE question is asked: the device's name (one device) or the
number of devices, typed back. Each is committed under 'commit confirmed N'
(config devices apply-confirm-timeout), proven by a fresh login as you, by what
landed being the change the check showed and by a read of the planned sections,
and then confirmed; the first device of every shape goes alone, and the rest of
its shape only when it applied. A device that fails a proof is rolled back; one
whose state could not be read is PENDING until the time shown, and nothing
may be typed on it before then (a 'commit check' confirms a pending commit).
--confirmed applies only shapes an earlier apply confirmed (the rest are
skipped) and is the only form --yes answers the question for, so a script runs
it without a terminal; --max (default 5) caps the devices of a run, --pause the
seconds between them (config devices apply-pause), --hold asks you to log in
with one account of each class and type OK before the change is kept,
--section limits the sections. Never written: the break-glass and
NETCONF sections, the root and your own account, system services, interfaces,
groups. Exit status: 0 every device applied, was checked or had no change, 1 a
device failed, was rolled back or is pending, 2 wrong arguments (or, with
--check --exit-code, a device that needs a change), 130 interrupted (the first
Ctrl-C starts no more devices, the second cancels the running ones).
'shapes' lists the shapes seen and which were confirmed by an apply, with
--show <hash> one shape's statements; 'shapes seed <name>' files the shape of
the device's last check or apply as confirmed on your word (one question,
-y answers it), for a device that was applied and verified by hand.

'list' shows each device's state: ok (every managed section agrees), differs,
never (not pulled), failed (the last pull failed) or pull (a Cisco device whose
syntax is unknown: its record has no version line and its config-syntax is
auto: every record made by an earlier tacctl), computed against today's rendering,
so a change in tacctl makes a device differ without a new pull. --stale is
never, failed, differs and pull together. Once a device was checked or applied
the table has an APPLIED column (checked, applied <time>, PENDING <time>,
rolled-back, failed). 'forget' deletes the records (they are derived: a pull
makes them again).

Examples:
  tacctl device config show core-sw1
  tacctl device config pull core-sw1
  tacctl device config pull --all --diff
  tacctl device config pull --scope lab --vendor juniper --concurrency 4
  tacctl device config diff core-sw1 --section aaa,snmp
  tacctl device config plan core-sw1
  tacctl device config plan --scope lab --out-dir ~/plans
  tacctl device config apply core-sw1 --check
  tacctl device config apply --scope lab
  tacctl device config apply --scope lab --confirmed --yes
  tacctl device config shapes
  tacctl device config list --stale

`)
	return b.String()
}

// deviceConfig dispatches 'device config': no sub-command, help, -h and
// --help are the usage (exit 0); anything else unknown is an error, then the
// usage (exit 1).
func (inv *invocation) deviceConfig(args []string) error {
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(deviceConfigUsage())
		return nil
	case "show":
		if err := inv.deviceConfigAllowed("show"); err != nil {
			return err
		}
		return inv.deviceConfigShow(args)
	case "pull":
		return inv.deviceConfigPull(args[1:])
	case "diff":
		return inv.deviceConfigDiff(args[1:])
	case "plan":
		return inv.deviceConfigPlan(args[1:])
	case "apply":
		if err := inv.deviceConfigAllowed("apply"); err != nil {
			return err
		}
		return inv.deviceConfigApply(args[1:])
	case "shapes":
		if err := inv.deviceConfigAllowed("shapes"); err != nil {
			return err
		}
		return inv.deviceConfigShapes(args[1:])
	case "list":
		return inv.deviceConfigList(args[1:])
	case "forget":
		return inv.deviceConfigForget(args[1:])
	default:
		// A verb the table holds is refused to a lower tier as the verb itself
		// will refuse it.
		if _, held := deviceConfigNeeds[sub]; held {
			if err := inv.deviceConfigAllowed(sub); err != nil {
				return err
			}
		}
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(deviceConfigUsage())
		return exit(1)
	}
}

// deviceConfigShow is 'device config show <name> [--protocol ...]': args
// starts with "show".
func (inv *invocation) deviceConfigShow(args []string) error {
	p, err := inv.deviceParse("config", args)
	if err != nil {
		return err
	}
	if len(p.Args) < 2 {
		return inv.usageErr("Usage: tacctl device config show <name> [--protocol tacacs|radius] [--legacy] [--server <address|name>] [--source <address>]")
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, p.Args[1])
	if err != nil {
		return err
	}
	switch {
	case e.Source == devreg.SourceHost:
		return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; it has no device walkthrough. See: tacctl host show " + e.Name)
	case !slices.Contains(sortedVendors(), e.Vendor):
		return inv.usageErr("Device '"+e.Name+"' has vendor '"+e.Vendor+"', and only cisco, juniper and wti have a walkthrough.",
			"Set the vendor with: tacctl device vendor "+e.Name+" cisco|juniper|wti")
	case !e.Configured:
		return inv.usageErr("Device '"+e.Name+"' ("+dashAddrText(e.Address)+") is in no scope: no scope's prefixes cover its address.",
			"Add them with: tacctl scope prefixes <scope> add <cidr>")
	case p.Has("--legacy") && e.Vendor != "cisco":
		return inv.usageErr("--legacy (IOS 12.x syntax) applies to Cisco devices; '" + e.Name + "' is a " + e.Vendor + " device.")
	}
	cfg := []string{"--scope", e.Scope, "--name", e.Name}
	for _, f := range []string{"--protocol", "--server", "--source"} {
		if p.Has(f) {
			cfg = append(cfg, f, p.Value(f))
		}
	}
	if p.Has("--legacy") {
		cfg = append(cfg, "--legacy")
	}
	// The walkthrough is built first: a refusal prints no data block.
	var walk bytes.Buffer
	out := inv.app.Out
	inv.app.Out.Stdout = &walk
	note, err := inv.configDeviceNote(e.Vendor, cfg, nil)
	inv.app.Out = out
	if err != nil {
		return err
	}
	inv.printDeviceData(e)
	// A device that is neither set nor pulled is walked through in the
	// modern syntax, and the line says why (D113).
	if note != "" {
		inv.echo(note)
	}
	_, err = io.Copy(inv.app.Out.Stdout, &walk)
	return err
}

// printDeviceData is the data block of 'device config show': the device as
// registered, with the scope that covers it.
func (inv *invocation) printDeviceData(e devreg.Entry) {
	head := "Device " + e.Name
	inv.echo("")
	inv.echoE(ui.Bold + head + ui.NC)
	inv.echo(ui.Rule(head))
	row := func(k, v string) { inv.write(fmt.Sprintf("  %-13s %s\n", k+":", v)) }
	row("Name", e.Name)
	row("Address", dash(e.Address))
	row("Hostname", dash(e.Hostname))
	row("Vendor", e.Vendor)
	row("Scope", e.Scope+"  (via prefix "+e.Prefix+")")
	row("Description", dash(e.Description))
	row("Location", dash(e.Location))
	// What the SNMP step below is rendered with, and where each value comes
	// from (D72): the device's own over its scope's over the default.
	inv.deviceSNMPRows(e, func(k, v string) {
		if k == "" {
			inv.write(fmt.Sprintf("  %-13s %s\n", "", v))
			return
		}
		row(k, v)
	})
	inv.echo("")
}
