package cli

// 'device rename <new> <name> --replace' (0.2.23, D308) puts a device that
// was registered at a bench address ('device clone', 'config <vendor>
// --staging --name') where the device it replaces is: the original is
// removed with what belongs to it, the replacement takes its name and its
// address, which ends the replacement's staging /32, and a break-glass hold
// of the original is cleared, never moved to the replacement (a hold stands
// on an address, and the address is now the replacement's). One snapshot
// covers the steps and one question, or --yes, starts them.

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/snmpcred"
)

// replaceFiles counts what the original has in files of its own, for the plan
// and the audit line.
type replaceFiles struct {
	snmp, blockFiles, notices int
	record                    bool
}

func (inv *invocation) replaceFilesOf(d *devreg.Device) replaceFiles {
	var n replaceFiles
	if p, err := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, d.Name); err == nil && fileThere(p) {
		n.snmp = 1
	}
	if files, err := inv.deviceBlockStore().ReadDevice(d.Name); err == nil {
		n.blockFiles = len(files)
	}
	if names, err := inv.configStore().Names(); err == nil {
		for _, x := range names {
			if strings.EqualFold(x, d.Name) {
				n.record = true
			}
		}
	}
	n.notices = len(d.Ack)
	return n
}

// text is the files as the plan names them.
func (n replaceFiles) text() string {
	var parts []string
	if n.snmp > 0 {
		parts = append(parts, "its SNMP credentials file")
	}
	if n.blockFiles > 0 {
		parts = append(parts, strconv.Itoa(n.blockFiles)+" configuration block "+plural(n.blockFiles, "file", "files"))
	}
	if n.record {
		parts = append(parts, "its configuration record")
	}
	if n.notices > 0 {
		parts = append(parts, strconv.Itoa(n.notices)+" acknowledged "+plural(n.notices, "notice", "notices"))
	}
	if len(parts) == 0 {
		return "nothing else of its own"
	}
	return strings.Join(parts, ", ")
}

func (inv *invocation) deviceReplace(p Parsed) error {
	a := inv.app
	if p.Has("--allow-generic") {
		return inv.usageErr("--allow-generic does not go with --replace: the replacement takes the name of the device it replaces.", deviceUsageLines("rename")[1])
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	repl, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	orig, err := inv.deviceEditable(res, f, p.Args[1])
	if err != nil {
		return err
	}
	if strings.EqualFold(repl.Name, orig.Name) {
		return inv.usageErr("'" + repl.Name + "' is the one device: --replace takes the device that replaces and the device it replaces. Nothing was changed.")
	}
	replName, origName, addr, bench := repl.Name, orig.Name, orig.Address, repl.Address
	staged, ok := inv.stagingEntryOf(bench)
	if !ok {
		return inv.usageErr("'"+replName+"' is not staged: no staging address of the scope holds "+bench+". --replace takes over from the original a device that is registered at a bench address.",
			"Register it from the original with 'tacctl device clone "+shellquote.Q(origName)+" "+shellquote.Q(replName)+" --staging <bench-ip>' or stage it with 'tacctl config <vendor> --scope <scope> --staging <bench-ip> --name "+shellquote.Q(replName)+"'. Nothing was changed.")
	}
	// The original's hold is a superuser's to clear (release is, and an
	// engineer has no break-glass privilege); the replacement's own would be
	// orphaned by the rename.
	hold, held := inv.holdOf(origName, addr)
	if held && inv.callerScopes().restricted {
		return inv.deniedUsage(reasonSuperuser, "break-glass is held on "+origName+": replacing it clears the hold, which is the superuser's ('tacctl breakglass release "+origName+"' is). Nothing was changed.")
	}
	if inv.isHeld(replName, bench) {
		return inv.usageErr("break-glass is held on " + replName + ": release it first (tacctl breakglass release " + replName + "). Nothing was changed.")
	}

	// Where the replacement will be answered from: the scope of the
	// original's address, which may not be the scope of its bench address.
	m, err := inv.model()
	if err != nil {
		return err
	}
	scopeNow := ""
	if info, found := m.LookupAddr(addr); found {
		scopeNow = info.Scope
	}
	files := inv.replaceFilesOf(orig)

	a.Out.Warn("About to replace '" + origName + "' with '" + replName + "'.")
	inv.echo("  Removed:  '" + origName + "' (" + addr + ") from the registry, with " + files.text() + ".")
	where := "no scope answers " + addr + " yet, so it is unconfigured until a scope's prefixes cover it"
	if scopeNow != "" {
		where = "scope " + scopeNow
		if scopeNow != staged.Scope {
			where += ", not scope " + staged.Scope + " of its bench address"
		}
	}
	inv.echo("  Replaced: '" + replName + "' (" + bench + ") is renamed '" + origName + "' and moves to " + addr + " (" + where + "); it keeps its own host keys, and none of '" + origName + "' is carried.")
	if staged.Covered {
		inv.echo("  Staging:  the entry of " + bench + " ends; scope '" + staged.Scope + "' answers it by its own prefixes, which stay.")
	} else {
		inv.echo("  Staging:  " + staged.CIDR + " ends in scope '" + staged.Scope + "'.")
	}
	if held {
		a.Out.Warn("Break-glass is held on " + origName + " (" + addr + ") " + inv.holdSummary(hold) + ": '" + origName + "' is answered again once it is released here (the hold is cleared, never moved to '" + replName + "').")
	}
	if !p.Has("--yes") && !a.Prompter().ConfirmPrefix("  Confirm the replacement? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}

	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	defer a.Snapshots().Hold()()
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		o, r := f.Find(origName), f.Find(replName)
		if o == nil || r == nil {
			return inv.usageErr("Device '" + origName + "' or '" + replName + "' is no longer registered. Nothing was changed.")
		}
		f.Remove(o.Name)
		r.Name, r.Address = o.Name, o.Address
		// The DNS name names the device that is there: the replacement has
		// the original's when it has none of its own.
		if r.Hostname == "" {
			r.Hostname = o.Hostname
		}
		return nil
	}); err != nil {
		return err
	}
	// What belonged to the original goes first, so that what belongs to the
	// replacement can take the name. A file that cannot be carried is a
	// failure of the verb: the device named '<name>' would be running the
	// original's credentials or settings.
	var failed []string
	carry := func(problems ...string) {
		for _, pr := range problems {
			if pr != "" {
				failed = append(failed, pr+" Check the files of '"+origName+"' before it is used.")
			}
		}
	}
	carry(inv.configCarryProblem(origName, ""))
	carry(inv.snmpCarryProblem(origName, ""))
	carry(inv.blocksCarryProblems(origName, "")...)
	carry(inv.configCarryProblem(replName, origName))
	carry(inv.snmpCarryProblem(replName, origName))
	carry(inv.blocksCarryProblems(replName, origName)...)

	cleared, rendered := "no", ""
	if held {
		var err error
		if rendered, err = inv.replaceClearHold(m, hold); err != nil {
			failed = append(failed, strings.Join(msgs(err), " ")+" The hold of "+origName+" may still stand, and now on '"+origName+"', the replacement: tacctl breakglass release "+origName)
		} else {
			cleared = "yes"
		}
	}
	// The replacement's staging lines follow the rename first: if the /32
	// cannot be ended now, the line names a device that is registered, and
	// the sweep ends it. The original's own lines stay (they name the device
	// at its address, which is the replacement now), with their /32s.
	inv.stagingRenameLines(replName, origName, true)
	if err := inv.stagingEnd(staged, "scope staging done", "device="+origName+" seen="+addr); err != nil {
		failed = append(failed, "the staging address "+staged.CIDR+" stays in scope '"+staged.Scope+"': "+strings.Join(msgs(err), " ")+" (tacctl scope staging remove "+staged.CIDR+", a superuser's verb)")
	}
	inv.detail("device replace", kvp("old", origName), kvp("new", replName), kvp("address", addr), kvp("hold_cleared", cleared),
		kvp("snmp_files", strconv.Itoa(files.snmp)), kvp("block_files", strconv.Itoa(files.blockFiles)), kvp("notices", strconv.Itoa(files.notices)), kvp("count", "1"))

	a.Out.Info("Device '" + replName + "' replaces '" + origName + "': it is now '" + origName + "' at " + addr + ".")
	if cleared == "yes" {
		inv.echo("  Break-glass on " + origName + " (" + addr + ") released; rendered: " + rendered)
	}
	inv.echo("  Next:     tacctl device config pull " + shellquote.Q(origName) + " (the replacement's own record starts there)")
	inv.echo("")
	if len(failed) > 0 {
		for _, f := range failed {
			a.Out.ErrorE("Not done: " + f)
		}
		return exit(1)
	}
	return nil
}

// replaceClearHold releases the record of the original's hold, as
// 'breakglass release' does (one render, the backends that serve the address
// restarted), with the same audit line, and returns the sentence that says
// what was rendered.
func (inv *invocation) replaceClearHold(m *model.Model, h conf.Hold) (string, error) {
	a := inv.app
	held := holdAge(h, a.Knobs.Now())
	if t := h.SinceTime(); !t.IsZero() {
		held = a.Knobs.Now().Sub(t).Round(time.Minute).String()
	}
	res, err := a.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		return a.Conf().UnsetHold(h.Device)
	})
	inv.loaded = false
	if err != nil {
		inv.releaseFailed("breakglass release device="+h.Device+" addr="+h.Address, failReason(err, "store"))
		return "", err
	}
	a.Audit().Raw("auth.info", "breakglass release device="+h.Device+" addr="+h.Address+" held="+held+" by="+inv.sudoUser()+" result=ok")
	if len(res.RestartFailed) > 0 {
		return "", errors.New("the record is removed and the rendered files are kept, but the release is not in force until the backend that serves " + h.Address + " is restarted")
	}
	return inv.renderedSentence(m, h.Address, res, false), nil
}
