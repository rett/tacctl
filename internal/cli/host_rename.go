package cli

// 'host rename <old> <new>' (docs/plans/0.2.14-plan.md D182-D186 and
// D197-D201): an enrolled host gets another name. It is local: the remote
// host records no registry name, so nothing is sent over ssh, which is also
// why a held host may be renamed. The name lives in the registry line, the
// pins of devices.yaml (keys, address, history, acknowledgements), the
// record, the staging addresses, the break-glass hold and the host-key cache,
// and in the host's own scope when that is the one made for it
// (linux-<name>), which is renamed with it after a question.

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/names"
)

// hostRenameUsage is the usage line of 'host rename'.
const hostRenameUsage = "Usage: tacctl host rename <old> <new> [-y]"

// hostRenamePlan is what a rename has found out before it writes anything.
type hostRenamePlan struct {
	oldName, newName string
	entry            hosts.Entry
	// holdAddr is the address a hold on the host carves, read before the pin
	// moves with the name ("" for this server's own host or an unknown one).
	holdAddr string
	// leftover is what the new name has from an earlier host.
	leftover []string
	// leftPin and leftRecord say which leftovers are there.
	leftPin, leftRecord bool
	// offer is the host's own scope when it is offered the same rename.
	oldScope, newScope string
	offer              bool
	// stays is why the scope is not offered ("" when it is, or when the host
	// is not in a scope named for it).
	stays string
}

// hostRename is 'host rename <old> <new> [-y]'.
func (inv *invocation) hostRename(args []string) error {
	a := inv.app
	yes := false
	var pos []string
	for _, w := range args {
		switch {
		case w == "-y" || w == "--yes":
			yes = true
		case strings.HasPrefix(w, "-"):
			return inv.usageErr("Unknown option: '"+w+"'", hostRenameUsage)
		default:
			pos = append(pos, w)
		}
	}
	if len(pos) != 2 {
		return inv.usageErr(hostRenameUsage)
	}
	if err := inv.confReadable(); err != nil {
		return err
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	p, err := inv.hostRenameChecks(reg, pos[0], pos[1])
	if err != nil {
		return err
	}
	oldName, newName := p.oldName, p.newName

	// Another command holds the host's lock: it is not waited for (D185).
	unlock, err := hosts.LockHost(filepath.Join(a.Paths.StateDir, "locks"), oldName)
	switch {
	case errors.Is(err, hosts.ErrRotationBusy):
		return inv.hostLockBusyErr(oldName)
	case err != nil:
		return err
	}
	defer unlock()
	if p.stays != "" {
		a.Out.WarnE("Scope 'linux-" + oldName + "' keeps its name: " + p.stays + ".")
	}

	// The questions, all before the first write (D184, D200). --yes answers
	// them yes; a question that gets no answer is a no.
	if len(p.leftover) > 0 {
		a.Out.WarnE("The name '" + newName + "' has what an earlier host of that name left, which the rename replaces: " + strings.Join(p.leftover, "; ") + ".")
		if !yes && !a.Prompter().Confirm("  Replace it? [y/N]: ") {
			a.Out.InfoE("Nothing was changed.")
			return exit(1)
		}
	}
	renameScope := false
	if p.offer {
		renameScope = yes || a.Prompter().Confirm("  Scope '"+p.oldScope+"' is this host's own (no other host uses it). Rename it to '"+p.newScope+"' too? [y/N]: ")
	}

	// The state before anything changes (D191).
	if err := inv.snapshotFirst(); err != nil {
		return err
	}

	// The registry line, in place, atomically; a name taken meanwhile is
	// found under the registry's lock.
	if err := reg.Rename(oldName, newName); err != nil {
		var taken *hosts.NameTakenError
		switch {
		case errors.As(err, &taken):
			return inv.usageErr(taken.Error() + " Nothing was changed.")
		case errors.Is(err, hosts.ErrNotEnrolled):
			return inv.usageErr("No enrolled host named '" + oldName + "' any more. Nothing was changed.")
		}
		return inv.usageErr(strings.Join(msgs(err), " ") + " Nothing was changed.")
	}
	inv.hooks.renameStep("registry")

	// The pin, the address history and the acknowledgements in one write of
	// devices.yaml (known_hosts regenerated). It runs whether or not there
	// is a pin (it writes nothing when the bytes do not change), because it
	// is also where a device registered under the new name since the checks
	// is found: the registry line has been written, and a command that
	// registers a device reads the hosts under this same lock. If it fails
	// the registry line goes back, and nothing was changed.
	changed, err := devreg.Mutate(a.Paths.DevicesFile, a.Paths.KnownHosts, nil, func(f *devreg.File) error {
		if d := f.Find(newName); d != nil {
			return errors.New("A device named '" + d.Name + "' (" + d.Address + ") was registered meanwhile; a host and a device cannot share a name.")
		}
		f.RenameHost(oldName, newName)
		return nil
	})
	if err != nil {
		return inv.hostRenameUndo(reg, p, changed, err)
	}
	inv.hooks.renameStep("pins")

	// What follows is informational or recoverable: a failure is a warning
	// that names what stayed and how to put it right.
	inv.hostRenameRecord(p)
	inv.hostRenameStaging(p)
	if p.holdAddr != "" {
		// The hold stays on the same address and follows the name (it prints
		// its own warning when it cannot).
		inv.holdCarry(oldName, newName, p.holdAddr)
	}
	inv.hostRenameSeen(p)

	a.Logger(inv.ctx, "auth.info", "host rename old="+oldName+" new="+newName+" by="+inv.sudoUser())
	a.Out.InfoE("Host '" + oldName + "' renamed to '" + newName + "'. Nothing was sent to the host.")

	if renameScope {
		// The question's premise was that no other host uses the scope; a
		// host enrolled into it since is read from the registry again.
		if now, rerr := inv.registry(); rerr == nil && now.OtherHostsUse(p.oldScope, newName) {
			a.Out.WarnE("Scope '" + p.oldScope + "' keeps its name: other enrolled hosts use it.")
			inv.echo("")
			inv.echo("  To rename the scope as well: tacctl scope rename " + p.oldScope + " " + p.newScope)
			inv.echo("")
			return nil
		}
		err := inv.scopeRenameCheck(p.oldScope, p.newScope)
		if err == nil {
			err = inv.scopeRenameRun(p.oldScope, p.newScope)
		}
		if err != nil {
			return inv.hostRenameScopeFailed(p, err)
		}
		return nil
	}
	inv.echo("")
	if p.offer {
		inv.echo("  To rename the scope as well: tacctl scope rename " + p.oldScope + " " + p.newScope)
		inv.echo("")
	}
	return nil
}

// hostRenameScopeFailed is D201: the host is renamed and keeps its scope.
func (inv *invocation) hostRenameScopeFailed(p *hostRenamePlan, err error) error {
	return inv.usageErr("Host renamed. Scope '" + p.oldScope + "' was NOT renamed: " + strings.TrimRight(strings.Join(msgs(err), " "), ".") +
		"; the host keeps it. Retry: tacctl scope rename " + p.oldScope + " " + p.newScope + ".")
}

// hostRenameChecks is every refusal of a rename and the facts the rest of it
// works from. Nothing has been changed when it returns, and nothing is
// written by it.
func (inv *invocation) hostRenameChecks(reg *hosts.Registry, oldArg, newName string) (*hostRenamePlan, error) {
	a := inv.app
	e, ok := reg.Find(oldArg)
	if !ok || e.Line == "" {
		return nil, inv.usageErr("No enrolled host named '" + oldArg + "'. See 'tacctl host list'.")
	}
	oldName := e.Name
	if oldName == newName {
		return nil, inv.usageErr("'" + oldName + "' already has that name.")
	}
	if !reHostName.MatchString(newName) {
		return nil, inv.usageErr("Invalid host name '" + newName + "'. Use letters, digits, _ or -, starting with a letter, max 26.")
	}
	f, err := inv.hostDevices()
	if err != nil {
		return nil, err
	}
	if err := devreg.CheckRenameHostName(reg, f, oldName, newName); err != nil {
		return nil, err
	}
	sameHost := strings.EqualFold(oldName, newName)

	// A hold under the new name is another host's or device's: only
	// 'breakglass release' removes it (D184). The host's own, under its old
	// name, is carried.
	if h, held := inv.holdNamed(newName); held && !sameHost {
		return nil, inv.hostRefuse(
			"A break-glass hold is recorded under the name '"+h.Device+"' ("+h.Address+") "+inv.holdSummary(h)+": "+h.Reason+".",
			"A hold is removed only by 'tacctl breakglass release "+h.Device+"'. Nothing was changed.")
	}

	// A new name is lower case; changing only the spelling to lower case is
	// how an old name is fixed.
	if err := names.RequireLower(newName); err != nil {
		return nil, err
	}

	p := &hostRenamePlan{oldName: oldName, newName: newName, entry: e}
	if e.Target != hosts.Local {
		p.holdAddr = hostHoldAddress(f, e)
	}

	// What an earlier host of the new name left (D184).
	if !sameHost && f.Host(newName) != nil {
		p.leftPin = true
		p.leftover = append(p.leftover, "its pinned ssh keys and address in the device registry")
	}
	if oldName != newName && inv.hostRecords().Has(newName) {
		p.leftRecord = true
		p.leftover = append(p.leftover, "its record "+filepath.Join(a.Paths.HostRecords, newName+".json"))
	}
	if n := inv.hostRenameStrays(oldName, newName); n > 0 {
		p.leftover = append(p.leftover, strconv.Itoa(n)+" staging address(es)")
	}

	inv.hostRenameOffer(reg, p)
	return p, nil
}

// hostRenameStrays counts the staging entries of a host equal to newName
// ignoring case that is not oldName: they belong to no registry line.
func (inv *invocation) hostRenameStrays(oldName, newName string) int {
	n := 0
	for _, s := range inv.stagingLoad() {
		if s.Kind == "host" && s.Name != oldName && strings.EqualFold(s.Name, newName) {
			n++
		}
	}
	return n
}

// hostRenameOffer decides whether the host's own scope is offered the same
// rename (D197): the scope is linux-<old>, no other host uses it, the store
// has it, linux-<new> does not exist and 'scope rename' itself would accept
// it. Otherwise one line says why it stays.
func (inv *invocation) hostRenameOffer(reg *hosts.Registry, p *hostRenamePlan) {
	oldScope := "linux-" + p.oldName
	if p.entry.Scope != oldScope {
		return
	}
	newScope := "linux-" + p.newName
	why := ""
	switch {
	case reg.OtherHostsUse(oldScope, p.oldName):
		why = "other enrolled hosts use it"
	case !cfgIsFile(inv.app.Paths.StoreFile):
		why = "there is no store"
	default:
		m, err := inv.model()
		switch {
		case err != nil:
			why = "the store cannot be read"
		case !m.Exists("scopes", oldScope):
			why = "the store has no such scope"
		case m.Exists("scopes", newScope):
			why = "scope '" + newScope + "' exists"
		default:
			if err := inv.scopeRenameCheck(oldScope, newScope); err != nil {
				why = strings.TrimRight(strings.Join(msgs(err), " "), ".")
			}
		}
	}
	if why != "" {
		p.stays = why
		return
	}
	p.oldScope, p.newScope, p.offer = oldScope, newScope, true
}

// hostRenameUndo puts the registry line back after the pins could not be
// renamed (and the pins too, when devices.yaml was written and only
// known_hosts failed). Nothing was changed when that works; when it does not,
// both states are named and the exit status is 1.
func (inv *invocation) hostRenameUndo(reg *hosts.Registry, p *hostRenamePlan, pinsWritten bool, cause error) error {
	a := inv.app
	inv.hooks.renameStep("undo")
	var pinBack, back error
	// The pins are back under the old name when they were never moved, or
	// when devices.yaml was written again (a failure after that write is
	// known_hosts alone).
	restored := !pinsWritten
	if pinsWritten {
		var rewritten bool
		rewritten, pinBack = devreg.Mutate(a.Paths.DevicesFile, a.Paths.KnownHosts, nil, func(f *devreg.File) error {
			f.RenameHost(p.newName, p.oldName)
			return nil
		})
		restored = pinBack == nil || rewritten
		if pinBack != nil && rewritten {
			a.Out.WarnE("The host-key file (" + a.Paths.KnownHosts + ") could not be written: " + strings.Join(msgs(pinBack), " ") + ". Any later change of the device registry writes it again.")
			pinBack = nil
		}
	}
	if restored {
		back = reg.Rename(p.newName, p.oldName)
	}
	snapshot := "The state before is the latest snapshot: tacctl backup list, tacctl backup restore <id>."
	switch {
	case !restored:
		// The pins are under the new name and so is the registry line.
		a.Out.ErrorE("The device registry could not be changed back (" + strings.Join(msgs(cause), " ") + "; " + strings.Join(msgs(pinBack), " ") + ").")
		a.Out.ErrorE("The host registry and the device registry both name the host '" + p.newName + "'; the host-key file (" + a.Paths.KnownHosts + ") may be stale. " + snapshot)
		return exit(1)
	case back != nil:
		a.Out.ErrorE("The device registry could not be changed (" + strings.Join(msgs(cause), " ") + ") and the registry line could not be put back (" + strings.Join(msgs(back), " ") + ").")
		a.Out.ErrorE("The host registry names the host '" + p.newName + "'; its pinned ssh keys and address are under '" + p.oldName + "'. " + snapshot)
		return exit(1)
	}
	if pinsWritten && p.leftPin {
		// The pins were written, so the pin an earlier host of the new name
		// left was replaced, and putting the old name back does not restore it.
		return inv.usageErr(strings.Join(msgs(cause), " "), "Host '"+p.oldName+"' was not renamed. The pinned ssh keys and address an earlier host of the name '"+p.newName+"' left were replaced; the latest snapshot has them: tacctl backup list.")
	}
	return inv.usageErr(strings.Join(msgs(cause), " "), "Host '"+p.oldName+"' was not renamed; nothing was changed.")
}

// hostRenameRecord moves the record over a leftover record of the new name
// (the move replaces it); with no record of the old name, the leftover goes by
// itself. A failure is a warning: the record is only shown.
func (inv *invocation) hostRenameRecord(p *hostRenamePlan) {
	rs := inv.hostRecords()
	if p.leftRecord && !rs.Has(p.oldName) {
		if err := rs.Forget(p.newName); err != nil {
			inv.app.Out.WarnE(p.newName + ": the record of an earlier host of that name could not be removed: " + strings.Join(msgs(err), " ") + ". Remove it, then: tacctl host sync " + p.newName)
		}
		return
	}
	if err := rs.Rename(p.oldName, p.newName); err != nil {
		inv.app.Out.WarnE(p.newName + ": its record (" + filepath.Join(inv.app.Paths.HostRecords, p.oldName+".json") + ") could not be moved: " + strings.Join(msgs(err), " ") + ". It stays under the old name, where nothing reads it (tacctl host forget " + p.oldName + " drops it); 'tacctl host sync " + p.newName + "' writes a new one.")
	}
}

// hostRenameStaging renames the host's staging entries, and drops the strays
// of the new name. A failure is a warning that names the addresses.
func (inv *invocation) hostRenameStaging(p *hostRenamePlan) {
	entries := inv.stagingLoad()
	var out []stagingEntry
	changed := false
	var addrs []string
	for _, s := range entries {
		switch {
		case s.Kind == "host" && s.Name == p.oldName:
			s.Name, changed = p.newName, true
			addrs = append(addrs, s.addr())
		case s.Kind == "host" && strings.EqualFold(s.Name, p.newName):
			changed = true
			continue
		}
		out = append(out, s)
	}
	if !changed {
		return
	}
	if err := inv.stagingSave(out); err != nil {
		inv.app.Out.WarnE(p.newName + ": its staging addresses still name '" + p.oldName + "' (" + strings.Join(addrs, ", ") + "): " + strings.Join(msgs(err), " ") +
			". They end when the host is seen in place, or: tacctl scope staging remove <address>")
	}
}

// hostRenameSeen moves the host-key cache entry (keyed in lower case, so a
// change of spelling moves nothing). A failure is a warning: the next
// 'tacctl device check' writes it again.
func (inv *invocation) hostRenameSeen(p *hostRenamePlan) {
	a := inv.app
	if strings.EqualFold(p.oldName, p.newName) || !inv.seenLoad().HasKeyScanFor(p.oldName, p.newName) {
		return
	}
	warn := func(err error) {
		a.Out.WarnE(p.newName + ": its host-key scan result (" + a.Paths.SeenCache + ") still names '" + p.oldName + "': " + strings.Join(msgs(err), " ") + ". 'tacctl device check' scans again.")
	}
	unlock, err := devreg.LockSeen(a.Paths.SeenCache)
	if err != nil {
		warn(err)
		return
	}
	defer unlock()
	seen := inv.seenLoad()
	if seen.RenameKeyScan(p.oldName, p.newName) {
		if err := seen.Save(a.Paths.SeenCache); err != nil {
			warn(err)
		}
	}
}
