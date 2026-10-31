package cli

// 'device clone <name> <new> --staging <bench-ip>' (0.2.23, D307) registers a
// copy of a device's intent at the address the new device has on the bench:
// the registry's plain fields, the SNMP settings and credentials, the NETCONF
// settings, the timing scale and the configuration blocks with their
// manifest. It copies nothing that belongs to the one device that is there:
// the address, the name, the DNS name (it names the original), the pinned
// host keys, the acknowledged notices, a break-glass hold and the pull record.
// The bench /32 is added to the device's scope first, as the other
// --staging verbs do, and 'device rename <new> <name> --replace'
// (device_replace.go) later puts the clone where the original is.
//
// The copy is all or nothing: what can be read is read before anything is
// written, and a write that fails takes the registry line, the files and the
// staging address back.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/snmpcred"
)

func (inv *invocation) deviceClone(args []string) error {
	a := inv.app
	p, err := inv.deviceParse("clone", args)
	if err != nil {
		return err
	}
	if !p.Has("--staging") {
		return inv.usageErr(append([]string{"--staging <bench-ip> is required: the clone is registered at the address it has on the bench, since the registry holds one device for each address."},
			deviceUsageLines("clone")...)...)
	}
	bench, problem := stagingBench(p.Value("--staging"))
	if problem != "" {
		return inv.usageErr(problem)
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	src, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	srcName, newName := src.Name, p.Args[1]
	if err := devreg.ValidateName(newName); err != nil {
		return err
	}
	if strings.EqualFold(newName, srcName) {
		return inv.usageErr("'" + srcName + "' is the device to copy: give the clone a name of its own. Nothing was changed.")
	}
	entry, _ := res.Lookup(srcName, devreg.ScopeFilter{})
	scope := entry.Scope
	if scope == "" {
		return inv.usageErr("'"+srcName+"' is at "+src.Address+", which no scope answers: the bench address is added to the scope that answers the device.",
			"Add its prefixes first ('tacctl scope prefixes <scope> add <cidr>'). Nothing was changed.")
	}

	// What is copied beside the registry line, read before anything is
	// written: a file that cannot be read stops the verb here.
	creds, err := snmpcred.LoadDevice(a.Paths.SNMPDir, srcName)
	if err != nil {
		return inv.unreadableOwn(srcName, err)
	}
	var files []blocks.File
	if blocks.ValidateDevice(srcName) == nil {
		if files, err = inv.deviceBlockStore().ReadDevice(srcName); err != nil {
			return err
		}
	}

	keep := "tacctl device clone " + shellquote.Q(srcName) + " " + shellquote.Q(newName) + " --staging " + bench + " --allow-generic"
	build := func(f *devreg.File, r *devreg.Resolver) error {
		o := f.Find(srcName)
		if o == nil {
			return inv.usageErr("Device '" + srcName + "' not found.")
		}
		if err := r.CheckName(newName, o.Vendor, p.Has("--allow-generic"), keep); err != nil {
			return err
		}
		// A new name is lower case (0.2.14).
		if err := names.RequireLower(newName); err != nil {
			return err
		}
		if err := r.CheckAddress(bench, ""); err != nil {
			return err
		}
		c := o.Clone()
		c.Name, c.Address = newName, bench
		c.Hostname, c.Ack, c.HostKeys = "", nil, nil
		f.Devices = append(f.Devices, &c)
		return nil
	}
	// Every refusal that needs no change comes before the first one.
	trial := f.Clone()
	pre := devreg.NewResolver(trial, nil, res.Model)
	pre.Hosts = res.Hosts
	if err := build(trial, pre); err != nil {
		return err
	}
	if err := inv.snmpNewNamesFree(f, trial); err != nil {
		return err
	}
	if err := inv.blocksNewNamesFree(f, trial); err != nil {
		return err
	}
	if _, err := trial.Text(); err != nil {
		return err
	}

	// One snapshot of the state before the staging address, the registry
	// line and the files.
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	defer a.Snapshots().Hold()()
	inv.cloneOf = srcName
	defer func() { inv.cloneOf = "" }()

	_, hadStaging := inv.stagingEntryOf(bench)
	if err := inv.stagingAdd(scope, bench, "device", newName); err != nil {
		return err
	}
	staged, added := inv.stagingEntryOf(bench)
	added = added && !hadStaging

	// undo takes back what this run made, newest first, and says what it
	// could not.
	undo := func(cause error, registered bool) error {
		var left []string
		if registered {
			if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error { f.Remove(newName); return nil }); err != nil {
				left = append(left, "the registry line of '"+newName+"' (tacctl device remove "+newName+")")
			}
			inv.snmpDeviceCarry(newName, "")
			inv.blocksDeviceCarry(newName, "")
		}
		if added {
			if err := inv.stagingEnd(staged, "scope staging remove", "device="+newName+" by="+inv.sudoUser()); err != nil {
				left = append(left, "the staging address "+staged.CIDR+" (tacctl scope staging remove "+staged.CIDR+", a superuser's verb)")
			}
		}
		lines := msgs(cause)
		if len(left) > 0 {
			return inv.usageErr(append(lines, "The clone was not made, but could not take back "+strings.Join(left, " and ")+".")...)
		}
		return inv.usageErr(append(lines, "The clone was not made. Nothing was kept.")...)
	}

	after, err := inv.deviceWrite(build)
	if err != nil {
		if added {
			if serr := inv.stagingEnd(staged, "scope staging remove", "device="+newName+" by="+inv.sudoUser()); serr != nil {
				a.Out.WarnE("The staging address " + staged.CIDR + " stays in scope '" + scope + "': tacctl scope staging remove " + staged.CIDR)
			}
		}
		return err
	}
	// The registry first, then the file in the format the entry as it stands
	// allows, as 'device snmp <name> community' does: the copy is a new device,
	// which snmpReconcile (an entry that changes) does not touch, and its entry
	// is the source's own, or none.
	if err := snmpcred.SaveDevice(a.Paths.SNMPDir, newName, creds, inv.deviceHasSNMPEntry(newName)); err != nil {
		return undo(err, true)
	}
	if err := inv.deviceBlockStore().WriteDevice(newName, files); err != nil {
		return undo(err, true)
	}
	if err := policy.CopyDeviceBlocks(a.Conf(), srcName, newName); err != nil {
		return undo(err, true)
	}

	inv.detail("device clone", kvp("from", srcName), kvp("to", newName), kvp("address", bench), kvp("scope", scope),
		kvp("snmp_users", strconv.Itoa(len(creds.Users))), kvp("block_files", strconv.Itoa(len(files))), kvp("count", "1"))
	inv.cloneReport(srcName, newName, bench, scope, src, creds, files, after)
	return nil
}

// cloneReport says what was copied and what was not, and what comes next.
func (inv *invocation) cloneReport(srcName, newName, bench, scope string, src *devreg.Device, creds snmpcred.Creds, files []blocks.File, after *devreg.Resolver) {
	a := inv.app
	a.Out.Info("Device '" + newName + "' registered as a copy of '" + srcName + "': " + bench + ", " + src.Vendor + ", scope " + scope + ".")
	copied := []string{"the registry settings"}
	if !creds.Empty() {
		what := "the SNMP credentials"
		if n := len(creds.Users); n > 0 {
			what += " (" + strconv.Itoa(n) + " v3 " + plural(n, "user", "users") + ")"
		}
		copied = append(copied, what)
	}
	if n := len(files); n > 0 {
		copied = append(copied, strconv.Itoa(n)+" configuration block "+plural(n, "file", "files"))
	}
	inv.echo("  Copied:     " + strings.Join(copied, ", "))
	inv.echo("  Not copied: the address, name, DNS name, host keys, acknowledged notices, break-glass hold and configuration record of '" + srcName + "'")
	e, _ := after.Lookup(newName, devreg.ScopeFilter{})
	for _, n := range devreg.Open(after.NoticesFor(e)) {
		a.Out.Warn(n.Kind + ": " + n.Text)
	}
	inv.echo("  Next:       pin its host key (tacctl device hostkey " + shellquote.Q(newName) + " accept), then, once it is installed:")
	inv.echo("              tacctl device rename " + shellquote.Q(newName) + " " + shellquote.Q(srcName) + " --replace")
	inv.echo("")
}
