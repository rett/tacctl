package cli

// 'host forget <name>' and the findings about duplicate and orphaned hosts
// (docs/plans/0.2.14-plan.md D187). The registration of a host is several
// pieces of state: the registry line, the pinned keys and address of
// devices.yaml, the record, the staging addresses and the host-key scan of
// the cache. 'forget' drops them without a word to the host (it is local
// only: no ssh), which is the repair for a host registered twice under
// spellings of one name, and for the pieces a registry line no longer has
// (an orphan). 'host unenroll --force' is not the repair: it runs the removal
// script on the machine the surviving registration shares.

import (
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
)

// hostForgetUsage is the usage line of 'host forget'.
const hostForgetUsage = "Usage: tacctl host forget <name> [--yes]"

// hostPieces is what the state of one host name holds besides its registry
// line.
type hostPieces struct {
	name string
	// pin: devices.yaml has pinned keys or an address for the name (compared
	// ignoring case, as the pins are).
	pin bool
	// record: the file hosts/<name>.json is there.
	record bool
	// staging are the staging entries of the host (kind host, this name).
	staging []stagingEntry
}

func (p hostPieces) any() bool { return p.pin || p.record || len(p.staging) > 0 }

// hostPiecesOf reads what the state holds under name; f is the device
// registry (nil when it could not be read).
func (inv *invocation) hostPiecesOf(f *devreg.File, name string) hostPieces {
	p := hostPieces{name: name, record: inv.hostRecords().Has(name)}
	if f != nil && f.Host(name) != nil {
		p.pin = true
	}
	for _, s := range inv.stagingLoad() {
		if s.Kind == "host" && s.Name == name {
			p.staging = append(p.staging, s)
		}
	}
	return p
}

// hostForget is 'host forget <name> [--yes]'.
func (inv *invocation) hostForget(args []string) error {
	a := inv.app
	yes := false
	var pos []string
	for _, w := range args {
		switch {
		case w == "--yes":
			yes = true
		case strings.HasPrefix(w, "-"):
			return inv.usageErr("Unknown option: '"+w+"'", hostForgetUsage)
		default:
			pos = append(pos, w)
		}
	}
	if len(pos) != 1 {
		return inv.usageErr(hostForgetUsage)
	}
	if err := inv.confReadable(); err != nil {
		return err
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	f, ferr := inv.hostDevices()
	if ferr != nil {
		// The pins are in the registry that cannot be read: nothing is
		// dropped half way.
		return inv.usageErr(strings.Join(msgs(ferr), " ") + " Nothing was changed.")
	}
	name, entry, registered, err := inv.hostForgetFind(reg, f, pos[0])
	if err != nil {
		return err
	}

	// A held host is not forgotten: the server's silence on its address is
	// the hold's, and the way back is the release (D187).
	if registered {
		h, held, err := inv.hostHold(entry)
		if err != nil {
			return err
		}
		if held {
			return inv.hostRefuse(inv.hostHoldLine(entry, h),
				"Break-glass is held on '"+name+"': release it first (tacctl breakglass release "+name+"). Nothing was changed.")
		}
	} else if h, held := inv.holdNamed(name); held {
		return inv.hostRefuse("A break-glass hold is recorded under the name '"+h.Device+"' ("+h.Address+") "+inv.holdSummary(h)+": "+h.Reason+".",
			"Release it first: tacctl breakglass release "+h.Device+". Nothing was changed.")
	}

	// A rotation of the host is running: its lock is not waited for.
	unlock, err := hosts.LockHost(filepath.Join(a.Paths.StateDir, "locks"), name)
	switch {
	case errors.Is(err, hosts.ErrRotationBusy):
		return inv.usageErr("Another rotation of '"+name+"' is running; nothing was changed.",
			"Run this again when it has finished.")
	case err != nil:
		return err
	}
	defer unlock()

	// What goes: the registry line, and what the name has besides it. The
	// pins and the scan result are shared by every name equal to it ignoring
	// case, so they stay while another registered host (or, for the scan, a
	// device) has such a name.
	pieces := inv.hostPiecesOf(f, name)
	other := hostEqualFoldOther(reg, name)
	if other != "" {
		pieces.pin = false
	}
	if !registered && !pieces.any() {
		return inv.usageErr("No enrolled host or leftover named '" + name + "'. See 'tacctl host list'.")
	}

	subject := "Forget the host '" + name + "'"
	if registered {
		target := entry.Target
		if target == hosts.Local {
			target = "this server"
		}
		subject += " (" + target + ", scope " + entry.Scope + ")"
	} else {
		subject = "Forget what remains of the host '" + name + "', which is not enrolled"
	}
	a.Out.InfoE(subject + ". Dropped from this server:")
	if registered {
		a.Out.InfoE("  - its line in the host registry (" + a.Paths.LinuxHosts + ")")
	}
	if pieces.pin {
		a.Out.InfoE("  - its pinned ssh keys, address and history (" + a.Paths.DevicesFile + ")")
	}
	if pieces.record {
		a.Out.InfoE("  - its record (" + filepath.Join(a.Paths.HostRecords, name+".json") + ")")
	}
	if n := len(pieces.staging); n > 0 {
		a.Out.InfoE("  - " + strconv.Itoa(n) + " staging address(es): " + strings.Join(stagingCIDRs(pieces.staging), ", ") + " (the scope keeps its prefix)")
	}
	if other != "" {
		a.Out.InfoE("  The pinned keys stay: the enrolled host '" + other + "' has the same name ignoring case.")
	}
	a.Out.InfoE("The host itself is not touched: nothing is sent to it, and its accounts, secrets and PAM setup stay as they are. 'tacctl host unenroll' cleans a host that can be reached.")
	if !yes && !a.Prompter().Confirm("Forget it? [y/N] ") {
		a.Out.InfoE("Nothing was changed.")
		return exit(1)
	}

	// The state before (D191).
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	if registered {
		// Under the registry's lock, the line is read again: a host that
		// changed meanwhile is not forgotten from stale facts.
		if err := reg.Forget(name); err != nil {
			return err
		}
	}
	if pieces.pin {
		if _, err := devreg.Mutate(a.Paths.DevicesFile, a.Paths.KnownHosts, nil, func(f *devreg.File) error {
			f.ForgetHost(name)
			return nil
		}); err != nil {
			a.Out.WarnE(name + ": its pinned ssh keys and address could not be removed: " + msgsJoin(err) + ". Run: tacctl host forget " + name)
		}
	}
	if pieces.record {
		if err := inv.hostRecords().Forget(name); err != nil {
			a.Out.WarnE(name + ": its record (" + filepath.Join(a.Paths.HostRecords, name+".json") + ") could not be removed: " + msgsJoin(err) + ". Run: tacctl host forget " + name)
		}
	}
	if len(pieces.staging) > 0 {
		var kept []stagingEntry
		for _, s := range inv.stagingLoad() {
			if s.Kind != "host" || s.Name != name {
				kept = append(kept, s)
			}
		}
		if err := inv.stagingSave(kept); err != nil {
			a.Out.WarnE(name + ": its staging addresses could not be dropped from " + inv.stagingPath() + ": " + msgsJoin(err) + ". Run: tacctl host forget " + name)
		}
	}
	inv.hostForgetSeen(reg, f, name)

	a.Logger(inv.ctx, "auth.info", "host forget name="+name+" by="+inv.sudoUser())
	a.Out.InfoE("Host '" + name + "' forgotten. Nothing was sent to the host.")
	inv.echo("")
	for _, s := range pieces.staging {
		inv.echo("  The scope '" + s.Scope + "' still answers " + s.CIDR + ". To drop it: tacctl scope prefixes " + s.Scope + " remove " + s.CIDR)
	}
	if registered && !reg.ScopeInUse(entry.Scope) {
		inv.echo("  No enrolled host uses scope '" + entry.Scope + "' any more. To stop its secret being accepted: tacctl scope remove " + entry.Scope)
	}
	if len(pieces.staging) > 0 || registered && !reg.ScopeInUse(entry.Scope) {
		inv.echo("")
	}
	return nil
}

// stagingCIDRs are the addresses of entries.
func stagingCIDRs(es []stagingEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.CIDR)
	}
	return out
}

// hostEqualFoldOther is the name of an enrolled host, other than name itself,
// that is equal to name ignoring case ("" when there is none).
func hostEqualFoldOther(reg *hosts.Registry, name string) string {
	for _, e := range reg.Entries() {
		if e.Name != name && strings.EqualFold(e.Name, name) {
			return e.Name
		}
	}
	return ""
}

// hostForgetSeen drops the host-key scan result kept under the name unless
// another host or a device is equal to it ignoring case (the cache keys are
// lower case, so the result may be theirs). A failure is a warning: the next
// 'tacctl device check' writes the cache again.
func (inv *invocation) hostForgetSeen(reg *hosts.Registry, f *devreg.File, name string) {
	a := inv.app
	if !inv.seenLoad().HasKeyScanFor(name) || hostEqualFoldOther(reg, name) != "" || f.Find(name) != nil {
		return
	}
	warn := func(err error) {
		a.Out.WarnE(name + ": its host-key scan result (" + a.Paths.SeenCache + ") could not be removed: " + msgsJoin(err) + ". 'tacctl device check' scans again.")
	}
	unlock, err := devreg.LockSeen(a.Paths.SeenCache)
	if err != nil {
		warn(err)
		return
	}
	defer unlock()
	seen := inv.seenLoad()
	if seen.ForgetKeyScan(name) {
		if err := seen.Save(a.Paths.SeenCache); err != nil {
			warn(err)
		}
	}
}

// hostForgetFind says which name 'host forget' means by arg: the enrolled
// host of exactly that spelling; else the leftovers of exactly that spelling
// (an orphan: a pin, a record or a staging entry with no registry line); else
// the one enrolled host equal to it ignoring case (this is how a stray 'Web1'
// is forgotten by typing 'web1'). Several candidates, or none, is a refusal.
func (inv *invocation) hostForgetFind(reg *hosts.Registry, f *devreg.File, arg string) (name string, entry hosts.Entry, registered bool, err error) {
	if e, ok := reg.Find(arg); ok && e.Line != "" {
		return e.Name, e, true, nil
	}
	// Exact spelling, leftovers: the pin is found by its own spelling here.
	// (A pin of that spelling belongs to the enrolled host equal to it
	// ignoring case, if there is one, and is not a leftover.)
	pinned := false
	for _, h := range f.Hosts {
		pinned = pinned || h.Name == arg && hostEqualFoldOther(reg, arg) == ""
	}
	p := inv.hostPiecesOf(f, arg)
	if pinned || p.record || len(p.staging) > 0 {
		return arg, hosts.Entry{}, false, nil
	}
	var fold []hosts.Entry
	for _, e := range reg.Entries() {
		if strings.EqualFold(e.Name, arg) {
			fold = append(fold, e)
		}
	}
	switch len(fold) {
	case 0:
		return "", hosts.Entry{}, false, inv.usageErr("No enrolled host or leftover named '" + arg + "'. See 'tacctl host list'.")
	case 1:
		return fold[0].Name, fold[0], true, nil
	}
	var names []string
	for _, e := range fold {
		names = append(names, e.Name)
	}
	return "", hosts.Entry{}, false, inv.usageErr("'"+arg+"' matches the hosts "+quoteJoin(names)+" ignoring case; give the exact spelling of the one to forget.", "Nothing was changed.")
}

// --- findings ----------------------------------------------------------------------

// hostFinding is one thing the registrations of the hosts get wrong, with
// the verb that puts it right. Findings are read-only: nothing is repaired
// where they are reported.
type hostFinding struct{ Text, Fix string }

// String is the finding on one line.
func (f hostFinding) String() string { return f.Text + " (" + f.Fix + ")" }

// hostFindings are the findings of the superuser's view of the hosts (a
// restricted caller is told nothing: what they would name is not theirs): two
// registry names equal ignoring case, a host named like a device, two hosts
// with one recorded address (the recorded one: nothing is resolved), and a
// pin, record or staging entry that no registry line has. A break-glass hold
// with no host is the hold's own orphan line, in 'config validate' and
// 'breakglass list'.
func (inv *invocation) hostFindings() []hostFinding {
	if inv.callerScopes().restricted {
		return nil
	}
	reg, err := inv.registry()
	if err != nil {
		return nil
	}
	f, err := inv.hostDevices()
	if err != nil {
		f = nil
	}
	entries := reg.Entries()
	var out []hostFinding

	// Names equal ignoring case.
	var order []string
	byFold := map[string][]string{}
	for _, e := range entries {
		k := strings.ToLower(e.Name)
		if !slices.Contains(byFold[k], e.Name) {
			if len(byFold[k]) == 0 {
				order = append(order, k)
			}
			byFold[k] = append(byFold[k], e.Name)
		}
	}
	for _, k := range order {
		if names := byFold[k]; len(names) > 1 {
			out = append(out, hostFinding{
				Text: "the hosts " + quoteJoin(names) + " are one name ignoring case and share one record of pinned keys",
				Fix:  "tacctl host forget <name> drops the stray registration; tacctl host rename <name> <new> gives it a name of its own",
			})
		}
	}

	if f != nil {
		// A host named like a device.
		for _, e := range entries {
			if d := f.Find(e.Name); d != nil {
				out = append(out, hostFinding{
					Text: "the host '" + e.Name + "' has the name of the device '" + d.Name + "' (" + d.Address + ")",
					Fix:  "tacctl host rename " + e.Name + " <new>",
				})
			}
		}

		// Two hosts with one recorded address; names equal ignoring case are
		// one registration found above.
		var addrs []string
		byAddr := map[string][]string{}
		seen := map[string]bool{}
		for _, e := range entries {
			if seen[strings.ToLower(e.Name)] {
				continue
			}
			seen[strings.ToLower(e.Name)] = true
			if a := f.HostAddressOf(e.Name); a != "" {
				if len(byAddr[a]) == 0 {
					addrs = append(addrs, a)
				}
				byAddr[a] = append(byAddr[a], e.Name)
			}
		}
		for _, a := range addrs {
			if names := byAddr[a]; len(names) > 1 {
				out = append(out, hostFinding{
					Text: "the hosts " + quoteJoin(names) + " have the same recorded address, " + a,
					Fix:  "tacctl host forget <name> drops a registration made twice",
				})
			}
		}
	}

	// What no registry line has.
	registered := map[string]bool{}
	foldRegistered := map[string]bool{}
	for _, e := range entries {
		registered[e.Name] = true
		foldRegistered[strings.ToLower(e.Name)] = true
	}
	type orphan struct {
		pin, record bool
		staging     int
	}
	orphans := map[string]*orphan{}
	get := func(n string) *orphan {
		if orphans[n] == nil {
			orphans[n] = &orphan{}
		}
		return orphans[n]
	}
	if f != nil {
		for _, h := range f.Hosts {
			if !foldRegistered[strings.ToLower(h.Name)] {
				get(h.Name).pin = true
			}
		}
	}
	for _, n := range inv.hostRecords().Names() {
		if !registered[n] {
			get(n).record = true
		}
	}
	for _, s := range inv.stagingLoad() {
		if s.Kind == "host" && !registered[s.Name] {
			get(s.Name).staging++
		}
	}
	var names []string
	for n := range orphans {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		o := orphans[n]
		var what []string
		if o.pin {
			what = append(what, "pinned ssh keys or an address")
		}
		if o.record {
			what = append(what, "a record")
		}
		if o.staging > 0 {
			what = append(what, strconv.Itoa(o.staging)+" staging address(es)")
		}
		out = append(out, hostFinding{
			Text: "'" + n + "' is not an enrolled host but has " + strings.Join(what, ", "),
			Fix:  "tacctl host forget " + n,
		})
	}
	return out
}
