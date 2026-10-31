package cli

// Staging addresses (item 67). A host or network device provisioned
// off-site, at a bench address its target scope does not cover, gets that
// address as a /32 prefix of the target scope: the scope's own secret and
// users answer it there, so nothing changes on the device when it is
// installed in the scope's prefixes. tacctl records each such /32 in
// StateDir/staging ('<cidr>|<scope>|<kind>|<name>|<since>', kind host or
// device) and removes it once the host or registered device is seen at an
// address the scope covers by another prefix (stagingSweep), or by hand
// ('scope staging remove').

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

type stagingEntry struct {
	CIDR, Scope, Kind, Name, Since string
	// Covered marks a device's entry made for an address the scope answered
	// already (by a prefix of its own): no /32 was added, so none is ever
	// taken out, and the sweep keeps the entry until the device is seen
	// elsewhere. The line carries a sixth field, 'covered'.
	Covered bool
}

// addr is the entry's address (its /32 without the length).
func (e stagingEntry) addr() string { a, _, _ := strings.Cut(e.CIDR, "/"); return a }

func (e stagingEntry) line() string {
	f := []string{e.CIDR, e.Scope, e.Kind, e.Name, e.Since}
	if e.Covered {
		f = append(f, "covered")
	}
	return strings.Join(f, "|")
}

func (inv *invocation) stagingPath() string {
	return filepath.Join(inv.app.Paths.StateDir, "staging")
}

func (inv *invocation) stagingLoad() []stagingEntry {
	data, err := os.ReadFile(inv.stagingPath())
	if err != nil {
		return nil
	}
	var out []stagingEntry
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) < 5 || f[0] == "" {
			continue
		}
		out = append(out, stagingEntry{f[0], f[1], f[2], f[3], f[4], len(f) > 5 && f[5] == "covered"})
	}
	return out
}

func (inv *invocation) stagingSave(entries []stagingEntry) error {
	inv.app.Audit().Touch()
	path := inv.stagingPath()
	if len(entries) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.line() + "\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stagingCheck is the read-only half of stagingAdd: it refuses, changing
// nothing, an address that cannot be staged in scope (another scope owns it,
// an enrolled host is there, a prefix collides, a vendor tag conflicts), and
// says whether scope answers it already (covered: no /32 is needed). The
// verbs that take a snapshot first call it before the snapshot.
func (inv *invocation) stagingCheck(scope, addr string) (covered bool, err error) {
	a := inv.app
	m, err := inv.model()
	if err != nil {
		return false, err
	}
	if info, found := m.LookupAddr(addr); found && info.Scope == scope {
		return true, nil
	}
	// An engineer stages in their own scopes only, and never an address
	// another scope answers: the /32 would take it, and its devices'
	// logins, from that scope (D18).
	if f := inv.callerScopes(); f.restricted {
		if err := inv.ownScope(f, scope); err != nil {
			return false, err
		}
		if info, found := m.LookupAddr(addr); found && !f.allows(info.Scope) {
			return false, inv.usageErr("--staging: " + addr + " is answered by scope '" + info.Scope + "', which is not one of yours; staging it would take it from that scope. Nothing was changed.")
		}
		// A host is not a device: the scope that answers a host's address
		// is the superuser's to change, since the host's next sync is
		// checked against it.
		if inv.hostWithin(addr) {
			return false, inv.usageErr("--staging: " + addr + " is not available for staging. Nothing was changed.")
		}
	}
	cidr := addr + "/32"
	collisions, err := inv.scopePrefixCollisions([]string{cidr}, scope)
	if err != nil {
		return false, err
	}
	if len(collisions) > 0 {
		return false, inv.usageErr(append(append([]string{"Cannot stage " + cidr + " in scope '" + scope + "':"}, collisions...), collisionAdvice(collisions)...)...)
	}
	csv := joinNonEmpty(append(append([]string(nil), m.ScopePrefixes(scope)...), cidr), ",")
	if problems, ok := m.DeviceProblems(scope, csv, "", ""); !ok {
		a.Out.ErrorE("Cannot stage " + cidr + " in scope '" + scope + "': it would take over an address another scope has tagged with a vendor:")
		inv.scopeDeviceProblems(problems)
		return false, inv.usageErr("Nothing was changed.")
	}
	return false, nil
}

// stagingAdd answers addr from scope with a staging /32 (for the host or
// device kind/name), unless scope already answers it. Nothing is changed
// when the /32 cannot be added (another scope owns it, a tagged address).
// A device that is named gets a staging entry for an address the scope
// answers already too (Covered, no /32), so that 'device rename --replace'
// finds the device staged whichever address the bench has.
func (inv *invocation) stagingAdd(scope, addr, kind, name string) error {
	a := inv.app
	covered, err := inv.stagingCheck(scope, addr)
	if err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	cidr := addr + "/32"
	if covered {
		info, _ := m.LookupAddr(addr)
		a.Out.InfoE("--staging: scope '" + scope + "' already answers " + addr + " (prefix " + info.Prefix + "); no staging address is needed.")
		if kind != "device" || name == "" {
			return nil
		}
		entries := inv.stagingLoad()
		for _, e := range entries {
			if e.CIDR == cidr {
				return nil
			}
		}
		entries = append(entries, stagingEntry{cidr, scope, kind, name, a.Knobs.Now().Format("2006-01-02 15:04"), true})
		return inv.stagingSave(entries)
	}
	csv := joinNonEmpty(append(append([]string(nil), m.ScopePrefixes(scope)...), cidr), ",")
	if info, found := m.LookupAddr(addr); found {
		a.Out.WarnE("--staging: " + addr + " is answered by scope '" + info.Scope + "' (prefix " + info.Prefix + ") until now; the staging /32 answers it from '" + scope + "' instead.")
	}
	addBase := "scope staging add cidr=" + cidr + " scope=" + scope + " " + kind + "=" + name + " by=" + inv.sudoUser()
	if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(scope, "prefixes="+csv) }); err != nil {
		inv.verbResult(audit.Info, addBase, failReason(err, "store"))
		return err
	}
	entries := inv.stagingLoad()
	var kept []stagingEntry
	for _, e := range entries {
		if e.CIDR != cidr {
			kept = append(kept, e)
		}
	}
	kept = append(kept, stagingEntry{cidr, scope, kind, name, a.Knobs.Now().Format("2006-01-02 15:04"), false})
	if err := inv.stagingSave(kept); err != nil {
		inv.verbResult(audit.Info, addBase, "write")
		return err
	}
	who := kind
	if name != "" {
		who += " '" + name + "'"
	}
	inv.verbResult(audit.Info, addBase, "")
	how := "removed once it is seen at an address '" + scope + "' covers"
	if name == "" {
		how = "remove it once the device is installed: tacctl scope staging remove " + cidr
	}
	a.Out.InfoE("Staging address " + cidr + " added to scope '" + scope + "' (its secret and users) for " + who + "; " + how + ".")
	return nil
}

// hostWithin reports whether an enrolled host is at an address of cidr: the
// address recorded at its last enroll or sync, or an address literal as its
// target (nothing is resolved). A registry or a devices file that cannot be
// read counts as yes (fail closed).
func (inv *invocation) hostWithin(cidr string) bool {
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return true
	}
	reg, err := inv.registry()
	if err != nil {
		return true
	}
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return true
	}
	in := func(addr string) bool { ip := net.ParseIP(addr); return ip != nil && n.Contains(ip) }
	for _, e := range reg.Entries() {
		if in(f.HostAddressOf(e.Name)) {
			return true
		}
		if host, _, ok := hosts.ScanTarget(e.Target, e.Port); ok && in(host) {
			return true
		}
	}
	return false
}

// stagingSeen is where the entry's host or device is now ("" unknown).
func (inv *invocation) stagingSeen(e stagingEntry) string {
	if e.Name == "" {
		return ""
	}
	if e.Kind == "host" {
		reg, err := inv.registry()
		if err != nil {
			return ""
		}
		h, ok := reg.Find(e.Name)
		if !ok {
			return ""
		}
		if f, err := devreg.Load(inv.app.Paths.DevicesFile); err == nil {
			return f.HostAddressOf(h.Name)
		}
		return ""
	}
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return ""
	}
	if d := f.Find(e.Name); d != nil {
		return d.Address
	}
	return ""
}

// stagingBench is the bench address of --staging <ip>: one IPv4 address, no
// prefix length, in its canonical form; a problem is the refusal's text.
func stagingBench(flag string) (addr, problem string) {
	norm, err := devreg.NormalizeAddress(flag)
	if err != nil || strings.Contains(norm, ":") || strings.Contains(flag, "/") {
		return "", "--staging takes the device's bench IPv4 address (a single address, no prefix length): '" + flag + "'"
	}
	return norm, ""
}

// stagingEntryOf is the staging line of the device registered at addr (kind
// device, the /32 of that address), and whether there is one.
func (inv *invocation) stagingEntryOf(addr string) (stagingEntry, bool) {
	for _, e := range inv.stagingLoad() {
		if e.Kind == "device" && e.CIDR == addr+"/32" {
			return e, true
		}
	}
	return stagingEntry{}, false
}

// stagingEnd takes the staging /32 of e out of its scope and out of the
// staging file now, whatever address the device is seen at: the verbs that
// decide the device is in place (a replacement that took its original's
// address) or that undo the /32 they just added. A scope that no longer lists
// the /32 keeps nothing to remove, and a /32 that is the scope's only prefix
// stays (a scope without a prefix answers nothing). An entry made for an
// address the scope answered already (Covered) has no /32: only the entry
// goes. The change is audited as the sweep's is, with event and what, for the
// device or the reason.
func (inv *invocation) stagingEnd(e stagingEntry, event, what string) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	base := event + " cidr=" + e.CIDR + " scope=" + e.Scope + " " + what
	if !e.Covered && m.Exists("scopes", e.Scope) && contains(m.ScopePrefixes(e.Scope), e.CIDR) {
		rest := without(m.ScopePrefixes(e.Scope), e.CIDR)
		if joinNonEmpty(rest, "") == "" {
			return errors.New("staging address " + e.CIDR + " is the only prefix of scope '" + e.Scope + "'; add its real prefixes first")
		}
		if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(e.Scope, "prefixes="+joinNonEmpty(rest, ",")) }); err != nil {
			inv.verbResult(audit.Info, base, failReason(err, "store"))
			return err
		}
	}
	var kept []stagingEntry
	for _, o := range inv.stagingLoad() {
		if o.CIDR != e.CIDR {
			kept = append(kept, o)
		}
	}
	if err := inv.stagingSave(kept); err != nil {
		inv.verbResult(audit.Info, base, "write")
		return err
	}
	inv.verbResult(audit.Info, base, "")
	return nil
}

// stagingRenameDevice names the new device name in the staging entries of
// the device (the fourth field of the line), so that the sweep still finds
// the device where it is registered and ends the /32 once it is in place.
// Names compare without regard to case, as the registry's do (a line is
// written with the name as typed to 'config <vendor> --staging --name'): the
// old name is matched first, so a rename of the spelling only keeps the
// line, and only a line of the new name that is not the device's own, left
// by an earlier device, is dropped, as a host's is (hostRenameStaging). The
// registry was renamed already: a failure here is a warning that names the
// addresses of the lines renamed and dropped and the way out.
func (inv *invocation) stagingRenameDevice(oldName, newName string) {
	entries := inv.stagingLoad()
	var out []stagingEntry
	changed := false
	var addrs []string
	for _, s := range entries {
		switch {
		case s.Kind == "device" && strings.EqualFold(s.Name, oldName):
			s.Name, changed = newName, true
			addrs = append(addrs, s.addr())
		case s.Kind == "device" && strings.EqualFold(s.Name, newName):
			changed = true
			addrs = append(addrs, s.addr())
			continue
		}
		out = append(out, s)
	}
	if !changed {
		return
	}
	if err := inv.stagingSave(out); err != nil {
		inv.app.Out.WarnE(newName + ": its staging lines still name '" + oldName + "' or an earlier device of that name (" + strings.Join(addrs, ", ") + "): " + strings.Join(msgs(err), " ") +
			". The sweep does not find the device under its new name; remove them: tacctl scope staging remove <address>")
	}
}

// stagingSweep removes each staging /32 whose host or device is now seen
// at another address its scope answers, and forgets entries whose /32 is
// no longer a prefix of the scope (removed by hand). Every problem is a
// warning: the command that ran it has done its work.
func (inv *invocation) stagingSweep() {
	a := inv.app
	entries := inv.stagingLoad()
	if len(entries) == 0 {
		return
	}
	m, err := inv.model()
	if err != nil {
		return
	}
	var kept []stagingEntry
	changed := false
	// A host's staging address ends with a host's sync, which is the
	// superuser's: a restricted caller's device change leaves it as it is.
	restricted := inv.callerScopes().restricted
	for _, e := range entries {
		if restricted && e.Kind == "host" {
			kept = append(kept, e)
			continue
		}
		if !m.Exists("scopes", e.Scope) || (!e.Covered && !contains(m.ScopePrefixes(e.Scope), e.CIDR)) {
			changed = true
			continue
		}
		seen := inv.stagingSeen(e)
		if e.Covered {
			// No /32 was added for it: the entry only lasts until the
			// device is seen at another address.
			if seen != "" && seen != e.addr() {
				changed = true
				continue
			}
			kept = append(kept, e)
			continue
		}
		info, found := m.LookupAddr(seen)
		if seen == "" || seen == e.addr() || !found || info.Scope != e.Scope {
			kept = append(kept, e)
			continue
		}
		rest := joinNonEmpty(without(m.ScopePrefixes(e.Scope), e.CIDR), ",")
		if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(e.Scope, "prefixes="+rest) }); err != nil {
			inv.verbResult(audit.Info, "scope staging done cidr="+e.CIDR+" scope="+e.Scope+" "+e.Kind+"="+e.Name+" seen="+seen, failReason(err, "store"))
			inv.reportOnly(err)
			a.Out.WarnE("Could not remove staging address " + e.CIDR + " from scope '" + e.Scope + "'; remove it by hand: tacctl scope staging remove " + e.CIDR)
			kept = append(kept, e)
			continue
		}
		changed = true
		inv.verbResult(audit.Info, "scope staging done cidr="+e.CIDR+" scope="+e.Scope+" "+e.Kind+"="+e.Name+" seen="+seen, "")
		a.Out.InfoE("Staging address " + e.CIDR + " removed from scope '" + e.Scope + "': " + e.Name + " is now seen at " + seen + " (prefix " + info.Prefix + ").")
		if m, err = inv.model(); err != nil {
			return
		}
	}
	if changed {
		if err := inv.stagingSave(kept); err != nil {
			a.Out.WarnE("Could not update " + inv.stagingPath() + ": " + err.Error())
		}
	}
}

// stdoutToStderr runs fn with everything it writes to stdout (its own
// lines, the pre-change snapshot's and the backend modules') sent to
// stderr instead.
func (inv *invocation) stdoutToStderr(fn func() error) error {
	a := inv.app
	env, snaps := a.BackendEnv(), a.Snapshots()
	saved, savedEnv, savedSnaps := a.Out, env.Out, snaps.Out
	a.Out.Stdout, env.Out.Stdout, snaps.Out.Stdout = a.Out.Stderr, env.Out.Stderr, snaps.Out.Stderr
	defer func() { a.Out, env.Out, snaps.Out = saved, savedEnv, savedSnaps }()
	return fn()
}

// scopeStaging is 'scope staging [list | remove <cidr>]'.
func (inv *invocation) scopeStaging(args []string) error {
	a := inv.app
	// An engineer lists the staging addresses of their own scopes (D47) and
	// changes nothing: the sweep, which edits scopes, is the administrators'.
	f := inv.callerScopes()
	if sub := arg(args, 0); f.restricted && sub != "" && sub != "list" {
		return inv.deniedUsage(reasonSuperuser, "The engineer tier lists the staging addresses of its scopes: tacctl scope staging list. Removing one is the superuser's. Nothing was changed.")
	}
	switch sub := arg(args, 0); sub {
	case "", "list":
		if !f.restricted {
			inv.stagingSweep()
		}
		var entries []stagingEntry
		for _, e := range inv.stagingLoad() {
			if f.allows(e.Scope) {
				entries = append(entries, e)
			}
		}
		inv.echo("")
		if len(entries) == 0 {
			inv.echoE(ui.Bold + "Staging addresses" + ui.NC)
			inv.echo(ui.Rule("Staging addresses"))
			inv.echo("  None. Provision a device off-site with --staging (host enroll, config cisco|juniper|wti).")
			inv.echo("")
			return nil
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].CIDR < entries[j].CIDR })
		t := ui.NewTable("Staging addresses", ui.Left("ADDRESS"), ui.Left("SCOPE"), ui.Left("FOR"), ui.Left("SINCE"), ui.Left("SEEN AT"))
		for _, e := range entries {
			who := e.Kind
			if e.Name != "" {
				who += " " + e.Name
			}
			t.Add(e.CIDR, e.Scope, who, e.Since, dash(inv.stagingSeen(e)))
		}
		inv.write(t.String())
		inv.echo("")
		return nil
	case "remove":
		cidr := arg(args, 1)
		if cidr == "" {
			return inv.usageErr(usageLinesOf("scope staging", scopeStagingRows[1])...)
		}
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		if err := inv.requireStore(); err != nil {
			return err
		}
		var hit *stagingEntry
		var kept []stagingEntry
		for _, e := range inv.stagingLoad() {
			if e.CIDR == cidr {
				e := e
				hit = &e
				continue
			}
			kept = append(kept, e)
		}
		if hit == nil {
			return inv.usageErr("No staging address " + cidr + ". See 'tacctl scope staging'.")
		}
		m, err := inv.model()
		if err != nil {
			return err
		}
		removeBase := "scope staging remove cidr=" + cidr + " scope=" + hit.Scope + " by=" + inv.sudoUser()
		if !hit.Covered && m.Exists("scopes", hit.Scope) && contains(m.ScopePrefixes(hit.Scope), cidr) {
			rest := without(m.ScopePrefixes(hit.Scope), cidr)
			if joinNonEmpty(rest, "") == "" {
				return inv.usageErr("Staging address " + cidr + " is the only prefix of scope '" + hit.Scope + "'; add its real prefixes first.")
			}
			if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(hit.Scope, "prefixes="+joinNonEmpty(rest, ",")) }); err != nil {
				inv.verbResult(audit.Info, removeBase, failReason(err, "store"))
				return err
			}
		}
		if err := inv.stagingSave(kept); err != nil {
			inv.verbResult(audit.Info, removeBase, "write")
			return err
		}
		inv.verbResult(audit.Info, removeBase, "")
		if hit.Covered {
			a.Out.Info("Staging entry " + cidr + " removed; scope '" + hit.Scope + "' answers the address by its own prefixes, which are unchanged.")
			return nil
		}
		a.Out.Info("Staging address " + cidr + " removed from scope '" + hit.Scope + "'.")
		return nil
	default:
		return inv.usageErr(usageLinesOf("scope staging", scopeStagingRows...)...)
	}
}
