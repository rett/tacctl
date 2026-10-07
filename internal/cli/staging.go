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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

type stagingEntry struct {
	CIDR, Scope, Kind, Name, Since string
}

// addr is the entry's address (its /32 without the length).
func (e stagingEntry) addr() string { a, _, _ := strings.Cut(e.CIDR, "/"); return a }

func (e stagingEntry) line() string {
	return strings.Join([]string{e.CIDR, e.Scope, e.Kind, e.Name, e.Since}, "|")
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
		out = append(out, stagingEntry{f[0], f[1], f[2], f[3], f[4]})
	}
	return out
}

func (inv *invocation) stagingSave(entries []stagingEntry) error {
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

// stagingAdd answers addr from scope with a staging /32 (for the host or
// device kind/name), unless scope already answers it. Nothing is changed
// when the /32 cannot be added (another scope owns it, a tagged address).
func (inv *invocation) stagingAdd(scope, addr, kind, name string) error {
	a := inv.app
	m, err := inv.model()
	if err != nil {
		return err
	}
	if info, found := m.LookupAddr(addr); found && info.Scope == scope {
		a.Out.InfoE("--staging: scope '" + scope + "' already answers " + addr + " (prefix " + info.Prefix + "); no staging address is needed.")
		return nil
	}
	cidr := addr + "/32"
	collisions, err := inv.scopePrefixCollisions([]string{cidr}, scope)
	if err != nil {
		return err
	}
	if len(collisions) > 0 {
		return inv.usageErr(append([]string{"Cannot stage " + cidr + " in scope '" + scope + "':"}, collisions...)...)
	}
	current := m.ScopePrefixes(scope)
	csv := joinNonEmpty(append(append([]string(nil), current...), cidr), ",")
	if problems, ok := m.DeviceProblems(scope, csv, "", ""); !ok {
		a.Out.ErrorE("Cannot stage " + cidr + " in scope '" + scope + "': it would take over an address another scope has tagged with a vendor:")
		inv.scopeDeviceProblems(problems)
		return inv.usageErr("Nothing was changed.")
	}
	if info, found := m.LookupAddr(addr); found {
		a.Out.WarnE("--staging: " + addr + " is answered by scope '" + info.Scope + "' (prefix " + info.Prefix + ") until now; the staging /32 answers it from '" + scope + "' instead.")
	}
	if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(scope, "prefixes="+csv) }); err != nil {
		return err
	}
	entries := inv.stagingLoad()
	var kept []stagingEntry
	for _, e := range entries {
		if e.CIDR != cidr {
			kept = append(kept, e)
		}
	}
	kept = append(kept, stagingEntry{cidr, scope, kind, name, a.Knobs.Now().Format("2006-01-02 15:04")})
	if err := inv.stagingSave(kept); err != nil {
		return err
	}
	who := kind
	if name != "" {
		who += " '" + name + "'"
	}
	a.Logger(inv.ctx, "auth.info", "scope staging add cidr="+cidr+" scope="+scope+" "+kind+"="+name+" by="+inv.sudoUser())
	how := "removed once it is seen at an address '" + scope + "' covers"
	if name == "" {
		how = "remove it once the device is installed: tacctl scope staging remove " + cidr
	}
	a.Out.InfoE("Staging address " + cidr + " added to scope '" + scope + "' (its secret and users) for " + who + "; " + how + ".")
	return nil
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
	for _, e := range entries {
		if !m.Exists("scopes", e.Scope) || !contains(m.ScopePrefixes(e.Scope), e.CIDR) {
			changed = true
			continue
		}
		seen := inv.stagingSeen(e)
		info, found := m.LookupAddr(seen)
		if seen == "" || seen == e.addr() || !found || info.Scope != e.Scope {
			kept = append(kept, e)
			continue
		}
		rest := joinNonEmpty(without(m.ScopePrefixes(e.Scope), e.CIDR), ",")
		if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(e.Scope, "prefixes="+rest) }); err != nil {
			inv.reportOnly(err)
			a.Out.WarnE("Could not remove staging address " + e.CIDR + " from scope '" + e.Scope + "'; remove it by hand: tacctl scope staging remove " + e.CIDR)
			kept = append(kept, e)
			continue
		}
		changed = true
		a.Logger(inv.ctx, "auth.info", "scope staging done cidr="+e.CIDR+" scope="+e.Scope+" "+e.Kind+"="+e.Name+" seen="+seen)
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
	switch sub := arg(args, 0); sub {
	case "", "list":
		inv.stagingSweep()
		entries := inv.stagingLoad()
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
			return inv.usageErr("Usage: tacctl scope staging remove <address>/32")
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
		if m.Exists("scopes", hit.Scope) && contains(m.ScopePrefixes(hit.Scope), cidr) {
			rest := without(m.ScopePrefixes(hit.Scope), cidr)
			if joinNonEmpty(rest, "") == "" {
				return inv.usageErr("Staging address " + cidr + " is the only prefix of scope '" + hit.Scope + "'; add its real prefixes first.")
			}
			if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(hit.Scope, "prefixes="+joinNonEmpty(rest, ",")) }); err != nil {
				return err
			}
		}
		if err := inv.stagingSave(kept); err != nil {
			return err
		}
		a.Logger(inv.ctx, "auth.info", "scope staging remove cidr="+cidr+" scope="+hit.Scope+" by="+inv.sudoUser())
		a.Out.Info("Staging address " + cidr + " removed from scope '" + hit.Scope + "'.")
		return nil
	default:
		return inv.usageErr("Usage: tacctl scope staging [list | remove <address>/32]")
	}
}
