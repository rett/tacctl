package cli

// 'device scan', 'device discover', 'device check', 'device list
// --scan|--probe' and the seen columns of 'device list|show'
// (docs/plans/operator-console.md 3.3, 3.4, 3.6, 3.7). The scan reads every
// enabled backend's log of its devices (backend.Sighter) into the seen cache
// (/var/lib/tacctl/devices-seen.json, internal/devreg/seen.go), re-scans the
// pinned host keys and prints the scan-time notices. 'list' and 'show' read
// the cache only; 'scan' is explicit. A scan never writes devices.yaml.

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// seenTime is how the seen columns print a time.
func seenTime(t time.Time) string { return t.Format("2006-01-02 15:04") }

// deviceSeenCols are the LAST SEEN, BY and VIA columns of an entry from the
// seen cache, and whether it is stale: '-' with no seen data at all,
// 'never' for an address no scan has seen, 'rejected <when> (<why>)' when
// the last exchange was a refusal.
func deviceSeenCols(inv *invocation, res *devreg.Resolver, e devreg.Entry) (last, by, via string, stale bool) {
	if !res.Seen.HasData() {
		return "-", "-", "-", false
	}
	x, ok := res.Seen.Of(e.Address)
	if e.Address == "" || !ok {
		return "never", "-", "-", false
	}
	last = seenTime(x.Last)
	if x.Rejected() {
		last = "rejected " + last
		switch x.LastOutcome {
		case backend.SightBadSecret:
			last += " (bad secret)"
		case backend.SightNoScope:
			last += " (no scope)"
		}
	}
	days := res.File.StaleDays
	if days < 1 {
		days = devreg.DefaultStaleDays
	}
	stale = x.Last.Before(inv.app.Knobs.Now().AddDate(0, 0, -days))
	return last, dash(x.LastUser), x.Via, stale
}

// deviceSeenFooter is the line under 'device list' about the seen data.
func deviceSeenFooter(res *devreg.Resolver) string {
	if !res.Seen.HasData() {
		return "seen data: none (tacctl device scan)"
	}
	return "seen data as of " + seenTime(res.Seen.Updated) + " (tacctl device scan to refresh); stale after " +
		strconv.Itoa(res.File.StaleDays) + " days"
}

// seenLoad reads the seen cache; one that cannot be read is empty here
// (the next scan rebuilds it and says so).
func (inv *invocation) seenLoad() *devreg.Seen {
	s, err := devreg.LoadSeen(inv.app.Paths.SeenCache)
	if err != nil {
		return devreg.NewSeen()
	}
	return s
}

// scanAllowed reports whether the caller may run a scan or a probe
// (operator tier and up, as 'device scan').
func (inv *invocation) scanAllowed() bool {
	return tier.Permits(inv.tierGate().Caller(inv.ctx), "device", "scan")
}

// --- the scan ------------------------------------------------------------------------

// scanRequest is what a scan reads: --full, --since, --backend.
type scanRequest struct {
	full  bool
	since time.Duration
	only  string
}

// scanResult is what runScan leaves for the printing.
type scanResult struct {
	reports []devreg.SourceReport
	keys    []devreg.KeyResult
	keyErr  error
	res     *devreg.Resolver
	rebuilt bool
}

// scanBackends are the sources of a scan: every enabled backend, or the one
// --backend names.
func (inv *invocation) scanBackends(only string) ([]devreg.ScanSource, error) {
	set := inv.app.Backends()
	ids := []string{only}
	if only == "" {
		var err error
		if ids, err = inv.enabledOrFail(); err != nil {
			return nil, err
		}
	} else if !set.Registry.Has(only) {
		return nil, inv.usageErr("Unknown backend '" + only + "' (known: " + strings.Join(set.IDs(), " ") + ").")
	}
	var out []devreg.ScanSource
	for _, id := range ids {
		b, err := set.Get(id)
		if err != nil {
			return nil, err
		}
		src := devreg.ScanSource{ID: id}
		if s, ok := b.(backend.Sighter); ok {
			src.Sighter = s
		}
		out = append(out, src)
	}
	return out, nil
}

// keyTargets are the entries whose host keys a scan reads again: every
// entry with a pinned key (all, with unpinned too) and a target to scan.
func keyTargets(entries []devreg.Entry, unpinned bool) []devreg.KeyTarget {
	var out []devreg.KeyTarget
	for _, e := range entries {
		if len(e.HostKeys) == 0 && !unpinned {
			continue
		}
		addr, port, legacy, ok := scanTarget(e)
		if !ok || addr == "" {
			continue
		}
		out = append(out, devreg.KeyTarget{Name: e.Name, Address: addr, Port: port, Legacy: legacy})
	}
	return out
}

// runScan reads the logs into the seen cache, re-scans the pinned host
// keys and saves the cache, under its lock.
func (inv *invocation) runScan(rq scanRequest) (*scanResult, error) {
	srcs, err := inv.scanBackends(rq.only)
	if err != nil {
		return nil, err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return nil, err
	}
	path := inv.app.Paths.SeenCache
	unlock, err := devreg.LockSeen(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	out := &scanResult{}
	seen, lerr := devreg.LoadSeen(path)
	if lerr != nil {
		out.rebuilt = true
		seen = devreg.NewSeen()
	}
	now := inv.app.Knobs.Now()
	out.reports = devreg.ScanSources(inv.ctx, seen, srcs, devreg.ScanOptions{
		Now: now, StaleDays: f.StaleDays, Full: rq.full || out.rebuilt, Since: rq.since})
	all := res.All()
	out.keys = devreg.RescanKeys(inv.ctx, inv.app.Runner, keyTargets(all, false), keyFallback(inv))
	out.keyErr = seen.RecordKeyResults(out.keys, now)
	var names []string
	for _, e := range all {
		names = append(names, e.Name)
	}
	seen.Prune(now, f.StaleDays, names)
	if err := seen.Save(path); err != nil {
		return nil, err
	}
	res.Seen = seen
	out.res = res
	return out, nil
}

// printScan is the report of a scan: one line per source with the window
// it read, the host-key re-scans, and the totals of the cache.
func (inv *invocation) printScan(sr *scanResult) {
	a := inv.app
	inv.echo("")
	inv.echoE(ui.Bold + "Device scan" + ui.NC)
	inv.echo(ui.Rule("Device scan"))
	if sr.rebuilt {
		a.Out.Warn("The seen cache could not be read; it was rebuilt from the logs.")
	}
	w := 0
	for _, r := range sr.reports {
		w = max(w, len(r.ID))
	}
	for _, r := range sr.reports {
		var text string
		switch {
		case r.NoLog:
			text = "keeps no log of its devices"
		case r.Err != nil:
			text = "could not be read: " + firstLineOf(r.Err.Error())
		default:
			text = r.Window
			if r.Sightings > 0 {
				text += ": " + howMany(r.Sightings, "sighting") + " of " + howMany(r.Addresses, "address")
			}
			if r.Unattributed > 0 {
				text += " (" + strconv.Itoa(r.Unattributed) + " without an address)"
			}
		}
		inv.echo(fmt.Sprintf("  %-*s  %s", w, r.ID, text))
	}
	same, changed, added, none := 0, 0, 0, 0
	for _, k := range sr.keys {
		if k.Err != nil {
			none++
			continue
		}
		e, _ := sr.res.Lookup(k.Target.Name, devreg.ScopeFilter{})
		switch c := devreg.Compare(e.HostKeys, k.Keys); {
		case c.Changed:
			changed++
		case len(c.Added) > 0:
			added++
		default:
			same++
		}
	}
	keys := "none pinned"
	if n := len(sr.keys); n > 0 {
		keys = howMany(n, "entry") + " re-scanned: " + strconv.Itoa(same) + " unchanged"
		if changed > 0 {
			keys += ", " + strconv.Itoa(changed) + " CHANGED"
		}
		if added > 0 {
			keys += ", " + strconv.Itoa(added) + " with a new key type"
		}
		if none > 0 {
			keys += ", " + strconv.Itoa(none) + " no answer"
		}
	}
	inv.echo("  Host keys: " + keys)
	if sr.keyErr != nil {
		a.Out.Warn("Host keys could not be read: " + firstLineOf(strings.Join(msgs(sr.keyErr), " ")))
	}
	reg, unreg := 0, 0
	held := map[string]bool{}
	for _, e := range sr.res.All() {
		held[e.Address] = true
	}
	for _, s := range sr.res.Seen.All() {
		if held[s.Address] {
			reg++
		} else {
			unreg++
		}
	}
	line := "  Seen: " + howMany(reg+unreg, "address") + ", " + strconv.Itoa(reg) + " registered, " + strconv.Itoa(unreg) + " not"
	if unreg > 0 {
		line += " (tacctl device discover)"
	}
	inv.echo(line)
}

func howMany(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	switch {
	case strings.HasSuffix(word, "ss"):
		return strconv.Itoa(n) + " " + word + "es"
	case strings.HasSuffix(word, "y"):
		return strconv.Itoa(n) + " " + strings.TrimSuffix(word, "y") + "ies"
	}
	return strconv.Itoa(n) + " " + word + "s"
}

func firstLineOf(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// printNotices prints the open notices of the entries the caller may see.
func (inv *invocation) printNotices(res *devreg.Resolver) {
	var lines []string
	for _, e := range res.Visible(inv.deviceFilter()) {
		for _, n := range devreg.Open(res.NoticesFor(e)) {
			lines = append(lines, "    "+e.Name+"  "+n.Kind+": "+n.Text)
		}
	}
	inv.echo("")
	if len(lines) == 0 {
		inv.echo("  Notices: none")
		return
	}
	inv.echo("  Notices (" + strconv.Itoa(len(lines)) + "):")
	for _, l := range lines {
		inv.echo(l)
	}
}

// scanFlags reads --full, --since and --backend.
func (inv *invocation) scanFlags(p Parsed) (scanRequest, error) {
	rq := scanRequest{full: p.Has("--full"), only: p.Value("--backend")}
	if p.Has("--backend") && rq.only == "" {
		return rq, inv.usageErr("--backend needs a backend id.")
	}
	if p.Has("--since") {
		if rq.full {
			return rq, inv.usageErr("Give --full or --since, not both.")
		}
		d, err := devreg.ParseSince(p.Value("--since"))
		if err != nil {
			return rq, err
		}
		rq.since = d
	}
	return rq, nil
}

func (inv *invocation) deviceScan(args []string) error {
	p, err := inv.deviceParse("scan", args)
	if err != nil {
		return err
	}
	rq, err := inv.scanFlags(p)
	if err != nil {
		return err
	}
	sr, err := inv.runScan(rq)
	if err != nil {
		return err
	}
	inv.printScan(sr)
	inv.printNotices(sr.res)
	inv.echo("")
	return nil
}

// --- discover ------------------------------------------------------------------------

func (inv *invocation) deviceDiscover(args []string) error {
	p, err := inv.deviceParse("discover", args)
	if err != nil {
		return err
	}
	rq, err := inv.scanFlags(p)
	if err != nil {
		return err
	}
	sr, err := inv.runScan(rq)
	if err != nil {
		return err
	}
	inv.printScan(sr)
	us := sr.res.Unregistered(p.Has("--all"))
	head := "Unregistered addresses that authenticated (" + strconv.Itoa(len(us)) + ")"
	if p.Has("--all") {
		head = "Unregistered addresses seen (" + strconv.Itoa(len(us)) + ")"
	}
	inv.echo("")
	if len(us) == 0 {
		inv.echoE(ui.Bold + head + ui.NC)
		inv.echo(ui.Rule(head))
		if p.Has("--all") {
			inv.echo("  None: every address in the seen cache is registered.")
		} else {
			inv.echo("  None. 'tacctl device discover --all' adds the addresses that were only refused.")
		}
	} else {
		t := ui.NewTable(head, ui.Left("ADDRESS"), ui.Left("SCOPE"), ui.Left("TAG"), ui.Left("FIRST SEEN"), ui.Left("LAST SEEN"),
			ui.Left("COUNT"), ui.Left("LAST USER"), ui.Left("RESULT"), ui.Left("VIA"), ui.Left("NAS-ID"))
		for _, u := range us {
			t.Add(u.Address, dash(u.Scope), dash(u.Tag), seenTime(u.First), seenTime(u.Last),
				strconv.Itoa(u.Count), dash(u.LastUser), u.LastOutcome, u.Via, dash(u.LastNASID))
		}
		inv.write(t.String())
		inv.echo("")
		inv.echo("  Register them with:")
		for _, u := range us {
			inv.echo("    tacctl device add " + u.Suggest + " " + u.Address)
		}
	}
	inv.printNotices(sr.res)
	inv.echo("")
	return nil
}

// --- check ---------------------------------------------------------------------------

func (inv *invocation) deviceCheck(args []string) error {
	p, err := inv.deviceParse("check", args)
	if err != nil {
		return err
	}
	switch {
	case p.Has("--all") && len(p.Args) > 0:
		return inv.usageErr("--all takes no name.", "Usage: tacctl device check <name>|--all [--json]")
	case !p.Has("--all") && len(p.Args) == 0:
		return inv.usageErr("Usage: tacctl device check <name>|--all [--json]")
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	entries := res.Visible(inv.deviceFilter())
	if !p.Has("--all") {
		e, err := inv.deviceFind(res, p.Args[0])
		if err != nil {
			return err
		}
		entries = []devreg.Entry{e}
	}
	if len(entries) == 0 {
		inv.app.Out.Info("No devices or hosts to check. Register one with: tacctl device add <name> <address>")
		return nil
	}
	// Host keys and reachability, all at once; the keys are kept in the
	// seen cache for the notices.
	targets := keyTargets(entries, true)
	var probes []devreg.ProbeTarget
	var probeOf []int
	for i, e := range entries {
		if host := checkHost(e); host != "" {
			probes = append(probes, devreg.ProbeTarget{Host: host, Port: e.SSHPort()})
			probeOf = append(probeOf, i)
		}
	}
	// The sysNames too, alongside.
	reach := make([]string, len(entries))
	var sys []checkSysName
	done := make(chan struct{}, 2)
	go func() {
		for j, r := range devreg.Probe(inv.ctx, probes) {
			reach[probeOf[j]] = r
		}
		done <- struct{}{}
	}()
	go func() {
		sys = inv.checkSysNames(entries)
		done <- struct{}{}
	}()
	keys := devreg.RescanKeys(inv.ctx, inv.app.Runner, targets, keyFallback(inv))
	<-done
	<-done
	path := inv.app.Paths.SeenCache
	unlock, err := devreg.LockSeen(path)
	if err != nil {
		return err
	}
	seen := inv.seenLoad()
	keyErr := seen.RecordKeyResults(keys, inv.app.Knobs.Now())
	if seen.HasData() || len(keys) > 0 {
		err = seen.Save(path)
	}
	unlock()
	if err != nil {
		return err
	}
	res.Seen = seen
	if keyErr != nil {
		inv.app.Out.Warn("Host keys could not be read: " + firstLineOf(strings.Join(msgs(keyErr), " ")))
	}
	byName := map[string]devreg.KeyResult{}
	for _, k := range keys {
		byName[strings.ToLower(k.Target.Name)] = k
	}
	js := []deviceCheckJSON{}
	configs := inv.configRecords()
	for i, e := range entries {
		k, scanned := byName[strings.ToLower(e.Name)]
		rows := inv.checkRows(res, e, reach[i], k, scanned, sys[i])
		if r, ok := netconfRow(e, configs); ok {
			// Before the notices, which close the checklist.
			at := slices.IndexFunc(rows, func(x checkRow) bool { return x.label == "Notices" })
			if at < 0 {
				at = len(rows)
			}
			rows = slices.Insert(rows, at, r)
		}
		if p.Has("--json") {
			cj := checkJSONOf(res, e, reach[i], rows, sys[i])
			if e.Source == devreg.SourceDevice {
				if info, err := inv.deviceSNMPInfoOf(e); err == nil {
					cj.SNMP = info.json()
				}
			}
			js = append(js, cj)
			continue
		}
		inv.printCheck(e, rows)
	}
	if p.Has("--json") {
		return inv.printJSON(js)
	}
	inv.echo("")
	return nil
}

// deviceCheckJSON is one entry of 'device check --json': the rows as the
// checklist prints them, and the sysName on its own.
type deviceCheckJSON struct {
	Name      string             `json:"name"`
	Source    string             `json:"source"`
	Address   string             `json:"address"`
	Vendor    string             `json:"vendor"`
	Scope     string             `json:"scope"`
	Seen      string             `json:"seen"`
	Reachable string             `json:"reachable"`
	HostKey   string             `json:"host_key"`
	Notices   []deviceNoticeJSON `json:"notices"`
	// SysName is the SNMP sysName (null: none read), SysNameMatch whether
	// it is the device's own name, SysNameError why there is none.
	SysName      *string `json:"sysname"`
	SysNameMatch *bool   `json:"sysname_match"`
	SysNameError string  `json:"sysname_error,omitempty"`
	// SysLocation is the SNMP sysLocation (null: none read), SysLocationMatch
	// whether it is the registry's location (null: the registry has none),
	// SysLocationError why there is none.
	SysLocation      *string `json:"syslocation"`
	SysLocationMatch *bool   `json:"syslocation_match"`
	SysLocationError string  `json:"syslocation_error,omitempty"`
	// Netconf is the NETCONF probe of the device's last pull: hello ok,
	// port closed, no hello or not probed (none for a host and for a
	// vendor that is not read).
	Netconf string `json:"netconf,omitempty"`
	// SNMP is what the name and the location were read with and where each
	// value comes from (D72); never a secret.
	SNMP *deviceSNMPJSON `json:"snmp,omitempty"`
}

func checkJSONOf(res *devreg.Resolver, e devreg.Entry, reach string, rows []checkRow, sys checkSysName) deviceCheckJSON {
	j := deviceCheckJSON{Name: e.Name, Source: string(e.Source), Address: e.Address, Vendor: e.Vendor, Scope: e.Scope,
		Reachable: dash(reach), Notices: []deviceNoticeJSON{}}
	for _, r := range rows {
		switch r.label {
		case "Seen":
			j.Seen = r.value
		case "Host key":
			j.HostKey = r.value
		case "NETCONF":
			j.Netconf, _, _ = strings.Cut(r.value, " (")
		}
	}
	for _, n := range devreg.Open(res.NoticesFor(e)) {
		j.Notices = append(j.Notices, deviceNoticeJSON{Kind: n.Kind, Text: n.Text})
	}
	switch {
	case sys.err == nil && sys.name != "":
		name, match := sys.name, devreg.NameMatches(e, sys.name)
		j.SysName, j.SysNameMatch = &name, &match
	case sys.problem != "":
		j.SysNameError = sys.problem
	case sys.err != nil:
		j.SysNameError = "no answer"
		if why := snmpReason(sys.err); why != "" {
			j.SysNameError += " (" + why + ")"
		}
	}
	if e.Source == devreg.SourceDevice {
		switch {
		case sys.problem != "":
			j.SysLocationError = sys.problem
		case errors.Is(sys.locErr, errEmptySysLocation):
			j.SysLocationError = "empty"
		case sys.locErr != nil:
			j.SysLocationError = "no answer"
			if why := snmpReason(sys.locErr); why != "" {
				j.SysLocationError += " (" + why + ")"
			}
		default:
			loc := sys.loc
			j.SysLocation = &loc
			if reg := strings.TrimSpace(e.Location); reg != "" {
				match := strings.EqualFold(reg, loc)
				j.SysLocationMatch = &match
			}
		}
	}
	return j
}

// checkHost is what a probe of e connects to: its hostname, else its
// address (” for a host enrolled with --local).
func checkHost(e devreg.Entry) string {
	if e.Source == devreg.SourceHost {
		addr, _, _, ok := scanTarget(e)
		if !ok {
			return ""
		}
		return addr
	}
	if e.Hostname != "" {
		return e.Hostname
	}
	return e.Address
}

// checkRow is one line of the checklist.
type checkRow struct{ label, value string }

// netconfRow is the NETCONF row of a device's checklist (D61): what the
// last pull's probe found, with when. A check logs in to nothing, so the
// probe is the pull's; a device never pulled says so and how to probe it.
func netconfRow(e devreg.Entry, recs *devconf.Records) (checkRow, bool) {
	// Only a Junos device is probed (and read) over NETCONF (D61): a Cisco
	// device's pull does not try it, so it has no row.
	if e.Source != devreg.SourceDevice || e.Vendor != "juniper" {
		return checkRow{}, false
	}
	rec, ok := recs.Of(e.Name)
	if !ok || rec.Netconf == "" || rec.Netconf == netconfNotProbed {
		return checkRow{"NETCONF", netconfNotProbed + " (a pull probes it: tacctl device config pull " + e.Name + ")"}, true
	}
	when := ""
	if !rec.NetconfAt.IsZero() {
		when = " (probed " + seenTime(rec.NetconfAt) + " by a pull)"
	}
	return checkRow{"NETCONF", rec.Netconf + when}, true
}

// printCheck is the checklist of one entry.
func (inv *invocation) printCheck(e devreg.Entry, rows []checkRow) {
	head := "Check " + e.Name + " (" + dashAddrText(e.Address) + ", " + e.Vendor + ")"
	inv.echo("")
	inv.echoE(ui.Bold + head + ui.NC)
	inv.echo(ui.Rule(head))
	for _, r := range rows {
		inv.write(fmt.Sprintf("  %-12s %s\n", r.label+":", r.value))
	}
}

// checkRows are the checklist rows of one entry.
func (inv *invocation) checkRows(res *devreg.Resolver, e devreg.Entry, reach string, k devreg.KeyResult, scanned bool, sys checkSysName) []checkRow {
	var rows []checkRow
	row := func(k, v string) { rows = append(rows, checkRow{k, v}) }
	switch {
	case e.Source == devreg.SourceHost && e.Configured:
		row("Scope", e.Scope)
	case e.Source == devreg.SourceHost:
		row("Scope", dash(e.Scope)+"  (no such scope)")
	case e.Configured:
		row("Scope", e.Scope+"  (via prefix "+e.Prefix+")")
	default:
		row("Scope", "none: no scope's prefixes cover "+e.Address+" ('tacctl scope prefixes <scope> add <cidr>')")
	}
	if e.Source == devreg.SourceDevice {
		row("Vendor tag", dash(e.Tag))
	}
	last, by, via, stale := deviceSeenCols(inv, res, e)
	switch last {
	case "-":
		row("Seen", "no seen data (tacctl device scan)")
	case "never":
		row("Seen", "never (seen data as of "+seenTime(res.Seen.Updated)+")")
	default:
		s := last + " by " + by + " via " + via
		if stale {
			s += "  (stale: older than " + strconv.Itoa(res.File.StaleDays) + " days)"
		}
		row("Seen", s)
	}
	host := checkHost(e)
	switch reach {
	case "":
		row("Reachable", "- (enrolled with --local)")
	case devreg.ProbeOpen:
		row("Reachable", "open ("+host+" port "+strconv.Itoa(e.SSHPort())+")")
	case devreg.ProbeClosed:
		row("Reachable", "closed ("+host+" port "+strconv.Itoa(e.SSHPort())+": connection refused)")
	default:
		row("Reachable", reach+" ("+host+" port "+strconv.Itoa(e.SSHPort())+"; this server often has no path to management ports, so this may be a false alarm)")
	}
	switch {
	case !scanned:
		row("Host key", "- (not scanned)")
	case k.Err != nil && len(e.HostKeys) == 0:
		row("Host key", "not pinned; no key could be read")
	case k.Err != nil:
		row("Host key", "no answer (pinned: "+devreg.Displays(devreg.ParseHostKeys(e.HostKeys))+")")
	case len(e.HostKeys) == 0:
		row("Host key", "not pinned; offers "+devreg.Displays(k.Keys))
	default:
		switch c := devreg.Compare(e.HostKeys, k.Keys); {
		case c.Changed:
			row("Host key", "CHANGED: offers "+devreg.Displays(k.Keys)+"; pinned "+devreg.Displays(devreg.ParseHostKeys(e.HostKeys)))
		case len(c.Added) > 0:
			row("Host key", "matches; also offers "+devreg.Displays(c.Added)+" (not pinned)")
		default:
			row("Host key", "matches the pinned keys")
		}
	}
	if e.Source == devreg.SourceDevice {
		// The settings the name and the location were read with, and where
		// each comes from (D72); never a secret.
		if info, err := inv.deviceSNMPInfoOf(e); err != nil {
			row("SNMP", "cannot be read: "+strings.Join(msgs(err), " "))
		} else if info.Eff.Version == "" {
			row("SNMP", "not configured (tacctl device snmp "+shellquote.Q(e.Name)+" community|v3-user <user>)")
		} else {
			row("SNMP", info.settings())
			row("SNMP creds", info.credentials())
		}
	}
	if v := sys.row(e); v != "" {
		row("SNMP name", v)
	}
	if v := sys.locationRow(e); v != "" {
		row("Location", v)
	}
	ns := devreg.Open(res.NoticesFor(e))
	if len(ns) == 0 {
		row("Notices", "none")
	}
	for i, n := range ns {
		label := "Notices"
		if i > 0 {
			label = ""
		}
		row(label, n.Kind+": "+n.Text)
	}
	return rows
}

func dashAddrText(a string) string {
	if a == "" {
		return "no address"
	}
	return a
}

// --- list --probe ------------------------------------------------------------------

// probeEntries probes the entries' ssh ports, all at once.
func (inv *invocation) probeEntries(entries []devreg.Entry) []string {
	var targets []devreg.ProbeTarget
	var of []int
	for i, e := range entries {
		if h := checkHost(e); h != "" {
			targets = append(targets, devreg.ProbeTarget{Host: h, Port: e.SSHPort()})
			of = append(of, i)
		}
	}
	out := make([]string, len(entries))
	for i := range out {
		out[i] = "-"
	}
	for j, r := range devreg.Probe(inv.ctx, targets) {
		out[of[j]] = r
	}
	return out
}

// --- status ----------------------------------------------------------------------------

// statusDeviceNotices is the 'Device notices' section of 'tacctl status':
// the count of open notices of the entries the caller may see and the first
// five. Without a registry entry or an enrolled host there is no section.
func (inv *invocation) statusDeviceNotices() {
	_, res, err := inv.deviceLoad()
	if err != nil {
		return
	}
	entries := res.Visible(inv.deviceFilter())
	if len(res.All()) == 0 {
		return
	}
	var lines []string
	for _, e := range entries {
		for _, n := range devreg.Open(res.NoticesFor(e)) {
			lines = append(lines, e.Name+"  "+n.Kind+": "+n.Text)
		}
	}
	inv.echo("")
	if len(lines) == 0 {
		inv.write("  " + ui.Bold + "Device notices:" + ui.NC + " " + ui.Green + "none" + ui.NC + "\n")
		return
	}
	inv.write("  " + ui.Bold + "Device notices:" + ui.NC + " " + strconv.Itoa(len(lines)) + " (tacctl device notices)\n")
	for i, l := range lines {
		if i == 5 {
			inv.echo("    ... and " + strconv.Itoa(len(lines)-5) + " more: tacctl device notices")
			break
		}
		inv.write("    " + ui.Yellow + l + ui.NC + "\n")
	}
}
