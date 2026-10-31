package cli

// 'device scan', 'device discover', 'device check', 'device list
// --scan|--probe' and the seen columns of 'device list|show'
// (docs/plans/operator-console.md 3.3, 3.4, 3.6, 3.7). The scan reads every
// enabled backend's log of its devices (backend.Sighter) into the seen cache
// (/var/lib/tacctl/devices-seen.json, internal/devreg/seen.go), re-scans the
// pinned host keys and prints the scan-time notices. 'list' and 'show' read
// the cache only; 'scan' is explicit, and a session start runs it in the
// background (--if-stale --quiet, seen_refresh.go). A scan never writes devices.yaml.

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/snmp"
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
			// A device the server was told not to answer is refused on
			// purpose.
			if _, held := inv.holdAt(e.Address); held {
				last += " (break-glass held)"
			} else {
				last += " (no scope)"
			}
		}
	}
	days := res.File.StaleDays
	if days < 1 {
		days = devreg.DefaultStaleDays
	}
	stale = x.Last.Before(inv.app.Knobs.Now().AddDate(0, 0, -days))
	return last, dash(x.LastUser), x.Via, stale
}

// seenRemindAge is how old the seen data is before the list and show remind
// the reader to run 'device scan': a session start refreshes it, so older
// than this means no session has started since.
const seenRemindAge = time.Hour

// seenOldText is how old the seen data is when it is old enough to be
// reminded of ("3 hours", "2 days"), and "" when it is not.
func (inv *invocation) seenOldText(res *devreg.Resolver) string {
	if !res.Seen.HasData() {
		return ""
	}
	d := inv.app.Knobs.Now().Sub(res.Seen.Updated)
	switch {
	case d < seenRemindAge:
		return ""
	case d < 2*time.Hour:
		return "an hour"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " hours"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + " days"
}

// seenRunText is the reminder to bring old seen data up to date, worded for
// who may do it.
func (inv *invocation) seenRunText() string {
	if inv.scanAllowed() {
		return "run 'tacctl device scan' to bring it up to date"
	}
	return "an operator can run 'tacctl device scan' to bring it up to date"
}

// deviceSeenFooter is the line under 'device list' about the seen data.
func (inv *invocation) deviceSeenFooter(res *devreg.Resolver) string {
	if !res.Seen.HasData() {
		return "seen data: none (tacctl device scan)"
	}
	refresh := "tacctl device scan to refresh"
	if old := inv.seenOldText(res); old != "" {
		refresh = old + " old: " + inv.seenRunText()
	}
	return "seen data as of " + seenTime(res.Seen.Updated) + " (" + refresh + "); stale after " +
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
	// ifStale is the background form (a session start): do nothing when
	// another scan holds the cache or the cache is younger than
	// seenFreshAge, and re-scan a device's host keys only when its last scan
	// is older than keyRescanAge.
	ifStale bool
}

const (
	// seenFreshAge is how young the seen cache is when --if-stale leaves it.
	seenFreshAge = 5 * time.Minute
	// keyRescanAge is how old a device's host-key scan is before --if-stale
	// connects to it again: every session start must not touch every device.
	keyRescanAge = 24 * time.Hour
)

// scanResult is what runScan leaves for the printing.
type scanResult struct {
	reports []devreg.SourceReport
	keys    []devreg.KeyResult
	keyErr  error
	res     *devreg.Resolver
	rebuilt bool
	// skipped: --if-stale found the cache current, or a scan under way.
	skipped bool
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
func (inv *invocation) keyTargets(entries []devreg.Entry, unpinned bool) []devreg.KeyTarget {
	var out []devreg.KeyTarget
	for _, e := range entries {
		if len(e.HostKeys) == 0 && !unpinned {
			continue
		}
		addr, port, legacy, ok := scanTarget(e)
		if !ok || addr == "" {
			continue
		}
		out = append(out, devreg.KeyTarget{Name: e.Name, Address: addr, Port: port, Legacy: legacy,
			Timing: devssh.ScanTiming{}.Scaled(inv.scaleOfEntry(e))})
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
	var unlock func()
	if rq.ifStale {
		// Many sessions may start at once: the one that finds a scan
		// under way leaves it to that scan.
		var ok bool
		if unlock, ok, err = devreg.TryLockSeen(path); err != nil {
			return nil, err
		} else if !ok {
			return &scanResult{skipped: true, res: res}, nil
		}
	} else if unlock, err = devreg.LockSeen(path); err != nil {
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
	if rq.ifStale && seen.HasData() && now.Sub(seen.Updated) < seenFreshAge {
		// Another session's scan finished while this one started.
		res.Seen = seen
		return &scanResult{skipped: true, res: res}, nil
	}
	out.reports = devreg.ScanSources(inv.ctx, seen, srcs, devreg.ScanOptions{
		Now: now, StaleDays: f.StaleDays, Full: rq.full || out.rebuilt, Since: rq.since})
	all := res.All()
	targets := inv.keyTargets(all, false)
	if rq.ifStale {
		var due []devreg.KeyTarget
		for _, t := range targets {
			if k := seen.HostKeys[strings.ToLower(t.Name)]; k == nil || now.Sub(k.Scanned) >= keyRescanAge {
				due = append(due, t)
			}
		}
		targets = due
	}
	out.keys = devreg.RescanKeys(inv.ctx, inv.app.Runner, targets, inv.hooks.scanFallback(inv))
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
	rq := scanRequest{full: p.Has("--full"), only: p.Value("--backend"), ifStale: p.Has("--if-stale")}
	if rq.ifStale && (rq.full || p.Has("--since")) {
		return rq, inv.usageErr("--if-stale is the background form: give it without --full or --since.")
	}
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
	if p.Has("--sources") && (rq.ifStale || p.Has("--quiet")) {
		return inv.usageErr("--sources is not part of the background form: give it without --if-stale or --quiet.")
	}
	sr, err := inv.runScan(rq)
	if err != nil {
		return err
	}
	switch {
	case p.Has("--quiet"):
	case sr.skipped:
		inv.app.Out.Info("The seen data is current, or a scan is under way; nothing was read.")
	default:
		inv.printScan(sr)
		inv.printNotices(sr.res)
		if p.Has("--sources") {
			inv.scanSources(sr.res)
		}
		inv.echo("")
	}
	return nil
}

// scanSources tests the source addresses of the devices the caller may see and
// prints what it found, device by device (D315).
func (inv *invocation) scanSources(res *devreg.Resolver) {
	var entries []devreg.Entry
	for _, e := range res.Visible(inv.deviceFilter()) {
		if e.Source == devreg.SourceDevice {
			entries = append(entries, e)
		}
	}
	reps := inv.testDeviceSources(entries, false)
	inv.auditSources(reps)
	inv.echo("")
	inv.echoE(ui.Bold + "Source addresses" + ui.NC)
	inv.echo(ui.Rule("Source addresses"))
	shown, untested := 0, 0
	for _, r := range reps {
		if len(r.Results) > 0 || r.Registered || r.Note != noteNoSource {
			inv.printSources(r, r.Device+": ", true)
			shown++
		}
		if len(r.Results) == 0 && !r.Registered && r.Note != noteNoSource {
			untested++
		}
	}
	switch {
	case untested > 0:
		inv.app.Out.Info(howMany(untested, "device") + " not tested (see the lines above)")
	case shown == 0:
		inv.app.Out.Info("No device states a source address of its AAA client to test.")
	}
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
		var reads []discoverRead
		if p.Has("--snmp") {
			reads = inv.discoverSNMP(us)
		}
		inv.echo("  Register them with:")
		for i, u := range us {
			line := "    tacctl device add " + u.Suggest + " " + u.Address
			if reads != nil {
				line = reads[i].addLine(u)
			}
			inv.echo(line)
		}
	}
	inv.printNotices(sr.res)
	inv.echo("")
	return nil
}

// discoverRead is what 'device discover --snmp' read of one listed address
// (D260): its sysName and the vendor it names; problem is a lookup that
// cannot run (SNMP not set up for the address's scope).
type discoverRead struct {
	name    string
	nameErr error
	vend    vendorRead
	problem string
}

// discoverSNMP reads the sysName and the vendor of each address, with the
// credentials of the scope that answers it (the default's for none), at most
// 16 at once, and keeps the vendors in the seen cache for the notices. An
// address that does not answer the name is not asked for the vendor.
func (inv *invocation) discoverSNMP(us []devreg.Unregistered) []discoverRead {
	out := make([]discoverRead, len(us))
	getters := make([]snmp.Getter, len(us))
	for i, u := range us {
		getters[i], out[i].problem = inv.snmpGetterForAddr(u.Address)
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16)
	for i, u := range us {
		g := getters[i]
		if g == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			name, err := g.SysName(inv.ctx, u.Address)
			r := discoverRead{name: strings.TrimSpace(name), nameErr: err}
			if err != nil {
				r.vend = vendorRead{err: err}
			} else {
				r.vend = vendorReadOf(g.SysIdentity(inv.ctx, u.Address))
			}
			out[i] = r
		}()
	}
	wg.Wait()
	reads := map[string]vendorRead{}
	for i, u := range us {
		if out[i].problem == "" {
			reads[u.Address] = out[i].vend
		}
	}
	inv.keepDetections(reads)
	return out
}

// addLine is the suggested 'device add' line of u with what SNMP read: the
// sysName, lowercased, as the name when it may be offered, and --vendor when
// the device names one; what was not used follows as a comment.
func (r discoverRead) addLine(u devreg.Unregistered) string {
	name, vendor := u.Suggest, ""
	var notes []string
	switch {
	case r.problem != "":
		notes = append(notes, r.problem)
	case r.nameErr != nil:
		notes = append(notes, r.vend.readFailure())
	default:
		switch lower := strings.ToLower(r.name); {
		case r.name == "":
			notes = append(notes, "an empty sysName")
		case offerable(lower):
			name = lower
		default:
			notes = append(notes, "sysName '"+cleanLine(r.name)+"' is no name to offer")
		}
		switch {
		case r.vend.err != nil:
			notes = append(notes, "vendor: "+r.vend.readFailure())
		case r.vend.vendor != "":
			vendor = r.vend.vendor
		default:
			notes = append(notes, "vendor: "+r.vend.reason)
		}
	}
	line := "    tacctl device add " + name + " " + u.Address
	if vendor != "" {
		line += " --vendor " + vendor
	}
	if len(notes) > 0 {
		line += "    # SNMP: " + strings.Join(notes, "; ")
	}
	return line
}

// --- check ---------------------------------------------------------------------------

func (inv *invocation) deviceCheck(args []string) error {
	p, err := inv.deviceParse("check", args)
	if err != nil {
		return err
	}
	switch {
	case p.Has("--all") && len(p.Args) > 0:
		return inv.usageErr("--all takes no name.", "Usage: tacctl device check <name>|--all [--sources] [--json]")
	case !p.Has("--all") && len(p.Args) == 0:
		return inv.usageErr("Usage: tacctl device check <name>|--all [--sources] [--json]")
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
	targets := inv.keyTargets(entries, true)
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
		for j, r := range devreg.Probe(inv.ctx, probes, inv.hooks.probe()) {
			reach[probeOf[j]] = r
		}
		done <- struct{}{}
	}()
	go func() {
		sys = inv.checkSysNames(entries)
		done <- struct{}{}
	}()
	keys := devreg.RescanKeys(inv.ctx, inv.app.Runner, targets, inv.hooks.scanFallback(inv))
	<-done
	<-done
	path := inv.app.Paths.SeenCache
	unlock, err := devreg.LockSeen(path)
	if err != nil {
		return err
	}
	seen := inv.seenLoad()
	keyErr := seen.RecordKeyResults(keys, inv.app.Knobs.Now())
	// The vendors the devices named, for the vendor-differs notice (D260).
	reads := map[string]vendorRead{}
	for i, e := range entries {
		if e.Source == devreg.SourceDevice && e.Address != "" && sys[i].problem == "" {
			reads[e.Address] = sys[i].vend
		}
	}
	recordDetections(seen, reads, inv.app.Knobs.Now())
	if seen.HasData() || len(keys) > 0 || len(seen.Detected) > 0 {
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
	var sources []sourceReport
	if p.Has("--sources") {
		sources = inv.testDeviceSources(entries, p.Has("--json"))
		inv.auditSources(sources)
	}
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
			cj.Breakglass = inv.deviceHoldOf(e)
			if e.Source == devreg.SourceDevice {
				if info, err := inv.deviceSNMPInfoOf(e); err == nil {
					cj.SNMP = info.json()
				}
			}
			if sources != nil && e.Source == devreg.SourceDevice {
				list := sourcesJSON(sources[i])
				cj.Sources = &list
			}
			js = append(js, cj)
			continue
		}
		inv.printCheck(e, rows)
		if sources != nil {
			inv.printCheckSources(e, sources[i])
		}
	}
	if p.Has("--json") {
		return inv.printJSON(js)
	}
	if p.Has("--all") {
		inv.printVendorReport(entries, sys)
	}
	inv.echo("")
	return nil
}

// printVendorReport is the end of 'device check --all' (D260): the devices
// registered as other that name a vendor tacctl reads, each with the command
// that sets it from the device. It writes nothing.
func (inv *invocation) printVendorReport(entries []devreg.Entry, sys []checkSysName) {
	var lines []string
	for i, e := range entries {
		if e.Source == devreg.SourceDevice && e.Vendor == devreg.VendorOther && sys[i].problem == "" && sys[i].vend.vendor != "" {
			lines = append(lines, "  "+e.Name+"  "+sys[i].vend.vendor+" ("+sys[i].vend.reason+"): tacctl device vendor "+
				shellquote.Q(e.Name)+" --from-device")
		}
	}
	if len(lines) == 0 {
		return
	}
	head := "Registered as other, the device names a vendor (" + strconv.Itoa(len(lines)) + ")"
	inv.echo("")
	inv.echoE(ui.Bold + head + ui.NC)
	inv.echo(ui.Rule(head))
	for _, l := range lines {
		inv.echo(l)
	}
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
	// VendorDetected is the vendor the device names by SNMP (null: none),
	// VendorReason what was recognised or why none is named, VendorError
	// why nothing was read (D260).
	VendorDetected *string `json:"vendor_detected"`
	VendorReason   string  `json:"vendor_reason,omitempty"`
	VendorError    string  `json:"vendor_error,omitempty"`
	// Netconf is the NETCONF probe of the device's last pull: hello ok,
	// port closed, no hello or not probed (none for a host and for a
	// vendor that is not read).
	Netconf string `json:"netconf,omitempty"`
	// SNMP is what the name and the location were read with and where each
	// value comes from (D72); never a secret.
	SNMP *deviceSNMPJSON `json:"snmp,omitempty"`
	// Breakglass is the hold on the device while there is one.
	Breakglass *deviceHoldJSON `json:"breakglass,omitempty"`
	// Sources are the source addresses of the device's AAA client, tested
	// with --sources (D315); absent without it and for a host.
	Sources *[]sourceResult `json:"sources,omitempty"`
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
		switch v := sys.vend; {
		case sys.problem != "":
			j.VendorError = sys.problem
		case v.err != nil:
			j.VendorError = v.readFailure()
		default:
			j.VendorReason = v.reason
			if v.vendor != "" {
				name := v.vendor
				j.VendorDetected = &name
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
	if h := inv.deviceHoldOf(e); h != nil {
		hold, _ := inv.holdOf(e.Name, e.Address)
		rows[len(rows)-1].value += "; " + ui.Red + "NOT ANSWERED: break-glass " + inv.holdRowText(hold) + ui.NC
	}
	if e.Source == devreg.SourceDevice {
		row("Vendor tag", dash(e.Tag))
	}
	last, by, via, stale := deviceSeenCols(inv, res, e)
	switch last {
	case "-":
		row("Seen", "no seen data (tacctl device scan)")
	case "never":
		s := "never (seen data as of " + seenTime(res.Seen.Updated)
		if old := inv.seenOldText(res); old != "" {
			s += ", " + old + " old: " + inv.seenRunText()
		}
		row("Seen", s+")")
	default:
		s := last + " by " + by + " via " + via
		if stale {
			s += "  (stale: older than " + strconv.Itoa(res.File.StaleDays) + " days)"
		}
		if old := inv.seenOldText(res); old != "" {
			s += "  (seen data is " + old + " old: " + inv.seenRunText() + ")"
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
			row("SNMP", "not configured (tacctl device snmp "+shellquote.Q(e.Name)+" version v2c|v3)")
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
	if v := sys.vendorRow(e); v != "" {
		row("Vendor", v)
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
	for j, r := range devreg.Probe(inv.ctx, targets, inv.hooks.probe()) {
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
	inv.write("  " + ui.Bold + "Device notices:" + ui.NC + " " + strconv.Itoa(len(lines)) + " (tacctl device notice list)\n")
	for i, l := range lines {
		if i == 5 {
			inv.echo("    ... and " + strconv.Itoa(len(lines)-5) + " more: tacctl device notice list")
			break
		}
		inv.write("    " + ui.Yellow + l + ui.NC + "\n")
	}
}
