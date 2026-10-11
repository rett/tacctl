package cli

// 'tacctl breakglass hold <device> --reason "<text>" | release <device> |
// list [--json]' (docs/plans/0.2.5-plan.md D121-D126): make the server stop
// answering one managed device, so its local accounts are usable while the
// server is up, and answer it again. The record is breakglass_hold.<device>
// in tacctl.yaml (internal/conf); both renderers take its address out of
// every scope's prefixes (internal/model WithoutAddresses) and nothing in
// store.yaml changes. A hold is shown until it is released: there is no
// timer. 'hold' and 'release' are the superuser's (the tier table has no row
// for them, as for every change of what the scopes answer); 'list' is the
// engineer's, for the devices of their own scopes. 'scope breakglass'
// records the names of a scope's local accounts, which is another thing.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// KindHeld is the _completion-names kind of the devices with a hold (what
// 'breakglass release' completes).
const KindHeld = "held"

const (
	breakglassUsageHold    = `Usage: tacctl breakglass hold <device> --reason "<text>"`
	breakglassUsageRelease = "Usage: tacctl breakglass release <device>"
	breakglassUsageList    = "Usage: tacctl breakglass list [--json]"
)

// breakglassSpecs are the arguments of each verb (completion and parsing).
var breakglassSpecs = map[string]Spec{
	"hold": {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices},
		Flags: []Flag{{Names: []string{"--reason"}, Value: true}}},
	"release": {MinArgs: 1, MaxArgs: 1, Args: []string{KindHeld}},
	"list":    {Flags: []Flag{flagJSON}},
}

// breakglassVerbs are the family's rows: usage and one-line description.
var breakglassVerbs = [][2]string{
	{`hold <device> --reason "<text>"`, "Make the server stop answering one device, so its local accounts are usable (the superuser's)"},
	{"release <device>", "Make the server answer the device again (the superuser's)"},
	{"list [--json]", "The devices held now: since when, by whom and why; an engineer sees the devices of their own scopes"},
}

func init() {
	registerFamily(breakglassCmd)
	registerSpecs("breakglass", breakglassSpecs)
	shellHelpBlocks["breakglass"] = func(*invocation) string { return breakglassUsage() }
}

func breakglassCmd(inv *invocation) *cobra.Command {
	c := verb("breakglass <subcommand>", "Break-glass hold: make the server stop answering one device (hold, release, list)")
	c.RunE = inv.native(withPreflight, inv.breakglass)
	for _, v := range breakglassVerbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.breakglass(append([]string{word}, args...))
		})))
	}
	return c
}

// breakglassUsage is the usage of the family.
func breakglassUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Break-glass Hold" + ui.NC + "\n\nUsage: tacctl breakglass <subcommand> [arguments]\n\nSubcommands:\n")
	for _, v := range breakglassVerbs {
		if len(v[0]) > 36 {
			b.WriteString("  " + v[0] + "\n  " + strings.Repeat(" ", 36) + "  " + v[1] + "\n")
		} else {
			fmt.Fprintf(&b, "  %-36s  %s\n", v[0], v[1])
		}
	}
	b.WriteString(`      --reason "<text>"                 (hold) Why, 1 to 256 characters; kept with the record and in the log
      --json                            (list) Print the holds as a JSON array

A device that authenticates against this server is answered by a scope whose
prefixes cover its address. 'hold' takes that one address out of every
scope's prefixes (the stored scopes do not change), so the server stops
answering the device and its local accounts, the ones 'tacctl scope
breakglass <scope> list' records, are usable while the server is up. It
asks for the device's name typed back, restarts the backends that serve it
and shows the way in for the device's vendor. A hold is for one device, for an
exceptional case, and is shown until 'release' (there is no timer): 'status',
'device show|list|check', 'scope show|list|routing|lookup' and 'config
validate' say so while it stands. Only the superuser holds and releases; an
engineer lists the holds of the devices of their own scopes.

Examples:
  tacctl breakglass hold sw-lab-1 --reason "console recovery after a failed paste"
  tacctl breakglass list
  tacctl breakglass release sw-lab-1

`)
	return b.String()
}

// breakglass dispatches: no sub-command, help, -h and --help are the usage
// (exit 0); anything else unknown is an error, then the usage (exit 1).
func (inv *invocation) breakglass(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(breakglassUsage())
		return nil
	case "hold":
		return inv.breakglassHold(rest)
	case "release":
		return inv.breakglassRelease(rest)
	case "list":
		return inv.breakglassList(rest)
	default:
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(breakglassUsage())
		return exit(1)
	}
}

// --- the records -------------------------------------------------------------

// holds are the records of tacctl.yaml, by device name.
func (inv *invocation) holds() []conf.Hold { return inv.app.Conf().Holds() }

// holdOf is the record of a device (names compare without regard to case).
func (inv *invocation) holdOf(device string) (conf.Hold, bool) {
	for _, h := range inv.holds() {
		if strings.EqualFold(h.Device, device) {
			return h, true
		}
	}
	return conf.Hold{}, false
}

// isHeld reports whether a hold stands on the device.
func (inv *invocation) isHeld(device string) bool {
	_, ok := inv.holdOf(device)
	return ok
}

// holdAt is the record of an address.
func (inv *invocation) holdAt(addr string) (conf.Hold, bool) {
	for _, h := range inv.holds() {
		if h.Address == addr {
			return h, true
		}
	}
	return conf.Hold{}, false
}

// holdSeenBy are the records the caller is shown: all of them for an
// administrator, and for the lower tiers the holds of the devices of their
// own scopes (a record whose device is not registered, or at an address no
// scope answers, is no scope's). It reads the registry; a registry that
// cannot be read shows a restricted caller nothing.
func (inv *invocation) holdSeenBy() []conf.Hold {
	all := inv.holds()
	if len(all) == 0 || !inv.callerScopes().restricted {
		return all
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return nil
	}
	var out []conf.Hold
	for _, h := range all {
		if e, ok := res.Lookup(h.Device, inv.deviceFilter()); ok && e.Source == devreg.SourceDevice {
			out = append(out, h)
		}
	}
	return out
}

// holdTime is when the hold was made, in the local zone.
func holdTime(h conf.Hold) string {
	if t := h.SinceTime(); !t.IsZero() {
		return t.Local().Format("2006-01-02 15:04")
	}
	return h.Since
}

// holdAge is how long a hold has stood: "2 h 14 min", "45 min", "3 d 2 h".
func holdAge(h conf.Hold, now time.Time) string {
	t := h.SinceTime()
	if t.IsZero() {
		return "unknown time"
	}
	return durationText(now.Sub(t))
}

// durationText is a duration as days, hours and minutes, whole minutes.
func durationText(d time.Duration) string {
	if d < time.Minute {
		return "under 1 min"
	}
	mins := int(d / time.Minute)
	days, hours, m := mins/(24*60), mins/60%24, mins%60
	var parts []string
	switch {
	case days > 0:
		parts = append(parts, strconv.Itoa(days)+" d")
		if hours > 0 {
			parts = append(parts, strconv.Itoa(hours)+" h")
		}
	case hours > 0:
		parts = append(parts, strconv.Itoa(hours)+" h")
		if m > 0 {
			parts = append(parts, strconv.Itoa(m)+" min")
		}
	default:
		parts = append(parts, strconv.Itoa(m)+" min")
	}
	return strings.Join(parts, " ")
}

// holdSummary is "held 2 h 14 min by alice" for a one-line mention.
func (inv *invocation) holdSummary(h conf.Hold) string {
	return "since " + holdTime(h) + " by " + h.By + " (" + holdAge(h, inv.app.Knobs.Now()) + ")"
}

// heldNow is the lines that end every report: all the holds that stand.
func (inv *invocation) heldNow(remainder string) string {
	hs := inv.holds()
	if len(hs) == 0 {
		return remainder + "none"
	}
	now := inv.app.Knobs.Now()
	parts := make([]string, len(hs))
	for i, h := range hs {
		parts[i] = h.Device + " (" + holdAge(h, now) + ", " + h.By + ")"
	}
	return remainder + strings.Join(parts, ", ")
}

// --- addresses a hold would lock the superuser out of -------------------------

// serverOwnAddress is why addr cannot be held ("" when it can): loopback, a
// non-wildcard address a listener of either backend binds, or the recorded
// address of an enrolled host (this server's own logins come from 127.0.0.1).
func (inv *invocation) serverOwnAddress(addr string, f *devreg.File, hostEntries []hosts.Entry) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	if ip.IsLoopback() {
		return addr + " is a loopback address: this server's own logins come from 127.0.0.1, and a hold would lock the superuser out of the server"
	}
	set := inv.app.Backends()
	for _, id := range set.IDs() {
		b, err := set.Get(id)
		if err != nil {
			continue
		}
		ls, err := b.Listeners().List()
		if err != nil {
			continue
		}
		for _, l := range ls {
			host, _, err := net.SplitHostPort(l.Address)
			if err != nil {
				host = l.Address
			}
			la, err := netip.ParseAddr(strings.Trim(host, "[]"))
			if err != nil || la.IsUnspecified() {
				continue
			}
			if la == ip {
				return addr + " is where the " + id + " listener " + l.Name + " binds: this server answers there, and a hold would lock out its own clients"
			}
		}
	}
	for _, h := range hostEntries {
		recorded := ""
		switch h.Target {
		case hosts.Local:
			recorded = "127.0.0.1"
		default:
			if f != nil {
				recorded = f.HostAddressOf(h.Name)
			}
			if recorded == "" {
				if host, _, ok := hosts.ScanTarget(h.Target, h.Port); ok {
					if _, err := netip.ParseAddr(host); err == nil {
						recorded = host
					}
				}
			}
		}
		if ra, err := netip.ParseAddr(recorded); err == nil && ra == ip {
			return addr + " is the address of the enrolled host '" + h.Name + "': a host is never held (its logins would stop, and 'tacctl host' manages it)"
		}
	}
	return ""
}

// --- hold ---------------------------------------------------------------------

// vendorWayIn is the way into a held device, by vendor (D124).
func vendorWayIn(vendor string) []string {
	switch vendor {
	case "cisco":
		return []string{
			"ssh: log in as a local account; the device waits for the server first (a few seconds), then takes the local",
			"password, and the account lands at the level of its 'username ... privilege' line.",
			"Console: log in as the local account (the CONSOLE list is local), then 'enable' with the local enable secret:",
			"the server is silent, so 'enable' falls through to it.",
			"Logins by your TACACS+ name fail on this device until you release it.",
		}
	case "juniper":
		return []string{
			"ssh or console: log in as a local user ('system login user'); the switch waits out its tacplus-server timeout,",
			"then checks the local password ('authentication-order [ tacplus password ]').",
			"Root on the console is local always.",
		}
	case "wti":
		return []string{
			`the unit takes its local accounts only if its TACACS+ "Fallback Local" is On (Transport Failure) or On (All Failures)`,
			"(the walkthrough sets it from the scope's aaa-order); with Off, nobody logs in until you release this.",
			"The unit waits out its Fallback Timer first.",
		}
	}
	return []string{
		"Log in with an account the device keeps locally: the server answers nothing for this address, so its",
		"TACACS+ and RADIUS logins fail until you release it.",
	}
}

func (inv *invocation) breakglassHold(args []string) error {
	p, err := Parse(breakglassSpecs["hold"], args)
	if err != nil {
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			return inv.usageErr("Unknown option: '"+uf.Flag+"'", breakglassUsageHold)
		}
		return inv.usageErr(err.Error(), breakglassUsageHold)
	}
	if f := inv.callerScopes(); f.restricted {
		return inv.usageErr("'tacctl breakglass hold' is the superuser's. Nothing was changed.")
	}
	reason := strings.TrimSpace(p.Value("--reason"))
	if !p.Has("--reason") {
		return inv.usageErr("--reason is required: a hold is for one device in exceptional circumstances, and why is part of the record and of the log.", breakglassUsageHold)
	}
	if why := conf.HoldReasonProblem(reason); why != "" {
		return inv.usageErr("--reason "+why+".", breakglassUsageHold)
	}

	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	name := p.Args[0]
	// 1. A registered device (an enrolled Linux host is not one).
	e, ok := res.Lookup(name, devreg.ScopeFilter{})
	if !ok {
		return inv.usageErr("Device '" + name + "' not found. List them with: tacctl device list")
	}
	if e.Source == devreg.SourceHost {
		return inv.usageErr("'" + e.Name + "' is an enrolled host, not a registered device: a break-glass hold is for network devices ('tacctl host' manages hosts, which keep a local administrator).")
	}
	// 2. With an address.
	if e.Address == "" {
		return inv.usageErr("Device '" + e.Name + "' has no address: the hold is on the address the server sees. Register one: tacctl device address " + e.Name + " <address>")
	}
	// 3. Not already held.
	if cur, held := inv.holdOf(e.Name); held {
		inv.app.Out.Error("Break-glass is already held on '" + cur.Device + "' (" + cur.Address + ") " + inv.holdSummary(cur) + ".")
		inv.echo("  Reason: " + cur.Reason)
		return inv.usageErr("Release it first (tacctl breakglass release " + cur.Device + "), then hold again with the new reason. Nothing was changed.")
	}
	// 4. Not an address this server answers from or its own hosts use.
	if why := inv.serverOwnAddress(e.Address, f, res.Hosts); why != "" {
		return inv.usageErr(why + ". Nothing was changed.")
	}
	if other, held := inv.holdAt(e.Address); held {
		return inv.usageErr("Address " + e.Address + " is already held, on '" + other.Device + "'. Nothing was changed.")
	}
	// 5. Some scope answers it now.
	m, err := inv.model()
	if err != nil {
		return err
	}
	info, covered := m.LookupAddr(e.Address)
	if !covered {
		return inv.usageErr("'" + e.Name + "' is already unanswered: no scope covers " + e.Address + " (tacctl scope lookup " + e.Address + "), so its local accounts work now and there is nothing to record. Nothing was changed.")
	}

	// The prompt: the act is exceptional, and the name typed back is the
	// strongest confirmation the project has.
	pr := inv.app.Prompter()
	if !pr.Interactive() {
		return inv.usageErr("No terminal to confirm on: a hold is a person's act, and the device name is typed back. Nothing was changed.")
	}
	local := "no local account is recorded for scope '" + info.Scope + "' (tacctl scope breakglass " + info.Scope + " add <name>)"
	if us := policy.BreakGlassUsers(inv.app.Conf(), info.Scope); len(us) > 0 {
		parts := make([]string, len(us))
		for i, u := range us {
			parts[i] = u.Name + " [" + u.Role + "]"
		}
		local = strings.Join(parts, ", ")
	}
	vendor := e.Vendor
	if vendor == "" {
		vendor = "other"
	}
	inv.echo("")
	inv.echo("Hold break-glass on " + e.Name + " (" + e.Address + ", scope " + info.Scope + ", " + vendor + ")?")
	inv.echo("  This is for one device in exceptional circumstances. The server stops answering " + e.Address + ": every login at")
	inv.echo("  that device falls to its local accounts (" + local + "); nobody without one can")
	inv.echo("  log in there until you release it.")
	inv.echo("  The backends that serve it restart now and again at release (the restart every scope change makes).")
	inv.echo("  Nothing releases it but 'tacctl breakglass release " + e.Name + "'.")
	if typed := pr.Ask("  Type the device name to go on: "); typed != e.Name {
		return inv.usageErr("The name typed back is not '" + e.Name + "'. Nothing was changed.")
	}

	now := inv.app.Knobs.Now()
	h := conf.Hold{Device: e.Name, Address: e.Address, Since: now.Format(time.RFC3339), By: inv.sudoUser(), Reason: reason}
	var changed []string
	res2, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		// Another hold may have been made while the name was typed.
		c := inv.app.Conf()
		c.Reload()
		for _, x := range c.Holds() {
			if strings.EqualFold(x.Device, h.Device) || x.Address == h.Address {
				return fmt.Errorf("break-glass is held on %s (%s) now: nothing was changed", x.Device, x.Address)
			}
		}
		return c.SetHold(h)
	})
	inv.loaded = false
	if err != nil {
		return err
	}
	changed = res2.Changed
	inv.app.Logger(inv.ctx, "auth.info", "breakglass hold device="+e.Name+" addr="+e.Address+" reason="+strconv.Quote(reason)+" by="+h.By)

	inv.echo("")
	inv.echoE(ui.Red + "Break-glass HELD" + ui.NC + " on " + e.Name + " (" + e.Address + ") since " + holdTime(h) + " by " + h.By + ".")
	inv.echo("  Reason:   " + reason)
	inv.echo("  Rendered: " + inv.renderedSentence(m, e.Address, changed, true))
	inv.echo("")
	for _, l := range vendorWayIn(e.Vendor) {
		inv.echo("  " + l)
	}
	inv.echo("  Nothing it does is accounted here: a held device sends its accounting to a server that does not answer it;")
	inv.echo("  what the technician types is in the device's own log only.")
	inv.echo("")
	inv.echo("  " + inv.heldNow("Held now: "))
	inv.echo("  When done: tacctl breakglass release " + e.Name)
	inv.echo("")
	return nil
}

// renderedSentence says what a hold or release did to the rendering: the
// prefixes (and tagged addresses) of the scopes that hold addr, and which
// backends restarted. held is the state after the change.
func (inv *invocation) renderedSentence(m *model.Model, addr string, restarted []string, held bool) string {
	var parts []string
	for _, c := range m.CarvedFrom(addr, "", true) {
		what := c.CIDR + " of scope '" + c.Scope + "'"
		if c.Tagged {
			what = "the tagged " + c.CIDR + " of scope '" + c.Scope + "'"
		}
		n := len(cidr.Subtract([]string{c.CIDR}, []string{addr}))
		switch {
		case !held:
			parts = append(parts, what+" answers whole again")
		case n == 0:
			parts = append(parts, what+" is gone")
		default:
			parts = append(parts, what+" answers as "+strconv.Itoa(n)+" "+plural(n, "prefix", "prefixes")+" without "+addr)
		}
	}
	var s string
	switch {
	case len(parts) == 0:
		s = "no scope covers " + addr + ", so the rendering did not change"
	default:
		s = strings.Join(parts, "; ")
	}
	if len(restarted) == 0 {
		return s + "; no backend file changed, nothing restarted."
	}
	rs := make([]string, len(restarted))
	for i, id := range restarted {
		rs[i] = id + " restarted"
	}
	return s + "; " + strings.Join(rs, ", ") + "."
}

// --- release ------------------------------------------------------------------

func (inv *invocation) breakglassRelease(args []string) error {
	p, err := Parse(breakglassSpecs["release"], args)
	if err != nil {
		return inv.usageErr(err.Error(), breakglassUsageRelease)
	}
	if f := inv.callerScopes(); f.restricted {
		return inv.usageErr("'tacctl breakglass release' is the superuser's. Nothing was changed.")
	}
	name := p.Args[0]
	h, ok := inv.holdOf(name)
	if !ok {
		held := inv.heldNow("")
		return inv.usageErr("Break-glass is not held on '"+name+"'. Held now: "+held+" (tacctl breakglass list)", "Nothing was changed.")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	// What the hold stood for, before the record goes.
	age := holdAge(h, inv.app.Knobs.Now())
	res, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		return inv.app.Conf().UnsetHold(h.Device)
	})
	inv.loaded = false
	if err != nil {
		return err
	}
	held := age
	if t := h.SinceTime(); !t.IsZero() {
		held = inv.app.Knobs.Now().Sub(t).Round(time.Minute).String()
	}
	inv.app.Logger(inv.ctx, "auth.info", "breakglass release device="+h.Device+" addr="+h.Address+" held="+held+" by="+inv.sudoUser())

	inv.echo("")
	// echo, not echoE: the reason is free text and a backslash in it is a
	// backslash.
	inv.echo(ui.Green + "Break-glass RELEASED" + ui.NC + " on " + h.Device + " (" + h.Address + "): held " + age + " by " + h.By + " (" + h.Reason + ").")
	inv.echo("  Rendered: " + inv.renderedSentence(m, h.Address, res.Changed, false))
	if e := inv.registeredVendor(h.Device); e == "cisco" || e == "juniper" || e == "wti" {
		inv.echo("  Check:    tacctl device config pull " + h.Device + " --diff (aaa: ok), then a new ssh login as yourself.")
	} else {
		inv.echo("  Check:    a new login as yourself at the device.")
	}
	inv.echo("  " + inv.heldNow("Still held: "))
	inv.echo("")
	return nil
}

// registeredVendor is the vendor of a registered device ("" when it is not
// registered).
func (inv *invocation) registeredVendor(device string) string {
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return ""
	}
	if d := f.Find(device); d != nil {
		return d.Vendor
	}
	return ""
}

// --- list ---------------------------------------------------------------------

// holdJSON is a record as 'breakglass list --json' and the displays give it.
type holdJSON struct {
	Device     string `json:"device"`
	Address    string `json:"address"`
	Since      string `json:"since"`
	HeldSecs   int64  `json:"held_seconds"`
	By         string `json:"by"`
	Reason     string `json:"reason"`
	Scope      string `json:"scope"`
	Vendor     string `json:"vendor"`
	Registered bool   `json:"registered"`
	Covered    bool   `json:"covered"`
}

func (inv *invocation) holdJSONOf(h conf.Hold, m *model.Model, res *devreg.Resolver) holdJSON {
	j := holdJSON{Device: h.Device, Address: h.Address, Since: h.Since, By: h.By, Reason: h.Reason}
	if t := h.SinceTime(); !t.IsZero() {
		j.HeldSecs = int64(inv.app.Knobs.Now().Sub(t) / time.Second)
	}
	if res != nil {
		if e, ok := res.Lookup(h.Device, devreg.ScopeFilter{}); ok && e.Source == devreg.SourceDevice {
			j.Registered, j.Vendor = true, e.Vendor
		}
	}
	if m != nil {
		if info, ok := m.LookupAddr(h.Address); ok {
			j.Covered, j.Scope = true, info.Scope
		}
	}
	return j
}

func (inv *invocation) breakglassList(args []string) error {
	p, err := Parse(breakglassSpecs["list"], args)
	if err != nil {
		return inv.usageErr(err.Error(), breakglassUsageList)
	}
	holds := inv.holdSeenBy()
	m, err := inv.model()
	if err != nil {
		return err
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	rows := make([]holdJSON, len(holds))
	for i, h := range holds {
		rows[i] = inv.holdJSONOf(h, m, res)
	}
	if p.Has("--json") {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		inv.write(string(b) + "\n")
		return nil
	}
	inv.echo("")
	title := "Break-glass holds"
	if len(rows) == 0 {
		inv.echoE(ui.Bold + title + ui.NC)
		inv.echo(ui.Rule(title))
		inv.echo("  None held: the server answers every device its scopes cover.")
		inv.echo("")
		return nil
	}
	now := inv.app.Knobs.Now()
	t := ui.NewTable(fmt.Sprintf("%s (%d)", title, len(rows)), ui.Left("DEVICE"), ui.Left("ADDRESS"), ui.Left("SCOPE"), ui.Left("SINCE"), ui.Left("HELD"), ui.Left("BY"), ui.Left("REASON"))
	for i, h := range holds {
		scope := rows[i].Scope
		switch {
		case !rows[i].Registered:
			scope = "not registered"
		case !rows[i].Covered:
			scope = "no scope covers it now"
		}
		t.Add(ui.Styled(ui.Red, h.Device), h.Address, scope, holdTime(h), holdAge(h, now), h.By, h.Reason)
	}
	inv.write(t.String())
	inv.echo("")
	for i, h := range holds {
		switch {
		case !rows[i].Registered:
			inv.echoE("  " + ui.Red + h.Device + ui.NC + " is not a registered device any more; 'tacctl breakglass release " + h.Device + "' removes the record.")
		case !rows[i].Covered:
			inv.echo("  " + h.Device + ": no scope covers " + h.Address + " now, so it is unanswered whether held or not; 'release' changes nothing in the rendering.")
		}
	}
	inv.echo("  A held device is not answered by this server: its logins fall to its local accounts until it is released.")
	if !inv.callerScopes().restricted {
		inv.echo("  Release: tacctl breakglass release <device>")
	}
	inv.echo("")
	return nil
}

// statusHolds is the Break-glass line of the Security Posture section of
// 'status': none held (green), or one red line per hold that stands.
func (inv *invocation) statusHolds() {
	hs := inv.holdSeenBy()
	if len(hs) == 0 {
		if n := len(inv.holds()); n > 0 {
			inv.echoE("    " + ui.Green + "Break-glass:        none held in your scopes" + ui.NC)
			return
		}
		inv.echoE("    " + ui.Green + "Break-glass:        none held" + ui.NC)
		return
	}
	now := inv.app.Knobs.Now()
	for _, h := range hs {
		inv.echoE("    " + ui.Red + "Break-glass:        HELD on " + h.Device + " (" + h.Address + ") since " + holdTime(h) + " by " + h.By +
			" (" + holdAge(h, now) + "): the server does not answer it (tacctl breakglass list)" + ui.NC)
	}
}

// holdCarry moves a device's record to its new name ('device rename'): the
// hold stays on the same address, and the rendered files name the device in
// a comment, so they are rendered again; no backend is restarted (only a
// comment changed). A failure is a warning: the record keeps its old name
// ('breakglass release' works from the record alone).
func (inv *invocation) holdCarry(oldName, newName string) {
	h, ok := inv.holdOf(oldName)
	if !ok {
		return
	}
	a := inv.app
	moved := h
	moved.Device = newName
	_, err := a.Backends().StoreApply(inv.ctx, backend.ApplyOptions{DeferRestart: a.Backends().IDs()}, func() error {
		if err := a.Conf().SetHold(moved); err != nil {
			return err
		}
		return a.Conf().UnsetHold(h.Device)
	})
	inv.loaded = false
	if err != nil {
		a.Out.Warn("The break-glass hold of '" + oldName + "' was not moved to '" + newName + "'; it is still recorded under the old name (tacctl breakglass list).")
	}
}

// heldNames is '_completion-names held': the devices with a hold, for the
// superuser's 'release' (a restricted caller is told nothing).
func (inv *invocation) heldNames([]string) []string {
	if inv.callerScopes().restricted {
		return nil
	}
	var out []string
	for _, h := range inv.holds() {
		out = append(out, h.Device)
	}
	slices.Sort(out)
	return out
}
