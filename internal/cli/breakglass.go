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
prefixes cover its address. 'hold' takes that one address, the one the device
is registered at, out of every scope's prefixes (the stored scopes do not
change), so the server stops answering the device and its local accounts, the
ones 'tacctl scope breakglass <scope> list' records, are usable while the
server is up; a device that sends its AAA from another address (a source
interface, a NAT) is still answered, and the report says so. It
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

// sameAddress compares two addresses as addresses (not as text); text that
// is not an address compares as text.
func sameAddress(a, b string) bool {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return x == y
}

// holdNamed is the record under a device's name, whatever address it is at
// (names compare without regard to case): what 'release' and the refusal
// of a second hold work from.
func (inv *invocation) holdNamed(device string) (conf.Hold, bool) {
	for _, h := range inv.holds() {
		if strings.EqualFold(h.Device, device) {
			return h, true
		}
	}
	return conf.Hold{}, false
}

// holdOf is the record that holds a registered device: the one under its
// name whose address is the address the device is registered at. A record
// under the name at another address holds nothing of this device (it is an
// orphan: the address it silences is nobody's registered address).
func (inv *invocation) holdOf(device, addr string) (conf.Hold, bool) {
	if h, ok := inv.holdNamed(device); ok && sameAddress(h.Address, addr) {
		return h, true
	}
	return conf.Hold{}, false
}

// isHeld reports whether a hold stands on the device registered at addr.
func (inv *invocation) isHeld(device, addr string) bool {
	_, ok := inv.holdOf(device, addr)
	return ok
}

// holdAt is the record of an address.
func (inv *invocation) holdAt(addr string) (conf.Hold, bool) {
	for _, h := range inv.holds() {
		if sameAddress(h.Address, addr) {
			return h, true
		}
	}
	return conf.Hold{}, false
}

// holdOrphan says why a record holds no registered device ("" when one
// does): no device of its name is registered, or the one that is stands at
// another address than the record's.
func holdOrphan(h conf.Hold, res *devreg.Resolver) string {
	if res == nil {
		return ""
	}
	e, ok := res.Lookup(h.Device, devreg.ScopeFilter{})
	switch {
	case !ok || e.Source != devreg.SourceDevice || !strings.EqualFold(e.Name, h.Device):
		return "no device of that name is registered"
	case !sameAddress(e.Address, h.Address):
		return e.Name + " is registered at " + dash(e.Address) + ", not at " + h.Address
	}
	return ""
}

// holdOrphans are the records of the caller's view that hold no registered
// device, by device name, with why (the registry that cannot be read says
// none).
func (inv *invocation) holdOrphans(hs []conf.Hold) map[string]string {
	out := map[string]string{}
	if len(hs) == 0 {
		return out
	}
	if _, res, err := inv.deviceLoad(); err == nil {
		for _, h := range hs {
			if why := holdOrphan(h, res); why != "" {
				out[h.Device] = why
			}
		}
	}
	return out
}

// holdSeenBy are the records the caller is shown: all of them for an
// administrator, and for the lower tiers the holds of the devices of their
// own scopes (a record whose device is not registered at the record's
// address, or at an address no scope answers, is no scope's). It reads the
// registry; a registry that cannot be read shows a restricted caller
// nothing.
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
		if e, ok := res.Lookup(h.Device, inv.deviceFilter()); ok && e.Source == devreg.SourceDevice && sameAddress(e.Address, h.Address) {
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
	if cur, held := inv.holdNamed(e.Name); held {
		if !sameAddress(cur.Address, e.Address) {
			// A record of that name at another address (the device was
			// registered again): writing over it would drop its carve-out.
			inv.app.Out.Error("A break-glass record named '" + cur.Device + "' stands at " + cur.Address + " " + inv.holdSummary(cur) + ", not at the address the device is registered at (" + e.Address + ").")
			return inv.usageErr("Release it first (tacctl breakglass release " + cur.Device + "), then hold again. Nothing was changed.")
		}
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
	// Another hold may have been made while the name was typed: the check
	// and the write are one step under tacctl.yaml's lock (SetHoldIf), so
	// two superusers cannot both pass it.
	var raced *conf.Hold
	res2, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		err := inv.app.Conf().SetHoldIf(h, func(existing []conf.Hold) error {
			for _, x := range existing {
				if strings.EqualFold(x.Device, h.Device) || sameAddress(x.Address, h.Address) {
					return &heldNowError{x}
				}
			}
			return nil
		})
		var hn *heldNowError
		if errors.As(err, &hn) {
			// Nothing was written. Returning it would have StoreApply put
			// back its copy of tacctl.yaml, taken before the other hold
			// landed, over the record that did.
			raced = &hn.hold
			return nil
		}
		return err
	})
	inv.loaded = false
	if err != nil {
		return err
	}
	if raced != nil {
		inv.app.Out.Error("Break-glass is already held on '" + raced.Device + "' (" + raced.Address + ") " + inv.holdSummary(*raced) + ": another hold was made while the name was typed.")
		return inv.usageErr("Nothing was changed.")
	}
	inv.app.Logger(inv.ctx, "auth.info", "breakglass hold device="+e.Name+" addr="+e.Address+" reason="+strconv.Quote(reason)+" by="+h.By)

	inv.echo("")
	inv.echoE(ui.Red + "Break-glass HELD" + ui.NC + " on " + e.Name + " (" + e.Address + ") since " + holdTime(h) + " by " + h.By + ".")
	inv.echo("  Reason:   " + reason)
	inv.echo("  Rendered: " + inv.renderedSentence(m, e.Address, res2, true))
	inv.echo("  Carved:   " + holdCarvedText(e))
	if w := holdSourceWarning(e, res); w != "" {
		inv.echo("  " + ui.Yellow + "Warning:" + ui.NC + "  " + w)
	}
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
	if len(res2.RestartFailed) > 0 {
		// The record and the rendered files stay: they are what the next
		// restart, or the next boot, serves.
		inv.app.Out.Error("The hold is recorded and the rendered files are kept, but it is not in force until the backend named under Rendered is restarted; 'tacctl breakglass release " + e.Name + "' removes the record.")
		return exit(1)
	}
	return nil
}

// heldNowError is a hold that was found under the lock: the device or its
// address is held by another record.
type heldNowError struct{ hold conf.Hold }

func (e *heldNowError) Error() string {
	return "break-glass is already held on " + e.hold.Device + " (" + e.hold.Address + ")"
}

// holdCarvedText says plainly what a hold carves: the address the device is
// registered at, and not the address a device may send its AAA from.
func holdCarvedText(e devreg.Entry) string {
	return "only " + e.Address + ", the address registered for " + e.Name + ". A device that sends its AAA from another address (a source interface, a NAT) is still answered."
}

// holdSourceWarning is the warning the hold report adds when the server's
// own log data show no request from the registered address: the device may
// send from another one, which the hold does not carve ("" when the
// address has been seen, and when there is no log data to judge by).
func holdSourceWarning(e devreg.Entry, res *devreg.Resolver) string {
	if res == nil || !res.Seen.HasData() {
		return ""
	}
	if _, ok := res.Seen.Of(e.Address); ok {
		return ""
	}
	learn := "learn the address it sends from with 'tacctl device config pull " + e.Name + "' (its source interface) or on the device with 'show tacacs' and its own log."
	for _, x := range res.Seen.All() {
		if !sameAddress(x.Address, e.Address) && x.LastNASID != "" && devreg.NameMatches(e, x.LastNASID) {
			return "the server's logs hold no request from " + e.Address + ", but " + x.Address + " identifies as '" + x.LastNASID +
				"': that is most likely where " + e.Name + " sends from, and it is still answered; " + learn
		}
	}
	return "the server has seen " + e.Name + " from no address at all (no request from " + e.Address + ", none that identifies as '" + e.Name +
		"'). If it sends from another address it is still answered; " + learn
}

// renderedSentence says what a hold or release did to the rendering: the
// prefixes (and tagged addresses) of the scopes that hold addr, and which
// backends restarted (res is what the apply did). A backend whose restart
// did not succeed is said so, with what the running server answers until it
// is restarted and the command that does it. held is the state after the
// change.
func (inv *invocation) renderedSentence(m *model.Model, addr string, res backend.Result, held bool) string {
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
	if len(res.Changed) == 0 {
		return s + "; no backend file changed, nothing restarted."
	}
	still := "still answers " + addr
	if !held {
		still = "still does not answer " + addr
	}
	rs := make([]string, len(res.Changed))
	for i, id := range res.Changed {
		rs[i] = id + " restarted"
		for _, f := range res.RestartFailed {
			if f.ID == id {
				rs[i] = id + " NOT restarted: the running server " + still + " until it is restarted (run: " + f.Command + ")"
			}
		}
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
	h, ok := inv.holdNamed(name)
	if !ok {
		// An entry of that name that carved nothing (no address, or one that
		// is not an address): removed by name, as the validator tells.
		for _, d := range inv.app.Conf().HoldDefects() {
			if !d.Usable && strings.EqualFold(d.Device, name) {
				return inv.releaseUnusable(d)
			}
		}
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
	inv.echo("  Rendered: " + inv.renderedSentence(m, h.Address, res, false))
	if e := inv.registeredVendor(h.Device, h.Address); e == "cisco" || e == "juniper" || e == "wti" {
		inv.echo("  Check:    tacctl device config pull " + h.Device + " --diff (aaa: ok), then a new ssh login as yourself.")
	} else {
		inv.echo("  Check:    a new login as yourself at the device.")
	}
	inv.echo("  " + inv.heldNow("Still held: "))
	inv.echo("")
	if len(res.RestartFailed) > 0 {
		inv.app.Out.Error("The record is removed and the rendered files are kept, but the release is not in force until the backend named under Rendered is restarted.")
		return exit(1)
	}
	return nil
}

// releaseUnusable removes an entry that carved nothing (it has no address,
// or one that is not an address, or is not a record): the rendering does
// not change, so nothing restarts, and it is no hold that was released.
func (inv *invocation) releaseUnusable(d conf.HoldRecord) error {
	if _, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		return inv.app.Conf().UnsetHold(d.Device)
	}); err != nil {
		return err
	}
	inv.loaded = false
	inv.app.Logger(inv.ctx, "auth.info", "breakglass remove-record device="+d.Device+" by="+inv.sudoUser())
	inv.echo("")
	inv.echo(ui.Green + "Break-glass record REMOVED" + ui.NC + " for " + d.Device + ": the entry " + d.Defect + "; the rendering did not change.")
	inv.echo("  " + inv.heldNow("Still held: "))
	inv.echo("")
	return nil
}

// registeredVendor is the vendor of a registered device ("" when it is not
// registered at addr).
func (inv *invocation) registeredVendor(device, addr string) string {
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return ""
	}
	if d := f.Find(device); d != nil && sameAddress(d.Address, addr) {
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
	// Orphan is a record that holds no registered device: none of its name
	// is registered, or the one that is stands at another address. The
	// address it carves is still not answered.
	Orphan  bool `json:"orphan"`
	Covered bool `json:"covered"`
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
		j.Orphan = holdOrphan(h, res) != ""
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
		if !rows[i].Covered {
			scope = "no scope covers it now"
		}
		name := h.Device
		if rows[i].Orphan {
			name += " (orphan)"
		}
		t.Add(ui.Styled(ui.Red, name), h.Address, scope, holdTime(h), holdAge(h, now), h.By, h.Reason)
	}
	inv.write(t.String())
	inv.echo("")
	for i, h := range holds {
		switch {
		case rows[i].Orphan:
			inv.echo("  " + ui.Red + h.Device + ui.NC + " is an orphan record: " + holdOrphan(h, res) + ", so it holds no registered device, and it still silences " + h.Address +
				"; 'tacctl breakglass release " + h.Device + "' removes it.")
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
// 'status': none held (green), or one red line per hold that stands (a
// record that holds no registered device says so).
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
	orphans := inv.holdOrphans(hs)
	for _, h := range hs {
		if why, ok := orphans[h.Device]; ok {
			inv.echoE("    " + ui.Red + "Break-glass:        ORPHAN record " + h.Device + " (" + h.Address + ") since " + holdTime(h) + " by " + h.By +
				" (" + holdAge(h, now) + "): " + why + "; the server does not answer " + h.Address + " (tacctl breakglass release " + h.Device + ")" + ui.NC)
			continue
		}
		inv.echoE("    " + ui.Red + "Break-glass:        HELD on " + h.Device + " (" + h.Address + ") since " + holdTime(h) + " by " + h.By +
			" (" + holdAge(h, now) + "): the server does not answer it (tacctl breakglass list)" + ui.NC)
	}
}

// holdCarry moves a device's record to its new name ('device rename'): the
// hold stays on the same address, and the rendered files name the device in
// a comment, so they are rendered again; no backend is restarted (only a
// comment changed). A failure is a warning: the record keeps its old name
// ('breakglass release' works from the record alone). Only a record that
// holds the device (its address is the one the device is registered at, addr)
// moves with it; an orphan stays under the name it has.
func (inv *invocation) holdCarry(oldName, newName, addr string) {
	h, ok := inv.holdOf(oldName, addr)
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
