package cli

// 'tacctl breakglass hold <device>[=<reason>][,...] [--reason "<text>"] |
// release <device>[,...] | list [--json]' (docs/plans/0.2.5-plan.md
// D121-D126): make the server stop answering managed devices, so their local
// accounts are usable while the server is up, and answer them again. A list
// is held best effort: each device is checked on its own, those that pass are
// held together in one write, one render and one restart. The record is breakglass_hold.<device>
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
	breakglassUsageHold    = `Usage: tacctl breakglass hold <device>[=<reason>][,<device>[=<reason>]...] [--reason "<text>"]`
	breakglassUsageRelease = "Usage: tacctl breakglass release <device>[,<device>...]"
	breakglassUsageList    = "Usage: tacctl breakglass list [--json]"
)

// breakglassSpecs are the arguments of each verb (completion and parsing).
var breakglassSpecs = map[string]Spec{
	"hold": {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices + KindList},
		Flags: []Flag{{Names: []string{"--reason"}, Value: true}}},
	"release": {MinArgs: 1, MaxArgs: 1, Args: []string{KindHeld + KindList}},
	"list":    {Flags: []Flag{flagJSON}},
}

// breakglassVerbs are the family's rows: usage and one-line description.
var breakglassVerbs = [][2]string{
	{`hold <device>[=<reason>][,...] [--reason "<text>"]`, "Make the server stop answering the devices named, so their local accounts are usable (the superuser's)"},
	{"release <device>[,<device>...]", "Make the server answer the devices again (the superuser's)"},
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
                                        (the reason of every device that has no <device>=<reason>)
      --json                            (list) Print the holds as a JSON array

A device that authenticates against this server is answered by a scope whose
prefixes cover its address. 'hold' takes that one address, the one the device
is registered at, out of every scope's prefixes (the stored scopes do not
change), so the server stops answering the device and its local accounts, the
ones 'tacctl scope breakglass <scope> list' records, are usable while the
server is up; a device that sends its AAA from another address (a source
interface, a NAT) is still answered, and the report says so. It
asks for the device's name typed back, restarts the backends that serve it
and shows the way in for the device's vendor. A hold is for an exceptional
case, and is shown until 'release' (there is no timer). Several devices are
held in one command, each with its own reason or the --reason default:
every device is checked on its own, those that pass are held together (one
render, one restart of each backend) and the others are named under 'Not
held' with why, and the exit code is 1 when any was not held. 'status',
'device show|list|check', 'scope show|list|routing|lookup' and 'config
validate' say so while it stands. Only the superuser holds and releases; an
engineer lists the holds of the devices of their own scopes.

Examples:
  tacctl breakglass hold sw-lab-1 --reason "console recovery after a failed paste"
  tacctl breakglass hold sw-lab-1=console,sw-lab-2=paste --reason "failed paste"
  tacctl breakglass list
  tacctl breakglass release sw-lab-1,sw-lab-2

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
			"Console: log in as the local account (the CONSOLE list is local), then 'enable' with the local enable secret.",
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

// holdRequest is one device of a hold as typed: its name, and the reason it
// is held for (its own after '=', else the --reason default).
type holdRequest struct {
	Name, Reason string
	// Own is whether the reason came with the name.
	Own bool
}

// splitDeviceArgs reads the argument of 'breakglass hold' (with reasons) and
// 'breakglass release' (names only): a comma list. One argument only: an
// unquoted --reason would otherwise hold its words as devices. A name is
// given once, whatever its case.
// problem is "" when the list is usable. A per-device reason ends at the next
// comma, so one that holds a comma is given with --reason.
func splitDeviceArgs(args []string, withReason bool) (out []holdRequest, problem string) {
	for _, a := range args {
		for _, piece := range strings.Split(a, ",") {
			r := holdRequest{Name: strings.TrimSpace(piece)}
			if withReason {
				if n, why, ok := strings.Cut(piece, "="); ok {
					r.Name, r.Reason, r.Own = strings.TrimSpace(n), strings.TrimSpace(why), true
				}
			}
			if r.Name == "" {
				return nil, "A device name is missing in '" + a + "'"
			}
			if slices.ContainsFunc(out, func(x holdRequest) bool { return strings.EqualFold(x.Name, r.Name) }) {
				return nil, "'" + r.Name + "' is named twice"
			}
			out = append(out, r)
		}
	}
	return out, ""
}

// holdCandidate is a requested device that passed every check.
type holdCandidate struct {
	req    holdRequest
	e      devreg.Entry
	scope  string
	vendor string
	local  string
}

// holdNotHeld is a requested device that did not pass: why is the clause of
// its 'Not held:' line, and show and msg are what a single device's refusal
// prints (the lines before, and the final error).
type holdNotHeld struct {
	name, why string
	// dup is the name of the device an earlier element of the line
	// already named, when this one is the same device (by name and by
	// address): a mistake of the line, which refuses it whole.
	dup  string
	show func()
	msg  string
}

// quoteNames is 'a', 'b', 'c'.
func quoteNames(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = "'" + n + "'"
	}
	return strings.Join(q, ", ")
}

// holdCheck runs the five checks of a hold, in order, on one requested
// device. A refusal is returned, not printed; err is a failure of the
// checks themselves. taken are the candidates of the same command: two
// devices of one address cannot both be held. m is read once, when a device
// reaches the fifth check.
func (inv *invocation) holdCheck(r holdRequest, f *devreg.File, res *devreg.Resolver, taken []holdCandidate, m **model.Model) (c holdCandidate, rf *holdNotHeld, err error) {
	name := r.Name
	refuse := func(why, msg string, show func()) (holdCandidate, *holdNotHeld, error) {
		return holdCandidate{}, &holdNotHeld{name: name, why: why, show: show, msg: msg}, nil
	}
	// 1. A registered device (an enrolled Linux host is not one).
	e, ok := res.Lookup(name, devreg.ScopeFilter{})
	if !ok {
		return refuse("not found (tacctl device list)", "Device '"+name+"' not found. List them with: tacctl device list", nil)
	}
	if e.Source == devreg.SourceHost {
		return refuse("an enrolled host, not a registered device: a break-glass hold is for network devices ('tacctl host' manages hosts, which keep a local administrator)",
			"'"+e.Name+"' is an enrolled host, not a registered device: a break-glass hold is for network devices ('tacctl host' manages hosts, which keep a local administrator).", nil)
	}
	// 2. With an address.
	if e.Address == "" {
		return refuse("it has no address: the hold is on the address the server sees (register one: tacctl device address "+e.Name+" <address>)",
			"Device '"+e.Name+"' has no address: the hold is on the address the server sees. Register one: tacctl device address "+e.Name+" <address>", nil)
	}
	// 3. Not already held.
	if cur, held := inv.holdNamed(e.Name); held {
		if !sameAddress(cur.Address, e.Address) {
			// A record of that name at another address (the device was
			// registered again): writing over it would drop its carve-out.
			a := "A break-glass record named '" + cur.Device + "' stands at " + cur.Address + " " + inv.holdSummary(cur) + ", not at the address the device is registered at (" + e.Address + ")."
			return refuse("a break-glass record of that name stands at "+cur.Address+" "+inv.holdSummary(cur)+", not at the address the device is registered at ("+e.Address+"); release it first (tacctl breakglass release "+cur.Device+"), then hold again",
				"Release it first (tacctl breakglass release "+cur.Device+"), then hold again. Nothing was changed.",
				func() { inv.app.Out.Error(a) })
		}
		a := "Break-glass is already held on '" + cur.Device + "' (" + cur.Address + ") " + inv.holdSummary(cur) + "."
		return refuse("already held ("+cur.Address+") "+inv.holdSummary(cur)+": "+cur.Reason+"; release it first (tacctl breakglass release "+cur.Device+"), then hold again",
			"Release it first (tacctl breakglass release "+cur.Device+"), then hold again with the new reason. Nothing was changed.",
			func() {
				inv.app.Out.Error(a)
				inv.echo("  Reason: " + cur.Reason)
			})
	}
	// 4. Not an address this server answers from or its own hosts use.
	if why := inv.serverOwnAddress(e.Address, f, res.Hosts); why != "" {
		return refuse(why, why+". Nothing was changed.", nil)
	}
	if other, held := inv.holdAt(e.Address); held {
		return refuse("address "+e.Address+" is already held, on '"+other.Device+"'",
			"Address "+e.Address+" is already held, on '"+other.Device+"'. Nothing was changed.", nil)
	}
	for _, t := range taken {
		if strings.EqualFold(t.e.Name, e.Name) {
			// the same device named twice (by name and by address): a
			// mistake of the line, not a device that was refused
			return holdCandidate{}, &holdNotHeld{name: r.Name, dup: t.e.Name}, nil
		}
		if sameAddress(t.e.Address, e.Address) {
			return refuse("address "+e.Address+" is also the address of '"+t.e.Name+"', which is in this list",
				"Address "+e.Address+" is also the address of '"+t.e.Name+"'. Nothing was changed.", nil)
		}
	}
	// 5. Some scope answers it now.
	if *m == nil {
		if *m, err = inv.model(); err != nil {
			return holdCandidate{}, nil, err
		}
	}
	info, covered := (*m).LookupAddr(e.Address)
	if !covered {
		return refuse("it is already unanswered: no scope covers "+e.Address+" (tacctl scope lookup "+e.Address+"), so its local accounts work now and there is nothing to record",
			"'"+e.Name+"' is already unanswered: no scope covers "+e.Address+" (tacctl scope lookup "+e.Address+"), so its local accounts work now and there is nothing to record. Nothing was changed.", nil)
	}
	c = holdCandidate{req: r, e: e, scope: info.Scope, vendor: e.Vendor}
	c.local = "no local account is recorded for scope '" + info.Scope + "' (tacctl scope breakglass " + info.Scope + " add <name>)"
	if us := policy.BreakGlassUsers(inv.app.Conf(), info.Scope); len(us) > 0 {
		parts := make([]string, len(us))
		for i, u := range us {
			parts[i] = u.Name + " [" + u.Role + "]"
		}
		c.local = strings.Join(parts, ", ")
	}
	if c.vendor == "" {
		c.vendor = "other"
	}
	return c, nil, nil
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
	reqs, problem := splitDeviceArgs(p.Args, true)
	if problem != "" {
		return inv.usageErr(problem+".", breakglassUsageHold)
	}
	// The reason of each device: its own, or the --reason default.
	def := strings.TrimSpace(p.Value("--reason"))
	usesDefault := slices.ContainsFunc(reqs, func(r holdRequest) bool { return !r.Own })
	if p.Has("--reason") && usesDefault {
		if why := conf.HoldReasonProblem(def); why != "" {
			return inv.usageErr("--reason "+why+".", breakglassUsageHold)
		}
	}
	var missing []string
	for i := range reqs {
		r := &reqs[i]
		switch {
		case r.Own:
			if why := conf.HoldReasonProblem(r.Reason); why != "" {
				return inv.usageErr("The reason of '"+r.Name+"' "+why+".", breakglassUsageHold)
			}
		case p.Has("--reason"):
			r.Reason = def
		default:
			missing = append(missing, r.Name)
		}
	}
	switch {
	case len(missing) == 1 && len(reqs) == 1:
		return inv.usageErr("--reason is required: a hold is for one device in exceptional circumstances, and why is part of the record and of the log.", breakglassUsageHold)
	case len(missing) > 0:
		return inv.usageErr("A reason is required for "+quoteNames(missing)+": give --reason \"<text>\" for every device that has none, or <device>=<reason>. Why is part of the record and of the log.", breakglassUsageHold)
	}

	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	multi := len(reqs) > 1
	var (
		m        *model.Model
		cands    []holdCandidate
		refusals []holdNotHeld
	)
	for _, r := range reqs {
		c, rf, err := inv.holdCheck(r, f, res, cands, &m)
		if err != nil {
			return err
		}
		if rf != nil && rf.dup != "" {
			return inv.usageErr("'"+rf.name+"' is the device '"+rf.dup+"', which is in the list already. Nothing was changed.", breakglassUsageHold)
		}
		if rf != nil {
			refusals = append(refusals, *rf)
			continue
		}
		cands = append(cands, c)
	}
	if len(cands) == 0 {
		if !multi {
			rf := refusals[0]
			if rf.show != nil {
				rf.show()
			}
			return inv.usageErr(rf.msg)
		}
		var lines []string
		for _, rf := range refusals {
			lines = append(lines, "Not held: "+rf.name+": "+rf.why)
		}
		return inv.usageErr(append(lines, "Nothing was changed.")...)
	}

	// The prompt: the act is exceptional, and the name typed back is the
	// strongest confirmation the project has.
	pr := inv.app.Prompter()
	if !pr.Interactive() {
		return inv.usageErr("No terminal to confirm on: a hold is a person's act, and the device name is typed back. Nothing was changed.")
	}
	names := make([]string, len(cands))
	for i, c := range cands {
		names[i] = c.e.Name
	}
	typedBack := strings.Join(names, ",")
	inv.echo("")
	if !multi {
		c := cands[0]
		e := c.e
		inv.echo("Hold break-glass on " + e.Name + " (" + e.Address + ", scope " + c.scope + ", " + c.vendor + ")?")
		inv.echo("  This is for one device in exceptional circumstances. The server stops answering " + e.Address + ": every login at")
		inv.echo("  that device falls to its local accounts (" + c.local + "); nobody without one can")
		inv.echo("  log in there until you release it.")
		inv.echo("  The backends that serve it restart now and again at release (the restart every scope change makes).")
		inv.echo("  Nothing releases it but 'tacctl breakglass release " + e.Name + "'.")
		if typed := pr.Ask("  Type the device name to go on: "); typed != e.Name {
			return inv.usageErr("The name typed back is not '" + e.Name + "'. Nothing was changed.")
		}
	} else {
		inv.echo("Hold break-glass on " + strconv.Itoa(len(cands)) + " " + plural(len(cands), "device", "devices") + " (" + typedBack + ")?")
		for _, c := range cands {
			inv.echo("  " + c.e.Name + " (" + c.e.Address + ", scope " + c.scope + ", " + c.vendor + ")")
			inv.echo("    Reason: " + c.req.Reason)
			inv.echo("    Local accounts: " + c.local)
		}
		for _, rf := range refusals {
			inv.echo("  Not held: " + rf.name + ": " + rf.why)
		}
		inv.echo("  This is for devices in exceptional circumstances. The server stops answering each address: every login at")
		inv.echo("  those devices falls to their local accounts; nobody without one can log in there until you release them.")
		inv.echo("  The backends that serve them restart now (once) and again at release (the restart every scope change makes).")
		inv.echo("  Nothing releases them but 'tacctl breakglass release " + typedBack + "'.")
		if typed := pr.Ask("  Type the device names as printed above, to go on: "); strings.ReplaceAll(typed, " ", "") != typedBack {
			return inv.usageErr("The names typed back are not '" + typedBack + "'. Nothing was changed.")
		}
	}

	now := inv.app.Knobs.Now()
	holds := make([]conf.Hold, len(cands))
	for i, c := range cands {
		holds[i] = conf.Hold{Device: c.e.Name, Address: c.e.Address, Since: now.Format(time.RFC3339), By: inv.sudoUser(), Reason: c.req.Reason}
	}
	// Another hold may have been made while the names were typed: each
	// check and the write are one step under tacctl.yaml's lock
	// (SetHoldsIf), so two superusers cannot both pass it. The holds that
	// pass are written together.
	var (
		written []conf.Hold
		skipped []conf.HoldSkip
	)
	res2, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		var err error
		written, skipped, err = inv.app.Conf().SetHoldsIf(holds, func(existing []conf.Hold, h conf.Hold) error {
			for _, x := range existing {
				if strings.EqualFold(x.Device, h.Device) || sameAddress(x.Address, h.Address) {
					return &heldNowError{x}
				}
			}
			return nil
		})
		// Nothing was written when every hold was skipped: returning
		// nothing keeps StoreApply from putting back its copy of
		// tacctl.yaml, taken before the other hold landed, over the record
		// that did.
		return err
	})
	inv.loaded = false
	if err != nil {
		return err
	}
	var notHeld []string
	for _, rf := range refusals {
		notHeld = append(notHeld, rf.name+": "+rf.why)
	}
	for _, sk := range skipped {
		var hn *heldNowError
		if errors.As(sk.Err, &hn) {
			notHeld = append(notHeld, sk.Hold.Device+": break-glass is already held on '"+hn.hold.Device+"' ("+hn.hold.Address+") "+inv.holdSummary(hn.hold)+": another hold was made while the name was typed")
		}
	}
	if len(written) == 0 {
		if !multi {
			var hn *heldNowError
			errors.As(skipped[0].Err, &hn)
			raced := hn.hold
			inv.app.Out.Error("Break-glass is already held on '" + raced.Device + "' (" + raced.Address + ") " + inv.holdSummary(raced) + ": another hold was made while the name was typed.")
			return inv.usageErr("Nothing was changed.")
		}
		var lines []string
		for _, n := range notHeld {
			lines = append(lines, "Not held: "+n)
		}
		return inv.usageErr(append(lines, "Nothing was changed.")...)
	}
	// The candidates that were written, in the order asked.
	var done []holdCandidate
	for _, c := range cands {
		if slices.ContainsFunc(written, func(h conf.Hold) bool { return h.Device == c.e.Name }) {
			done = append(done, c)
		}
	}
	addrs := make([]string, len(done))
	doneNames := make([]string, len(done))
	for i, c := range done {
		h := written[slices.IndexFunc(written, func(h conf.Hold) bool { return h.Device == c.e.Name })]
		addrs[i], doneNames[i] = c.e.Address, c.e.Name
		inv.app.Logger(inv.ctx, "auth.info", "breakglass hold device="+c.e.Name+" addr="+c.e.Address+" reason="+strconv.Quote(c.req.Reason)+" by="+h.By)
	}
	releaseCmd := "tacctl breakglass release " + strings.Join(doneNames, ",")

	inv.echo("")
	rendered := inv.renderedSentenceOf(m, addrs, res2, true)
	for i, c := range done {
		h := written[slices.IndexFunc(written, func(h conf.Hold) bool { return h.Device == c.e.Name })]
		e := c.e
		inv.echoE(ui.Red + "Break-glass HELD" + ui.NC + " on " + e.Name + " (" + e.Address + ") since " + holdTime(h) + " by " + h.By + ".")
		inv.echo("  Reason:   " + c.req.Reason)
		if !multi {
			inv.echo("  Rendered: " + rendered)
		}
		inv.echo("  Carved:   " + holdCarvedText(e))
		if w := holdSourceWarning(e, res); w != "" {
			inv.echo("  " + ui.Yellow + "Warning:" + ui.NC + "  " + w)
		}
		if multi && i < len(done)-1 {
			inv.echo("")
		}
	}
	if multi {
		inv.echo("")
		inv.echo("  Rendered: " + rendered)
	}
	inv.echo("")
	if !multi {
		for _, l := range vendorWayIn(done[0].e.Vendor) {
			inv.echo("  " + l)
		}
	} else {
		var order []string
		byVendor := map[string][]string{}
		for _, c := range done {
			if _, ok := byVendor[c.e.Vendor]; !ok {
				order = append(order, c.e.Vendor)
			}
			byVendor[c.e.Vendor] = append(byVendor[c.e.Vendor], c.e.Name)
		}
		for _, v := range order {
			label := v
			if label == "" {
				label = "other"
			}
			inv.echo("  Way in, " + label + " (" + strings.Join(byVendor[v], ", ") + "):")
			for _, l := range vendorWayIn(v) {
				inv.echo("    " + l)
			}
		}
	}
	inv.echo("  Nothing it does is accounted here: a held device sends its accounting to a server that does not answer it;")
	inv.echo("  what the technician types is in the device's own log only.")
	inv.echo("")
	inv.echo("  " + inv.heldNow("Held now: "))
	inv.echo("  When done: " + releaseCmd)
	for _, n := range notHeld {
		inv.echo("  Not held: " + n)
	}
	inv.echo("")
	if len(notHeld) > 0 {
		inv.app.Out.Error(strconv.Itoa(len(notHeld)) + " of " + strconv.Itoa(len(reqs)) + " devices " + plural(len(notHeld), "was", "were") + " not held (see Not held).")
	}
	if len(res2.RestartFailed) > 0 {
		// The record and the rendered files stay: they are what the next
		// restart, or the next boot, serves.
		inv.app.Out.Error("The hold is recorded and the rendered files are kept, but it is not in force until the backend named under Rendered is restarted; '" + releaseCmd + "' removes the record.")
		return exit(1)
	}
	if len(notHeld) > 0 {
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
	return inv.renderedSentenceOf(m, []string{addr}, res, held)
}

// renderedSentenceOf is renderedSentence for the addresses of one command:
// what each did to the prefixes of its scopes, then the restarts, said once.
func (inv *invocation) renderedSentenceOf(m *model.Model, addrs []string, res backend.Result, held bool) string {
	// One entry per prefix that holds an address of the command, with the
	// addresses it held: a /16 that held two is said once.
	type carve struct {
		what  string
		cidr  string
		addrs []string
	}
	var carves []*carve
	for _, addr := range addrs {
		for _, c := range m.CarvedFrom(addr, "", true) {
			what := c.CIDR + " of scope '" + c.Scope + "'"
			if c.Tagged {
				what = "the tagged " + c.CIDR + " of scope '" + c.Scope + "'"
			}
			i := slices.IndexFunc(carves, func(x *carve) bool { return x.what == what })
			if i < 0 {
				carves = append(carves, &carve{what: what, cidr: c.CIDR})
				i = len(carves) - 1
			}
			carves[i].addrs = append(carves[i].addrs, addr)
		}
	}
	var parts []string
	for _, c := range carves {
		n := len(cidr.Subtract([]string{c.cidr}, c.addrs))
		switch {
		case !held:
			parts = append(parts, c.what+" answers whole again")
		case n == 0:
			parts = append(parts, c.what+" is gone")
		default:
			parts = append(parts, c.what+" answers as "+strconv.Itoa(n)+" "+plural(n, "prefix", "prefixes")+" without "+strings.Join(c.addrs, ", "))
		}
	}
	var s string
	switch {
	case len(parts) == 0:
		s = "no scope covers " + strings.Join(addrs, ", ") + ", so the rendering did not change"
	default:
		s = strings.Join(parts, "; ")
	}
	if len(res.Changed) == 0 {
		return s + "; no backend file changed, nothing restarted."
	}
	still := "still answers " + strings.Join(addrs, ", ")
	if !held {
		still = "still does not answer " + strings.Join(addrs, ", ")
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
	reqs, problem := splitDeviceArgs(p.Args, false)
	if problem != "" {
		return inv.usageErr(problem+".", breakglassUsageRelease)
	}
	if len(reqs) == 1 {
		return inv.breakglassReleaseOne(reqs[0].Name)
	}
	// Each name is a hold, an entry that carved nothing (removed by name,
	// as the validator tells), or not held; the ones found go in one write.
	var (
		holds    []conf.Hold
		unusable []conf.HoldRecord
		notHeld  []string
	)
	for _, r := range reqs {
		if h, ok := inv.holdNamed(r.Name); ok {
			holds = append(holds, h)
			continue
		}
		found := false
		for _, d := range inv.app.Conf().HoldDefects() {
			if !d.Usable && strings.EqualFold(d.Device, r.Name) {
				unusable, found = append(unusable, d), true
				break
			}
		}
		if !found {
			notHeld = append(notHeld, r.Name)
		}
	}
	if len(holds) == 0 && len(unusable) == 0 {
		lines := make([]string, 0, len(notHeld)+2)
		for _, n := range notHeld {
			lines = append(lines, "Not released: "+n+": break-glass is not held on it")
		}
		return inv.usageErr(append(lines, "Held now: "+inv.heldNow("")+" (tacctl breakglass list)", "Nothing was changed.")...)
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	// What the holds stood for, before the records go.
	ages := make([]string, len(holds))
	for i, h := range holds {
		ages[i] = holdAge(h, inv.app.Knobs.Now())
	}
	remove := make([]string, 0, len(holds)+len(unusable))
	addrs := make([]string, len(holds))
	for i, h := range holds {
		remove, addrs[i] = append(remove, h.Device), h.Address
	}
	for _, d := range unusable {
		remove = append(remove, d.Device)
	}
	res, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		return inv.app.Conf().UnsetHolds(remove)
	})
	inv.loaded = false
	if err != nil {
		return err
	}
	inv.echo("")
	var known []string
	for i, h := range holds {
		held := ages[i]
		if t := h.SinceTime(); !t.IsZero() {
			held = inv.app.Knobs.Now().Sub(t).Round(time.Minute).String()
		}
		inv.app.Logger(inv.ctx, "auth.info", "breakglass release device="+h.Device+" addr="+h.Address+" held="+held+" by="+inv.sudoUser())
		inv.echo(ui.Green + "Break-glass RELEASED" + ui.NC + " on " + h.Device + " (" + h.Address + "): held " + ages[i] + " by " + h.By + " (" + h.Reason + ").")
		if v := inv.registeredVendor(h.Device, h.Address); v == "cisco" || v == "juniper" || v == "wti" {
			known = append(known, h.Device)
		}
	}
	for _, d := range unusable {
		inv.app.Logger(inv.ctx, "auth.info", "breakglass remove-record device="+d.Device+" by="+inv.sudoUser())
		inv.echo(ui.Green + "Break-glass record REMOVED" + ui.NC + " for " + d.Device + ": the entry " + d.Defect + "; the rendering did not change.")
	}
	if len(holds) > 0 {
		inv.echo("  Rendered: " + inv.renderedSentenceOf(m, addrs, res, false))
		if len(known) > 0 {
			inv.echo("  Check:    tacctl device config pull " + strings.Join(known, ",") + " --diff (aaa: ok), then a new ssh login as yourself.")
		} else {
			inv.echo("  Check:    a new login as yourself at the device.")
		}
	}
	inv.echo("  " + inv.heldNow("Still held: "))
	for _, n := range notHeld {
		inv.echo("  Not released: " + n + ": break-glass is not held on it")
	}
	inv.echo("")
	if len(notHeld) > 0 {
		inv.app.Out.Error(strconv.Itoa(len(notHeld)) + " of " + strconv.Itoa(len(reqs)) + " devices " + plural(len(notHeld), "was", "were") + " not held, so not released.")
	}
	if len(res.RestartFailed) > 0 {
		inv.app.Out.Error("The records are removed and the rendered files are kept, but the release is not in force until the backend named under Rendered is restarted.")
		return exit(1)
	}
	if len(notHeld) > 0 {
		return exit(1)
	}
	return nil
}

// breakglassReleaseOne is the release of one name.
func (inv *invocation) breakglassReleaseOne(name string) error {
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
