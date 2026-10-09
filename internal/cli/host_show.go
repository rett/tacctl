package cli

// 'host show <name> [--all] [--json] [--check]' (0.2.2 plan 5.9): one
// enrolled host in full, from what tacctl records: how it is reached, its
// scope and the one that answers its address, its address history, the
// pinned keys, the sightings and notices the device registry has of it,
// the accounts the next sync makes there, and the record of its last
// enroll or sync and the facts that run read (hosts.Records, written here
// by recordRun). --check logs in read-only and compares the host with what
// tacctl would make it (hosts.Env.Check). Same tier as 'host list', except
// --check, which is the superuser's (it opens ssh as the invoker).

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// hostShowUsage is the usage line of 'host show'.
const hostShowUsage = "Usage: tacctl host show <name> [--all] [--json] [--check]"

// hostRecords are the per-host records.
func (inv *invocation) hostRecords() hosts.Records {
	return hosts.Records{Dir: inv.app.Paths.HostRecords}
}

// recordRun writes the record of a run of 'host enroll' or 'host sync'
// (command) on name: reason is why it failed ("" when it did not); he is
// the run's environment when the client script ran (its protocol, the
// accounts it changed and, after a success, the facts read), nil when it
// did not get that far. A record that cannot be written is a warning: it
// is only ever shown.
func (inv *invocation) recordRun(name, command, reason string, he *hosts.Env) {
	a := inv.app
	at := a.Knobs.Now().Format(time.RFC3339)
	err := inv.hostRecords().Update(name, func(r *hosts.Record) {
		s := &hosts.SyncRecord{At: at, By: inv.sudoUser(), Command: command, OK: reason == "", Reason: reason,
			Created: []string{}, Updated: []string{}, Removed: []string{}}
		if he != nil {
			s.Protocol = hosts.ScriptProtocol
			if c := he.Changes; c != nil {
				s.Created = append(s.Created, c.Created...)
				s.Updated = append(s.Updated, c.Updated...)
				s.Removed = append(s.Removed, c.Removed...)
			}
			if reason == "" && he.Facts != nil {
				r.Facts = hosts.RecordOfFacts(*he.Facts, at)
			}
		}
		r.LastSync = s
	})
	if err != nil {
		a.Out.WarnE(name + ": the record 'tacctl host show' prints could not be written: " + strings.Join(msgs(err), " "))
	}
}

// --- the view ----------------------------------------------------------------------

type hostShowJSON struct {
	Name       string             `json:"name"`
	Connection hostConnJSON       `json:"connection"`
	Scope      hostScopeJSON      `json:"scope"`
	Address    hostAddressJSON    `json:"address"`
	HostKeys   hostKeysJSON       `json:"host_keys"`
	Sightings  *deviceSeenJSON    `json:"sightings"`
	Notices    []deviceNoticeJSON `json:"notices"`
	Accounts   hostAccountsJSON   `json:"accounts"`
	LastSync   *hosts.SyncRecord  `json:"last_sync"`
	Facts      *hosts.FactsRecord `json:"facts"`
	Check      *hostCheckJSON     `json:"check,omitempty"`
}

type hostConnJSON struct {
	Local           bool   `json:"local"`
	Target          string `json:"target"`
	Port            int    `json:"port"`
	Identity        string `json:"identity"`
	IdentityMissing bool   `json:"identity_missing"`
	Server          string `json:"server"`
	Method          string `json:"method"`
}

type hostScopeJSON struct {
	Registered string `json:"registered"`
	Exists     bool   `json:"exists"`
	// Answering is the scope that answers Address (the address the host's
	// logins come from), via Prefix; "" when none does or it is unknown.
	Address   string            `json:"address"`
	Answering string            `json:"answering"`
	Prefix    string            `json:"prefix"`
	Drift     string            `json:"drift"`
	Staging   []hostStagingJSON `json:"staging"`
}

type hostStagingJSON struct {
	CIDR  string `json:"cidr"`
	Scope string `json:"scope"`
	Since string `json:"since"`
}

type hostAddressJSON struct {
	Recorded string `json:"recorded"`
	Previous string `json:"previous"`
	Changed  string `json:"changed"`
}

type hostKeysJSON struct {
	Pinned []hostKeyJSON `json:"pinned"`
	// Verify is how to see the fingerprints on the host itself.
	Verify string `json:"verify"`
}

type hostKeyJSON struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

type hostAccountsJSON struct {
	Users []hostAccountJSON `json:"users"`
	// Disabled counts the users of the scope with no login now (their
	// accounts are expired, not deleted).
	Disabled int `json:"disabled"`
	// Skipped are the users of the scope that get no account.
	Skipped []hostSkippedJSON `json:"skipped"`
}

type hostAccountJSON struct {
	Name string `json:"name"`
	Tier string `json:"tier"`
	// UID is "" for a user no UID has been given yet (the next sync does).
	UID    string   `json:"uid"`
	Groups []string `json:"groups"`
}

type hostSkippedJSON struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type hostCheckJSON struct {
	Differences []hostDiffJSON `json:"differences"`
	Notes       []string       `json:"notes"`
}

type hostDiffJSON struct {
	Text string `json:"text"`
	Fix  string `json:"fix"`
}

// hostShow is 'host show'.
func (inv *invocation) hostShow(args []string) error {
	p, err := Parse(hostSpecs["show"], args)
	if err != nil {
		msg := err.Error()
		if uf, ok := err.(*UnknownFlagError); ok {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.usageErr(msg, hostShowUsage)
	}
	name := p.Args[0]
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	e, ok := reg.Find(name)
	if !ok || e.Line == "" || !inv.callerScopes().allows(e.Scope) {
		return inv.usageErr("No enrolled host named '" + name + "'. See 'tacctl host list'.")
	}
	// --check opens an ssh session as the invoker; an engineer reads what
	// tacctl recorded of the host and does not log in to it.
	if p.Has("--check") && inv.callerScopes().restricted {
		return inv.usageErr("'host show --check' logs in to the host over ssh, which is the superuser's; 'tacctl host show " + name + "' shows what tacctl recorded of it.")
	}
	v, err := inv.hostView(e)
	if err != nil {
		return err
	}
	if p.Has("--check") {
		c, err := inv.hostCheck(e, v, p.Has("--json"))
		if err != nil {
			return err
		}
		v.Check = c
	}
	if p.Has("--json") {
		if err := inv.printJSON(v); err != nil {
			return err
		}
	} else {
		inv.hostShowText(v, p.Has("--all"))
	}
	if v.Check != nil && len(v.Check.Differences) > 0 {
		return exit(1)
	}
	return nil
}

// hostView gathers what is recorded of the enrolled host e (its sightings
// and notices from its entry in the device registry's view).
func (inv *invocation) hostView(e hosts.Entry) (*hostShowJSON, error) {
	a := inv.app
	_, res, err := inv.deviceLoad()
	if err != nil {
		return nil, err
	}
	var entry devreg.Entry
	for _, x := range res.All() {
		if x.Source == devreg.SourceHost && x.Name == e.Name {
			entry = x
		}
	}
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	local := e.Target == hosts.Local
	v := &hostShowJSON{Name: e.Name, Notices: []deviceNoticeJSON{}}

	// Connection.
	c := hostConnJSON{Local: local, Target: e.Target, Identity: e.Identity, Server: e.Server, Method: e.EffectiveMethod()}
	if !local {
		c.Port = 22
		if n, err := strconv.Atoi(e.Port); err == nil && n > 0 {
			c.Port = n
		}
	}
	if e.Identity != "" {
		if _, err := os.Stat(e.Identity); err != nil {
			c.IdentityMissing = true
		}
	}
	v.Connection = c

	// Scope.
	s := hostScopeJSON{Registered: e.Scope, Exists: m.Exists("scopes", e.Scope), Staging: []hostStagingJSON{}}
	s.Address = inv.hostAddress(e)
	if s.Address != "" {
		if info, found := m.LookupAddr(s.Address); found {
			s.Answering, s.Prefix = info.Scope, info.Prefix
		}
	}
	if local {
		s.Drift = inv.localScopeDrift(e)
	} else {
		s.Drift = inv.hostScopeDrift(e, s.Address)
	}
	for _, st := range inv.stagingLoad() {
		if st.Kind == "host" && st.Name == e.Name {
			s.Staging = append(s.Staging, hostStagingJSON{CIDR: st.CIDR, Scope: st.Scope, Since: st.Since})
		}
	}
	v.Scope = s

	// Address and keys.
	v.Address = hostAddressJSON{Recorded: entry.Address, Previous: entry.PrevAddress, Changed: entry.AddressChanged}
	v.HostKeys = hostKeysJSON{Pinned: []hostKeyJSON{}, Verify: devreg.VerifyHint(devreg.VendorLinux)}
	for _, k := range devreg.ParseHostKeys(entry.HostKeys) {
		v.HostKeys.Pinned = append(v.HostKeys.Pinned, hostKeyJSON{Type: k.Label(), Fingerprint: k.Fingerprint()})
	}

	// Sightings and notices: what the device registry's view has.
	v.Sightings = deviceSeenJSONOf(inv, res, entry)
	for _, n := range res.NoticesFor(entry) {
		v.Notices = append(v.Notices, deviceNoticeJSON{Kind: n.Kind, Text: n.Text, Acked: n.Acked})
	}

	// Accounts.
	rng, _ := inv.configuredUIDRange()
	if v.Accounts, err = inv.hostAccounts(e, rng); err != nil {
		return nil, err
	}

	// The record of the last run.
	rec, err := inv.hostRecords().Load(e.Name)
	if err != nil {
		// On stderr: stdout may be --json's.
		ui.Output{Stdout: a.Out.Stderr, Stderr: a.Out.Stderr}.WarnE(e.Name + ": its record could not be read (" + strings.Join(msgs(err), " ") + "); the next enroll or sync writes it again.")
	}
	v.LastSync, v.Facts = rec.LastSync, rec.Facts
	return v, nil
}

// hostAccounts are the accounts the next sync makes on e, worked out
// without writing anything: no UID is given out here (a user without one
// gets it at the next sync).
func (inv *invocation) hostAccounts(e hosts.Entry, rng hosts.Range) (hostAccountsJSON, error) {
	out := hostAccountsJSON{Users: []hostAccountJSON{}, Skipped: []hostSkippedJSON{}}
	m, err := inv.model()
	if err != nil {
		return out, err
	}
	local := e.Target == hosts.Local
	var pol *console.Policy
	if local {
		if pol, err = inv.consolePolicy(); err != nil {
			return out, err
		}
	}
	uids := hosts.UIDs{Path: inv.app.Paths.LinuxUIDs, Range: rng}
	for _, r := range m.LinuxUsers(e.Scope) {
		name, lvl, _ := strings.Cut(r, "|")
		if name == "" || name == "root" {
			continue
		}
		if !hosts.LinuxName(name) {
			out.Skipped = append(out.Skipped, hostSkippedJSON{name, "not a valid Linux account name"})
			continue
		}
		t := string(inv.userTier(name, lvl))
		if t == string(tier.None) {
			out.Skipped = append(out.Skipped, hostSkippedJSON{name, "its group has no priv-lvl"})
			continue
		}
		uid, err := uids.Lookup(name)
		if err != nil {
			return out, err
		}
		if uid != "" && !rng.Contains(uid) {
			out.Skipped = append(out.Skipped, hostSkippedJSON{name, "its UID " + uid + " is outside " + rng.String()})
			continue
		}
		groups := []string{"tac-users"}
		switch {
		case local:
			groups = append(groups, "tac-"+t)
			if pol.Decide(name, tier.Tier(t)).Console {
				groups = append(groups, console.Group)
			}
		case t == string(tier.Superuser), t == string(tier.Engineer):
			// A host has the two sudo groups only: superusers and engineers.
			groups = append(groups, "tac-"+t)
		}
		out.Users = append(out.Users, hostAccountJSON{Name: name, Tier: t, UID: uid, Groups: groups})
	}
	out.Disabled = len(m.LinuxInactive(e.Scope))
	return out, nil
}

// --- the text --------------------------------------------------------------------

// recordTime is a record's time as the other sections print times.
func recordTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return seenTime(t)
}

func (inv *invocation) hostShowText(v *hostShowJSON, all bool) {
	title := "Host " + v.Name
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	section := func(s string) { inv.echo(s) }
	row := func(k, val string) {
		if k != "" {
			k += ":"
		}
		inv.echo("  " + padTo(k, 13) + " " + val)
	}
	end := func() { inv.echo("") }

	// Connection.
	c := v.Connection
	section("Connection")
	if c.Local {
		row("Target", "this server (enrolled --local)")
		row("Port", "-")
	} else {
		row("Target", c.Target)
		row("Port", strconv.Itoa(c.Port))
	}
	ident := dash(c.Identity)
	if c.IdentityMissing {
		ident += "  (missing)"
	}
	row("Identity", ident)
	row("Server", dash(c.Server))
	row("Method", c.Method+" ("+hosts.ModuleOf(c.Method)+")")
	end()

	// Scope.
	s := v.Scope
	section("Scope")
	reg := s.Registered
	if !s.Exists {
		reg += "  (no such scope)"
	}
	row("Registered", reg)
	switch {
	case s.Address == "":
		row("Answering", "unknown: no address is recorded or resolves for the host")
	case s.Answering == "":
		row("Answering", "no scope covers "+s.Address)
	default:
		row("Answering", s.Answering+" (prefix "+s.Prefix+") for "+s.Address)
	}
	if s.Drift != "" {
		inv.app.Out.WarnE(s.Drift)
	}
	if len(s.Staging) == 0 {
		row("Staging", "none")
	}
	for i, st := range s.Staging {
		row(map[bool]string{true: "Staging", false: ""}[i == 0], st.CIDR+" in scope '"+st.Scope+"' since "+st.Since+" (tacctl scope staging)")
	}
	end()

	// Address.
	section("Address")
	if v.Address.Recorded == "" {
		row("Recorded", "none (the next enroll or sync records it)")
	} else {
		row("Recorded", v.Address.Recorded)
	}
	if v.Address.Previous != "" {
		row("Previous", v.Address.Previous+" (changed "+v.Address.Changed+")")
	}
	end()

	// Host keys.
	section("Host keys")
	if c.Local {
		row("Pinned", "none (this server is not reached over ssh)")
	} else if len(v.HostKeys.Pinned) == 0 {
		row("Pinned", "none (the next 'tacctl host sync "+v.Name+"' pins them)")
	}
	for i, k := range v.HostKeys.Pinned {
		row(map[bool]string{true: "Pinned", false: ""}[i == 0], padTo(k.Type, 8)+" "+k.Fingerprint)
	}
	if !c.Local {
		row("On the host", v.HostKeys.Verify)
	}
	end()

	// Sightings.
	section("Sightings")
	if x := v.Sightings; x == nil {
		row("Last seen", "never (as far as 'tacctl device scan' has read the logs)")
	} else {
		first, _ := time.Parse(time.RFC3339, x.First)
		last, _ := time.Parse(time.RFC3339, x.Last)
		l := seenTime(last)
		if x.Stale {
			l += "  (stale)"
		}
		row("Last seen", l)
		row("Seen by", dash(x.LastUser)+" via "+dash(x.Via))
		row("First seen", seenTime(first)+"  ("+howMany(x.Count, "sighting")+")")
		if x.NASID != "" {
			row("Identifies", "as '"+x.NASID+"' (NAS-Identifier)")
		}
	}
	end()

	// Notices, as 'device show' lists them.
	section("Notices")
	ns := v.Notices
	acked := 0
	for _, n := range ns {
		if n.Acked {
			acked++
		}
	}
	var shown []deviceNoticeJSON
	for _, n := range ns {
		if all || !n.Acked {
			shown = append(shown, n)
		}
	}
	hidden := ""
	if acked > 0 && !all {
		hidden = howMany(acked, "acknowledged notice") + " not shown: tacctl host show " + v.Name + " --all"
	}
	switch {
	case len(shown) == 0 && hidden != "":
		row("Open", "none; "+hidden)
		hidden = ""
	case len(shown) == 0:
		row("Open", "none")
	}
	for i, n := range shown {
		mark := ""
		if n.Acked {
			mark = " (acknowledged)"
		}
		row(map[bool]string{true: "Open", false: ""}[i == 0], n.Kind+mark+": "+n.Text)
	}
	if hidden != "" {
		row("", hidden)
	}
	end()

	// Accounts.
	section("Accounts (what the next sync makes there)")
	if len(v.Accounts.Users) == 0 {
		row("Users", "none")
	}
	width := 0
	for _, u := range v.Accounts.Users {
		width = max(width, len(u.Name))
	}
	pending := false
	for _, u := range v.Accounts.Users {
		uid := "UID " + u.UID
		if u.UID == "" {
			uid, pending = "UID -", true
		}
		inv.echo("  " + padTo(u.Name, width) + "  " + padTo(u.Tier, 9) + "  " + padTo(uid, 9) + "  " + strings.Join(u.Groups, ", "))
	}
	if pending {
		row("UID -", "given at the next sync")
	}
	if v.Accounts.Disabled > 0 {
		row("Disabled", howMany(v.Accounts.Disabled, "user")+" (accounts expired, files kept; not listed)")
	}
	for _, sk := range v.Accounts.Skipped {
		row("No account", sk.Name+": "+sk.Reason)
	}
	end()

	// Last sync.
	section("Last sync")
	if ls := v.LastSync; ls == nil {
		row("Recorded", "not recorded (before 0.2.2)")
	} else {
		row("When", recordTime(ls.At)+" by "+ls.By+" (host "+ls.Command+")")
		if ls.OK {
			row("Result", "ok")
		} else {
			row("Result", "failed: "+ls.Reason)
		}
		row("Protocol", dash(ls.Protocol))
		names := func(n []string) string {
			if len(n) == 0 {
				return "none"
			}
			return strings.Join(n, ", ")
		}
		row("Created", names(ls.Created))
		row("Updated", names(ls.Updated))
		row("Removed", names(ls.Removed))
	}
	end()

	// Host facts.
	section("Host facts")
	if fr := v.Facts; fr == nil {
		row("Recorded", "not recorded (before 0.2.2)")
	} else {
		f := fr.Facts()
		row("Read", recordTime(fr.At))
		row("OS", orNotReported(f.OS()))
		row("sshd", orNotReported(f.SSHD))
		want := hosts.ModuleOf(c.Method)
		if mod := f.Module(want); mod == nil {
			row("PAM module", want+": not found in the PAM module directories")
		} else {
			ver := mod.Version
			if ver == "" {
				ver = "version not reported"
			}
			row("PAM module", want+" "+ver+" ("+mod.Path+")")
		}
		if f.LoginDefs {
			row("useradd UIDs", strconv.Itoa(f.UIDMin)+"-"+strconv.Itoa(f.UIDMax)+" (/etc/login.defs UID_MIN/UID_MAX)")
		} else {
			row("useradd UIDs", "not read (no readable /etc/login.defs)")
		}
	}
	end()

	if v.Check != nil {
		inv.hostCheckText(v)
	}
}

func orNotReported(s string) string {
	if s == "" {
		return "not reported"
	}
	return s
}
