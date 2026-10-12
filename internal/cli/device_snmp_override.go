package cli

// 'device snmp' (D72 of docs/plans/0.2.4-plan.md): the SNMP settings of one
// registered device, over its scope's and the default's. The non-secret
// ones (version, port, timeout, the allowed clients) are an optional 'snmp:'
// map of the device in devices.yaml (internal/devreg, written only when
// set); the community and the v3 user with its passphrases are
// StateDir/snmp/devices/<name>.yaml (0600, internal/snmpcred; never printed
// but by 'show --reveal'). The resolution is the device's value, then its
// scope's, then the default's, then the built-in (snmpcred.ResolveDevice,
// snmp_scope.go); 'device show', 'device check', 'device config show', the
// walkthrough, the sysName lookups and the SNMP section of 'device config
// pull|diff' all go through it and say where each value comes from.
//
// Setting and clearing are the superuser's (an engineer changes no
// credential, D48); an engineer reads the devices of their own scopes, with
// or without --reveal, and every reveal is logged (D45). The tier gate sees
// 'device snmp' only, so the engineer's part is decided here, as 'scope
// snmp' does.

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/snmpcred"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// deviceSNMPUse is the row of 'device snmp' in the usage of 'device'.
const deviceSNMPUse = "snmp <name> [show [--reveal]|version v2c|v3|port <n>|timeout <s>|clients list|add|remove <cidr>|community|v3-user <user>|clear]"

// deviceSNMPSpecs are the arguments of each verb after the device's name.
var deviceSNMPSpecs = map[string]Spec{
	"show":      {MaxArgs: 0, Flags: []Flag{{Names: []string{"--reveal"}}}},
	"version":   {MaxArgs: 1, Args: []string{"v2c|v3"}},
	"community": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--stdin"}}}},
	"v3-user":   {MinArgs: 1, MaxArgs: 1, Args: []string{""}, Flags: []Flag{{Names: []string{"--stdin"}}}},
	"clients":   {MaxArgs: 2, Args: []string{"list|add|remove", ""}},
	"port":      {MaxArgs: 1, Args: []string{""}},
	"timeout":   {MaxArgs: 1, Args: []string{""}},
	"clear":     {MaxArgs: 0},
}

// deviceSNMPCompletion is the Spec of the whole verb for completion (the
// words after 'tacctl device snmp').
var deviceSNMPCompletion = Spec{MinArgs: 1, MaxArgs: -1, Args: []string{KindDevices,
	"show|version|port|timeout|clients|community|v3-user|clear", After("clients", "list|add|remove"), ""},
	Flags: []Flag{{Names: []string{"--reveal"}, Only: "show"}, {Names: []string{"--stdin"}}}}

// deviceSNMPOptions are the option lines under the verb's row.
var deviceSNMPOptions = [][2]string{
	{"--reveal", "(snmp show) Print the community or the v3 passphrases (an engineer: their own scopes' devices; logged)"},
	{"--stdin", "(snmp community, v3-user) Read the secrets from stdin, one per line"},
}

// --- a device's own settings -----------------------------------------------------

// deviceSNMPOwn is the SNMP settings a registered device has of its own: the
// map of devices.yaml and its credentials file. The zero value is none.
type deviceSNMPOwn struct {
	// Name is the device's registry name (the credentials file is its
	// lowercase).
	Name  string
	SNMP  devreg.SNMP
	Creds snmpcred.Creds
	// Orphan: the credentials file is there and the device has no snmp map.
	// The map gates the file (the verbs that write credentials set the
	// version, so a map always exists in use): a file without one is what a
	// rollback to 0.2.3 left, or a stray, and is ignored, not read.
	Orphan bool
}

// layer is the device's level of the resolution.
func (o deviceSNMPOwn) layer() snmpcred.Layer {
	return snmpcred.Layer{Version: o.SNMP.Version, Port: o.SNMP.Port, Timeout: o.SNMP.Timeout, Creds: o.Creds}
}

// isSet reports whether the device has anything of its own.
func (o deviceSNMPOwn) isSet() bool { return !o.SNMP.Empty() || !o.Creds.Empty() }

// chosen reports whether the device has chosen its version or credentials,
// the settings its own verbs finish.
func (o deviceSNMPOwn) chosen() bool {
	return o.Name != "" && (o.SNMP.Version != "" || !o.Creds.Empty())
}

// deviceSNMPOwnOf is the settings d has of its own: the map of the registry
// and, when it has one, the credentials file, read here (an unreadable one
// is the error). A file with no map beside it is ignored (Orphan).
func (inv *invocation) deviceSNMPOwnOf(d devreg.Device) (deviceSNMPOwn, error) {
	o := deviceSNMPOwn{Name: d.Name, SNMP: d.SNMP.Clone()}
	// A name too long for a file of its own has no credentials to read
	// (the verbs that would write them refuse).
	if _, err := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, d.Name); err != nil {
		return o, nil
	}
	if d.SNMP.Empty() {
		file, _ := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, d.Name)
		o.Orphan = fileThere(file)
		return o, nil
	}
	c, err := snmpcred.LoadDevice(inv.app.Paths.SNMPDir, d.Name)
	if err != nil {
		return deviceSNMPOwn{}, err
	}
	o.Creds = c
	return o, nil
}

// orphanNote is the line that says a credentials file is ignored.
func orphanNote(name string) string {
	return "credentials file present but the device has no settings of its own (ignored): tacctl device snmp " +
		shellquote.Q(name) + " clear removes it, or set its settings"
}

// unreadableOwn is the error of a credentials file that cannot be read, with
// the way out: the file is removed without being read.
func (inv *invocation) unreadableOwn(name string, err error) error {
	return &names.Error{Msgs: append(msgs(err),
		"Remove the unreadable file with: tacctl device snmp "+shellquote.Q(name)+" clear (a superuser's verb), then set the credentials again.")}
}

// deviceNamed is the registered device called name, nil for none or a
// registry that cannot be read.
func (inv *invocation) deviceNamed(name string) *devreg.Device {
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return nil
	}
	return f.Find(name)
}

// deviceAt is the registered device at addr, nil for none or a registry
// that cannot be read.
func (inv *invocation) deviceAt(addr string) *devreg.Device {
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return nil
	}
	return f.FindAddress(addr)
}

// snmpDeviceCarry follows a device's rename (newName set) or removal
// (newName empty): its credentials file. What cannot be carried is a
// warning, as the configuration record's is.
func (inv *invocation) snmpDeviceCarry(oldName, newName string) {
	dir := inv.app.Paths.SNMPDir
	var err error
	if newName == "" {
		err = snmpcred.RemoveDevice(dir, oldName)
	} else {
		err = snmpcred.RenameDevice(dir, oldName, newName)
	}
	if err != nil {
		inv.app.Out.Warn("The SNMP credentials of '" + oldName + "' were not carried over: " + strings.Join(msgs(err), " "))
	}
}

// snmpNewNamesFree is nil when no device that the registry change adds
// (after has it, before does not) finds a credentials file of an earlier
// device of its name on disk (the refusal a new scope's name gets).
func (inv *invocation) snmpNewNamesFree(before, after *devreg.File) error {
	for _, d := range after.Devices {
		if before.Find(d.Name) != nil {
			continue
		}
		if err := snmpcred.CheckNoDeviceFile(inv.app.Paths.SNMPDir, d.Name); err != nil {
			// A name too long for a file of its own has none to find.
			if _, perr := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, d.Name); perr != nil {
				continue
			}
			return err
		}
	}
	return nil
}

// --- what a device is read with, and where each value comes from -----------------

// deviceSNMPInfo is what a registered device is read with.
type deviceSNMPInfo struct {
	Scope string
	Own   deviceSNMPOwn
	Eff   snmpcred.Effective
	// Clients are the allowed ranges after the tacctl server's /32 and
	// ClientsFrom whose they are (device, scope, or "" for none listed).
	Clients     []string
	ClientsFrom string
	// HideUser: the caller is below the engineer tier and is not told the
	// SNMPv3 user's name (only that one is set).
	HideUser bool
}

// deviceSNMPInfoOf resolves e's settings.
func (inv *invocation) deviceSNMPInfoOf(e devreg.Entry) (deviceSNMPInfo, error) {
	own, err := inv.deviceSNMPOwnOf(e.Device)
	if err != nil {
		return deviceSNMPInfo{}, inv.unreadableOwn(e.Name, err)
	}
	eff, err := inv.snmpEffectiveOwn(e.Scope, own)
	if err != nil {
		return deviceSNMPInfo{}, err
	}
	info := deviceSNMPInfo{Scope: e.Scope, Own: own, Eff: eff, HideUser: !inv.snmpUserVisible()}
	var sc []string
	if e.Scope != "" {
		sc = policy.SNMPClients(inv.app.Conf(), e.Scope)
	}
	switch {
	case len(own.SNMP.Clients) > 0:
		info.Clients, info.ClientsFrom = slices.Clone(own.SNMP.Clients), snmpcred.FromDevice
	case len(sc) > 0:
		info.Clients, info.ClientsFrom = sc, snmpcred.FromScope
	}
	return info, nil
}

// snmpUserVisible reports whether the caller may be told an SNMPv3 user's
// name: the engineer tier and above (root and the superuser included). A
// user name is half of a credential, so the read-only and operator tiers
// are told only that one is set. The answer is kept for the invocation.
func (inv *invocation) snmpUserVisible() bool {
	if inv.snmpUserSeen == nil {
		g := inv.tierGate()
		t := g.Caller(inv.ctx)
		ok := t == tier.Unrestricted || t == tier.Superuser || (tier.Rank(t) >= 0 && tier.Rank(t) >= tier.Rank(tier.Engineer))
		inv.snmpUserSeen = &ok
	}
	return *inv.snmpUserSeen
}

// src is the label of where a value comes from: 'scope lab' names the
// scope.
func (i deviceSNMPInfo) src(from string) string {
	if from == snmpcred.FromScope && i.Scope != "" {
		return "scope " + i.Scope
	}
	return from
}

// settings is the one line of version, port and timeout with their
// sources.
func (i deviceSNMPInfo) settings() string {
	e := i.Eff
	version := "not set"
	if e.Version != "" {
		version = e.Version + " (" + i.src(e.VersionFrom) + ")"
	}
	return "version " + version + ", port " + strconv.Itoa(e.Port) + " (" + i.src(e.PortFrom) + "), timeout " +
		strconv.Itoa(e.Timeout) + " s (" + i.src(e.TimeoutFrom) + ")"
}

// credentials is the credentials line: never a value, and which kind the
// version needs.
func (i deviceSNMPInfo) credentials() string {
	e := i.Eff
	comm := "community not set"
	if e.Community != "" {
		comm = "community set (" + i.src(e.CommunityFrom) + ")"
	}
	v3 := "v3 user not set"
	if e.V3From != snmpcred.NotSet {
		user := e.User
		switch {
		case user == "":
			user = "not set"
		case i.HideUser:
			user = "set"
		}
		v3 = "v3 user " + user + ", passphrases " + map[bool]string{true: "set", false: "incomplete"}[e.HasV3()] + " (" + i.src(e.V3From) + ")"
	}
	switch e.Version {
	case snmp.V2c:
		return comm
	case snmp.V3:
		return v3
	}
	return comm + "; " + v3
}

// clients is the clients line.
func (i deviceSNMPInfo) clients() string {
	switch i.ClientsFrom {
	case "":
		return "the tacctl server only (no ranges listed)"
	case snmpcred.FromDevice:
		return strconv.Itoa(len(i.Clients)) + " range(s) of the device's own (" + i.src(i.ClientsFrom) + "), after the tacctl server"
	}
	return strconv.Itoa(len(i.Clients)) + " range(s) (" + i.src(i.ClientsFrom) + "), after the tacctl server"
}

// deviceSNMPJSON is a device's resolved SNMP settings as 'device show' and
// 'device check' print them as JSON: never a secret, only whether it is set
// and where it comes from.
type deviceSNMPJSON struct {
	Version        string   `json:"version"`
	VersionFrom    string   `json:"version_from"`
	Port           int      `json:"port"`
	PortFrom       string   `json:"port_from"`
	Timeout        int      `json:"timeout"`
	TimeoutFrom    string   `json:"timeout_from"`
	Community      bool     `json:"community"`
	CommunityFrom  string   `json:"community_from"`
	V3User         string   `json:"v3_user,omitempty"`
	V3UserSet      bool     `json:"v3_user_set"`
	V3Complete     bool     `json:"v3_complete"`
	V3From         string   `json:"v3_from"`
	Clients        []string `json:"clients"`
	ClientsFrom    string   `json:"clients_from"`
	OwnSettings    bool     `json:"own_settings"`
	OwnCredentials bool     `json:"own_credentials"`
	IgnoredFile    bool     `json:"ignored_credentials_file"`
}

func (i deviceSNMPInfo) json() *deviceSNMPJSON {
	e := i.Eff
	j := &deviceSNMPJSON{
		Version: e.Version, VersionFrom: e.VersionFrom, Port: e.Port, PortFrom: e.PortFrom, Timeout: e.Timeout, TimeoutFrom: e.TimeoutFrom,
		Community: e.Community != "", CommunityFrom: e.CommunityFrom, V3UserSet: e.User != "", V3Complete: e.HasV3(), V3From: e.V3From,
		Clients: append([]string{}, i.Clients...), ClientsFrom: i.ClientsFrom, OwnSettings: !i.Own.SNMP.Empty(), OwnCredentials: !i.Own.Creds.Empty(), IgnoredFile: i.Own.Orphan,
	}
	if !i.HideUser {
		j.V3User = e.User
	}
	if j.ClientsFrom == "" {
		j.ClientsFrom = snmpcred.NotSet
	}
	return j
}

// deviceSNMPRows are the 'SNMP' rows of 'device show' and of the data block
// of 'device config show': what the device is read with, where each value
// comes from, and never a secret. A device nothing is set for says so in one
// row.
func (inv *invocation) deviceSNMPRows(e devreg.Entry, row func(k, v string)) {
	info, err := inv.deviceSNMPInfoOf(e)
	if err != nil {
		row("SNMP", "cannot be read: "+strings.Join(msgs(err), " "))
		return
	}
	if info.Eff.Version == "" {
		fix := "tacctl device snmp " + shellquote.Q(e.Name) + " community|v3-user <user>"
		if e.Configured {
			fix += ", or for its scope: tacctl scope snmp " + e.Scope + " community|v3-user <user>"
		}
		row("SNMP", "not configured ("+fix+")")
		if !info.Own.SNMP.Empty() {
			row("", "its own settings: "+info.settings())
		}
		if info.Own.Orphan {
			row("", orphanNote(e.Name))
		}
		return
	}
	row("SNMP", info.settings())
	row("", "credentials: "+info.credentials())
	row("", "clients: "+info.clients())
	if info.Own.Orphan {
		row("", orphanNote(e.Name))
	}
}

// scopeDevicesWithSNMP are the registered devices the scope answers that
// have SNMP settings of their own, each with what it sets (never a value):
// 'sw1 (version, community)'. A registry that cannot be read says none.
func (inv *invocation) scopeDevicesWithSNMP(scope string) []string {
	_, res, err := inv.deviceLoad()
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range res.All() {
		if e.Source != devreg.SourceDevice || e.Scope != scope {
			continue
		}
		own, err := inv.deviceSNMPOwnOf(e.Device)
		if err != nil {
			out = append(out, e.Name+" (credentials file unreadable: tacctl device snmp "+shellquote.Q(e.Name)+" clear)")
			continue
		}
		if !own.isSet() {
			continue
		}
		var what []string
		if own.SNMP.Version != "" {
			what = append(what, "version")
		}
		if own.SNMP.Port != 0 {
			what = append(what, "port")
		}
		if own.SNMP.Timeout != 0 {
			what = append(what, "timeout")
		}
		if len(own.SNMP.Clients) > 0 {
			what = append(what, "clients")
		}
		if own.Creds.Community != "" {
			what = append(what, "community")
		}
		if own.Creds.User != "" || own.Creds.AuthPass != "" || own.Creds.PrivPass != "" {
			what = append(what, "v3-user")
		}
		out = append(out, e.Name+" ("+strings.Join(what, ", ")+")")
	}
	return out
}

// --- 'device snmp' ---------------------------------------------------------------

// deviceSNMPUsageErr is a wrong argument of a verb: the message and its
// usage line.
func (inv *invocation) deviceSNMPUsageErr(name, sub string, err error) error {
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return inv.usageErr(msg, "Usage: tacctl device snmp "+name+" "+sub+" ...")
}

// deviceSNMP dispatches 'device snmp <name> [<verb>] [args]': no verb is
// 'show'.
func (inv *invocation) deviceSNMP(args []string) error {
	const usage = "Usage: tacctl device " + deviceSNMPUse
	if len(args) == 0 {
		return inv.usageErr(usage)
	}
	key, sub := args[0], "show"
	rest := args[1:]
	if len(args) > 1 {
		sub, rest = args[1], args[2:]
	}
	spec, ok := deviceSNMPSpecs[sub]
	if !ok {
		return inv.usageErr("Unknown subcommand: '"+sub+"'", usage)
	}
	p, err := Parse(spec, rest)
	if err != nil {
		return inv.deviceSNMPUsageErr(key, sub, err)
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, key)
	if err != nil {
		return err
	}
	if e.Source != devreg.SourceDevice {
		return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; SNMP settings are for registered devices (tacctl device list).")
	}
	// An engineer reads and changes nothing (D45, D48; the gate sees
	// 'device snmp' only): the devices of their own scopes are all they see.
	if inv.callerScopes().restricted && !scopeSNMPRead(sub, p) {
		return inv.usageErr("The engineer tier reads a device's SNMP settings: tacctl device snmp " + shellquote.Q(e.Name) +
			" show [--reveal]. Changing them is the superuser's. Nothing was changed.")
	}
	switch sub {
	case "show":
		return inv.deviceSNMPShow(e, p.Has("--reveal"))
	case "version":
		return inv.deviceSNMPVersion(e, p)
	case "port":
		return inv.deviceSNMPNumber(e, p, "port", "UDP port", "1-65535", 1, 65535)
	case "timeout":
		return inv.deviceSNMPNumber(e, p, "timeout", "timeout", "1-10", snmp.MinTimeout, snmp.MaxTimeout)
	case "clients":
		return inv.deviceSNMPClients(e, p)
	case "community":
		return inv.deviceSNMPCommunity(e, p)
	case "v3-user":
		return inv.deviceSNMPV3User(e, p)
	default:
		return inv.deviceSNMPClear(e)
	}
}

// fromLabel is a value's source as the verbs print it.
func (i deviceSNMPInfo) fromLabel(from string) string { return "(" + i.src(from) + ")" }

// deviceSNMPShow is 'show': the effective settings with their sources and,
// with --reveal, the credentials. An engineer's reveal is logged (never the
// value).
func (inv *invocation) deviceSNMPShow(e devreg.Entry, reveal bool) error {
	info, err := inv.deviceSNMPInfoOf(e)
	if err != nil {
		return err
	}
	eff := info.Eff
	if reveal && inv.callerScopes().restricted {
		inv.logRevealed(e, info)
	}
	title := "SNMP for device '" + e.Name + "'"
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	if e.Configured {
		inv.echo("  scope:      " + e.Scope + "  (via prefix " + e.Prefix + ")")
	} else {
		inv.echo("  scope:      none: no scope's prefixes cover " + e.Address + " (the default applies)")
	}
	switch eff.Version {
	case "":
		inv.echo("  version:    not set (the walkthroughs say SNMP is not configured)  " + info.fromLabel(snmpcred.NotSet))
	case snmp.V2c:
		inv.echo("  version:    v2c (the community)  " + info.fromLabel(eff.VersionFrom))
	case snmp.V3:
		inv.echo("  version:    v3 (the user, authPriv)  " + info.fromLabel(eff.VersionFrom))
	default:
		inv.echo("  version:    " + eff.Version + "  " + info.fromLabel(eff.VersionFrom))
	}
	inv.echo("  port:       " + strconv.Itoa(eff.Port) + "  " + info.fromLabel(eff.PortFrom))
	inv.echo("  timeout:    " + strconv.Itoa(eff.Timeout) + " s, one retry  " + info.fromLabel(eff.TimeoutFrom))
	secret := func(set bool, value string) string {
		switch {
		case !set:
			return "not set"
		case reveal:
			return value
		}
		return "set"
	}
	inv.echo("  community:  " + secret(eff.Community != "", eff.Community) + "  " + info.fromLabel(eff.CommunityFrom))
	if eff.Version == snmp.V3 || eff.V3From != snmpcred.NotSet {
		user := "not set"
		if eff.User != "" {
			user = eff.User
		}
		inv.echo("  v3 user:    " + user + "  " + info.fromLabel(eff.V3From))
		inv.echo("  v3 passphrases: auth " + secret(eff.AuthPass != "", eff.AuthPass) + ", priv " + secret(eff.PrivPass != "", eff.PrivPass) + "  " + info.fromLabel(eff.V3From))
		inv.echo("  v3 auth:    " + eff.Auth + "  " + info.fromLabel(eff.AuthFrom) + "; priv: " + eff.Priv + "  " + info.fromLabel(eff.PrivFrom))
	}
	inv.echo("  clients:    the tacctl server first (its /32; always), then " + map[bool]string{
		true: "the ranges below  " + info.fromLabel(info.ClientsFrom), false: "none listed"}[len(info.Clients) > 0] +
		", then 0.0.0.0/0 refused (always, never stored)")
	for _, c := range info.Clients {
		inv.echo("              " + c)
	}
	inv.echo("  order:      the device's own setting, then its scope's, then the default's, then the built-in")
	switch {
	case reveal && inv.callerScopes().restricted:
		inv.echo("  Reveal logged: the secrets above are the device's own, its scope's or the default's, as labelled.")
	case !reveal && !info.Own.Creds.Empty():
		p, _ := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, e.Name)
		inv.echo("  Credentials: " + p + " (0600; 'show --reveal' prints them)")
	}
	if info.Own.Orphan {
		inv.echo("  Note:       " + orphanNote(e.Name))
	}
	inv.echo("")
	return nil
}

// logRevealed logs an engineer's reveal, one line for each level a secret
// that is printed comes from: the device's own, its scope's, the default's
// (never a value). A secret the device inherits is the scope's or the
// default's read, and is logged as that.
func (inv *invocation) logRevealed(e devreg.Entry, info deviceSNMPInfo) {
	eff := info.Eff
	var from []string
	if eff.Community != "" {
		from = append(from, eff.CommunityFrom)
	}
	if (eff.Version == snmp.V3 || eff.V3From != snmpcred.NotSet) && (eff.AuthPass != "" || eff.PrivPass != "") {
		from = append(from, eff.V3From)
	}
	logged := map[string]bool{}
	for _, f := range from {
		if logged[f] {
			continue
		}
		logged[f] = true
		switch f {
		case snmpcred.FromDevice:
			inv.secretRead("snmp-device", e.Name)
		case snmpcred.FromScope:
			inv.secretRead("snmp", e.Scope)
		case snmpcred.FromDefault:
			inv.secretRead("snmp-default", "default")
		}
	}
}

// deviceSNMPUpdate changes the device's map under the registry's lock, after
// a snapshot.
func (inv *invocation) deviceSNMPUpdate(name string, fn func(*devreg.SNMP) error) error {
	return inv.deviceSNMPUpdateWith(name, fn, true)
}

// deviceSNMPUpdateWith is deviceSNMPUpdate; warn says whether a credentials
// file that was ignored and is in force now is mentioned (the verbs that
// have just written the file have nothing to warn about).
func (inv *invocation) deviceSNMPUpdateWith(name string, fn func(*devreg.SNMP) error, warn bool) error {
	// A credentials file that was ignored (no map) is in force once the
	// device has settings: say so.
	wasIgnored := false
	if d := inv.deviceNamed(name); warn && d != nil && d.SNMP.Empty() {
		if file, err := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, name); err == nil {
			wasIgnored = fileThere(file)
		}
	}
	defer func() {
		if d := inv.deviceNamed(name); wasIgnored && d != nil && !d.SNMP.Empty() {
			inv.app.Out.Warn("The credentials file of '" + name + "', ignored until now, is in force: tacctl device snmp " +
				shellquote.Q(name) + " show --reveal prints it, clear removes it.")
		}
	}()
	_, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		live := f.Find(name)
		if live == nil {
			return inv.usageErr("Device '" + name + "' not found.")
		}
		s := live.SNMP.Clone()
		if err := fn(&s); err != nil {
			return err
		}
		live.SNMP = s
		return nil
	})
	return err
}

// deviceSNMPHint says what is missing for the device's lookups after a
// change, so a half-configured device is not a surprise.
func (inv *invocation) deviceSNMPHint(e devreg.Entry) {
	own, err := inv.deviceSNMPOwnOf(inv.deviceNamedOr(e))
	if err != nil {
		return
	}
	if _, problem := inv.snmpConfigOwn(e.Scope, own); problem != "" {
		inv.app.Out.Warn("Not usable yet: " + problem + ".")
	}
}

// deviceNamedOr is the registry's device e names, e's own record when the
// registry cannot be read.
func (inv *invocation) deviceNamedOr(e devreg.Entry) devreg.Device {
	if d := inv.deviceNamed(e.Name); d != nil {
		return *d
	}
	return e.Device
}

// deviceSNMPVersion shows or sets the device's version.
func (inv *invocation) deviceSNMPVersion(e devreg.Entry, p Parsed) error {
	if len(p.Args) == 0 {
		info, err := inv.deviceSNMPInfoOf(e)
		if err != nil {
			return err
		}
		if info.Eff.Version == "" {
			inv.echo("not set")
			return nil
		}
		inv.echo(info.Eff.Version + "  " + info.fromLabel(info.Eff.VersionFrom))
		return nil
	}
	v := p.Args[0]
	if v != snmp.V2c && v != snmp.V3 {
		return inv.usageErr("Unknown version '"+v+"': v2c or v3.", "Usage: tacctl device snmp "+shellquote.Q(e.Name)+" version [v2c|v3]")
	}
	if err := inv.deviceSNMPUpdate(e.Name, func(s *devreg.SNMP) error { s.Version = v; return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("SNMP version of device '" + e.Name + "' set to " + v + ".")
	inv.deviceSNMPHint(e)
	return nil
}

// deviceSNMPNumber shows or sets the device's port or timeout.
func (inv *invocation) deviceSNMPNumber(e devreg.Entry, p Parsed, key, what, rng string, lo, hi int) error {
	if len(p.Args) == 0 {
		info, err := inv.deviceSNMPInfoOf(e)
		if err != nil {
			return err
		}
		n, from := info.Eff.Port, info.Eff.PortFrom
		if key == "timeout" {
			n, from = info.Eff.Timeout, info.Eff.TimeoutFrom
		}
		inv.echo(strconv.Itoa(n) + "  " + info.fromLabel(from))
		return nil
	}
	v := p.Args[0]
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi || strconv.Itoa(n) != v {
		return inv.usageErr("Invalid " + what + " '" + v + "': expected " + rng + ".")
	}
	if err := inv.deviceSNMPUpdate(e.Name, func(s *devreg.SNMP) error {
		if key == "port" {
			s.Port = n
		} else {
			s.Timeout = n
		}
		return nil
	}); err != nil {
		return err
	}
	inv.app.Out.Info("SNMP " + what + " of device '" + e.Name + "' set to " + v + ".")
	return nil
}

// deviceSNMPClients lists, adds and removes the device's own allowed ranges
// (a device's list, when it has one, replaces its scope's).
func (inv *invocation) deviceSNMPClients(e devreg.Entry, p Parsed) error {
	a := inv.app
	action := "list"
	if len(p.Args) > 0 {
		action = p.Args[0]
	}
	info, err := inv.deviceSNMPInfoOf(e)
	if err != nil {
		return err
	}
	cur := info.Own.SNMP.Clients
	usage := "Usage: tacctl device snmp " + shellquote.Q(e.Name) + " clients list|add|remove [<cidr>[,<cidr>...]]"
	switch action {
	case "list":
		inv.echo("")
		title := "Allowed SNMP clients of device '" + e.Name + "'"
		inv.echoE(ui.Bold + title + ui.NC)
		inv.echo(ui.Rule(title))
		inv.echo("  1. the tacctl server's own /32 (always first; the address its route to the devices uses, or --source of the walkthrough)")
		for i, r := range info.Clients {
			inv.echo(fmt.Sprintf("  %d. %s  %s", i+2, r, info.fromLabel(info.ClientsFrom)))
		}
		switch {
		case len(info.Clients) == 0:
			inv.echo("  (no ranges are listed: only the tacctl server may query; add one with: tacctl device snmp " + shellquote.Q(e.Name) + " clients add <cidr>)")
		case info.ClientsFrom == snmpcred.FromScope:
			inv.echo("  (the scope's list applies; a list of the device's own replaces it)")
		}
		inv.echo(fmt.Sprintf("  %d. 0.0.0.0/0 refused (always last, never stored)", len(info.Clients)+2))
		for _, w := range cidr.OverlapWarnings(info.Clients) {
			inv.echo("  Note: " + w + " (both stay)")
		}
		inv.echo("")
		return nil
	case "add", "remove":
	default:
		return inv.usageErr("Unknown action '"+action+"': list, add or remove.", usage)
	}
	if len(p.Args) < 2 || p.Args[1] == "" {
		return inv.usageErr(usage)
	}
	requested, err := inv.parseCIDRList(p.Args[1])
	if err != nil {
		return err
	}
	if len(requested) == 0 {
		return inv.usageErr("No valid CIDRs provided.")
	}
	if action == "add" {
		for _, r := range requested {
			if why := cidr.ClientProblem(r); why != "" {
				return inv.usageErr("'" + r + "' " + why + ". Nothing was changed.")
			}
		}
		var added, skipped []string
		next := slices.Clone(cur)
		for _, r := range requested {
			if slices.Contains(next, r) {
				skipped = append(skipped, r)
				continue
			}
			next = append(next, r)
			added = append(added, r)
		}
		if len(added) == 0 {
			a.Out.Info("No new ranges to add to device '" + e.Name + "' (already present: " + strings.Join(skipped, " ") + ").")
			return nil
		}
		if len(next) > cidr.MaxSNMPClients {
			return inv.usageErr(fmt.Sprintf("A device lists at most %d client ranges (it has %d). Nothing was changed.", cidr.MaxSNMPClients, len(cur)))
		}
		if err := inv.deviceSNMPUpdate(e.Name, func(s *devreg.SNMP) error { s.Clients = next; return nil }); err != nil {
			return err
		}
		a.Out.Info(fmt.Sprintf("Added %d allowed SNMP client range(s) to device '%s': %s", len(added), e.Name, strings.Join(added, " ")))
		if len(skipped) > 0 {
			a.Out.Info("(Already present, unchanged: " + strings.Join(skipped, " ") + ")")
		}
		if len(cur) == 0 && info.ClientsFrom == snmpcred.FromScope {
			a.Out.Warn("The device's own list replaces the scope's " + strconv.Itoa(len(info.Clients)) + " range(s) for this device.")
		}
		for _, w := range cidr.OverlapWarnings(next) {
			for _, x := range added {
				if strings.Contains(w, x) {
					a.Out.Warn(w + " (both stay).")
					break
				}
			}
		}
		return nil
	}
	if len(cur) == 0 {
		a.Out.Warn("Nothing to remove: device '" + e.Name + "' lists no SNMP client ranges of its own.")
		return nil
	}
	var removed, missing []string
	next := slices.Clone(cur)
	for _, r := range requested {
		if i := slices.Index(next, r); i >= 0 {
			next = slices.Delete(next, i, i+1)
			removed = append(removed, r)
		} else {
			missing = append(missing, r)
		}
	}
	if len(removed) == 0 {
		a.Out.Warn("Nothing to remove (not in the list: " + strings.Join(missing, " ") + ").")
		return nil
	}
	if err := inv.deviceSNMPUpdate(e.Name, func(s *devreg.SNMP) error { s.Clients = next; return nil }); err != nil {
		return err
	}
	a.Out.Info(fmt.Sprintf("Removed %d SNMP client range(s) from device '%s': %s", len(removed), e.Name, strings.Join(removed, " ")))
	if len(missing) > 0 {
		a.Out.Info("(Not in the list, skipped: " + strings.Join(missing, " ") + ")")
	}
	if len(next) == 0 {
		a.Out.Info("The device lists none of its own now: its scope's list applies again.")
	}
	return nil
}

// credsToReplace is what the device's credentials file holds, for a verb that
// sets part of it. A file that cannot be read starts empty, and the verb
// says so: the file is replaced (it is repaired by setting again, or removed
// by 'clear', which never reads it).
func (inv *invocation) credsToReplace(name string) snmpcred.Creds {
	// No map: the file was ignored, and what it holds is not carried into
	// the credentials being set.
	if d := inv.deviceNamed(name); d != nil && d.SNMP.Empty() {
		file, _ := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, name)
		if fileThere(file) {
			inv.app.Out.Warn("The credentials file of '" + name + "' (" + file + ") was ignored, the device having no settings of its own; it is replaced.")
		}
		return snmpcred.Creds{}
	}
	cr, err := snmpcred.LoadDevice(inv.app.Paths.SNMPDir, name)
	if err != nil {
		file, _ := snmpcred.DeviceFile(inv.app.Paths.SNMPDir, name)
		inv.app.Out.Warn("The credentials file of '" + name + "' (" + file + ") was unreadable (" + strings.Join(msgs(err), " ") + "); it is replaced.")
		return snmpcred.Creds{}
	}
	return cr
}

// deviceSNMPCommunity sets the device's v2c community (asked twice, or one
// line on stdin); the device's version becomes v2c.
func (inv *invocation) deviceSNMPCommunity(e devreg.Entry, p Parsed) error {
	dir := inv.app.Paths.SNMPDir
	if _, err := snmpcred.DeviceFile(dir, e.Name); err != nil {
		return err
	}
	s, err := inv.readSecret(p.Has("--stdin"), "community")
	if err != nil {
		return err
	}
	if msg := secretProblem(s, "the community", 1, names.SNMPCommunityMax); msg != "" {
		return inv.usageErr(msg)
	}
	cr := inv.credsToReplace(e.Name)
	// The state as it is, before the credential is replaced.
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	cr.Community = s
	if err := snmpcred.SaveDevice(dir, e.Name, cr); err != nil {
		return err
	}
	if err := inv.deviceSNMPUpdateWith(e.Name, func(s *devreg.SNMP) error { s.Version = snmp.V2c; return nil }, false); err != nil {
		return err
	}
	file, _ := snmpcred.DeviceFile(dir, e.Name)
	inv.app.Out.InfoE("SNMP community of device '" + e.Name + "' set (" + file + "); the device's version is v2c. Try it: tacctl device check " + shellquote.Q(e.Name))
	return nil
}

// deviceSNMPV3User sets the device's v3 user and both passphrases
// (authPriv); the device's version becomes v3. The authentication and
// privacy protocols are the scope's or the default's.
func (inv *invocation) deviceSNMPV3User(e devreg.Entry, p Parsed) error {
	dir := inv.app.Paths.SNMPDir
	if _, err := snmpcred.DeviceFile(dir, e.Name); err != nil {
		return err
	}
	user := p.Args[0]
	if !reSNMPUser.MatchString(user) || names.SNMPTokenProblem(user, names.SNMPUserMax) != "" {
		return inv.usageErr("Invalid SNMPv3 user '" + user + "': 1-32 printable characters, no blanks, no '?' or '\"'.")
	}
	stdin := p.Has("--stdin")
	ap, err := inv.readSecret(stdin, "authentication passphrase")
	if err != nil {
		return err
	}
	if msg := secretProblem(ap, "the authentication passphrase", 8, names.SNMPPassphraseMax); msg != "" {
		return inv.usageErr(msg)
	}
	pp, err := inv.readSecret(stdin, "privacy passphrase")
	if err != nil {
		return err
	}
	if msg := secretProblem(pp, "the privacy passphrase", 8, names.SNMPPassphraseMax); msg != "" {
		return inv.usageErr(msg)
	}
	cr := inv.credsToReplace(e.Name)
	// The state as it is, before the credential is replaced.
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	cr.User, cr.AuthPass, cr.PrivPass = user, ap, pp
	if err := snmpcred.SaveDevice(dir, e.Name, cr); err != nil {
		return err
	}
	if err := inv.deviceSNMPUpdateWith(e.Name, func(s *devreg.SNMP) error { s.Version = snmp.V3; return nil }, false); err != nil {
		return err
	}
	info, err := inv.deviceSNMPInfoOf(e)
	if err != nil {
		return err
	}
	file, _ := snmpcred.DeviceFile(dir, e.Name)
	inv.app.Out.InfoE("SNMPv3 user and passphrases of device '" + e.Name + "' set (" + file + "); the device's version is v3, auth " +
		info.Eff.Auth + ", priv " + info.Eff.Priv + ". Try it: tacctl device check " + shellquote.Q(e.Name))
	return nil
}

// deviceSNMPClear removes everything the device has of its own: its map and
// its credentials file; its scope's settings (and the default's) apply
// again.
func (inv *invocation) deviceSNMPClear(e devreg.Entry) error {
	a := inv.app
	// The credentials file is removed, never read: one that cannot be parsed
	// is cleared all the same.
	d := inv.deviceNamedOr(e)
	file, ferr := snmpcred.DeviceFile(a.Paths.SNMPDir, e.Name)
	hasFile := ferr == nil && fileThere(file)
	hasMap := !d.SNMP.Empty()
	if !hasFile && !hasMap {
		a.Out.Info("Device '" + e.Name + "' has no SNMP settings of its own; nothing was changed.")
		return nil
	}
	// The state as it is, before anything goes: the snapshot holds the old
	// credential (the registry write's own comes after the file is gone).
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	if hasFile {
		if err := snmpcred.RemoveDevice(a.Paths.SNMPDir, e.Name); err != nil {
			return err
		}
	}
	if hasMap {
		if err := inv.deviceSNMPUpdate(e.Name, func(s *devreg.SNMP) error { *s = devreg.SNMP{}; return nil }); err != nil {
			return err
		}
	}
	a.Out.Info("SNMP settings, credentials and allowed clients of device '" + e.Name + "' removed: its scope's (and the default's) apply again.")
	return nil
}
