// Package devices is 'tacctl config cisco|juniper|wti' (lib/render_devices.sh
// at the 0.1.16 tag): the working configuration (or, for WTI, the
// serial-menu walkthrough) of a scope for a network device, over TACACS+ or
// RADIUS, rendered from the shipped templates (or the operator's copies)
// with the scope's values filled in, followed by the summary and notes.
//
// The CLI (internal/cli/devices.go) parses the arguments, finds the scope
// and resolves the protocol; this package builds the template variables
// from the model and tacctl.yaml, checks what a RADIUS config needs from
// the RADIUS backend (Prepare) and writes the output. It knows nothing of
// how the result reaches a device. Every line is 0.1.16's, except the
// 'Using template:' note (docs/plans/go-rewrite.md 3.9 item 3).
package devices

import (
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/mgmtacl"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/ui"
)

// The protocols a device config renders for (CONFIG_PROTOCOLS); TACACS+ is
// the default.
const (
	TACACS = "tacacs"
	RADIUS = "radius"
)

// Protocols is CONFIG_PROTOCOLS, in order.
var Protocols = []string{TACACS, RADIUS}

// Where a resolved protocol came from (CONFIG_PROTOCOL_SOURCE).
const (
	SourceFlag      = "flag"
	SourceScope     = "scope"
	SourceProtocols = "protocols"
	SourceDefault   = "default"
)

// ProtocolValid is config_protocol_valid: "" when p is a known protocol,
// else the error line.
func ProtocolValid(p string) string {
	for _, k := range Protocols {
		if p == k {
			return ""
		}
	}
	return "Unknown protocol '" + p + "'. Known protocols: " + strings.Join(Protocols, ", ")
}

// ResolveProtocol is config_protocol_resolve: --protocol (given) always
// wins; without it the scope decides (choice and choiceSource are
// scope_protocol_choice's: its auth-method, else the one protocol its
// filter names), and otherwise it is TACACS+.
func ResolveProtocol(given, choice, choiceSource string) (protocol, source string) {
	if given != "" {
		return given, SourceFlag
	}
	if choice == "" {
		return TACACS, SourceDefault
	}
	if choiceSource == "protocols" {
		return choice, SourceProtocols
	}
	return choice, SourceScope
}

// protocolNote is config_protocol_note: what the header adds after the
// scope for a RADIUS config.
func protocolNote(protocol, source string) string {
	if protocol != RADIUS {
		return ""
	}
	switch source {
	case SourceScope:
		return ", protocol: RADIUS — the scope's auth-method"
	case SourceProtocols:
		return ", protocol: RADIUS — the scope's only protocol"
	}
	return ", protocol: RADIUS"
}

// Request is one device config to render.
type Request struct {
	Vendor string // cisco, juniper or wti
	Scope  string // an existing scope
	Legacy bool   // cisco: IOS 12.x syntax (TACACS+ only)
	// Protocol and Source are ResolveProtocol's.
	Protocol, Source string
}

// Data is what the renderers read.
type Data struct {
	Model *model.Model
	Conf  *conf.Config
	// TemplateDir holds the operator's templates (TEMPLATE_DIR_LOCAL).
	TemplateDir string
	// ServerIP is ServerIP's answer (a RADIUS listener bound to one
	// address replaces it).
	ServerIP string
	// Release is the device's recorded OS release ('25.4R1-S2.3'), "" when
	// unknown: the version gates (gates.go) render the older form of a
	// statement for a release that lacks it.
	Release string
	// ACL is the management ACL (Cisco and Juniper).
	ACL MgmtACL
	// Radius is Prepare's result; required when Protocol is radius.
	Radius *Radius

	// SNMP is the scope's SNMP settings with the device's values, as the CLI
	// resolved them (D41, D46); Scope and Server are filled in here. The
	// zero value is "SNMP is not configured".
	SNMP SNMPInput
	// Blocks are the scope's configuration blocks in force, resolved for
	// the device (0.2.7, blocks.go): rendered into the Junos SNMP step and
	// the managed snmp section. The zero value is "no block".
	Blocks Blocks
	// Netconf is the effective NETCONF service setting of a Junos device
	// (D145 of docs/plans/0.2.10-plan.md): the walkthrough's NETCONF step
	// and the managed netconf section follow it. The zero value is leave: the
	// step stays commented and nothing is compared.
	Netconf NetconfSetting
	// Restricted is an engineer's walkthrough: the Cisco NETCONF step is a
	// superuser's (D53).
	Restricted bool
	// AuthServer is --server (D43): the address the devices are told to
	// authenticate against, replacing ServerIP (and a bound RADIUS
	// listener's address) in the lines that say where the server is;
	// AuthName is the host name it was resolved from, if it was given as
	// one. SourceIP is --source: the address tacctl itself reaches the
	// devices from, which the SNMP client list (and the ssh permits) use
	// instead of ServerIP. Neither is stored.
	AuthServer, AuthName, SourceIP string
}

// source is the address tacctl reaches devices from: --source, else the
// detected one.
func (d Data) source() string {
	if d.SourceIP != "" {
		return d.SourceIP
	}
	return d.ServerIP
}

// mgmtPermits are the permits of the Cisco VTY access list and the Junos
// management filter: the management ACL's IPv4 entries (the lists skip the
// rest), headed by the server's /32 (the address tacctl itself reaches the
// device from: --source, else the detected one), so that the access class
// or the filter cannot cut off tacctl's own ssh. An entry equal to that /32
// is not repeated. Nothing when the ACL has no IPv4 entry that permits ssh:
// no block is rendered then, and the server's address alone would be one
// that locks everybody else out.
//
// A standard access list and the filter's permit-mgmt term have no
// per-source services (0.2.7), so an entry is listed by its source: a plain
// entry as it always was, and an entry with services when they include
// tcp/22 (alone, in a range or as tcp/*). Any other entry is not listed
// (mgmtSkipped says which, and why).
func (d Data) mgmtPermits() []string {
	var rest []string
	for _, e := range d.mgmtEntries() {
		if e.permit && !slices.Contains(rest, e.net) {
			rest = append(rest, e.net)
		}
	}
	if len(rest) == 0 {
		return nil
	}
	srv := cidr.Host32(d.source())
	if srv == "" {
		return rest
	}
	out := []string{srv}
	for _, e := range rest {
		if e == srv {
			continue
		}
		out = append(out, e)
	}
	return out
}

// mgmtEntry is one IPv4 entry of the management ACL as the VTY access list
// and the Junos filter read it.
type mgmtEntry struct {
	net    string // the canonical CIDR
	text   string // the entry as stored
	permit bool   // listed: plain, or its services include ssh
	why    string // the services, for an entry that is not listed
}

// mgmtEntries are the IPv4 entries of the ACL, in the order stored (an
// IPv6 or unparsable entry is skipped, as it always was).
func (d Data) mgmtEntries() []mgmtEntry {
	var out []mgmtEntry
	for _, raw := range d.ACL.CIDRs {
		e, err := mgmtacl.ParseEntry(raw)
		if err != nil || e.IPv6() {
			continue
		}
		m := mgmtEntry{net: e.Net, text: e.String(), permit: e.AllowsSSH()}
		if !m.permit {
			m.why = mgmtacl.ServicesText(e.Services, ", ")
		}
		out = append(out, m)
	}
	return out
}

// mgmtSkipped are the notes on the entries the VTY access list and the Junos
// filter do not list (what is the entry, what it permits, where it is
// not): empty for a list of plain entries. where names the list or filter
// and says why it cannot hold services.
func (d Data) mgmtSkipped(where string) []string {
	var out []string
	for _, e := range d.mgmtEntries() {
		if !e.permit {
			out = append(out, "entry "+e.text+" permits "+e.why+" only: not in "+where+"; a source is listed there when its entry permits tcp/22 or has no services")
		}
	}
	return out
}

// authIP is the address a device is told to authenticate against:
// --server, else the address a RADIUS listener is bound to (bound), else
// the detected one.
func (d Data) authIP(bound string) string {
	switch {
	case d.AuthServer != "":
		return d.AuthServer
	case bound != "":
		return bound
	}
	return d.ServerIP
}

// boundAddr is the address of the RADIUS listener a RADIUS config names.
func (d Data) boundAddr(protocol string) string {
	if protocol == RADIUS && d.Radius != nil {
		return d.Radius.ServerAddr
	}
	return ""
}

// snmpInput is the SNMP step's input for scope.
func (d Data) snmpInput(scope string) SNMPInput {
	return d.snmpInputFor(scope, "juniper")
}

// snmpInputFor is snmpInput for a vendor: the block lines are the vendor's
// own (the Junos snmp block's 'set' lines, the IOS snmp block's
// configuration lines), and a request never renders another vendor's.
func (d Data) snmpInputFor(scope, vendor string) SNMPInput {
	in := d.SNMP
	in.Scope = scope
	in.Server = d.source()
	head := d.Blocks.snmpHead
	switch vendor {
	case "cisco":
		in.Block, head = d.Blocks.ciscoSNMPStatements(), d.Blocks.ciscoSNMPHead
	default:
		in.Block = d.Blocks.snmpStatements()
	}
	if len(in.Block) > 0 {
		in.BlockScope = d.Blocks.Scope
		if in.BlockScope == "" {
			in.BlockScope = scope
		}
		in.BlockHead = head(scope)
	}
	return in
}

// Render writes the device config of req to w.
func Render(w io.Writer, req Request, d Data) error {
	o := &out{w: w}
	var err error
	switch req.Vendor {
	case "cisco":
		err = renderCisco(o, req, d)
	case "juniper":
		err = renderJuniper(o, req, d)
	default:
		if req.Protocol == RADIUS {
			err = renderWTIRadius(o, req, d)
		} else {
			err = renderWTI(o, req, d)
		}
	}
	if err != nil {
		return err
	}
	return o.err
}

// --- reading the model and tacctl.yaml ----------------------------------------

// confGet is "$(conf_get <path> <fallback>)".
func confGet(c *conf.Config, path, fallback string) string {
	v, _ := c.Get(path, fallback)
	return strings.TrimRight(v, "\n")
}

// lines is a command substitution of printed items read back line by line
// ('while IFS= read -r x'): the items joined by newlines, trailing newlines
// dropped, split again (an empty input is no line).
func lines(items []string) []string {
	s := strings.TrimRight(strings.Join(items, "\n"), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// group is one line of model_group_info.
type group struct{ name, priv, class string }

// groupInfo is model_group_info split on '|'.
func groupInfo(m *model.Model) []group {
	var out []group
	for _, l := range m.GroupInfo() {
		f := strings.SplitN(l, "|", 3)
		for len(f) < 3 {
			f = append(f, "")
		}
		out = append(out, group{f[0], f[1], f[2]})
	}
	return out
}

// privGroups is "model_group_info | cut -d'|' -f1,2 | awk -F'|' '$2 != ""'"
// read as 'name|privlvl' lines (lines without a name skipped).
func privGroups(m *model.Model) []group {
	var out []group
	for _, g := range groupInfo(m) {
		if g.priv != "" && g.name != "" {
			out = append(out, g)
		}
	}
	return out
}

// otherScopes is the header's "other scopes": every scope in routing order
// but this one, comma-separated.
func otherScopes(m *model.Model, scope string) string {
	var out []string
	for _, s := range m.ScopesByRouting() {
		if s != scope {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}

// localFirst is whether the scope's aaa-order is local-first.
func localFirst(c *conf.Config, scope string) bool {
	return confGet(c, "aaa.order."+scope, "tacacs-first") == "local-first"
}

// fallbackLocal is the WTI 'Fallback Local' setting for the scope's
// aaa-order: never Off (with the server down nobody would get in).
func fallbackLocal(c *conf.Config, scope string) string {
	if localFirst(c, scope) {
		return "On (All Failures)"
	}
	return "On (Transport Failure)"
}

// execTimeout is the scope's exec_timeout (minutes; default 60).
func execTimeout(c *conf.Config, scope string) string {
	return confGet(c, "exec_timeout."+scope, "60")
}

// anyGroupHasCommands is any_group_has_commands: commands.* has a key.
func anyGroupHasCommands(c *conf.Config) bool {
	return strings.Join(c.GetKeys("commands"), "\n") != ""
}

// chars is ${#s} in a UTF-8 locale.
func chars(s string) int { return utf8.RuneCountInString(s) }

// MgmtACL is the scope's management ACL for a Cisco or Juniper config:
// read_mgmt_acl_cidrs <scope> and read_mgmt_acl_name <vendor> <scope>,
// which the CLI's helpers of 'config|scope mgmt-acl' answer (so the
// resolution rules live in one place).
type MgmtACL struct {
	// CIDRs are the scope's permits, else the global ones, in their
	// canonical form: a CIDR, or (0.2.7) a CIDR with its services
	// ('172.16.100.0/23:tcp/22,udp/161', internal/mgmtacl).
	CIDRs []string
	Name  string // the vendor's ACL (filter) name for the scope
	// Mode is the Junos filter's mode (0.2.20, 'scope mgmt-acl <scope>
	// mode'): MgmtModeStrict, or anything else for the ssh-only filter
	// ("" is ssh-only). Only the Junos filter reads it.
	Mode string
}

// The modes of the Junos management filter (conf's).
const (
	MgmtModeSSHOnly = conf.MgmtModeSSHOnly
	MgmtModeStrict  = conf.MgmtModeStrict
)

// Strict reports the deny-by-default mode of the Junos filter.
func (a MgmtACL) Strict() bool { return a.Mode == MgmtModeStrict }

// --- output -----------------------------------------------------------------------

// out writes the lines of a device config; the first write error sticks.
type out struct {
	w   io.Writer
	err error
	// ascii is set for a walkthrough that is pasted from (Cisco): nothing of
	// its text is outside ASCII, the header's dash included.
	ascii bool
}

func (o *out) write(s string) {
	if o.err == nil {
		_, o.err = io.WriteString(o.w, s)
	}
}

// echo is 'echo "<s>"'; echoE is 'echo -e "<s>"'.
func (o *out) echo(s string)  { o.write(s + "\n") }
func (o *out) echoE(s string) { o.write(ui.Echo(s)) }

// heading is 'echo -e "${YELLOW}<s>${NC}"' (or another colour).
func (o *out) heading(colour, s string) { o.echoE(colour + s + ui.NC) }

// header is the block above the config: the title with the scope, the
// other scopes, what to do with it, and the rule.
func (o *out) header(title, scope, note, other, instruction string) {
	o.echo("")
	o.echoE(ui.Bold + title + ui.NC + "  (scope: " + scope + note + ")")
	if other != "" {
		dash := "\u2014"
		if o.ascii {
			dash = "-"
		}
		o.heading(ui.Yellow, "(other scopes: "+other+" "+dash+" use --scope <name> to emit those)")
	}
	o.heading(ui.Yellow, instruction)
	o.echo("--------------------------------------------")
	o.echo("")
}

// addressRoles says which server address plays which role when --server or
// --source makes them differ (D43): nothing otherwise.
func (o *out) addressRoles(d Data, protocol string) {
	if d.AuthServer == "" && d.SourceIP == "" {
		return
	}
	auth, src := d.authIP(d.boundAddr(protocol)), d.source()
	if auth == src {
		return
	}
	how := "detected"
	if d.SourceIP != "" {
		how = "--source"
	}
	told := "detected"
	if d.AuthServer != "" {
		told = "--server"
		if d.AuthName != "" {
			told += ": resolved from " + d.AuthName
		}
	}
	o.heading(ui.Yellow, "Two server addresses:")
	o.echo("  - The device is told to authenticate against " + auth + " (" + told + ")")
	o.echo("  - tacctl reaches the device from " + src + " (" + how + "): the SNMP client list and the")
	o.echo("    permits for ssh and SNMP (the first entry of the Cisco access list and of the Junos")
	o.echo("    filter, a line of the WTI list) name it, and so do the 'tacctl' checks below")
	o.echo("")
}

// unfilled ends a walkthrough with the SNMP values it could not fill.
func (o *out) unfilled(u []Unfilled) {
	if line := UnfilledLine(u); line != "" {
		o.heading(ui.Yellow, line)
		o.echo("")
	}
}

// rule is the line between the config and the summary.
func (o *out) rule() {
	o.echo("")
	o.echo("--------------------------------------------")
}

// reASCIIWord is ^[A-Za-z0-9_-]+$ (ASCII, as bash matches it in C.UTF-8).
var reASCIIWord = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
