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
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/conf"
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
	// ACL is the management ACL (Cisco and Juniper).
	ACL MgmtACL
	// Radius is Prepare's result; required when Protocol is radius.
	Radius *Radius
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
	CIDRs []string // the scope's permits, else the global ones; canonical
	Name  string   // the vendor's ACL (filter) name for the scope
}

// --- output -----------------------------------------------------------------------

// out writes the lines of a device config; the first write error sticks.
type out struct {
	w   io.Writer
	err error
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
		o.heading(ui.Yellow, "(other scopes: "+other+" — use --scope <name> to emit those)")
	}
	o.heading(ui.Yellow, instruction)
	o.echo("--------------------------------------------")
	o.echo("")
}

// rule is the line between the config and the summary.
func (o *out) rule() {
	o.echo("")
	o.echo("--------------------------------------------")
}

// reASCIIWord is ^[A-Za-z0-9_-]+$ (ASCII, as bash matches it in C.UTF-8).
var reASCIIWord = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
