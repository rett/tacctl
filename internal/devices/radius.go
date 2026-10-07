package devices

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/ui"
)

// RadiusBackend is what a RADIUS device config needs of the RADIUS backend
// module (backend.Backend has it).
type RadiusBackend interface {
	DeviceVars(ctx context.Context, vendor, scope string) (map[string]string, error)
	SecretConstraints() backend.Constraints
	Listeners() backend.ListenerOps
}

// Radius is what radius_device_prepare sets: the listener ports, the
// scope's secret, the address a listener is bound to ("" when none is: the
// route lookup's address stays), how the vendor's attribute reaches the
// scope's devices ("scope" or "tagged") and the warnings for the summary
// (RADIUS_WARNINGS: lines, each ended by a newline).
type Radius struct {
	AuthPort, AcctPort string
	Secret             string
	ServerAddr         string
	VendorSent         string
	Warnings           string
}

// RefusedError is a RADIUS device config refused because it would not
// work: the lines are printed as error lines (through echo -e) and the
// command exits 1, with nothing on stdout.
type RefusedError struct{ Lines []string }

func (e *RefusedError) Error() string { return strings.Join(e.Lines, "\n") }

// vendorLabel is radius_vendor_label: the vendor's name in messages.
func vendorLabel(vendor string) string {
	switch vendor {
	case "cisco":
		return "Cisco"
	case "juniper":
		return "Juniper"
	case "wti":
		return "WTI"
	}
	return ""
}

// vendorAttr is radius_vendor_attr: the attribute that carries the
// vendor's privilege over RADIUS.
func vendorAttr(vendor string) string {
	switch vendor {
	case "cisco":
		return `Cisco-AVPair "shell:priv-lvl=N"`
	case "juniper":
		return "Juniper-Local-User-Name"
	case "wti":
		return "WTI-Super"
	}
	return ""
}

// reDeviceSecret is CONFIG_RADIUS_SECRET_RE, matched as 0.1.16 matches it
// (LC_ALL=C: bytes, so anything not ASCII fails): what pastes unquoted on
// IOS and Junos. Base64, what 'scope secret generate' makes, is inside it.
var reDeviceSecret = regexp.MustCompile(`^[A-Za-z0-9._+/=:@%^~-]+$`)

// Prepare is radius_device_prepare <vendor> <scope>: everything a RADIUS
// device config needs from the RADIUS backend, or a *RefusedError when the
// config would not work: the backend is not enabled (enabled is whether it
// is), the scope's protocols leave RADIUS out, the vendor's attribute
// reaches none of the scope's devices, the listener ports cannot be read,
// the scope has no secret, or the secret cannot be pasted. Advice that does
// not break the config is a warning.
func Prepare(ctx context.Context, vendor, scope string, m *model.Model, enabled bool, b RadiusBackend) (*Radius, error) {
	if !enabled || b == nil {
		return nil, &RefusedError{Lines: []string{
			"The RADIUS backend is not enabled, so nothing on this server answers RADIUS requests and this configuration would not work.",
			"Enable it first: tacctl backend enable radius   (tacctl backend list shows what is enabled)",
		}}
	}
	sc := m.Scope(scope)
	var protocols, attrs []string
	if sc != nil {
		protocols = lines(sc.Protocols)
		for _, a := range lines(sc.VendorAttrs) {
			if strings.Trim(a, " \t") != "" {
				attrs = append(attrs, a)
			}
		}
	}
	if p := strings.Join(protocols, ","); p != "" && !strings.Contains(","+p+",", ",radius,") {
		return nil, &RefusedError{Lines: []string{
			"Scope '" + scope + "' is limited to " + p + " (tacctl scope protocols), so the RADIUS backend ignores its devices and does not load its secret; this configuration would not work.",
			"Serve it over RADIUS too: tacctl scope protocols " + scope + " set " + p + ",radius   (or 'clear' for every protocol)",
		}}
	}

	r := &Radius{}
	var warn strings.Builder
	label := vendorLabel(vendor)
	var tagged []string
	for _, d := range m.ScopeDevices(scope) {
		f := strings.Split(d, "|")
		if len(f) > 1 && f[1] == vendor {
			tagged = append(tagged, f[0])
		}
	}
	switch {
	case strings.Contains(","+strings.Join(attrs, ",")+",", ","+vendor+","):
		r.VendorSent = "scope"
	case len(tagged) > 0:
		r.VendorSent = "tagged"
		warn.WriteString("  - Scope '" + scope + "' does not enable the " + label + " attribute; only its addresses tagged " + vendor + " get it: " + strings.Join(tagged, " ") + ".\n")
		warn.WriteString("    Configure only those devices from this, or enable it: tacctl scope vendor-attrs " + scope + " enable " + vendor + "\n")
	default:
		return nil, &RefusedError{Lines: []string{
			"Scope '" + scope + "' sends no " + label + " attribute over RADIUS (" + vendorAttr(vendor) + "): " + vendor + " is not enabled for the scope and no address of it is tagged " + vendor + ".",
			"A " + label + " device configured from this would log users in without the privilege level their group gives.",
			"Enable it for the scope's devices: tacctl scope vendor-attrs " + scope + " enable " + vendor,
			"or for one device only:            tacctl scope devices " + scope + " set <device-ip> " + vendor,
		}}
	}

	vars, _ := b.DeviceVars(ctx, vendor, scope)
	r.AuthPort, r.AcctPort, r.Secret = vars["AUTH_PORT"], vars["ACCT_PORT"], vars["SECRET"]
	if r.AuthPort == "" || r.AcctPort == "" {
		return nil, &RefusedError{Lines: []string{
			"Could not read the RADIUS auth and acct listener ports (tacctl config listen --backend radius show).",
		}}
	}
	if r.Secret == "" {
		return nil, &RefusedError{Lines: []string{
			"Scope '" + scope + "' has no shared secret: set one with 'tacctl scope secret " + scope + " generate'.",
		}}
	}
	if !reDeviceSecret.MatchString(r.Secret) {
		return nil, &RefusedError{Lines: []string{
			"The secret of scope '" + scope + "' has a character that IOS and Junos read as syntax (whitespace, a quote, ? ! # $ \\ ; { } [ ] | & < > , * ( ) ` or a non-ASCII character), so it cannot be pasted into a device configuration as it is.",
			"Use letters, digits and . _ + / = : @ % ^ ~ - : tacctl scope secret " + scope + " generate   (or: set <value>)",
			"The scope's secret is shared with TACACS+: change it on every device of the scope, whatever the protocol.",
		}}
	}

	// The backend's advice on shared secrets: a warning, not a refusal.
	c := b.SecretConstraints()
	if n := chars(r.Secret); c.MaxLen > 0 && n > c.MaxLen {
		warn.WriteString("  - The secret is " + strconv.Itoa(n) + " characters; some RADIUS clients take no more than " + strconv.Itoa(c.MaxLen) + ". FreeRADIUS accepts it, but check your\n")
		warn.WriteString("    device's limit before pasting (tacctl scope secret " + scope + " generate makes a 32-character one; the scope's secret is shared with TACACS+)\n")
	}
	if c.Charset != "" {
		// LC_ALL=C, as for the secret above; a charset that is no regex
		// fails the match, as bash's [[ =~ ]] does.
		re, err := regexp.Compile("^" + c.Charset + "+$")
		if err != nil || !re.MatchString(r.Secret) {
			warn.WriteString("  - The secret has characters outside " + c.Charset + ", which some RADIUS clients do not take\n")
		}
	}

	// A listener bound to one address answers there only.
	var boundV6 []string
	if ls, err := b.Listeners().List(); err == nil {
		for _, l := range ls {
			if l.Name != "auth" && l.Name != "acct" {
				continue
			}
			host := l.Address
			if i := strings.LastIndexByte(host, ':'); i >= 0 {
				host = host[:i]
			}
			host = strings.TrimPrefix(host, "[")
			host = strings.TrimSuffix(host, "]")
			if l.Network == "udp6" || strings.Contains(host, ":") {
				boundV6 = append(boundV6, l.Name+" ("+l.Network+" "+l.Address+")")
				continue
			}
			if host == "" || host == "0.0.0.0" {
				continue
			}
			if strings.HasPrefix(host, "127.") {
				warn.WriteString("  - The " + l.Name + " listener is bound to " + host + ": no device can reach it (tacctl config listen --backend radius)\n")
			}
			if r.ServerAddr == "" {
				r.ServerAddr = host
			} else if r.ServerAddr != host {
				warn.WriteString("  - The auth and acct listeners are bound to different addresses (" + r.ServerAddr + ", " + host + "); the device takes one address for both, this uses " + r.ServerAddr + "\n")
			}
		}
	}
	if len(boundV6) > 0 {
		warn.WriteString("  - IPv6 listener(s): " + strings.Join(boundV6, ", ") + ". This configuration addresses the server over IPv4 and will not reach them;\n")
		warn.WriteString("    adapt the server address by hand\n")
	}
	r.Warnings = warn.String()
	return r, nil
}

// summaryAccept is radius_summary_accept: what an Access-Accept for a
// device of the scope carries, and why.
func (o *out) summaryAccept(vendor, scope string, r *Radius) {
	why := "only to the addresses of the scope tagged " + vendor + " (tacctl scope devices " + scope + ")"
	if r.VendorSent == "scope" {
		why = "the scope enables it (tacctl scope vendor-attrs " + scope + "); an address tagged with another vendor gets that one's instead"
	}
	o.heading(ui.Yellow, "What an Access-Accept carries for this device:")
	o.echo("  - Service-Type: Administrative-User at privilege 15, else NAS-Prompt-User (always sent)")
	o.echo("  - " + vendorAttr(vendor) + " from the user's group: " + why)
	if vendor == "juniper" {
		o.echo("  - With it, Juniper-Deny-Commands and Juniper-Deny-Configuration where the group has")
		o.echo("    a set ('tacctl group junos <group> list')")
	}
	o.echo("  - No other vendor's attribute. A reject carries none")
}

// summaryLimits is radius_summary_limits <cisco|juniper>: what an
// Access-Accept carries, what a login over RADIUS does not have next to
// TACACS+, and Prepare's warnings.
func (o *out) summaryLimits(vendor, scope string, r *Radius) {
	o.summaryAccept(vendor, scope, r)
	o.echo("")
	o.heading(ui.Yellow, "What RADIUS does not give you (compared with TACACS+):")
	if vendor == "cisco" {
		o.echo("  - No per-command authorization. The only authorization is what the Access-Accept")
		o.echo("    carries: the privilege level (Cisco-AVPair shell:priv-lvl=N, with Service-Type).")
		o.echo("    'tacctl group commands' rules are not enforced; a user may run whatever their")
		o.echo("    privilege level allows, so review the 'privilege exec level' mappings above")
		o.echo("  - No command accounting. Only exec session start/stop records are sent")
		o.echo("    (TACACS+ also records every command at each privilege level in use)")
	} else {
		o.echo("  - No per-command authorization from the server. The only authorization is what the")
		o.echo("    Access-Accept carries: the login class (Juniper-Local-User-Name) and the group's")
		o.echo("    Juniper-Deny-Commands and Juniper-Deny-Configuration (Step 3), which Junos")
		o.echo("    enforces itself, as it does over TACACS+")
		o.echo("  - No command accounting. Only login and change-log events are sent")
		o.echo("    (TACACS+ also records commands)")
	}
	o.echo("  - Password logins only (PAP): no CHAP, MS-CHAP or EAP")
	o.echo("  - UDP, not TCP/49: allow UDP " + r.AuthPort + " (authentication) and " + r.AcctPort + " (accounting)")
	o.echo("    from the device to the server")
	o.echo("  - The server answers only a device whose source address lies in a prefix of scope")
	o.echo("    '" + scope + "' ('tacctl scope lookup <device-ip>' to check)")
	if r.Warnings != "" {
		o.echo("")
		o.heading(ui.Yellow, "Warnings:")
		o.write(r.Warnings)
	}
}
