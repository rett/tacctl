package devices

import (
	"strconv"
	"strings"
	"unicode"

	rr "github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/ui"
)

// The variables each WTI template may use (cmd_config_wti's and
// config_wti_radius's envsubst whitelists).
var (
	wtiTacacsVars = []string{"SERVER_IP", "SECRET", "SCOPE", "FALLBACK_LOCAL", "SERVICE_NAME", "GROUP_SUMMARY"}
	wtiRadiusVars = []string{"SERVER_IP", "SECRET", "SCOPE", "FALLBACK_LOCAL", "AUTH_PORT", "ACCT_PORT"}
)

// WTITemplate is the template a WTI walkthrough renders.
func WTITemplate(protocol string) string {
	if protocol == RADIUS {
		return "wti-radius"
	}
	return "wti"
}

// wtiServiceName is the authorization service the walkthrough has the unit
// send: the name of every exec_<group> service of tacquito.yaml.
const wtiServiceName = "shell"

// wtiLevel is wti_access_level_for_privlvl and wti_super_for_privlvl: the
// unit's access level for a priv-lvl (as bash's arithmetic reads it: a
// value that is no number is 0) and its WTI-Super number. The bands are
// the RADIUS renderer's, so the two cannot drift.
func wtiLevel(priv string) (super int, level string) {
	n, err := strconv.Atoi(strings.TrimSpace(priv))
	if err != nil {
		n = 0
	}
	return rr.WTISuper(n)
}

// wtiUnsafe is what 0.1.16's [[ "$secret" =~ [[:space:]] ]] ||
// [[ "$secret" =~ [^[:print:]] ]] finds in the C.UTF-8 locale (glibc's
// classes): a space character, or a character that is not printable
// (a control, a line or paragraph separator, a surrogate, an unassigned
// code point). Go's tables are Unicode 15.0 where glibc 2.39 has 15.1:
// the CJK additions of 15.1 count as unassigned here.
func wtiUnsafe(s string) bool {
	for _, r := range s {
		switch {
		case r == ' ', r == 0x1680, r >= 0x2000 && r <= 0x2006, r >= 0x2008 && r <= 0x200A, r == 0x205F, r == 0x3000:
			return true
		case !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Zs, unicode.Cf, unicode.Co):
			return true
		}
	}
	return false
}

// wtiUserWarnings are the members of the scope whose name is longer than
// a WTI username may be (32 characters).
func wtiUserWarnings(d Data, scope string) string {
	var b strings.Builder
	for _, u := range d.Model.Members(scope) {
		if n := chars(u); u != "" && n > 32 {
			b.WriteString("  - User '" + u + "' is " + strconv.Itoa(n) + " chars; WTI usernames max out at 32\n")
		}
	}
	return b.String()
}

// WTIVars are the template variables of a WTI walkthrough (the values
// cmd_config_wti or config_wti_radius exports to envsubst).
func WTIVars(req Request, d Data) map[string]string {
	vars := map[string]string{
		"SERVER_IP":      d.ServerIP,
		"SECRET":         scopeSecret(d, req.Scope),
		"SCOPE":          req.Scope,
		"FALLBACK_LOCAL": fallbackLocal(d.Conf, req.Scope),
		"SERVICE_NAME":   wtiServiceName,
	}
	var summary strings.Builder
	for _, g := range privGroups(d.Model) {
		super, level := wtiLevel(g.priv)
		if req.Protocol == RADIUS {
			summary.WriteString("  " + g.name + ": priv-lvl " + g.priv + " → WTI-Super " + strconv.Itoa(super) + " (" + level + ")\n")
		} else {
			summary.WriteString("  " + g.name + ": priv-lvl " + g.priv + " → " + level + "\n")
		}
	}
	vars["GROUP_SUMMARY"] = summary.String()
	if r := d.Radius; req.Protocol == RADIUS && r != nil {
		vars["SECRET"] = r.Secret
		vars["AUTH_PORT"], vars["ACCT_PORT"] = r.AuthPort, r.AcctPort
		if r.ServerAddr != "" {
			vars["SERVER_IP"] = r.ServerAddr
		}
	}
	return vars
}

// superUserBand reports whether a group lands in the SuperUser band.
func superUserBand(d Data) bool {
	for _, g := range privGroups(d.Model) {
		if _, level := wtiLevel(g.priv); level == "SuperUser" {
			return true
		}
	}
	return false
}

// portAccess prints which groups the unit's Default User Access port
// lists apply to: the groups that land at User or ViewOnly, which reach
// only the ports (and plugs) turned on there. menu is the Step 3 item.
func portAccess(o *out, d Data, menu string) {
	o.heading(ui.Yellow, "Port access ("+menu+" → Port Access, Step 3):")
	var limited []string
	for _, g := range privGroups(d.Model) {
		if _, level := wtiLevel(g.priv); level == "User" || level == "ViewOnly" {
			limited = append(limited, "    "+g.name+": "+level)
		}
	}
	if len(limited) == 0 {
		o.echo("  No group lands at User or ViewOnly, so the Port Access list is not used.")
		o.echo("  Administrator and SuperUser logins reach every port and plug.")
		o.echo("")
		return
	}
	o.echo("  These groups reach only the ports turned On there (factory: none), and on a")
	o.echo("  power unit only the plugs and plug groups turned On under Plug Access and")
	o.echo("  Plug Group Access. One list per unit, shared by every such login:")
	for _, l := range limited {
		o.echo(l)
	}
	o.echo("  Administrator and SuperUser logins reach every port and plug.")
	o.echo("")
}

// renderWTI is cmd_config_wti over TACACS+.
func renderWTI(o *out, req Request, d Data) error {
	t, err := ResolveTemplate(d.TemplateDir, WTITemplate(TACACS))
	if err != nil {
		return err
	}
	scope := req.Scope
	vars := WTIVars(req, d)
	secret := vars["SECRET"]

	// The unit takes the secret at a menu prompt and documents limits for
	// its other credential fields: flag what is likely to be mangled.
	var secretWarnings strings.Builder
	switch {
	case wtiUnsafe(secret):
		secretWarnings.WriteString("  - " + ui.Red + "Secret contains whitespace or non-printable characters — WTI rejects" + ui.NC + "\n")
		secretWarnings.WriteString("    " + ui.Red + "those in credential fields. Regenerate a hex key:" + ui.NC + "\n")
		secretWarnings.WriteString("      tacctl scope secret " + scope + " set $(openssl rand -hex 16)\n")
	case !reASCIIWord.MatchString(secret):
		secretWarnings.WriteString("  - Secret contains punctuation (e.g. + / =); the WTI menu prompt is untested\n")
		secretWarnings.WriteString("    with those. If tacquito logs 'bad secret detected' after saving, switch\n")
		secretWarnings.WriteString("    to a hex-only key: tacctl scope secret " + scope + " set $(openssl rand -hex 16)\n")
	}
	if n := chars(secret); n > 32 {
		secretWarnings.WriteString("  - Secret is " + strconv.Itoa(n) + " chars. WTI documents no Secret Word maximum, but its other\n")
		secretWarnings.WriteString("    credential fields cap at 16-32 chars; a silent truncation shows up on the\n")
		secretWarnings.WriteString("    tacquito side as 'bad secret detected'. A 32-char hex key is the safe choice.\n")
	}
	userWarnings := wtiUserWarnings(d, scope)

	o.echo("")
	o.echoE(ui.Bold + "WTI Console Server Configuration" + ui.NC + "  (scope: " + scope + ", firmware v8.x text interface)")
	if other := otherScopes(d.Model, scope); other != "" {
		o.heading(ui.Yellow, "(other scopes: "+other+" — use --scope <name> to emit those)")
	}
	o.heading(ui.Yellow, "Follow these steps on the WTI serial (SetUp) console:")
	o.echo("--------------------------------------------")
	o.echo("")
	o.write(Expand(t.Text, wtiTacacsVars, vars))
	o.rule()
	o.heading(ui.Yellow, "Group → WTI Access Level Mapping (from priv-lvl):")
	o.write(vars["GROUP_SUMMARY"])
	o.echo("  (WTI bands: 0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator)")
	if !superUserBand(d) {
		o.echo("  No group lands in the SuperUser band; to grant it, add a group at")
		o.echo("  priv-lvl 10-14, e.g. 'tacctl group add wtisuper 12 OP-CLASS'.")
	}
	o.echo("")
	portAccess(o, d, "8. Default User Access")
	if secretWarnings.Len() > 0 || userWarnings != "" {
		o.heading(ui.Yellow, "Warnings:")
		// echo -en: the scope name is the only value in it.
		s, _ := ui.EchoE(secretWarnings.String())
		o.write(s)
		o.write(userWarnings)
		o.echo("")
	}
	o.heading(ui.Yellow, "Notes:")
	for _, l := range []string{
		"  - WTI authenticates with PAP (password travels inside the TACACS+ body,",
		"    obfuscated with the shared secret) — tacquito's bcrypt authenticator",
		"    handles PAP, no server-side change needed",
		"  - The Account/Session Management Module items are PAM terms (the unit's",
		"    client is pam_tacplus-style): 'Account' is the TACACS+ authorization",
		"    request that carries priv-lvl back — without it every login gets the",
		"    'Default User Access' level; 'Session' is accounting start/stop",
		"  - Service Name '" + wtiServiceName + "' makes the unit's authorization request match",
		"    tacquito's configured service directly. Leaving the factory 'wti' also",
		"    works, but only via the default-service-permit patch (patches/0001),",
		"    which answers an unmatched service with the group's shell priv-lvl",
		"  - Default User Access must be On (Access Level ViewOnly is only the floor;",
		"    the priv-lvl tacquito returns sets the effective level). SSH logins go",
		"    through the unit's OpenSSH, which must resolve the account locally: with",
		"    it Off, a TACACS-only user is invalid to sshd, which sends a junk password",
		"    (OpenSSH's 'INCORRECT' filler) — tacquito then logs 'failed to validate",
		"    the user' on every attempt whatever was typed, and a plain ssh is closed",
		"    unprompted",
		"  - Session Management (accounting) needs tacquito built with tacctl's patch",
		"    0002 (patches/): upstream answers accounting with a non-empty server_msg,",
		"    and the unit drops the SSH session right after login when it gets one.",
		"    'tacctl upgrade' applies the patch overlay and rebuilds",
		"  - A User- or ViewOnly-level login that lands at the right level but sees no",
		"    ports has none turned On under 8. Default User Access → Port Access (see",
		"    \"Port access\" above). A same-named LOCAL account on the unit overrides",
		"    the server-assigned level — keep the two directories disjoint",
		"  - Fallback Local '" + vars["FALLBACK_LOCAL"] + "' mirrors this scope's aaa-order;",
		"    keep a local Administrator account on the unit as break-glass. It acts",
		"    only after the TACACS+ transport fails (Fallback Timer expiry), not on an",
		"    immediate 'Connection closed' or 'Permission denied'",
		"  - A firewall that drops tacquito's replies (the unit's own IP Tables",
		"    without ESTABLISHED,RELATED — Step 5) shows up on the server only as",
		"    SYNs in tcpdump and half-open (SYN-RECV) sockets; tacquito logs nothing",
		"  - The unit's source IP must fall inside a prefix of scope '" + scope + "'",
		"    ('tacctl scope lookup <wti-ip>' to check)",
		"  - Using template: " + t.Origin(),
	} {
		o.echo(l)
	}
	o.echo("")
	o.echoE(ui.Bold + "Verify on the tacquito side:" + ui.NC)
	for _, l := range []string{
		"  tacctl config loglevel debug          # then log in on the WTI (Step 7) and watch:",
		"  tacctl log tail 50                    # 1. 'accepting user [x] using a bcrypt password'  (PAP authen)",
		"                                        # 2. 'session authz user [x]: client args [service=" + wtiServiceName + " ...]'",
		"                                        # 3. 'authorized user [x] as session based; args [priv-lvl=N]'",
		"  tacctl log accounting                 # start record at login, stop record after /X",
		"  tacctl log failures                   # 'bad secret detected' = Secret Word mismatch;",
		"                                        # 'failed to validate the user [x] using a bcrypt",
		"                                        # password' on EVERY attempt = Default User Access Off;",
		"                                        # 'unknown authenticate start packet type' = unit did not",
		"                                        # send PAP with TACACS+ minor version 1 (open an issue)",
		"  tacctl config loglevel info           # restore when done",
		"  On the WTI (Step 8): with 12. Debug: On the unit echoes each TACACS+ exchange on",
		"  the serial session; line up the authen/author/acct replies with the entries above",
	} {
		o.echo(l)
	}
	o.echo("")
	return nil
}

// renderWTIRadius is config_wti_radius (not verified on a unit).
func renderWTIRadius(o *out, req Request, d Data) error {
	t, err := ResolveTemplate(d.TemplateDir, WTITemplate(RADIUS))
	if err != nil {
		return err
	}
	scope := req.Scope
	vars := WTIVars(req, d)
	secret := vars["SECRET"]
	r := d.Radius

	// Prepare has refused what a device CLI reads as syntax already.
	var secretWarnings strings.Builder
	if !reASCIIWord.MatchString(secret) {
		secretWarnings.WriteString("  - Secret contains punctuation (e.g. + / =); the WTI menu prompt is untested with those.\n")
		secretWarnings.WriteString("    A mismatch shows on the server as rejects or as no answer at all. A hex-only key avoids the\n")
		secretWarnings.WriteString("    question: tacctl scope secret " + scope + " set $(openssl rand -hex 16)   (shared with every device of the scope)\n")
	}
	if n := chars(secret); n > 32 {
		secretWarnings.WriteString("  - Secret is " + strconv.Itoa(n) + " chars. WTI documents no Secret Word maximum, but its other credential\n")
		secretWarnings.WriteString("    fields cap at 16-32 chars. A 32-char hex key is the safe choice.\n")
	}
	userWarnings := wtiUserWarnings(d, scope)

	o.echo("")
	o.echoE(ui.Bold + "WTI Console Server Configuration" + ui.NC + "  (scope: " + scope + protocolNote(req.Protocol, req.Source) + ", firmware v8.x text interface)")
	if other := otherScopes(d.Model, scope); other != "" {
		o.heading(ui.Yellow, "(other scopes: "+other+" — use --scope <name> to emit those)")
	}
	o.echoE(ui.Red + "NOT VERIFIED ON A UNIT:" + ui.NC + " this RADIUS walkthrough is written from WTI's documents")
	o.echo("(docs/radius-notes.md), not tested on a WTI device. The TACACS+ walkthrough")
	o.echo("('tacctl config wti --scope " + scope + " --protocol tacacs') was verified on a v8.10 unit.")
	o.heading(ui.Yellow, "Follow these steps on the WTI serial (SetUp) console:")
	o.echo("--------------------------------------------")
	o.echo("")
	o.write(Expand(t.Text, wtiRadiusVars, vars))
	o.rule()
	o.heading(ui.Yellow, "Group → WTI-Super (sent by the server over RADIUS, from priv-lvl):")
	o.write(vars["GROUP_SUMMARY"])
	o.echo("  (bands as for TACACS+: 0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator)")
	if !superUserBand(d) {
		o.echo("  No group lands in the SuperUser band; to grant it, add a group at")
		o.echo("  priv-lvl 10-14, e.g. 'tacctl group add wtisuper 12 OP-CLASS'.")
	}
	o.echo("")
	portAccess(o, d, "Default RADIUS User Access")
	o.summaryAccept("wti", scope, r)
	o.echo("")
	o.heading(ui.Yellow, "What RADIUS does not give you here:")
	for _, l := range []string{
		"  - Only the access level. The server sends no WTI-Port-Access, WTI-Plug-Access or",
		"    WTI-Group-Access: which ports and plugs a login reaches is the unit's own setting",
		"    (\"Port access\" above)",
		"  - No per-command authorization: the access level is all the unit is told",
		"  - Accounting is not verified: whether the unit sends any, and what (Session Module",
		"    Type), is not documented",
		"  - Password logins only (PAP; WTI documents nothing else): no CHAP, MS-CHAP or EAP",
		"  - UDP, not TCP/49: the unit sends to " + vars["AUTH_PORT"] + " (authentication) and " + vars["ACCT_PORT"] + " (accounting)",
		"  - The server answers only a unit whose source address lies in a prefix of scope",
		"    '" + scope + "' ('tacctl scope lookup <wti-ip>' to check)",
	} {
		o.echo(l)
	}
	o.echo("")
	o.heading(ui.Yellow, "Where WTI's documents disagree (not checked on a unit):")
	for _, l := range []string{
		"  - The level a login gets when the Access-Accept carries no WTI-Super: the user's guide",
		"    says Default RADIUS User Access hands out its Access Level (factory default User);",
		"    WTI's knowledge base says View only. This walkthrough sets the level to ViewOnly",
		"    explicitly, and tacctl refuses this walkthrough for a scope that sends no WTI-Super",
		"  - Whether a WTI-Super in the reply overrides a same-named LOCAL account on the unit is not",
		"    documented (for TACACS+ the local account wins): keep the two directories disjoint",
	} {
		o.echo(l)
	}
	o.echo("")
	if secretWarnings.Len() > 0 || userWarnings != "" || r.Warnings != "" {
		o.heading(ui.Yellow, "Warnings:")
		o.write(secretWarnings.String())
		o.write(userWarnings)
		o.write(r.Warnings)
		o.echo("")
	}
	o.heading(ui.Yellow, "Notes:")
	for _, l := range []string{
		"  - Fallback Local '" + vars["FALLBACK_LOCAL"] + "' mirrors this scope's aaa-order; keep a local",
		"    Administrator account on the unit as break-glass. With Fallback Local Off (the factory",
		"    default) a unit whose server is unreachable admits nobody over the services RADIUS covers",
		"  - Default RADIUS User Access On (ViewOnly) is the floor, the WTI-Super the server returns",
		"    sets the level. By analogy with TACACS+ (verified there, not here): with it Off the unit's",
		"    OpenSSH treats server-only users as invalid and every SSH login fails",
		"  - A firewall that drops the server's replies (the unit's own IP Tables without",
		"    ESTABLISHED,RELATED -- Step 5) shows on the server as an Access-Accept in the auth log for",
		"    a login that still fails on the unit after the Fallback Timer",
		"  - Repeated failures arm the unit's Invalid Access Lockout: a plain 'ssh' is then closed",
		"    without a password prompt; /UL on the serial session clears it",
		"  - Using template: " + t.Origin(),
	} {
		o.echo(l)
	}
	o.echo("")
	o.echoE(ui.Bold + "Verify on the server:" + ui.NC)
	for _, l := range []string{
		"  tacctl log tail 20 --backend radius   # one line per attempt: Access-Accept or Access-Reject,",
		"                                        # scope=" + scope + ", and nas= -- what the unit sent as its",
		"                                        # NAS-Identifier (else NAS-IP-Address). WTI documents the",
		"                                        # identifier only as starting with the product family",
		"  tacctl log failures --backend radius  # reason= says why a login was refused",
		"  tacctl scope lookup <wti-ip>          # the unit's address must answer scope '" + scope + "'",
		"  On the WTI (Step 8): with Debug On the unit logs its RADIUS exchanges; line them up with",
		"  the server's auth log above",
	} {
		o.echo(l)
	}
	o.echo("")
	return nil
}
