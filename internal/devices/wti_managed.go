package devices

// The managed sections of a WTI unit (0.2.7, design W7-W10): the statements
// tacctl would render for one unit, in the vocabulary of the unit's page
// tables (internal/devconf/wti/canon.go: one 'key value' line per item of a
// menu page, a pick as a lower-case word, a number bare, a text quoted when it
// holds a blank, one 'iptables <command>' per entry of the IP tables list).
//
// A unit has no configuration listing and a walkthrough of menu steps, so the
// statements are not lines of the walkthrough as they are for Junos and IOS.
// They are built from the walkthrough's own builders (WTIVars, WTIIPTables,
// WTISNMP's input and BreakGlassFor), never from the template text: what a
// walkthrough tells the unit and what a pull expects of it cannot drift, and
// the test that every statement's value is in the walkthrough of the same
// input (wti_managed_test.go) keeps the few constants honest.
//
// What the pull cannot see, or the walkthrough does not say, is not
// rendered, so a unit is never told it lacks what tacctl does not render:
// the RADIUS secondary server and its secret, the one-time authentication
// timer and type, the session module type and the message authenticator (the
// walkthrough leaves them alone), the default access page of RADIUS (the page
// is not read, design W3), a unit's system name, its trap settings and the
// tail of the IP tables list (the unit's own, the planner keeps them), and
// every value the scope leaves unset (no server address, no contact or
// location, no community, no secret, no permit list).

import (
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
)

// managedWTI is Managed for a WTI unit: aaa, mgmt-acl, snmp and breakglass,
// in the order the other vendors use. The sections roles, netconf and system
// have nothing on a unit.
func managedWTI(req Request, d Data) []Section {
	v := WTIVars(req, d)
	s := &sections{secret: wtiSecret}

	s.add(sectionAAA, wtiAAA(req.Protocol == RADIUS, v))
	s.add(sectionMgmtACL, wtiMgmtACL(req, d))
	s.add(sectionSNMP, wtiSNMPStatements(d.snmpInput(req.Scope)))
	s.add(sectionBreakGlass, wtiBreakGlassStatements(BreakGlassFor(req, d)))
	return s.out
}

// wtiAAA are the statements of the protocol's page (Step 3 of its
// walkthrough, in the order of the steps): the page of the other protocol is
// the unit's own and says nothing here.
func wtiAAA(radius bool, v map[string]string) []string {
	var out []string
	add := func(key, value string) {
		if value != "" {
			out = append(out, key+" "+value)
		}
	}
	server := wtiAddress(v["SERVER_IP"])
	fallback := wtiSlug(v["FALLBACK_LOCAL"])
	if radius {
		add("radius enable", "on")
		add("radius primary", server)
		add("radius primary-secret", v["SECRET"])
		add("radius fallback-timer", "3")
		add("radius fallback-local", fallback)
		add("radius retries", "3")
		add("radius port", v["AUTH_PORT"])
		add("radius accounting-port", v["ACCT_PORT"])
		add("radius onetime-auth", "off")
		add("radius default-access", "on")
		add("radius debug", "off")
		return out
	}
	add("tacacs enable", "on")
	add("tacacs primary", server)
	add("tacacs secret", v["SECRET"])
	add("tacacs fallback-timer", "15")
	add("tacacs fallback-local", fallback)
	add("tacacs port", "49")
	// Item 8, Default User Access: its page's level and services.
	add("tacacs default-access", "on")
	add("tacacs default-level", "viewonly")
	add("tacacs default-services", "telnet-ssh")
	add("tacacs account-module", "enabled")
	add("tacacs session-module", "enabled")
	add("tacacs service-name", wtiQuote(v["SERVICE_NAME"]))
	add("tacacs debug", "off")
	return out
}

// wtiMgmtACL are the entries of Step 5 (the commands of the list, in order;
// the final DROP and the policies of the last step are the walkthrough's,
// pasted by the operator, and not part of it). A scope with no permit list is
// told no list (the list would admit only the server and the unit's own
// traffic, and the plan that makes the unit's list that one would cut every
// other administrator off at the unit's final DROP), and neither is a list the
// builder could not fill (the server's address is not known).
func wtiMgmtACL(req Request, d Data) []string {
	in := d.iptablesInput(req.Scope)
	if permits, _ := iptablesNets(in.Permits, cidr.Host32(in.Server)); len(permits) == 0 {
		return nil
	}
	b := WTIIPTables(in)
	if len(b.Unfilled) > 0 {
		return nil
	}
	return b.Commands
}

// wtiSNMPStatements are the statements of the SNMP step: the access page's
// switch, version, read-only mark, contact, location and community. A scope
// with no version is not configured and renders none.
//
// SNMP access is enabled and read-only on a unit that follows the step: the
// step names the version, the community, the location and the contact, and
// sets nothing that makes the unit writable. A v3 scope's user statements are
// the builder's (user, protocols, passphrases); the unit's V3 users are not
// read in 0.2.7 (the comparison marks the section n/a).
func wtiSNMPStatements(in SNMPInput) []string {
	if in.Version == "" {
		return nil
	}
	out := []string{"snmp enable on"}
	missing := in.missingCreds()
	switch in.Version {
	case snmpV2c:
		out = append(out, "snmp version v1-v2-only")
	case snmpV3:
		out = append(out, "snmp version v3")
	}
	out = append(out, "snmp read-only yes")
	if c := strings.TrimSpace(in.Contact); c != "" {
		out = append(out, "snmp contact "+wtiQuote(c))
	}
	if l := strings.TrimSpace(in.Location); l != "" {
		out = append(out, "snmp location "+wtiQuote(l))
	}
	switch {
	case missing != "":
	case in.Version == snmpV2c:
		out = append(out, "snmp ro-community "+in.Community)
	default:
		auth := "sha"
		if in.V3Auth == "sha256" {
			auth = "sha-256"
		}
		out = append(out,
			"snmp v3 user "+in.V3User,
			"snmp v3 auth-protocol "+auth,
			"snmp v3 auth-passphrase "+in.V3AuthPass,
			"snmp v3 privacy-protocol aes-128",
			"snmp v3 privacy-passphrase "+in.V3PrivPass)
	}
	return out
}

// wtiBreakGlassStatements are the local accounts of Step 10: the name with
// its access level (the group's 'wti-level' override when it has one, as the
// walkthrough's mapping table), and the password placeholder the operator
// replaces (tacctl stores no credential; the unit shows only that one is
// set).
func wtiBreakGlassStatements(in BreakGlassInput) []string {
	var out []string
	for _, u := range in.Users {
		name := wtiQuote(u.Name)
		out = append(out,
			"user "+name+" level "+strings.ToLower(in.Level[u.Role]),
			"user "+name+" password "+breakGlassPassword)
	}
	return out
}

// reWTISecret is a WTI statement that carries a secret: a server's secret, an
// SNMP community (the string is the secret) or v3 passphrase, a local user's
// password. The unit shows these as '(defined)' or, for a community, in
// clear; they are compared by presence or by label.
var reWTISecret = regexp.MustCompile(`^(` +
	`(tacacs secret|radius (primary|secondary)-secret|snmp (ro|rw)-community|snmp trap community) ` +
	`|snmp v3 (auth|privacy)-passphrase ` +
	`|user (\S+|"[^"]*") password ` +
	`)`)

func wtiSecret(line string) bool { return reWTISecret.MatchString(line) }

// wtiAddress is the server address a walkthrough names, "" when it names
// none (the route lookup found none, or the variable is a placeholder).
func wtiAddress(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == UnknownServer || strings.HasPrefix(s, "<") {
		return ""
	}
	return s
}

// wtiQuote writes a text value as the unit's statements do: bare, or in
// double quotes when it holds a blank.
func wtiQuote(v string) string {
	if v != "" && strings.ContainsAny(v, " \t") {
		return `"` + v + `"`
	}
	return v
}

// wtiSlug is a pick's printed text as one lower-case word, as the page
// tables read it: 'On (Transport Failure)' is 'on-transport-failure'.
func wtiSlug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		default:
			dash = true
		}
	}
	return b.String()
}

// WTIListFacts are what the plan of a unit needs of the IP tables builder
// that the rendered statements do not say: the address the list must permit
// for tacctl's own queries ("" when it is not known), and why the list was
// not rendered although the scope has a permit list (the builder's unfilled
// value), "" when it was or the scope has none.
func WTIListFacts(req Request, d Data) (server, why string) {
	in := d.iptablesInput(req.Scope)
	host := cidr.Host32(in.Server)
	server = strings.TrimSuffix(host, "/32")
	if permits, _ := iptablesNets(in.Permits, host); len(permits) == 0 {
		return server, ""
	}
	if b := WTIIPTables(in); len(b.Unfilled) > 0 {
		return server, b.Unfilled[0].What + " is not known (" + b.Unfilled[0].Fix + ")"
	}
	return server, ""
}
