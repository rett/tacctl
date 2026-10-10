package devices

// The SNMP step of the walkthroughs (D41, D43, D46 of docs/plans/0.2.3-plan.md):
// the block that makes a device answer tacctl's SNMP reads (and nobody
// else's), built per vendor over one input struct. The builders read nothing
// but their input: no terminal, no tacctl.yaml, no state files, no clock. A
// later batch can render one block per device in parallel, and a push can
// reuse the text.
//
// The client list as each vendor receives it: the tacctl server's own /32
// first (tacctl must reach its devices), the scope's ranges in the order
// given, then a final 0.0.0.0/0 restrict that is always rendered and never
// stored.

import (
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/names"
)

// The names the SNMP step defines on the device.
const (
	snmpACLName   = "TACCTL-SNMP"
	snmpViewName  = "TACCTL-VIEW"
	snmpGroupName = "TACCTL-GROUP"
)

// The SNMP versions (internal/snmp's constants, repeated so this package's
// builders stay free of it).
const (
	snmpV2c = "v2c"
	snmpV3  = "v3"
)

// SNMPInput is everything a vendor's SNMP step is built from.
type SNMPInput struct {
	// Scope is the scope the walkthrough is for (named in the hints).
	Scope string
	// Version is "", v2c or v3; empty means SNMP is not configured for the
	// scope or the default beneath it, and the step says so.
	Version string
	// Community is the v2c community.
	Community string
	// V3User and the passphrases are the v3 credentials; V3Auth is sha or
	// sha256, V3Priv aes128.
	V3User, V3Auth, V3Priv, V3AuthPass, V3PrivPass string
	// CredFrom says where the credentials came from, for a comment: device,
	// scope or default (snmpcred.FromDevice, FromScope, FromDefault); empty
	// adds no line.
	CredFrom string
	// Server is the tacctl server's own address, the first client (an IPv4
	// address; anything else is rendered as a commented placeholder).
	Server string
	// Ranges are the allowed clients, as stored, in the order given: the
	// scope's, or the device's own (RangesFrom).
	Ranges []string
	// RangesFrom is "device" when Ranges are the device's own (D72 of
	// docs/plans/0.2.4-plan.md); empty is the scope's.
	RangesFrom string
	// Contact is the scope's contact; Location, SysName and Description are
	// the device's. Empty is "not set".
	Contact, Location, SysName, Description string
	// MgmtFilter says that the Junos management filter of Step 4 carries a
	// udp port 161 term for the clients below (set by the Junos builder
	// of the walkthrough).
	MgmtFilter bool
	// DeviceName is the registry name of the device the values are of (the
	// hint of the Unfilled line); empty is the placeholder <name>.
	DeviceName string
}

// Unfilled is a value the step could not fill, and the command that sets it.
type Unfilled struct{ What, Fix string }

// SNMPBlock is a vendor's SNMP step: the text for the template and the
// values left unfilled.
type SNMPBlock struct {
	Text     string
	Unfilled []Unfilled
}

// snmpGaps are the values of the SNMP step left unfilled, or none when the
// template (an operator's copy may lack the step) does not carry the step.
func (t Template) snmpGaps(b SNMPBlock) []Unfilled {
	if !strings.Contains(t.Text, "SNMP_BLOCK") {
		return nil
	}
	return b.Unfilled
}

// UnfilledLine is the line that ends a walkthrough with gaps, or "" for
// none.
func UnfilledLine(u []Unfilled) string {
	if len(u) == 0 {
		return ""
	}
	parts := make([]string, len(u))
	for i, x := range u {
		parts[i] = x.What + " (" + x.Fix + ")"
	}
	return "Unfilled SNMP values: " + strings.Join(parts, ", ")
}

// serverNet is the server's /32 entry, "" when the address is no IPv4
// address (the route lookup found none).
func (in SNMPInput) serverNet() string { return cidr.Host32(in.Server) }

// clientList is the entries the vendor renders as permits, in order: the
// server's /32 when it is known, then the scope's ranges (the server's own
// /32 not listed twice). The restrict is the builders' to add.
func (in SNMPInput) clientList() []string {
	var out []string
	server := in.serverNet()
	if server != "" {
		out = append(out, server)
	}
	for _, r := range in.Ranges {
		if r != server {
			out = append(out, r)
		}
	}
	return out
}

// missingCreds is "" when the step can be built, else why not: the credentials the
// version needs are missing, or one that is stored would be misread by a
// device CLI (a blank, '?' or a quote in a value from a hand-edited file or
// an older release: the setters refuse them now). Such a value is rendered
// as a commented NOT SET line, with the command that sets it again, never
// as a line to paste.
func (in SNMPInput) missingCreds() string {
	bad := func(s string, max int) bool { return names.SNMPTokenProblem(s, max) != "" }
	switch in.Version {
	case snmpV2c:
		if in.Community == "" || bad(in.Community, names.SNMPCommunityMax) {
			return "community"
		}
	case snmpV3:
		if in.V3User == "" || in.V3AuthPass == "" || in.V3PrivPass == "" ||
			bad(in.V3User, names.SNMPUserMax) || bad(in.V3AuthPass, names.SNMPPassphraseMax) || bad(in.V3PrivPass, names.SNMPPassphraseMax) {
			return "v3-user"
		}
	}
	return ""
}

// unfilled are the gaps shared by every vendor: what the step needs and has
// not got, in the order contact, then the credentials and the server
// address. The location is a setting of one device and is not a gap of the
// walkthrough: its placeholder line names the command that sets it.
func (in SNMPInput) unfilled() []Unfilled {
	var out []Unfilled
	if in.Contact == "" {
		out = append(out, Unfilled{"contact", "tacctl scope snmp " + in.Scope + " contact '<text>'"})
	}
	switch in.missingCreds() {
	case "community":
		out = append(out, Unfilled{"community", "tacctl scope snmp " + in.Scope + " community"})
	case "v3-user":
		out = append(out, Unfilled{"v3 user", "tacctl scope snmp " + in.Scope + " v3-user <user>"})
	}
	if in.serverNet() == "" {
		out = append(out, Unfilled{"tacctl server address", "pass --source <address>"})
	}
	return out
}

// notConfiguredLines are the lines of the step when no version is set.
func (in SNMPInput) notConfiguredLines(what string) []string {
	rows := [][2]string{
		{"tacctl scope snmp " + in.Scope + " community", "(v2c)"},
		{"tacctl scope snmp " + in.Scope + " v3-user <user>", "(v3, authPriv)"},
		{"tacctl config snmp community|v3-user", "(the default for every scope that sets none)"},
	}
	w := 0
	for _, r := range rows {
		w = max(w, len(r[0]))
	}
	l := []string{
		"SNMP is not configured in tacctl for scope '" + in.Scope + "': nothing is " + what + " here.",
		"Set it up on the tacctl server, then run this command again:",
	}
	for _, r := range rows {
		l = append(l, "  "+r[0]+strings.Repeat(" ", w-len(r[0]))+"  "+r[1])
	}
	return l
}

// notConfigured is the step's text when no version is set.
func (in SNMPInput) notConfigured(c string) string {
	return commented(c, in.notConfiguredLines("rendered"))
}

// commented prefixes every line with the vendor's comment leader.
func commented(c string, lines []string) string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = strings.TrimRight(c+" "+l, " ")
	}
	return strings.Join(out, "\n")
}

// credNote says where the credentials came from.
func (in SNMPInput) credNote() string {
	switch in.CredFrom {
	case "device":
		return "Credentials: this device's own (tacctl device snmp " + devName(in) + " show --reveal)."
	case "scope":
		return "Credentials: this scope's own (tacctl scope snmp " + in.Scope + " show --reveal)."
	case "default":
		return "Credentials: inherited from the default (tacctl config snmp), not set for scope '" + in.Scope + "'."
	}
	return ""
}

// rangesWord names the ranges after the server's /32 in a comment.
func (in SNMPInput) rangesWord() string {
	if in.RangesFrom == "device" {
		return "this device's own ranges"
	}
	return "the scope's ranges"
}

// clientNotes are the lines under the client list: the notice for a scope
// without ranges, and an unknown server address.
func (in SNMPInput) clientNotes() []string {
	var out []string
	if in.serverNet() == "" {
		out = append(out, "The tacctl server's address could not be detected: add its /32 first by hand, or pass --source <address>.")
	}
	if len(in.Ranges) == 0 {
		out = append(out, "Scope '"+in.Scope+"' has no client ranges: only the tacctl server may query (tacctl scope snmp "+in.Scope+" clients add <cidr>).")
	}
	return out
}

// verifyHint is the line that shows how to check the result from the server.
func (in SNMPInput) verifyHint() string {
	s := "Check from the tacctl server: tacctl scope snmp " + in.Scope + " test <device-address>"
	if in.SysName != "" {
		s += "   (expects sysName '" + in.SysName + "')"
	}
	return s
}

// --- Cisco -------------------------------------------------------------------

// CiscoSNMP is the SNMP step of the IOS and IOS-XE walkthroughs: a standard
// access list TACCTL-SNMP (the clients, then 'deny any' as the 0.0.0.0/0
// restrict), the community or the v3 group and user bound to it, location
// and contact.
func CiscoSNMP(in SNMPInput) SNMPBlock {
	const c = "!"
	if in.Version == "" {
		return SNMPBlock{Text: "! --- SNMP ---\n" + in.notConfigured(c)}
	}
	var b []string
	add := func(l ...string) { b = append(b, l...) }
	add("! --- SNMP (read-only; managed by tacctl) ---")
	if n := in.credNote(); n != "" {
		add("! " + n)
	}
	add("! Allowed clients: the tacctl server first, " + in.rangesWord() + ", then everything else (0.0.0.0/0) refused.")
	for _, n := range in.clientNotes() {
		add("! " + n)
	}
	add("! If TACCTL-SNMP already exists on the device, its old lines stay: 'no ip access-list standard " + snmpACLName + "' first.")
	add("ip access-list standard " + snmpACLName)
	if in.serverNet() == "" {
		add("  remark the tacctl server's address is not known: add 'permit host <address>' first")
	}
	for _, r := range in.clientList() {
		if p := cidr.CiscoPermit(r); p != "" {
			add("  permit " + p)
		}
	}
	add("  remark everything else (0.0.0.0/0) is refused", "  deny   any")
	add("!")
	if missing := in.missingCreds(); missing != "" {
		if missing == "community" {
			add("! snmp-server community <community> RO " + snmpACLName + "   ! NOT SET: tacctl scope snmp " + in.Scope + " community")
		} else {
			add("! snmp-server user <user> " + snmpGroupName + " v3 auth sha <passphrase> priv aes 128 <passphrase>   ! NOT SET: tacctl scope snmp " + in.Scope + " v3-user <user>")
		}
	} else if in.Version == snmpV2c {
		add("snmp-server community " + in.Community + " RO " + snmpACLName)
	} else {
		auth := "sha"
		if in.V3Auth == "sha256" {
			auth = "sha256"
			add("! SHA-256 for SNMPv3 users needs a release that has it; the keyword is not verified on a device.")
		}
		add("snmp-server view "+snmpViewName+" iso included",
			"snmp-server group "+snmpGroupName+" v3 priv read "+snmpViewName+" access "+snmpACLName,
			"snmp-server user "+in.V3User+" "+snmpGroupName+" v3 auth "+auth+" "+in.V3AuthPass+" priv aes 128 "+in.V3PrivPass)
	}
	add("!")
	if in.Location != "" {
		add("snmp-server location " + in.Location)
	} else {
		add("! snmp-server location <location>   ! NOT SET: tacctl device location " + devName(in) + " '<text>'")
	}
	if in.Contact != "" {
		add("snmp-server contact " + in.Contact)
	} else {
		add("! snmp-server contact <contact>   ! NOT SET: tacctl scope snmp " + in.Scope + " contact '<text>'")
	}
	add("! " + in.verifyHint())
	return SNMPBlock{Text: strings.Join(b, "\n"), Unfilled: in.unfilled()}
}

func devName(in SNMPInput) string {
	if in.DeviceName != "" {
		return in.DeviceName
	}
	return "<name>"
}

// --- Junos -------------------------------------------------------------------

// junosQuote is s as a Junos string: in double quotes, with a backslash and
// a double quote escaped.
func junosQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// JuniperSNMP is the SNMP step of the Junos walkthroughs: a client list
// TACCTL-SNMP (the clients, then '0.0.0.0/0 restrict'), the community
// read-only and bound to it, or the v3 usm user with its vacm group and
// view, and location, contact and description.
func JuniperSNMP(in SNMPInput) SNMPBlock {
	const c = "#"
	if in.Version == "" {
		return SNMPBlock{Text: in.notConfigured(c)}
	}
	var b []string
	add := func(l ...string) { b = append(b, l...) }
	add("# Read-only; managed by tacctl.")
	if n := in.credNote(); n != "" {
		add("# " + n)
	}
	add("# Allowed clients: the tacctl server first, " + in.rangesWord() + ", then everything else (0.0.0.0/0) refused.")
	for _, n := range in.clientNotes() {
		add("# " + n)
	}
	if in.serverNet() == "" {
		add("# set snmp client-list " + snmpACLName + " <tacctl-server-address>/32   (its address is not known)")
	}
	for _, r := range in.clientList() {
		add("set snmp client-list " + snmpACLName + " " + r)
	}
	add("set snmp client-list " + snmpACLName + " 0.0.0.0/0 restrict")
	if missing := in.missingCreds(); missing != "" {
		if missing == "community" {
			add("# set snmp community <community> authorization read-only   (NOT SET: tacctl scope snmp " + in.Scope + " community)")
		} else {
			add("# set snmp v3 usm local-engine user <user> ...   (NOT SET: tacctl scope snmp " + in.Scope + " v3-user <user>)")
		}
	} else if in.Version == snmpV2c {
		add("set snmp community "+in.Community+" authorization read-only",
			"set snmp community "+in.Community+" client-list-name "+snmpACLName)
	} else {
		authKW := "authentication-sha"
		if in.V3Auth == "sha256" {
			authKW = "authentication-sha256"
			add("# SHA-256 for SNMPv3 users needs a release that has it; the keyword is not verified on a device.")
		}
		u := "set snmp v3 usm local-engine user " + in.V3User
		add(u+" "+authKW+" authentication-password "+junosQuote(in.V3AuthPass),
			u+" privacy-aes128 privacy-password "+junosQuote(in.V3PrivPass),
			"set snmp v3 vacm security-to-group security-model usm security-name "+in.V3User+" group "+snmpGroupName,
			"set snmp v3 vacm access group "+snmpGroupName+" default-context-prefix security-model usm security-level privacy read-view "+snmpViewName,
			"set snmp view "+snmpViewName+" oid .1 include",
			"# The client list binds to communities only: it does not restrict a v3 user (not verified on a device).")
		if in.MgmtFilter {
			add("# The management filter of Step 4 does: its permit-snmp and deny-snmp terms accept udp port 161 from the",
				"# clients above only, once you apply the filter to lo0.")
		} else {
			add("# No management filter with a udp port 161 term is rendered (Step 4): without one on lo0 a v3 user is",
				"# not restricted to the clients above.")
		}
	}
	if in.Location != "" {
		add("set snmp location " + junosQuote(in.Location))
	} else {
		add("# set snmp location \"<location>\"   (NOT SET: tacctl device location " + devName(in) + " '<text>')")
	}
	if in.Contact != "" {
		add("set snmp contact " + junosQuote(in.Contact))
	} else {
		add("# set snmp contact \"<contact>\"   (NOT SET: tacctl scope snmp " + in.Scope + " contact '<text>')")
	}
	if strings.Contains(in.Description, "?") {
		// Stored before the setters refused it: a pasted '?' is a request
		// for help on a Junos CLI.
		add("# set snmp description " + junosQuote(in.Description) + "   (NOT SET: the description holds '?', which a CLI reads as help; tacctl device description " + devName(in) + " '<text>')")
	} else if in.Description != "" {
		add("set snmp description " + junosQuote(in.Description))
	}
	add("# " + in.verifyHint())
	return SNMPBlock{Text: strings.Join(b, "\n"), Unfilled: in.unfilled()}
}

// --- WTI ---------------------------------------------------------------------

// WTISNMP is the SNMP step of the WTI walkthroughs, in the template's menu
// style. The menu's labels are from WTI's documents and the client
// restriction is the udp/161 lines of the unit's IP Tables list (D42,
// iptables.go); none of it is verified on a unit.
func WTISNMP(in SNMPInput) SNMPBlock {
	pre := "        "
	if in.Version == "" {
		l := in.notConfiguredLines("listed")
		for i := range l {
			l[i] = pre + l[i]
		}
		return SNMPBlock{Text: strings.Join(l, "\n")}
	}
	var b []string
	add := func(l ...string) {
		for _, x := range l {
			b = append(b, pre+x)
		}
	}
	add("Not verified on a unit: the menu item names below are from WTI's documents.")
	if n := in.credNote(); n != "" {
		add(n)
	}
	add("/N [Enter]              Network Parameters",
		"<n> [Enter]             SNMP Parameters -- the item number varies by model/firmware;",
		"                        pick the entry labelled \"SNMP\"",
		"Set each item (type the item number, [Enter], then the value):")
	value := func(label, v string) { add("  " + padLabel(label) + ": " + v) }
	if missing := in.missingCreds(); missing != "" {
		if missing == "community" {
			value("Read-only Community", "(NOT SET: tacctl scope snmp "+in.Scope+" community)")
		} else {
			value("SNMPv3 User", "(NOT SET: tacctl scope snmp "+in.Scope+" v3-user <user>)")
		}
	} else if in.Version == snmpV2c {
		value("Version", "v2c")
		value("Read-only Community", in.Community)
	} else {
		auth := "SHA"
		if in.V3Auth == "sha256" {
			auth = "SHA-256"
		}
		value("Version", "v3 (authPriv)")
		value("SNMPv3 User", in.V3User)
		value("Authentication Protocol", auth)
		value("Authentication Passphrase", in.V3AuthPass)
		value("Privacy Protocol", "AES-128")
		value("Privacy Passphrase", in.V3PrivPass)
	}
	if in.Location != "" {
		value("Location", in.Location)
	} else {
		value("Location", "(NOT SET: tacctl device location "+devName(in)+" '<text>')")
	}
	if in.Contact != "" {
		value("Contact", in.Contact)
	} else {
		value("Contact", "(NOT SET: tacctl scope snmp "+in.Scope+" contact '<text>')")
	}
	b = append(b, "")
	add("Client restriction (not verified on a unit): the udp port 161 lines of the IP Tables list (Step 5) are",
		"  the restriction: they accept SNMP only from the clients below and the final DROP (last step) refuses",
		"  the rest. If the unit has an SNMP access menu of its own, enter the same clients there instead.")
	for _, n := range in.clientNotes() {
		add("  " + n)
	}
	for _, e := range in.clientList() {
		add("  allow  " + e)
	}
	add("  refuse 0.0.0.0/0 (everything else)",
		"  "+in.verifyHint())
	return SNMPBlock{Text: strings.Join(b, "\n"), Unfilled: in.unfilled()}
}

// padLabel pads a menu label to the width of the longest.
func padLabel(s string) string {
	const w = 26
	for len(s) < w {
		s += " "
	}
	return s
}

// --- NETCONF (D53) -------------------------------------------------------------

// NetconfInput is what the NETCONF step needs.
type NetconfInput struct {
	// Restricted is an engineer's walkthrough: the Cisco step is a
	// superuser's, and says to ask one.
	Restricted bool
	// Legacy is the IOS 12.x walkthrough, which has no NETCONF.
	Legacy bool
	// MgmtFilter says that the walkthrough renders a management filter
	// (Junos), which already permits tcp/830 next to ssh.
	MgmtFilter bool
}

// JuniperNetconf is the Junos NETCONF step: commented, to review and
// uncomment. Nothing is enabled by tacctl.
func JuniperNetconf(in NetconfInput) string {
	l := []string{
		"# NETCONF over ssh is off by default. Review, then uncomment to enable it:",
		"#   set system services netconf ssh",
		"# Optional limits (uncomment and adjust):",
		"#   set system services netconf ssh connection-limit 5",
		"#   set system services netconf ssh rate-limit 10",
	}
	if in.MgmtFilter {
		l = append(l,
			"# The management filter of Step 4 permits tcp port 830 next to ssh from the same",
			"# sources, so enabling NETCONF needs no filter change.")
	} else {
		l = append(l,
			"# No management filter is rendered (Step 4): when you add one, permit tcp port 830",
			"# next to ssh from the same sources.")
	}
	l = append(l,
		"# Who may use it is decided by the login class bits of the user (the template users",
		"# of Step 1), not by this step.",
		"# Check after the commit, from a permitted address:",
		"#   ssh -p 830 -s <user>@<device> netconf     (expect a <hello> from the device)",
		"# and on the device:",
		"#   show system connections | match \"\\.830 \"")
	return strings.Join(l, "\n")
}

// CiscoNetconf is the IOS-XE NETCONF step: commented, for superusers; an
// engineer's walkthrough says to ask one, and IOS 12.x has none.
func CiscoNetconf(in NetconfInput) string {
	switch {
	case in.Legacy:
		return commented("!", []string{"--- NETCONF ---", "NETCONF (netconf-yang) does not exist on IOS 12.x."})
	case in.Restricted:
		return commented("!", []string{"--- NETCONF ---",
			"NETCONF (netconf-yang) is enabled by a superuser: ask one to run 'tacctl config cisco' for this scope.",
		})
	}
	return commented("!", []string{
		"--- NETCONF (optional; IOS-XE; review, then uncomment) ---",
		"Prerequisite: exec authorization above ('aaa authorization exec default ...') and a",
		"privilege 15 user, because NETCONF logs in over ssh and takes its privilege from them.",
		"netconf-yang",
		"Check: show netconf-yang status",
		"       ssh -p 830 -s <user>@<device> netconf     (expect a <hello> from the device)",
	})
}

// netconfDoesNotExistWTI is the WTI walkthroughs' line on NETCONF.
const netconfDoesNotExistWTI = "NETCONF does not exist on the unit (it has a text interface over ssh and a serial port only)"
