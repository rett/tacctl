package plan

// The ownership table of a WTI console server (0.2.7, design W7-W10): data
// for the planner of a later change, and the resolver that names the row of
// a statement. A unit's statements are the canonical 'key value' lines of its
// menu pages (internal/devconf/wti): a setting is one item with one value, so
// a rendered value replaces the unit's in place (ModeSingle) and what the
// rendering does not set is the unit's own. The IP tables list is one ordered
// object: any difference rewrites the whole list, as the unit's bulk paste
// does (ModeList).
//
// The rows whose Kept column the comparison treats as the device's own are
// the shapes of devconf's KeptShapes(FamilyWTI), named by Row; a test keeps
// the two in step. A Kept column that names a finding (a second server, a
// read/write community, an account nobody recorded) is kept by the planner
// and listed as a difference, never removed unless the person asks for it
// (--converge). A contact, location or read-only community the device has
// and tacctl renders none of is the same: left as it is, and a difference.
//
// Patterns are the statement's words ('$' is an object's number or name); a
// pattern with alternatives in parentheses names several keys of one row, as
// the IOS rows do, and WTIRowID is the matcher.

import (
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// wtiOwned is the table for a WTI unit.
var wtiOwned = []OwnedRow{
	{ID: "wti.aaa.tacacs", Section: "aaa", Pattern: "tacacs", Mode: ModeSingle,
		Why:  "the TACACS+ settings tacctl renders (server, secret word, timer, fallback, port, default access, modules, service name, debug), each set to the rendered value",
		Kept: "the secondary host and the secret word when tacctl renders none"},
	{ID: "wti.aaa.radius", Section: "aaa", Pattern: "radius", Mode: ModeSingle,
		Why:  "the RADIUS settings tacctl renders (server, secret, timer, fallback, retries, ports, default access, one-time authentication, debug), each set to the rendered value",
		Kept: "the secondary host"},
	{ID: "wti.aaa.radius-unrendered", Section: "aaa", Pattern: "radius (secondary-secret|onetime-timer|onetime-type|session-module|message-authenticator|default-level|default-services)", Mode: ModeSingle,
		Why:  "the RADIUS items the walkthrough leaves alone are not set",
		Kept: "the secondary secret word, the one-time authentication timer and type, the session module type, the message authenticator and the default access level and services"},
	{ID: "wti.aaa.inactive-protocol", Section: "aaa", Pattern: "(tacacs|radius)", Mode: ModeRenderedLeaves,
		Why:  "only the page of the protocol the scope uses is set",
		Kept: "the whole page of the protocol the scope does not use while the unit has it turned off"},

	{ID: "wti.snmp.access", Section: "snmp", Pattern: "snmp (enable|version|read-only)", Mode: ModeSingle,
		Why: "the SNMP access switch, version and read-only mark tacctl renders", Kept: ""},
	{ID: "wti.snmp.contact", Section: "snmp", Pattern: "snmp contact", Mode: ModeSingle,
		Why: "the contact tacctl renders", Kept: "the contact when tacctl renders none"},
	{ID: "wti.snmp.location", Section: "snmp", Pattern: "snmp location", Mode: ModeSingle,
		Why: "the location tacctl renders", Kept: "the location when tacctl renders none"},
	{ID: "wti.snmp.ro-community", Section: "snmp", Pattern: "snmp ro-community", Mode: ModeSingle,
		Why:  "the read-only community tacctl renders (compared by label, typed by value)",
		Kept: ""},
	{ID: "wti.snmp.rw-community", Section: "snmp", Pattern: "snmp rw-community", Mode: ModeSingle,
		Why:  "the read/write community: tacctl renders none, so the unit's is a finding, cleared only on request (--converge)",
		Kept: "the read/write community"},
	{ID: "wti.snmp.system-name", Section: "snmp", Pattern: "snmp system-name", Mode: ModeSingle,
		Why: "the unit's system name is its own", Kept: "the system name"},
	{ID: "wti.snmp.trap-manager", Section: "snmp", Pattern: "snmp trap manager $", Mode: ModeSingle,
		Why: "the trap managers are the unit's own", Kept: "every trap manager"},
	{ID: "wti.snmp.trap-community", Section: "snmp", Pattern: "snmp trap community", Mode: ModeSingle,
		Why: "the trap community is the unit's own", Kept: "the trap community"},
	{ID: "wti.snmp.trap-version", Section: "snmp", Pattern: "snmp trap version", Mode: ModeSingle,
		Why: "the trap version is the unit's own", Kept: "the trap version"},
	{ID: "wti.snmp.trap-engine-id", Section: "snmp", Pattern: "snmp trap engine-id", Mode: ModeSingle,
		Why: "the V3 trap engine id is the unit's own", Kept: "the V3 trap engine id"},
	{ID: "wti.snmp.v3", Section: "snmp", Pattern: "snmp v3 <setting>", Mode: ModeSingle,
		Why:  "the SNMPv3 user tacctl renders: the unit's V3 users are not read in 0.2.7, so a v3 scope's section is not compared and not planned",
		Kept: "the unit's V3 users"},

	{ID: "wti.mgmt-acl.list", Section: "mgmt-acl", Pattern: "iptables", Mode: ModeList, Ordered: true,
		Why:  "the IP tables list tacctl renders (its entries and their order): any difference rewrites the whole list, as the unit's bulk paste does",
		Kept: "the tail of the list when the unit has it (the final DROP, the OUTPUT ACCEPT and the three policies of the walkthrough's last step), in place"},

	{ID: "wti.breakglass.level", Section: "breakglass", Pattern: "user $ level", Mode: ModeSingle,
		Why:  "the access level of the accounts the scope names",
		Kept: "every other account of the unit's directory (a finding when nobody recorded it)"},
	{ID: "wti.breakglass.password", Section: "breakglass", Pattern: "user $ password", Mode: ModeSingle,
		Why:  "the password of a recorded account: a value the person keeps (tacctl stores none), asked for and never typed as the placeholder",
		Kept: "the account's other credentials (authorization keys, API token)"},
}

// wtiRadiusLeftAlone are the RADIUS items the walkthrough leaves alone.
var wtiRadiusLeftAlone = map[string]bool{
	"secondary-secret": true, "onetime-timer": true, "onetime-type": true, "session-module": true,
	"message-authenticator": true, "default-level": true, "default-services": true,
}

// WTIRowID is the ownership row of a statement of a unit's section ("" for a
// statement of no row). proto is the protocol the rendering is for (tacacs or
// radius; "" when it has none): a statement of the other protocol's page is
// the unit's own page of an unused protocol.
func WTIRowID(section, stmt, proto string) string {
	w := strings.Fields(stmt)
	if len(w) < 2 {
		return ""
	}
	switch section {
	case devconf.SectionAAA:
		switch w[0] {
		case "tacacs", "radius":
			switch {
			case proto != "" && w[0] != proto:
				return "wti.aaa.inactive-protocol"
			case w[0] == "radius" && wtiRadiusLeftAlone[w[1]]:
				return "wti.aaa.radius-unrendered"
			}
			return "wti.aaa." + w[0]
		}
	case devconf.SectionSNMP:
		if w[0] != "snmp" {
			return ""
		}
		switch k := w[1]; {
		case k == "enable" || k == "version" || k == "read-only":
			return "wti.snmp.access"
		case k == "contact" || k == "location" || k == "ro-community" || k == "rw-community" || k == "system-name":
			return "wti.snmp." + k
		case k == "trap" && len(w) >= 3:
			switch w[2] {
			case "manager", "community", "version", "engine-id":
				return "wti.snmp.trap-" + w[2]
			}
		case strings.HasPrefix(k, "v3"):
			return "wti.snmp.v3"
		}
	case devconf.SectionMgmtACL:
		if w[0] == "iptables" {
			return "wti.mgmt-acl.list"
		}
	case devconf.SectionBreakGlass:
		if w[0] == "user" && len(w) >= 3 {
			switch w[2] {
			case "level":
				return "wti.breakglass.level"
			case "password", "keys", "api-token":
				return "wti.breakglass.password"
			}
		}
	}
	return ""
}
