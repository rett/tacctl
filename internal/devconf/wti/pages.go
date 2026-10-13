// Package wti reads the screens of a WTI console server's command menu
// (version 8.10, docs/plans/wti-interface.md) into the fields tacctl
// manages, and defines the canonical statements those fields become.
//
// The unit has no configuration listing: its settings are the items of
// numbered menu pages. A page table (Pages) declares every page tacctl
// opens, by path and title, with each item's number, label, statement key,
// value parser, section, risk class and whether its value is a secret. A
// screen whose title is in no row is refused (ErrUnknownPage) and nothing
// further is read from it; a known page whose layout is not the table's is
// refused too (ErrLayout). Both errors name the title only, never a value:
// a screen may hold a secret (a community is printed in clear).
//
// The package is pure text: no terminal, no network. The terminal walker
// that produces a Document's text is the reader's (internal/devconf's
// ReadWTI); the section extraction and comparison are internal/devconf's.
package wti

import (
	"regexp"
	"strings"
)

// Version is the command menu version the tables were verified on.
const Version = "8.10"

// The managed sections the statements are in (the names devconf uses).
const (
	SectionAAA        = "aaa"
	SectionSNMP       = "snmp"
	SectionMgmtACL    = "mgmt-acl"
	SectionBreakGlass = "breakglass"
)

// Kind is the kind of a page.
type Kind string

// The kinds of page the tables hold. Only these are ever opened. A page
// that asks for input (a number, a pick or a secret prompt) is not in the
// table, so the reader never enters one; the exception is KindPrompt, the
// text prompts of the three SNMP texts, which are entered to read a value
// and left with ESC.
const (
	// KindMenu: numbered items with their current values.
	KindMenu Kind = "menu"
	// KindList: numbered slots (the IP tables).
	KindList Kind = "list"
	// KindStatus: the network status table (/SN).
	KindStatus Kind = "status"
	// KindHelp: the command menu (/H).
	KindHelp Kind = "help"
	// KindLine: a one-line display (/J).
	KindLine Kind = "line"
	// KindUsers: the user directory's list of names.
	KindUsers Kind = "users"
	// KindPrompt: the text prompt page of an item whose menu value is
	// printed truncated ('...'). The page prints the item's whole value
	// under its footer, and leaves it unchanged on ESC. The reader opens it
	// with the item's number and a CR, and leaves it with ESC: nothing is
	// ever typed at it. The table holds no prompt row of a secret.
	KindPrompt Kind = "prompt"
)

// Risk is the risk class of changing a setting (wti-interface.md section 6).
type Risk string

const (
	// RiskSafe: no effect on the way in.
	RiskSafe Risk = "safe"
	// RiskGuarded: can lock out the AAA path; needs the verification.
	RiskGuarded Risk = "guarded"
	// RiskForbidden: can lock out the management path; never changed
	// remotely.
	RiskForbidden Risk = "forbidden"
)

// Item is one numbered item of a page.
type Item struct {
	Number int
	// Label is the item's name as the page prints it, compared without
	// regard to case. A page whose item of this number has another label is
	// not the page of the table.
	Label string
	// Key is the statement key the item's value becomes ("tacacs primary").
	// It is "" for an item that is read as a fact only, or not at all. In a
	// user's page a "{user}" in the key stands for the user's name.
	Key string
	// Fact names the fact the value is kept as when Key is "".
	Fact string
	// Parse turns the printed value into its canonical form; "" is a
	// setting that is not set ("(undefined)", an empty value).
	Parse Parser
	// Form is the statement's value form (Key is set).
	Form Form
	// Section is the section the statement is in.
	Section string
	Risk    Risk
	// Secret marks an item whose value is a secret or a credential: it is
	// kept as a presence only, never as a value.
	Secret bool
	// Optional: the page may lack the item (another model or build).
	Optional bool
}

// Page is one page of the table.
type Page struct {
	// Path is the keys typed from the prompt ("/N > 28 > 8"), as the
	// document's page header names them; "<name>" stands for a user's name.
	Path string
	// Name is a short word for the page.
	Name  string
	Title *regexp.Regexp
	Kind  Kind
	// Columns: the page prints two columns of items (the network menu).
	Columns bool
	Items   []Item
	// Required says a document is not complete without the page.
	Required bool
}

var (
	reScope  = `(?:\s+\[[^\]]{1,24}\])?`
	reIPv    = `(?:\s+IPv[46])?`
	reNoTail = `\s*$`
)

// Pages is the page table. The order is the order statements are listed
// in.
var Pages = []Page{
	{Path: "/H", Name: "help", Kind: KindHelp,
		Title: regexp.MustCompile(`^COMMAND MENU:\s+Version\s+(\d+(?:\.\d+)*)\s*$`)},
	{Path: "/SN", Name: "status", Kind: KindStatus,
		Title: regexp.MustCompile(`^NETWORK STATUS:`)},
	{Path: "/J", Name: "site", Kind: KindLine,
		Title: regexp.MustCompile(`^Site ID:\s*(.*)$`)},
	{Path: "/N", Name: "network", Kind: KindMenu, Columns: true,
		Title: regexp.MustCompile(`^NETWORK PARAMETERS:` + reScope + reIPv + `(?:\s+.*)?$`),
		Items: []Item{
			{Number: 5, Label: "IP Tables", Fact: "iptables", Parse: pPick, Optional: true},
			{Number: 25, Label: "SNMP Access", Fact: "snmp", Parse: pPick, Optional: true},
			{Number: 26, Label: "SNMP Trap", Fact: "snmp-trap", Parse: pPick, Optional: true},
			{Number: 28, Label: "TACACS", Fact: "tacacs", Parse: pPick, Optional: true},
			{Number: 29, Label: "RADIUS", Fact: "radius", Parse: pPick, Optional: true},
			{Number: 31, Label: "Multiple Logins", Fact: "multiple-logins", Parse: pPick, Optional: true},
		}},
	{Path: "/N > 25", Name: "snmp", Kind: KindMenu, Required: true,
		Title: regexp.MustCompile(`^SNMP ACCESS:` + reScope + reIPv + reNoTail),
		Items: []Item{
			{Number: 1, Label: "Enable", Key: "snmp enable", Parse: pOnOff, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 2, Label: "Version", Key: "snmp version", Parse: pPick, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 3, Label: "Read Only", Key: "snmp read-only", Parse: pYesNo, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 4, Label: "System Name", Key: "snmp system-name", Parse: pText, Form: FormText, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 5, Label: "Contact", Key: "snmp contact", Parse: pText, Form: FormText, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 6, Label: "SNMP Location", Key: "snmp location", Parse: pText, Form: FormText, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 7, Label: "Read-Only Community", Key: "snmp ro-community", Parse: pCommunity, Form: FormCommunity, Section: SectionSNMP, Risk: RiskSafe, Secret: true},
			{Number: 8, Label: "Read/Write Community", Key: "snmp rw-community", Parse: pCommunity, Form: FormCommunity, Section: SectionSNMP, Risk: RiskSafe, Secret: true},
			{Number: 9, Label: "V3 Users", Parse: pAny, Optional: true},
		}},
	// The text prompts of the three texts the menu prints truncated: the
	// whole value follows the footer. Each row's item is the menu item of the
	// same number and key; the prompt's value replaces the menu's.
	{Path: "/N > 25 > 4", Name: "snmp-system-name", Kind: KindPrompt,
		Title: regexp.MustCompile(`^SYSTEM NAME:` + reNoTail),
		Items: []Item{
			{Number: 4, Label: "System Name", Key: "snmp system-name", Parse: pText, Form: FormText, Section: SectionSNMP, Risk: RiskSafe},
		}},
	{Path: "/N > 25 > 5", Name: "snmp-contact", Kind: KindPrompt,
		Title: regexp.MustCompile(`^CONTACT:` + reNoTail),
		Items: []Item{
			{Number: 5, Label: "Contact", Key: "snmp contact", Parse: pText, Form: FormText, Section: SectionSNMP, Risk: RiskSafe},
		}},
	{Path: "/N > 25 > 6", Name: "snmp-location", Kind: KindPrompt,
		Title: regexp.MustCompile(`^SNMP LOCATION:` + reNoTail),
		Items: []Item{
			{Number: 6, Label: "SNMP Location", Key: "snmp location", Parse: pText, Form: FormText, Section: SectionSNMP, Risk: RiskSafe},
		}},
	{Path: "/N > 26", Name: "trap", Kind: KindMenu, Required: true,
		Title: regexp.MustCompile(`^SNMP TRAP:` + reScope + reIPv + reNoTail),
		Items: []Item{
			{Number: 1, Label: "Manager 1", Key: "snmp trap manager 1", Parse: pAddr, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 2, Label: "Manager 2", Key: "snmp trap manager 2", Parse: pAddr, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 3, Label: "Manager 3", Key: "snmp trap manager 3", Parse: pAddr, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 4, Label: "Manager 4", Key: "snmp trap manager 4", Parse: pAddr, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 5, Label: "Community", Key: "snmp trap community", Parse: pCommunity, Form: FormCommunity, Section: SectionSNMP, Risk: RiskSafe, Secret: true},
			{Number: 6, Label: "Trap Version", Key: "snmp trap version", Parse: pPick, Form: FormWord, Section: SectionSNMP, Risk: RiskSafe},
			{Number: 7, Label: "V3 Trap Engine ID", Key: "snmp trap engine-id", Parse: pText, Form: FormText, Section: SectionSNMP, Risk: RiskSafe, Optional: true},
		}},
	{Path: "/N > 28", Name: "tacacs", Kind: KindMenu, Required: true,
		Title: regexp.MustCompile(`^TACACS:` + reScope + reNoTail),
		Items: []Item{
			{Number: 1, Label: "Enable", Key: "tacacs enable", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 2, Label: "Primary host/address", Key: "tacacs primary", Parse: pAddr, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 3, Label: "Secondary host/address", Key: "tacacs secondary", Parse: pAddr, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 4, Label: "Secret Word", Key: "tacacs secret", Parse: pSecret, Form: FormSecret, Section: SectionAAA, Risk: RiskGuarded, Secret: true},
			{Number: 5, Label: "Fallback Timer", Key: "tacacs fallback-timer", Parse: pSeconds, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 6, Label: "Fallback Local", Key: "tacacs fallback-local", Parse: pFallback, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 7, Label: "Authentication Port", Key: "tacacs port", Parse: pNumber, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 8, Label: "Default User Access", Key: "tacacs default-access", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 9, Label: "Account Management Module", Key: "tacacs account-module", Parse: pModule, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 10, Label: "Session Management Module", Key: "tacacs session-module", Parse: pModule, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 11, Label: "Service Name", Key: "tacacs service-name", Parse: pText, Form: FormText, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 12, Label: "Debug", Key: "tacacs debug", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
		}},
	{Path: "/N > 28 > 8", Name: "tacacs-default", Kind: KindMenu, Required: true,
		Title: regexp.MustCompile(`^TACACS Default User Access:` + reScope + `:?` + reNoTail),
		Items: []Item{
			{Number: 1, Label: "Default User Access", Fact: "tacacs-default-access", Parse: pPick, Optional: true},
			{Number: 2, Label: "Access Level", Key: "tacacs default-level", Parse: pLevel, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 3, Label: "Port Access", Fact: "tacacs-port-access", Parse: pPresence, Optional: true},
			{Number: 4, Label: "Service Access", Key: "tacacs default-services", Parse: pServices, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
		}},
	{Path: "/N > 29", Name: "radius", Kind: KindMenu, Required: true,
		Title: regexp.MustCompile(`^RADIUS:` + reScope + reNoTail),
		Items: []Item{
			{Number: 1, Label: "Enable", Key: "radius enable", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 2, Label: "Primary Host/Address", Key: "radius primary", Parse: pAddr, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 3, Label: "Primary Secret Word", Key: "radius primary-secret", Parse: pSecret, Form: FormSecret, Section: SectionAAA, Risk: RiskGuarded, Secret: true},
			{Number: 4, Label: "Secondary Host/Address", Key: "radius secondary", Parse: pAddr, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 5, Label: "Secondary Secret Word", Key: "radius secondary-secret", Parse: pSecret, Form: FormSecret, Section: SectionAAA, Risk: RiskGuarded, Secret: true},
			{Number: 6, Label: "Fallback Timer", Key: "radius fallback-timer", Parse: pSeconds, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 7, Label: "Fallback Local", Key: "radius fallback-local", Parse: pFallback, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 8, Label: "Retries", Key: "radius retries", Parse: pNumber, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 9, Label: "Authentication Port", Key: "radius port", Parse: pNumber, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 10, Label: "Accounting Port", Key: "radius accounting-port", Parse: pNumber, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 11, Label: "Default User Access", Key: "radius default-access", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 12, Label: "OneTime Auth", Key: "radius onetime-auth", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 13, Label: "OneTime Auth Timer", Key: "radius onetime-timer", Parse: pSeconds, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 14, Label: "OneTime Auth Type", Key: "radius onetime-type", Parse: pPick, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 15, Label: "Session Module Type", Key: "radius session-module", Parse: pModule, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 16, Label: "Require Message Authentic", Key: "radius message-authenticator", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
			{Number: 17, Label: "Debug", Key: "radius debug", Parse: pOnOff, Form: FormWord, Section: SectionAAA, Risk: RiskSafe},
		}},
	{Path: "/N > 29 > 11", Name: "radius-default", Kind: KindMenu,
		Title: regexp.MustCompile(`^RADIUS Default User Access:` + reScope + `:?` + reNoTail),
		Items: []Item{
			{Number: 1, Label: "Default User Access", Fact: "radius-default-access", Parse: pPick, Optional: true},
			{Number: 2, Label: "Access Level", Key: "radius default-level", Parse: pLevel, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
			{Number: 3, Label: "Port Access", Fact: "radius-port-access", Parse: pPresence, Optional: true},
			{Number: 4, Label: "Service Access", Key: "radius default-services", Parse: pServices, Form: FormWord, Section: SectionAAA, Risk: RiskGuarded},
		}},
	{Path: "/N > 5", Name: "iptables", Kind: KindList, Required: true,
		Title: regexp.MustCompile(`^IPTABLES ENTRIES:` + reIPv + reNoTail)},
	{Path: "/F", Name: "system", Kind: KindMenu,
		Title: regexp.MustCompile(`^SYSTEM PARAMETERS:\s*$`),
		Items: []Item{
			{Number: 4, Label: "Invalid Access Lockout", Fact: "lockout", Parse: pPick, Optional: true},
		}},
	{Path: "/F > 1 > 1", Name: "users", Kind: KindUsers,
		Title: regexp.MustCompile(`^VIEW USER DIRECTORY:\s*$`)},
	{Path: "/F > 1 > 1 > <name>", Name: "user", Kind: KindMenu,
		Title: regexp.MustCompile(`^VIEW USER DIRECTORY DETAILS:\s*$`),
		Items: []Item{
			{Number: 1, Label: "Username", Fact: "user-name", Parse: pText},
			{Number: 4, Label: "Access Level", Key: "user {user} level", Parse: pLevel, Form: FormUser, Section: SectionBreakGlass, Risk: RiskGuarded},
			{Number: 2, Label: "Password", Key: "user {user} password", Parse: pSecret, Form: FormUser, Section: SectionBreakGlass, Risk: RiskGuarded, Secret: true},
			{Number: 3, Label: "Authorization Keys", Key: "user {user} keys", Parse: pPresence, Form: FormUser, Section: SectionBreakGlass, Risk: RiskGuarded, Secret: true, Optional: true},
			{Number: 5, Label: "Port Access", Fact: "user-port-access", Parse: pPresence, Optional: true},
			{Number: 6, Label: "Service Access", Fact: "user-services", Parse: pServices, Optional: true},
			{Number: 7, Label: "Callback Phone #", Fact: "user-callback", Parse: pPresence, Optional: true},
			{Number: 8, Label: "User API Token", Key: "user {user} api-token", Parse: pPresence, Form: FormUser, Section: SectionBreakGlass, Risk: RiskGuarded, Secret: true, Optional: true},
		}},
}

// --- value parsers -------------------------------------------------------------

// Parser turns a printed value into its canonical form. ok is false when
// the value is not one the page can print (the page is then not the
// table's); the value itself is never put in an error. A canonical "" is a
// setting that is not set.
type Parser func(raw string) (value string, ok bool)

// presenceMark is the value of a secret or credential that is set: only
// that it is.
const presenceMark = "defined"

// undefinedValue reports the unit's words for no value.
func undefinedValue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "(undefined)", "undefined":
		return true
	}
	return false
}

var reSlugDrop = regexp.MustCompile(`[^a-z0-9]+`)

// slug is a pick's printed text as one lower-case word: 'On (Transport
// failure)' is 'on-transport-failure', 'V1/V2 Only' 'v1-v2-only'.
func slug(s string) string {
	return strings.Trim(reSlugDrop.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func pAny(raw string) (string, bool) { return strings.TrimSpace(raw), true }

func pOnOff(raw string) (string, bool) {
	switch v := strings.ToLower(strings.TrimSpace(raw)); v {
	case "on", "off":
		return v, true
	}
	return "", false
}

func pYesNo(raw string) (string, bool) {
	switch v := strings.ToLower(strings.TrimSpace(raw)); v {
	case "yes", "no":
		return v, true
	}
	return "", false
}

// pPick is a pick or a fact whose words are not enumerated: its slug.
func pPick(raw string) (string, bool) {
	if undefinedValue(raw) {
		return "", true
	}
	v := slug(raw)
	return v, v != ""
}

// pText is free text as printed (a menu may truncate it with '...').
func pText(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if undefinedValue(v) {
		return "", true
	}
	return v, len(v) <= 512
}

var reAddr = regexp.MustCompile(`^[^\s"]{1,128}$`)

// pAddr is a host name or address as printed.
func pAddr(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if undefinedValue(v) {
		return "", true
	}
	return v, reAddr.MatchString(v)
}

var reNumber = regexp.MustCompile(`^[0-9]{1,6}$`)

func pNumber(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if undefinedValue(v) {
		return "", true
	}
	return v, reNumber.MatchString(v)
}

var reSeconds = regexp.MustCompile(`(?i)^([0-9]{1,6})(?:\s*sec(?:onds?)?)?$`)

// pSeconds is '15 Sec' (or a bare number): 15.
func pSeconds(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if undefinedValue(v) {
		return "", true
	}
	m := reSeconds.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// pSecret is a secret the menu shows as '(defined)': a presence. Anything
// else, a value in clear included, is refused (and never reported).
func pSecret(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case undefinedValue(v):
		return "", true
	case v == "(defined)":
		return presenceMark, true
	}
	return "", false
}

// pPresence is a credential or list that is set, whatever it holds: only
// that it is set is kept.
func pPresence(raw string) (string, bool) {
	if undefinedValue(raw) {
		return "", true
	}
	return presenceMark, true
}

// pCommunity is a community string, printed in clear: the value is
// returned for the in-memory comparison (the comparison elides it to a
// label) and must not be stored or printed by anyone else.
func pCommunity(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if undefinedValue(v) {
		return "", true
	}
	return v, len(v) <= 128
}

// pFallback is the Fallback Local pick: off, on-all-failures or
// on-transport-failure.
func pFallback(raw string) (string, bool) {
	if undefinedValue(raw) {
		return "", true
	}
	v := slug(raw)
	if v == "off" || strings.HasPrefix(v, "on") {
		return v, true
	}
	return "", false
}

// pLevel is an access level: viewonly, user, superuser, administrator.
func pLevel(raw string) (string, bool) {
	if undefinedValue(raw) {
		return "", true
	}
	v := strings.ReplaceAll(slug(raw), "-", "")
	return v, v != ""
}

// pModule is a module's pick: enabled or disabled ('Enable' too).
func pModule(raw string) (string, bool) {
	if undefinedValue(raw) {
		return "", true
	}
	switch v := slug(raw); v {
	case "enable", "enabled":
		return "enabled", true
	case "disable", "disabled":
		return "disabled", true
	default:
		return v, v != ""
	}
}

// pServices is a service list: 'Serial Port, Telnet/SSH, Web, RESTful API'
// is 'serial,telnet-ssh,web,restful-api'.
func pServices(raw string) (string, bool) {
	if undefinedValue(raw) {
		return "", true
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		w := slug(s)
		switch w {
		case "":
			continue
		case "serial-port":
			w = "serial"
		}
		out = append(out, w)
	}
	return strings.Join(out, ","), len(out) > 0
}
