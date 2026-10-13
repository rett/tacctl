package blocks

// The IOS and IOS-XE snmp block (0.2.7, docs/plans/0.2.7-blocks-plan.md "IOS
// snmp block as built"): configuration lines for the SNMP things the
// structured settings do not hold, one statement per line, '#' and '!'
// comment lines and blank lines, nothing else:
//
//	snmp-server community <string> RO|RW [<acl-name>]
//	snmp-server host <address> [version 1|2c] <community> [udp-port <n>] [<type> ...]
//	snmp-server enable traps [<type> [<subtype> ...]]
//	ip access-list standard <NAME>
//	 permit <address> [<wildcard>] | permit host <address> | permit any
//
// A 'no ...' line says "not managed on this device": it is kept
// (IOSNotManaged), never rendered, and in a more specific layer it takes the
// less specific layer's object it names out of the resolved block.
//
// Everything here is a pure function of text. A block carries community
// strings (a string is its own secret, and so is the community a trap host
// is sent with), so no finding and no message of this package ever holds a
// word of the input that could be one: objects are named by their ordinal
// ('community 2') and a word that is off the grammar by its position on the
// line.

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/names"
)

// MaxIOSName is the longest access list name of an IOS block.
const MaxIOSName = 64

// The values of the grammar.
const (
	AccessRO = "RO"
	AccessRW = "RW"
)

// IOSTrapTypes are the notification types a trap host or an 'enable traps'
// statement may name: a table of the keywords of 'snmp-server enable traps
// ?', extended as a type is checked against a device.
var IOSTrapTypes = []string{
	"aaa_server", "atm", "bfd", "bgp", "bridge", "c6kxbar", "call-home", "cef", "cluster", "config", "config-copy",
	"config-ctid", "cpu", "dhcp", "dial", "dnis", "dot1x", "eigrp", "energywise", "entity", "entity-diag", "envmon",
	"errdisable", "event-manager", "flash", "flex-links", "fru-ctrl", "hsrp", "ike", "ipmulticast", "ipsec", "ipsla",
	"isdn", "isis", "l2tc", "license", "lldp", "mac-notification", "memory", "mpls", "msdp", "mvpn", "ospf", "pim",
	"port-security", "power-ethernet", "pw", "rep", "repeater", "resource-policy", "rf", "rsvp", "rtr", "sdlc", "slb",
	"snmp", "srst", "stackwise", "stpx", "syslog", "tty", "vlan-membership", "vlancreate", "vlandelete", "voice",
	"vrrp", "vtp", "x25",
}

// maxTrapWords is the most words an 'enable traps' statement may have (the
// type and its subtypes).
const maxTrapWords = 12

// ACLEntry is one 'permit' entry of a standard access list in the form the
// block writes it: 'permit any', 'permit host <address>' or 'permit
// <address> <wildcard>'.
type ACLEntry struct {
	Any      bool
	Addr     netip.Addr
	Wildcard netip.Addr
}

// Host reports a single-address entry.
func (e ACLEntry) Host() bool { return !e.Any && e.Wildcard == netip.AddrFrom4([4]byte{}) }

// Text is the entry as the block writes it (and as a pull compares it:
// 'permit host A', which a device prints as 'permit A').
func (e ACLEntry) Text() string {
	switch {
	case e.Any:
		return "permit any"
	case e.Host():
		return "permit host " + e.Addr.String()
	}
	return "permit " + e.Addr.String() + " " + e.Wildcard.String()
}

// IOSCommunity is one 'snmp-server community <string> RO|RW [<acl>]'
// object. String is the community string, a secret.
type IOSCommunity struct {
	String string
	Access string // RO or RW
	ACL    string // "" for none
	Lines  []int
}

// IOSACL is one 'ip access-list standard <name>' object, owned whole: its
// entries are the list.
type IOSACL struct {
	Name    string
	Entries []ACLEntry
	Lines   []int
}

// HasAny reports an entry that permits every address.
func (a *IOSACL) HasAny() bool {
	return slices.ContainsFunc(a.Entries, func(e ACLEntry) bool { return e.Any })
}

// IOSHost is one 'snmp-server host' object, keyed by its address and
// community. Community is a secret.
type IOSHost struct {
	Addr      netip.Addr
	Version   string // "", "1" or "2c"
	Community string
	UDPPort   int // 0: the device's default
	Types     []string
	Lines     []int
}

func (h *IOSHost) key() string { return h.Addr.String() + " " + h.Community }

// IOSTraps is one 'snmp-server enable traps' statement: no word (every
// type), a type, or a type and its subtypes.
type IOSTraps struct {
	Words []string
	Lines []int
}

func (t *IOSTraps) key() string { return strings.Join(t.Words, " ") }

// IOS 'no' line kinds.
const (
	IOSNoCommunity = "community"
	IOSNoACL       = "acl"
	IOSNoHost      = "host"
	IOSNoTraps     = "traps"
)

// IOSNotManaged is one 'no ...' line: not managed on this device. Name is
// the community string (IOSNoCommunity), the list's name (IOSNoACL) or the
// community of a host (IOSNoHost); Addr and Version are the host's, and
// Words the traps' type and subtypes.
type IOSNotManaged struct {
	Line    int
	Kind    string
	Name    string
	Addr    netip.Addr
	Version string
	Words   []string
}

// IOSSNMPBlock is a parsed IOS snmp block. Objects are in the order of
// their first statement.
type IOSSNMPBlock struct {
	Communities []*IOSCommunity
	ACLs        []*IOSACL
	Hosts       []*IOSHost
	Traps       []*IOSTraps
	NotManaged  []IOSNotManaged
}

// Empty reports a block with no object and no 'no' line.
func (b *IOSSNMPBlock) Empty() bool {
	return b == nil || len(b.Communities)+len(b.ACLs)+len(b.Hosts)+len(b.Traps)+len(b.NotManaged) == 0
}

func (b *IOSSNMPBlock) community(name string) *IOSCommunity {
	if b == nil {
		return nil
	}
	for _, c := range b.Communities {
		if c.String == name {
			return c
		}
	}
	return nil
}

// ACL is the list of that name (nil for none).
func (b *IOSSNMPBlock) ACL(name string) *IOSACL {
	if b == nil {
		return nil
	}
	for _, a := range b.ACLs {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func (b *IOSSNMPBlock) host(key string) *IOSHost {
	if b == nil {
		return nil
	}
	for _, h := range b.Hosts {
		if h.key() == key {
			return h
		}
	}
	return nil
}

func (b *IOSSNMPBlock) traps(key string) *IOSTraps {
	if b == nil {
		return nil
	}
	for _, t := range b.Traps {
		if t.key() == key {
			return t
		}
	}
	return nil
}

// --- parsing ----------------------------------------------------------------

type iosParser struct {
	b        *IOSSNMPBlock
	findings []Finding
	line     int
	// acl is the list the entries that follow belong to; skip is set when
	// the header was refused (its entries are not reported again).
	acl  *IOSACL
	skip bool
}

func (p *iosParser) errf(format string, a ...any) {
	p.findings = append(p.findings, Finding{p.line, SevError, fmt.Sprintf(format, a...)})
}

// ParseIOSSNMP reads an IOS snmp block's text: its objects, and a finding
// (line number, severity, text) for everything that is off the grammar. A
// block with an error finding is partial and must not be used. Findings are
// in line order.
func ParseIOSSNMP(text string) (*IOSSNMPBlock, []Finding) {
	p := &iosParser{b: &IOSSNMPBlock{}}
	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		if i == len(lines)-1 && raw == "" {
			break
		}
		p.line = i + 1
		p.parseLine(raw)
	}
	return p.b, p.findings
}

func (p *iosParser) parseLine(raw string) {
	trimmed := strings.TrimLeft(raw, " ")
	comment := strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!")
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\t':
			p.errf("a tab at column %d (a block is typed with blanks)", i+1)
			return
		case c < 0x20 || c == 0x7f:
			p.errf("a control character (0x%02x) at column %d", c, i+1)
			return
		case c >= 0x80 && !comment:
			p.errf("a character that is not ASCII at column %d (only a comment may hold one)", i+1)
			return
		}
	}
	if comment && !utf8.ValidString(raw) {
		p.errf("a comment that is not valid UTF-8")
		return
	}
	if strings.TrimSpace(raw) == "" || comment {
		return
	}
	if len(raw) > MaxLine {
		p.errf("the line is longer than %d characters", MaxLine)
		return
	}
	if strings.ContainsAny(raw, `"'`) {
		p.errf("a quote: a block holds words separated by blanks, and IOS has no quoting")
		return
	}
	t := strings.Fields(raw)
	switch t[0] {
	case "permit", "deny", "remark":
		p.entry(t)
		return
	}
	// anything else is a statement of its own and ends the list
	p.acl, p.skip = nil, false
	switch t[0] {
	case "snmp-server":
		p.snmpServer(t[1:])
	case "ip":
		p.ipAccessList(t[1:])
	case "no":
		p.no(t[1:])
	case "access-list":
		p.errf("a numbered access list is not accepted: name the list ('ip access-list standard <NAME>')")
	default:
		p.errf("a block holds 'snmp-server', 'ip access-list standard' and 'no' statements only (word 1)")
	}
}

// iosNameProblem is why s cannot be the name of an access list of a block
// ("" when it can). The reason never holds s.
func iosNameProblem(s string) string {
	switch {
	case s == "":
		return "is empty"
	case len(s) > MaxIOSName:
		return fmt.Sprintf("is longer than %d characters", MaxIOSName)
	case reAllDigits.MatchString(s):
		return "is a number: a numbered access list is not accepted, name the list"
	case !reACLName.MatchString(s):
		return "holds a character other than letters, digits, '.', '_' and '-'"
	}
	return ""
}

var (
	reACLName   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	reAllDigits = regexp.MustCompile(`^[0-9]+$`)
)

// iosCommunityProblem is why s cannot be a community string of an IOS block
// ("" when it can): printable ASCII without blanks, at most 32 characters
// (IOS's limit), none that a CLI reads specially, and no placeholder.
func iosCommunityProblem(s string) string {
	if p := names.SNMPTokenProblem(s, names.SNMPCommunityMax); p != "" {
		return p
	}
	if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
		return "is a placeholder (a block holds the real string; <secret:N> marks are only what an engineer is shown)"
	}
	if strings.ContainsAny(s, "\\{};#|<>[]'") {
		return "holds a character a block cannot write back the same way or a CLI reads specially (one of \\ { } ; # | < > [ ] ')"
	}
	return ""
}

// ownACL is the refusal of a name tacctl renders itself ("" when it is
// not).
func ownACL(what, s string) string {
	if names.IsTacctlSNMPName(s) {
		return fmt.Sprintf("%s is a name tacctl renders itself (%s, %s, %s): the structured SNMP settings own it",
			what, names.SNMPClientList, names.SNMPView, names.SNMPGroup)
	}
	return ""
}

func (b *IOSSNMPBlock) commOrd(name string) int {
	for i, c := range b.Communities {
		if c.String == name {
			return i + 1
		}
	}
	return len(b.Communities) + 1
}

func (b *IOSSNMPBlock) hostOrd(key string) int {
	for i, h := range b.Hosts {
		if h.key() == key {
			return i + 1
		}
	}
	return len(b.Hosts) + 1
}

func (p *iosParser) snmpServer(t []string) {
	if len(t) == 0 {
		p.errf("'snmp-server' needs community, host or enable (word 2)")
		return
	}
	switch t[0] {
	case "community":
		p.community(t[1:])
	case "host":
		h := p.hostLine(t[1:], false)
		if h == nil {
			return
		}
		if prev := p.b.host(h.key()); prev != nil {
			p.errf("host %d is stated twice (one address and community, one line)", p.b.hostOrd(h.key()))
			return
		}
		h.Lines = []int{p.line}
		p.b.Hosts = append(p.b.Hosts, h)
	case "enable":
		w := p.trapWords(t[1:], "snmp-server enable")
		if w == nil {
			return
		}
		tr := &IOSTraps{Words: w, Lines: []int{p.line}}
		if p.b.traps(tr.key()) != nil {
			p.errf("an 'enable traps' statement is stated twice")
			return
		}
		p.b.Traps = append(p.b.Traps, tr)
	case "contact", "location", "chassis-id":
		p.errf("snmp-server %s is a setting of the structured SNMP settings or the device's own: it is never part of a block", t[0])
	case "trap-source", "source-interface":
		p.errf("snmp-server %s is not accepted in a block yet: the source address of a device's traps is not a setting tacctl has", t[0])
	case "engineID":
		p.errf("snmp-server engineID is the device's identity: it is never part of a block")
	case "user", "group", "view":
		p.errf("snmp-server %s is SNMPv3 (the structured settings render the one v3 user): it is never part of a block", t[0])
	default:
		p.errf("word 2 is not one of community, host, enable")
	}
}

func (p *iosParser) community(t []string) {
	if len(t) == 0 {
		p.errf("'snmp-server community' needs a community string (word 3)")
		return
	}
	if why := iosCommunityProblem(t[0]); why != "" {
		p.errf("the community string (word 3) %s", why)
		return
	}
	if why := ownACL("the community string (word 3)", t[0]); why != "" {
		p.errf("%s", why)
		return
	}
	what := fmt.Sprintf("community %d", p.b.commOrd(t[0]))
	if len(t) < 2 {
		p.errf("%s needs RO or RW (word 4)", what)
		return
	}
	acc := strings.ToUpper(t[1])
	if acc != AccessRO && acc != AccessRW {
		p.errf("%s: word 4 is RO or RW (a view and the other keywords of IOS are not in a block)", what)
		return
	}
	c := &IOSCommunity{String: t[0], Access: acc, Lines: []int{p.line}}
	if len(t) > 3 {
		p.errf("%s: the access list name is the last word (a view and an IPv6 list are not in a block)", what)
		return
	}
	if len(t) == 3 {
		if why := iosNameProblem(t[2]); why != "" {
			p.errf("%s: the access list name (word 5) %s", what, why)
			return
		}
		if why := ownACL(what+": the access list name", t[2]); why != "" {
			p.errf("%s", why)
			return
		}
		c.ACL = t[2]
	}
	if p.b.community(t[0]) != nil {
		p.errf("%s is stated twice", what)
		return
	}
	p.b.Communities = append(p.b.Communities, c)
}

func (p *iosParser) ipAccessList(t []string) {
	if len(t) < 1 || t[0] != "access-list" {
		p.errf("only 'ip access-list standard <NAME>' is accepted after 'ip' (word 2)")
		return
	}
	p.skip = true
	if len(t) < 2 || t[1] != "standard" {
		p.errf("only standard access lists are accepted ('ip access-list standard <NAME>', word 3)")
		return
	}
	if len(t) != 3 {
		p.errf("'ip access-list standard' takes one name (word 4)")
		return
	}
	if why := iosNameProblem(t[2]); why != "" {
		p.errf("the access list name (word 4) %s", why)
		return
	}
	if why := ownACL("the access list name (word 4)", t[2]); why != "" {
		p.errf("%s", why)
		return
	}
	if p.b.ACL(t[2]) != nil {
		p.errf("access list %d is stated twice", p.aclOrd(t[2]))
		return
	}
	a := &IOSACL{Name: t[2], Lines: []int{p.line}}
	p.b.ACLs = append(p.b.ACLs, a)
	p.acl, p.skip = a, false
}

func (p *iosParser) aclOrd(name string) int {
	for i, a := range p.b.ACLs {
		if a.Name == name {
			return i + 1
		}
	}
	return len(p.b.ACLs) + 1
}

// entry reads an entry of the access list being read.
func (p *iosParser) entry(t []string) {
	if p.skip {
		return
	}
	if p.acl == nil {
		p.errf("'%s' is an access list entry and belongs under 'ip access-list standard <NAME>'", t[0])
		return
	}
	what := fmt.Sprintf("access list %d", p.aclOrd(p.acl.Name))
	switch t[0] {
	case "deny":
		p.errf("%s: a block states permit entries only (a standard list ends in an implicit deny)", what)
		return
	case "remark":
		p.errf("%s: a remark is not kept: write a '#' comment line", what)
		return
	}
	e, why := parseACLEntry(t[1:])
	if why != "" {
		p.errf("%s: the entry %s", what, why)
		return
	}
	if slices.Contains(p.acl.Entries, e) {
		p.errf("%s: the entry is listed twice", what)
		return
	}
	p.acl.Entries = append(p.acl.Entries, e)
	p.acl.Lines = append(p.acl.Lines, p.line)
}

// parseACLEntry reads the words after 'permit': 'any', 'host <address>',
// '<address>' (a host) or '<address> <wildcard>'. The address must be the
// network the wildcard describes (no bit set where the wildcard says "any"),
// as a device prints it. The reason holds no input.
func parseACLEntry(t []string) (ACLEntry, string) {
	zero := netip.AddrFrom4([4]byte{})
	switch {
	case len(t) == 1 && t[0] == "any":
		return ACLEntry{Any: true}, ""
	case len(t) == 2 && t[0] == "host":
		a, why := parseIPv4(t[1])
		if why != "" {
			return ACLEntry{}, "host address " + why
		}
		return ACLEntry{Addr: a, Wildcard: zero}, ""
	case len(t) == 1:
		a, why := parseIPv4(t[0])
		if why != "" {
			return ACLEntry{}, "address " + why
		}
		return ACLEntry{Addr: a, Wildcard: zero}, ""
	case len(t) == 2:
		a, why := parseIPv4(t[0])
		if why != "" {
			return ACLEntry{}, "address " + why
		}
		w, why := parseIPv4(t[1])
		if why != "" {
			return ACLEntry{}, "wildcard " + why + " (log and the other keywords are not in a block)"
		}
		ab, wb := a.As4(), w.As4()
		for i := range ab {
			if ab[i]&wb[i] != 0 {
				return ACLEntry{}, "has address bits set where its wildcard says any (write the network: the address ANDed with the inverse of the wildcard)"
			}
		}
		return ACLEntry{Addr: a, Wildcard: w}, ""
	}
	return ACLEntry{}, "is 'any', 'host <address>', '<address>' or '<address> <wildcard>' (log and the other keywords are not in a block)"
}

// parseIPv4 is a dotted quad in canonical text.
func parseIPv4(s string) (netip.Addr, string) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.String() != s {
		return netip.Addr{}, "is not an IPv4 address in dotted form"
	}
	return a, ""
}

// hostLine reads the words after 'snmp-server host': <address> [version
// 1|2c] <community> [udp-port <n>] [<type> ...]. With forNo the port and the
// types are not accepted (a 'no' line names the entry only).
func (p *iosParser) hostLine(t []string, forNo bool) *IOSHost {
	if len(t) == 0 {
		p.errf("'snmp-server host' needs an address (word 3)")
		return nil
	}
	a, why := parseAddr(t[0])
	if why != "" {
		p.errf("the host address (word 3) %s", why)
		return nil
	}
	h := &IOSHost{Addr: a}
	rest := t[1:]
	if len(rest) > 0 && rest[0] == "version" {
		if len(rest) < 2 || (rest[1] != "1" && rest[1] != "2c") {
			p.errf("version takes 1 or 2c (SNMPv3 needs a user, which a block does not hold)")
			return nil
		}
		h.Version, rest = rest[1], rest[2:]
	}
	switch {
	case len(rest) > 0 && (rest[0] == "traps" || rest[0] == "informs" || rest[0] == "vrf"):
		p.errf("host: '%s' is not in the grammar of a block", rest[0])
		return nil
	case len(rest) == 0:
		p.errf("host needs the community the notifications are sent with")
		return nil
	}
	if why := iosCommunityProblem(rest[0]); why != "" {
		p.errf("the host's community %s", why)
		return nil
	}
	if why := ownACL("the host's community", rest[0]); why != "" {
		p.errf("%s", why)
		return nil
	}
	h.Community = rest[0]
	rest = rest[1:]
	what := fmt.Sprintf("host %d", p.b.hostOrd(h.key()))
	if forNo {
		if len(rest) > 0 {
			p.errf("a 'no snmp-server host' line names the address, the version and the community only")
			return nil
		}
		return h
	}
	if len(rest) >= 1 && rest[0] == "udp-port" {
		if len(rest) < 2 {
			p.errf("%s: udp-port takes a port number", what)
			return nil
		}
		n, err := strconv.Atoi(rest[1])
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != rest[1] {
			p.errf("%s: udp-port takes a number from 1 to 65535", what)
			return nil
		}
		h.UDPPort, rest = n, rest[2:]
	}
	for _, w := range rest {
		if !slices.Contains(IOSTrapTypes, w) {
			p.errf("%s: a notification type is one of: %s", what, strings.Join(IOSTrapTypes, ", "))
			return nil
		}
		if slices.Contains(h.Types, w) {
			p.errf("%s: the notification type %s is listed twice", what, w)
			return nil
		}
		h.Types = append(h.Types, w)
	}
	return h
}

var reTrapSubtype = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)

// trapWords reads the words of an 'enable traps' statement: after 'enable'
// the word 'traps', then nothing, a type, or a type and its subtypes.
func (p *iosParser) trapWords(t []string, head string) []string {
	if len(t) == 0 || t[0] != "traps" {
		p.errf("'%s' takes 'traps' (word 3)", head)
		return nil
	}
	w := t[1:]
	if len(w) > maxTrapWords {
		p.errf("an 'enable traps' statement has at most %d words after traps", maxTrapWords)
		return nil
	}
	if len(w) > 0 && !slices.Contains(IOSTrapTypes, w[0]) {
		p.errf("the trap type (word 4) is one of: %s", strings.Join(IOSTrapTypes, ", "))
		return nil
	}
	for i, x := range w {
		if i == 0 {
			continue
		}
		if !reTrapSubtype.MatchString(x) {
			p.errf("the trap subtype (word %d) is not a keyword of lower case letters, digits, '.', '_' and '-'", i+4)
			return nil
		}
	}
	for i := range w {
		if slices.Contains(w[:i], w[i]) {
			p.errf("the word %d of the statement repeats an earlier one", i+4)
			return nil
		}
	}
	return slices.Clone(w)
}

// no reads a 'no ...' line: not managed on this device.
func (p *iosParser) no(t []string) {
	if len(t) == 0 {
		p.errf("'no' needs a statement (word 2)")
		return
	}
	nm := IOSNotManaged{Line: p.line}
	switch {
	case t[0] == "snmp-server" && len(t) >= 2 && t[1] == "community":
		nm.Kind = IOSNoCommunity
		if len(t) != 3 {
			p.errf("'no snmp-server community' takes the community string and nothing else")
			return
		}
		if why := iosCommunityProblem(t[2]); why != "" {
			p.errf("the community string (word 4) %s", why)
			return
		}
		if why := ownACL("the community string (word 4)", t[2]); why != "" {
			p.errf("%s", why)
			return
		}
		nm.Name = t[2]
	case t[0] == "snmp-server" && len(t) >= 2 && t[1] == "host":
		nm.Kind = IOSNoHost
		h := p.hostLine(t[2:], true)
		if h == nil {
			return
		}
		nm.Addr, nm.Version, nm.Name = h.Addr, h.Version, h.Community
	case t[0] == "snmp-server" && len(t) >= 2 && t[1] == "enable":
		nm.Kind = IOSNoTraps
		w := p.trapWords(t[2:], "no snmp-server enable")
		if w == nil {
			return
		}
		nm.Words = w
	case t[0] == "ip" && len(t) >= 2 && t[1] == "access-list":
		nm.Kind = IOSNoACL
		if len(t) != 4 || t[2] != "standard" {
			p.errf("'no ip access-list' takes 'standard <NAME>'")
			return
		}
		if why := iosNameProblem(t[3]); why != "" {
			p.errf("the access list name (word 5) %s", why)
			return
		}
		if why := ownACL("the access list name (word 5)", t[3]); why != "" {
			p.errf("%s", why)
			return
		}
		nm.Name = t[3]
	default:
		p.errf("a 'no' line takes 'snmp-server community', 'snmp-server host', 'snmp-server enable traps' or 'ip access-list standard' (words 2 and 3)")
		return
	}
	p.b.NotManaged = append(p.b.NotManaged, nm)
}

// --- checking ---------------------------------------------------------------

// CheckIOSSNMP is what a parsed IOS block has to answer for in its layer.
// Errors: a read-write community with no access list or whose list permits
// every address, an access list with no entry, and, in the default layer,
// any list entry or host. Notes: a read-only community that answers every
// address, a list the block does not define (the device's own is used), the
// objects that become owned, the statements that carry a secret, and the no
// lines. Findings name an object by its ordinal, never by its string.
func CheckIOSSNMP(b *IOSSNMPBlock, layer Layer) []Finding {
	var out []Finding
	add := func(line int, sev Severity, format string, a ...any) {
		out = append(out, Finding{line, sev, fmt.Sprintf(format, a...)})
	}
	first := func(lines []int) int {
		if len(lines) == 0 {
			return 0
		}
		return lines[0]
	}
	referenced := map[string]bool{}
	for i, c := range b.Communities {
		n := i + 1
		acl := b.ACL(c.ACL)
		if c.ACL != "" {
			referenced[c.ACL] = true
		}
		switch {
		case c.Access == AccessRW && c.ACL == "":
			add(first(c.Lines), SevError, "community %d is read-write and names no access list: it would answer every address", n)
		case c.Access == AccessRW && acl != nil && acl.HasAny():
			add(first(c.Lines), SevError, "community %d is read-write and its access list permits any: it would answer every address", n)
		case c.Access == AccessRW:
			add(first(c.Lines), SevNote, "community %d is read-write: it can change the device", n)
		case c.ACL == "":
			add(first(c.Lines), SevNote, "community %d names no access list: it answers every address", n)
		case acl != nil && acl.HasAny():
			add(first(c.Lines), SevNote, "community %d is open to every client (its access list permits any)", n)
		}
		if c.ACL != "" && acl == nil {
			add(first(c.Lines), SevNote, "community %d names the access list %s, which this block does not define: the device's own list of that name is used, and kept", n, c.ACL)
			if c.Access == AccessRW {
				add(first(c.Lines), SevNote, "community %d is read-write with a list tacctl cannot see: check on the device that it does not permit any", n)
			}
		}
		add(first(c.Lines), SevNote, "community %d becomes owned by tacctl: the plan sets its line (the access list and the access) when it differs", n)
		add(first(c.Lines), SevNote, "community %d carries a community string, a secret, on %s", n, lineList(c.Lines))
	}
	for i, a := range b.ACLs {
		n := i + 1
		switch {
		case len(a.Entries) == 0:
			add(first(a.Lines), SevError, "access list %d has no entry: it would permit no address (a list ends in an implicit deny)", n)
		case layer == LayerDefault:
			add(first(a.Lines), SevError, "access list %d: the default block names no address (a scope or a device does)", n)
		}
		add(first(a.Lines), SevNote, "access list %d (%s) becomes owned by tacctl: the plan sets its entries and removes the ones this block does not state", n, a.Name)
		if !referenced[a.Name] {
			add(first(a.Lines), SevNote, "access list %d (%s) is named by no community of this block (a community of the device may use it)", n, a.Name)
		}
	}
	for i, h := range b.Hosts {
		n := i + 1
		if layer == LayerDefault {
			add(first(h.Lines), SevError, "host %d: the default block names no host (a scope or a device does)", n)
		}
		add(first(h.Lines), SevNote, "host %d is set when the device lacks it, and its line is replaced when it differs; the device's other hosts are kept", n)
		add(first(h.Lines), SevNote, "host %d carries a community string, a secret, on %s", n, lineList(h.Lines))
	}
	for _, t := range b.Traps {
		w := "every notification type"
		if len(t.Words) > 0 {
			w = strings.Join(t.Words, " ")
		}
		note := "'enable traps' for " + w + " is set when the device lacks it; what the device enables beside it is kept"
		if len(t.Words) == 0 {
			note += " (a device prints every type on a line of its own, so a pull takes this as present once the device has any 'enable traps' line)"
		}
		add(first(t.Lines), SevNote, "%s", note)
	}
	for _, d := range b.NotManaged {
		add(d.Line, SevNote, "a 'no' line: what it names is not managed on this device; it is kept and never rendered")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// LintIOSSNMP is ParseIOSSNMP then CheckIOSSNMP: the block and every
// finding, in line order. Check runs only on a block that parsed without
// error, so one mistake is not reported twice.
func LintIOSSNMP(text string, layer Layer) (*IOSSNMPBlock, []Finding) {
	b, fs := ParseIOSSNMP(text)
	if HasErrors(fs) {
		return b, fs
	}
	fs = append(fs, CheckIOSSNMP(b, layer)...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
	return b, fs
}

// --- resolution -------------------------------------------------------------

// ResolveIOSSNMP is the block a device is rendered from: the default's
// objects, then the scope's, then the device's, per object (a community by
// its string, an access list by its name, a host by its address and
// community, an 'enable traps' statement by its words): the more specific
// layer's object replaces the less specific one's of the same key whole. A
// 'no' line of a layer takes the less specific layers' object it names out.
// Any of the three may be nil. The result is a new block: its objects are in
// the order of their first appearance from the default down, and its
// NotManaged holds every layer's 'no' lines, the least specific first.
func ResolveIOSSNMP(def, scope, dev *IOSSNMPBlock) *IOSSNMPBlock {
	out := &IOSSNMPBlock{}
	for _, l := range []*IOSSNMPBlock{def, scope, dev} {
		if l == nil {
			continue
		}
		for _, d := range l.NotManaged {
			switch d.Kind {
			case IOSNoCommunity:
				out.Communities = slices.DeleteFunc(out.Communities, func(c *IOSCommunity) bool { return c.String == d.Name })
			case IOSNoACL:
				out.ACLs = slices.DeleteFunc(out.ACLs, func(a *IOSACL) bool { return a.Name == d.Name })
			case IOSNoHost:
				k := d.Addr.String() + " " + d.Name
				out.Hosts = slices.DeleteFunc(out.Hosts, func(h *IOSHost) bool { return h.key() == k })
			case IOSNoTraps:
				k := strings.Join(d.Words, " ")
				out.Traps = slices.DeleteFunc(out.Traps, func(t *IOSTraps) bool { return t.key() == k })
			}
		}
		for _, c := range l.Communities {
			cp := *c
			cp.Lines = slices.Clone(c.Lines)
			if i := slices.IndexFunc(out.Communities, func(o *IOSCommunity) bool { return o.String == c.String }); i >= 0 {
				out.Communities[i] = &cp
			} else {
				out.Communities = append(out.Communities, &cp)
			}
		}
		for _, a := range l.ACLs {
			cp := *a
			cp.Entries = slices.Clone(a.Entries)
			cp.Lines = slices.Clone(a.Lines)
			if i := slices.IndexFunc(out.ACLs, func(o *IOSACL) bool { return o.Name == a.Name }); i >= 0 {
				out.ACLs[i] = &cp
			} else {
				out.ACLs = append(out.ACLs, &cp)
			}
		}
		for _, h := range l.Hosts {
			cp := *h
			cp.Types = slices.Clone(h.Types)
			cp.Lines = slices.Clone(h.Lines)
			if i := slices.IndexFunc(out.Hosts, func(o *IOSHost) bool { return o.key() == h.key() }); i >= 0 {
				out.Hosts[i] = &cp
			} else {
				out.Hosts = append(out.Hosts, &cp)
			}
		}
		for _, t := range l.Traps {
			cp := *t
			cp.Words = slices.Clone(t.Words)
			cp.Lines = slices.Clone(t.Lines)
			if i := slices.IndexFunc(out.Traps, func(o *IOSTraps) bool { return o.key() == t.key() }); i < 0 {
				out.Traps = append(out.Traps, &cp)
			}
		}
		for _, d := range l.NotManaged {
			d.Words = slices.Clone(d.Words)
			out.NotManaged = append(out.NotManaged, d)
		}
	}
	return out
}

// --- statements, text -------------------------------------------------------

// IOSSNMPUnits are the objects of the block as groups of lines in the
// canonical order: the access lists first (a community that names one comes
// after it), then the communities, the hosts and the 'enable traps'
// statements, one line each; an access list is a group of its header and
// its entries, indented by one blank. This is what the managed snmp
// section appends after the structured settings (with the entries indented
// as the walkthrough indents them), and what the diff of 'check' compares.
func IOSSNMPUnits(b *IOSSNMPBlock) [][]string {
	if b == nil {
		return nil
	}
	var out [][]string
	for _, a := range b.ACLs {
		u := []string{"ip access-list standard " + a.Name}
		for _, e := range a.Entries {
			u = append(u, " "+e.Text())
		}
		out = append(out, u)
	}
	for _, c := range b.Communities {
		s := "snmp-server community " + c.String + " " + c.Access
		if c.ACL != "" {
			s += " " + c.ACL
		}
		out = append(out, []string{s})
	}
	for _, h := range b.Hosts {
		out = append(out, []string{h.text()})
	}
	for _, t := range b.Traps {
		out = append(out, []string{"snmp-server enable traps" + joinWords(t.Words)})
	}
	return out
}

func joinWords(w []string) string {
	if len(w) == 0 {
		return ""
	}
	return " " + strings.Join(w, " ")
}

func (h *IOSHost) text() string {
	s := "snmp-server host " + h.Addr.String()
	if h.Version != "" {
		s += " version " + h.Version
	}
	s += " " + h.Community
	if h.UDPPort != 0 {
		s += " udp-port " + strconv.Itoa(h.UDPPort)
	}
	return s + joinWords(h.Types)
}

// IOSSNMPStatements are the lines of the block in the canonical order,
// flattened (IOSSNMPUnits).
func IOSSNMPStatements(b *IOSSNMPBlock) []string {
	var out []string
	for _, u := range IOSSNMPUnits(b) {
		out = append(out, u...)
	}
	return out
}

func (d IOSNotManaged) text() string {
	switch d.Kind {
	case IOSNoCommunity:
		return "no snmp-server community " + d.Name
	case IOSNoACL:
		return "no ip access-list standard " + d.Name
	case IOSNoHost:
		s := "no snmp-server host " + d.Addr.String()
		if d.Version != "" {
			s += " version " + d.Version
		}
		return s + " " + d.Name
	}
	return "no snmp-server enable traps" + joinWords(d.Words)
}

// ElideIOSSNMP is a copy of the block in which every community string (a
// community's and a host's) is replaced by <secret:N>, N counting in the
// order the strings first appear (the communities, then the hosts, then the
// strings only a 'no' line names), for the engineers' reads. The marks are
// local to the block: they are not the labels of a device comparison.
func ElideIOSSNMP(b *IOSSNMPBlock) *IOSSNMPBlock {
	if b == nil {
		return nil
	}
	secret := map[string]string{}
	mark := func(s string) string {
		if v, ok := secret[s]; ok {
			return v
		}
		v := fmt.Sprintf("<secret:%d>", len(secret)+1)
		secret[s] = v
		return v
	}
	out := &IOSSNMPBlock{}
	for _, c := range b.Communities {
		cp := *c
		cp.String = mark(c.String)
		cp.Lines = slices.Clone(c.Lines)
		out.Communities = append(out.Communities, &cp)
	}
	for _, a := range b.ACLs {
		cp := *a
		cp.Entries = slices.Clone(a.Entries)
		cp.Lines = slices.Clone(a.Lines)
		out.ACLs = append(out.ACLs, &cp)
	}
	for _, h := range b.Hosts {
		cp := *h
		cp.Community = mark(h.Community)
		cp.Types = slices.Clone(h.Types)
		cp.Lines = slices.Clone(h.Lines)
		out.Hosts = append(out.Hosts, &cp)
	}
	for _, t := range b.Traps {
		cp := *t
		cp.Words = slices.Clone(t.Words)
		cp.Lines = slices.Clone(t.Lines)
		out.Traps = append(out.Traps, &cp)
	}
	for _, d := range b.NotManaged {
		cp := d
		cp.Words = slices.Clone(d.Words)
		if d.Kind == IOSNoCommunity || d.Kind == IOSNoHost {
			cp.Name = mark(d.Name)
		}
		out.NotManaged = append(out.NotManaged, cp)
	}
	return out
}

// String is the block as canonical text: IOSSNMPStatements, one per line,
// then the 'no' lines in the order given; comments and blank lines are not
// kept. A block read back from it is the same block, and its own String is
// the same text. With elided, community strings are the marks of
// ElideIOSSNMP.
func (b *IOSSNMPBlock) String(elided bool) string {
	if b == nil {
		return ""
	}
	if elided {
		b = ElideIOSSNMP(b)
	}
	lines := IOSSNMPStatements(b)
	for _, d := range b.NotManaged {
		lines = append(lines, d.text())
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// IOSNotManagedLines are the 'no' lines of the block as written.
func IOSNotManagedLines(b *IOSSNMPBlock, elided bool) []string {
	if b == nil {
		return nil
	}
	if elided {
		b = ElideIOSSNMP(b)
	}
	var out []string
	for _, d := range b.NotManaged {
		out = append(out, d.text())
	}
	return out
}

// LintFor is LintBlock for the vendor's grammar of a block: the Doc is
// *SNMPBlock (juniper snmp), *SystemBlock (juniper system) or *IOSSNMPBlock
// (cisco snmp). A vendor and block with no grammar is an error: the IOS
// system block is not built.
func LintFor(vendor, block, text string, layer Layer) (Doc, []Finding, error) {
	switch {
	case vendor == VendorCisco && block == BlockSNMP:
		b, fs := LintIOSSNMP(text, layer)
		return b, fs, nil
	case vendor == VendorCisco && block == BlockSystem:
		return nil, nil, fail("The IOS system block is not built: only the snmp block exists for vendor cisco.")
	case vendor == VendorJuniper:
		return LintBlock(block, text, layer)
	}
	return nil, nil, fail("Unknown vendor '" + vendor + "' for a block (one of: " + strings.Join(Vendors, ", ") + ").")
}
