package blocks

// The Junos snmp block (0.2.7, docs/plans/0.2.7-blocks-plan.md B2): Junos
// 'set' statements for the SNMP things the structured settings do not hold,
// one statement per line, '#' comment lines and blank lines, nothing else:
//
//	set snmp community <name> authorization read-only|read-write
//	set snmp community <name> clients <cidr> [restrict]
//	set snmp community <name> client-list-name <list>
//	set snmp trap-group <name> version v1|v2
//	set snmp trap-group <name> categories <category>
//	set snmp trap-group <name> targets <address>
//	set snmp trap-options agent-address outgoing-interface
//	set snmp trap-options source-address <address>|lo0
//
// A 'delete snmp ...' line says "not managed on this device": it is kept
// (NotManaged), never rendered, and in a more specific layer it takes the
// less specific layer's object of that name out of the resolved block.
//
// Everything here is a pure function of text. A block carries community
// strings (a community's name is its secret, and so is a trap group's, which
// the traps are sent with), so no finding and no message of this package
// ever holds a word of the input that could be one: objects are named by
// their ordinal ('community 2'), and a word that is off the allow-list is
// named by its position on the line.

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/names"
)

// MaxName is the longest community string, trap group name or client list
// name of a block.
const MaxName = 64

// MaxLine is the longest line of a block: a human pasting a longer one into
// an interactive terminal has it truncated there (1,023 characters).
const MaxLine = 1000

// Severity of a finding.
type Severity string

const (
	// SevError is what stops a block from being installed.
	SevError Severity = "error"
	// SevNote is what the person installing it should know.
	SevNote Severity = "note"
)

// Finding is one thing Parse or Check has to say; Line is 0 for the block as
// a whole. Text never holds a community string.
type Finding struct {
	Line     int
	Severity Severity
	Text     string
}

// String is "line 3: error: text" (without the line for the whole block).
func (f Finding) String() string {
	if f.Line == 0 {
		return string(f.Severity) + ": " + f.Text
	}
	return fmt.Sprintf("line %d: %s: %s", f.Line, f.Severity, f.Text)
}

// HasErrors reports whether any finding is an error.
func HasErrors(fs []Finding) bool {
	return slices.ContainsFunc(fs, func(f Finding) bool { return f.Severity == SevError })
}

// Layer is where in the resolution a block sits.
type Layer int

const (
	// LayerDefault is the block beneath every scope: it carries nothing that
	// names a client or a target.
	LayerDefault Layer = iota
	// LayerScope is a scope's block.
	LayerScope
	// LayerDevice is one device's own block.
	LayerDevice
)

// The values of the grammar.
const (
	AuthReadOnly  = "read-only"
	AuthReadWrite = "read-write"
	RestrictWord  = "restrict"
)

// TrapCategories are the trap categories a trap group may list: a table,
// extended as a category is checked against a device.
var TrapCategories = []string{
	"authentication", "chassis", "chassis-cluster", "configuration", "link", "login", "remote-operations",
	"rmon-alarm", "routing", "services", "sonet-alarms", "startup", "timing-events", "vrrp-events",
}

// trapOptionLeaves are the trap-options leaves a block may state, with the
// words each takes (a table, easy to extend). source-address takes one
// address (or the keyword lo0) and is read by trapSourceAddress: it is a
// statement of a device by nature, allowed at the scope level for an address
// the devices of the scope share, with a note.
var trapOptionLeaves = map[string][]string{
	"agent-address":  {"outgoing-interface"},
	"source-address": nil,
}

// trapSourceLeaf is the trap-options leaf that takes an address.
const trapSourceLeaf = "source-address"

// trapSourceAddress is the one word 'set snmp trap-options source-address'
// takes in a block: an IPv4 or IPv6 address in canonical text, or the keyword
// lo0 (the address of the loopback). The reason holds no input.
func trapSourceAddress(s string) string {
	if s == "lo0" {
		return ""
	}
	if _, why := parseAddr(s); why != "" {
		return "is not an address (an IPv4 or IPv6 address in canonical text, or the keyword lo0): " + why
	}
	return ""
}

// Client is one 'clients' statement of a community.
type Client struct {
	Prefix   netip.Prefix
	Restrict bool
}

// Community is one 'set snmp community <string>' object. String is the
// community string, a secret.
type Community struct {
	String         string
	Authorization  string
	Clients        []Client
	ClientListName string
	Lines          []int // the lines of its statements
}

// TrapGroup is one 'set snmp trap-group <name>' object; the name is the
// community string the traps are sent with, a secret.
type TrapGroup struct {
	Name       string
	Version    string
	Categories []string
	Targets    []netip.Addr
	Lines      []int
}

// TrapOption is one 'set snmp trap-options <leaf> <args>' statement.
type TrapOption struct {
	Leaf  string
	Args  []string
	Lines []int
}

// NotManaged is one 'delete snmp ...' line: not managed on this device. Kind
// is community, trap-group or trap-options; Name is the community string or
// trap group (empty for trap-options); Rest is what follows the name (empty:
// the whole object).
type NotManaged struct {
	Line int
	Kind string
	Name string
	Rest []string
}

// SNMPBlock is a parsed snmp block. Communities, trap groups and trap
// options are in the order of their first statement.
type SNMPBlock struct {
	Communities []*Community
	TrapGroups  []*TrapGroup
	TrapOptions []*TrapOption
	NotManaged  []NotManaged
}

// Empty reports a block with no object and no delete line.
func (b *SNMPBlock) Empty() bool {
	return b == nil || len(b.Communities)+len(b.TrapGroups)+len(b.TrapOptions)+len(b.NotManaged) == 0
}

// --- parsing ----------------------------------------------------------------

type tok struct {
	s      string
	quoted bool
}

// word reports an unquoted token equal to w.
func (t tok) word(w string) bool { return !t.quoted && t.s == w }

type parser struct {
	b        *SNMPBlock
	findings []Finding
	line     int
}

func (p *parser) errf(format string, a ...any) {
	p.findings = append(p.findings, Finding{p.line, SevError, fmt.Sprintf(format, a...)})
}

// Parse reads a block's text: its objects, and a finding (line number,
// severity, text) for everything that is off the grammar. A block with an
// error finding is partial and must not be used. Findings are in line
// order.
func Parse(text string) (*SNMPBlock, []Finding) {
	p := &parser{b: &SNMPBlock{}}
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

func (p *parser) parseLine(raw string) {
	trimmed := strings.TrimLeft(raw, " ")
	comment := strings.HasPrefix(trimmed, "#")
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
	toks, problem := tokenize(raw)
	if problem != "" {
		p.errf("%s", problem)
		return
	}
	switch {
	case toks[0].word("set"):
		p.parseSet(toks[1:])
	case toks[0].word("delete"):
		p.parseDelete(toks[1:])
	default:
		p.errf("a block holds 'set' and 'delete' statements only (word 1)")
	}
}

// tokenize splits a line into words; a word may be quoted, as Junos quotes a
// string that holds a blank. A quoted word holds no quote and no backslash
// (what cannot be written back the same way is refused).
func tokenize(line string) ([]tok, string) {
	var out []tok
	i := 0
	for i < len(line) {
		if line[i] == ' ' {
			i++
			continue
		}
		n := len(out) + 1
		if line[i] == '"' {
			end := strings.IndexByte(line[i+1:], '"')
			if end < 0 {
				return nil, fmt.Sprintf("word %d starts a quote that is never closed", n)
			}
			body := line[i+1 : i+1+end]
			if strings.Contains(body, `\`) {
				return nil, fmt.Sprintf("word %d holds a backslash, which a block cannot write back the same way", n)
			}
			i += end + 2
			if i < len(line) && line[i] != ' ' {
				return nil, fmt.Sprintf("word %d is a quoted string followed by more text without a blank", n)
			}
			out = append(out, tok{body, true})
			continue
		}
		j := i
		for j < len(line) && line[j] != ' ' {
			if line[j] == '"' {
				return nil, fmt.Sprintf("word %d holds a quote inside it", n)
			}
			j++
		}
		out = append(out, tok{line[i:j], false})
		i = j
	}
	return out, ""
}

// nameProblem is why s cannot be the string of a community, the name of a
// trap group or of a client list in a block ("" when it can): printable
// ASCII, no more than MaxName characters, and none that a CLI reads
// specially or that a block cannot write back the same way. The reason never
// holds s.
func nameProblem(s string) string {
	switch {
	case s == "":
		return "is empty"
	case len(s) > MaxName:
		return fmt.Sprintf("is longer than %d characters", MaxName)
	case strings.HasPrefix(s, " ") || strings.HasSuffix(s, " "):
		return "starts or ends with a blank"
	case strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">"):
		return "is a placeholder (a block holds the real string; <secret:N> marks are only what an engineer is shown)"
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c < 0x20 || c > 0x7e:
			return "holds a character that is not printable ASCII"
		case strings.IndexByte("\"\\?[]{};#|<>", c) >= 0:
			return "holds a character a block cannot write back the same way or a CLI reads specially (one of \" \\ ? [ ] { } ; # | < >)"
		}
	}
	return ""
}

// ownName is the refusal of a name tacctl renders itself ("" when it is
// not).
func ownName(what, s string) string {
	if names.IsTacctlSNMPName(s) {
		return fmt.Sprintf("%s is a name tacctl renders itself (%s, %s, %s): the structured SNMP settings own it",
			what, names.SNMPClientList, names.SNMPView, names.SNMPGroup)
	}
	return ""
}

func (p *parser) parseSet(t []tok) {
	if len(t) == 0 || !t[0].word("snmp") {
		p.errf("only 'set snmp ...' statements are accepted in an snmp block (word 2)")
		return
	}
	if len(t) < 2 {
		p.errf("'set snmp' needs community, trap-group or trap-options (word 3)")
		return
	}
	switch {
	case t[1].word("community"):
		p.setCommunity(t[2:])
	case t[1].word("trap-group"):
		p.setTrapGroup(t[2:])
	case t[1].word("trap-options"):
		p.setTrapOptions(t[2:])
	default:
		p.errf("word 3 is not one of community, trap-group, trap-options")
	}
}

func (b *SNMPBlock) community(name string) *Community {
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

func (b *SNMPBlock) trapGroup(name string) *TrapGroup {
	if b == nil {
		return nil
	}
	for _, g := range b.TrapGroups {
		if g.Name == name {
			return g
		}
	}
	return nil
}

// commOrd is the ordinal the community of that name has or will have.
func (b *SNMPBlock) commOrd(name string) int {
	for i, c := range b.Communities {
		if c.String == name {
			return i + 1
		}
	}
	return len(b.Communities) + 1
}

func (b *SNMPBlock) groupOrd(name string) int {
	for i, g := range b.TrapGroups {
		if g.Name == name {
			return i + 1
		}
	}
	return len(b.TrapGroups) + 1
}

func (p *parser) setCommunity(t []tok) {
	if len(t) == 0 {
		p.errf("'set snmp community' needs a community string (word 4)")
		return
	}
	name := t[0]
	if why := nameProblem(name.s); why != "" {
		p.errf("the community string (word 4) %s", why)
		return
	}
	if why := ownName("the community string (word 4)", name.s); why != "" {
		p.errf("%s", why)
		return
	}
	what := fmt.Sprintf("community %d", p.b.commOrd(name.s))
	if len(t) < 2 {
		p.errf("%s needs authorization, clients or client-list-name (word 5)", what)
		return
	}
	rest := t[2:]
	var apply func(c *Community)
	switch {
	case t[1].word("authorization"):
		if len(rest) != 1 || (!rest[0].word(AuthReadOnly) && !rest[0].word(AuthReadWrite)) {
			p.errf("%s: authorization takes read-only or read-write and nothing else", what)
			return
		}
		v := rest[0].s
		apply = func(c *Community) {
			if c.Authorization != "" {
				p.errf("%s: authorization is stated twice", what)
				return
			}
			c.Authorization = v
		}
	case t[1].word("clients"):
		if len(rest) < 1 || len(rest) > 2 || (len(rest) == 2 && !rest[1].word(RestrictWord)) {
			p.errf("%s: clients takes an address with a prefix length and, optionally, restrict", what)
			return
		}
		pfx, why := parsePrefix(rest[0].s)
		if why != "" {
			p.errf("%s: the client %s", what, why)
			return
		}
		cl := Client{Prefix: pfx, Restrict: len(rest) == 2}
		apply = func(c *Community) {
			if slices.ContainsFunc(c.Clients, func(o Client) bool { return o.Prefix == cl.Prefix }) {
				p.errf("%s: the client %s is listed twice", what, pfx)
				return
			}
			c.Clients = append(c.Clients, cl)
		}
	case t[1].word("client-list-name"):
		if len(rest) != 1 {
			p.errf("%s: client-list-name takes one client list name", what)
			return
		}
		if why := nameProblem(rest[0].s); why != "" {
			p.errf("%s: the client list name %s", what, why)
			return
		}
		if why := ownName(what+": the client list name", rest[0].s); why != "" {
			p.errf("%s", why)
			return
		}
		v := rest[0].s
		apply = func(c *Community) {
			if c.ClientListName != "" {
				p.errf("%s: client-list-name is stated twice", what)
				return
			}
			c.ClientListName = v
		}
	default:
		p.errf("%s: word 5 is not one of authorization, clients, client-list-name", what)
		return
	}
	c := p.b.community(name.s)
	if c == nil {
		c = &Community{String: name.s}
		p.b.Communities = append(p.b.Communities, c)
	}
	c.Lines = append(c.Lines, p.line)
	apply(c)
}

func (p *parser) setTrapGroup(t []tok) {
	if len(t) == 0 {
		p.errf("'set snmp trap-group' needs a trap group name (word 4)")
		return
	}
	name := t[0]
	if why := nameProblem(name.s); why != "" {
		p.errf("the trap group name (word 4) %s", why)
		return
	}
	if why := ownName("the trap group name (word 4)", name.s); why != "" {
		p.errf("%s", why)
		return
	}
	what := fmt.Sprintf("trap-group %d", p.b.groupOrd(name.s))
	if len(t) < 2 {
		p.errf("%s needs version, categories or targets (word 5)", what)
		return
	}
	rest := t[2:]
	var apply func(g *TrapGroup)
	switch {
	case t[1].word("version"):
		if len(rest) != 1 || (!rest[0].word("v1") && !rest[0].word("v2")) {
			p.errf("%s: version takes v1 or v2", what)
			return
		}
		v := rest[0].s
		apply = func(g *TrapGroup) {
			if g.Version != "" {
				p.errf("%s: version is stated twice", what)
				return
			}
			g.Version = v
		}
	case t[1].word("categories"):
		if len(rest) != 1 || rest[0].quoted || !slices.Contains(TrapCategories, rest[0].s) {
			p.errf("%s: categories takes one category of: %s", what, strings.Join(TrapCategories, ", "))
			return
		}
		v := rest[0].s
		apply = func(g *TrapGroup) {
			if slices.Contains(g.Categories, v) {
				p.errf("%s: the category %s is listed twice", what, v)
				return
			}
			g.Categories = append(g.Categories, v)
		}
	case t[1].word("targets"):
		if len(rest) != 1 {
			p.errf("%s: targets takes one address", what)
			return
		}
		a, why := parseAddr(rest[0].s)
		if why != "" {
			p.errf("%s: the target %s", what, why)
			return
		}
		apply = func(g *TrapGroup) {
			if slices.Contains(g.Targets, a) {
				p.errf("%s: the target %s is listed twice", what, a)
				return
			}
			g.Targets = append(g.Targets, a)
		}
	default:
		p.errf("%s: word 5 is not one of version, categories, targets", what)
		return
	}
	g := p.b.trapGroup(name.s)
	if g == nil {
		g = &TrapGroup{Name: name.s}
		p.b.TrapGroups = append(p.b.TrapGroups, g)
	}
	g.Lines = append(g.Lines, p.line)
	apply(g)
}

func (p *parser) setTrapOptions(t []tok) {
	if len(t) == 0 {
		p.errf("'set snmp trap-options' needs a leaf (word 4)")
		return
	}
	var want []string
	var known bool
	if !t[0].quoted {
		want, known = trapOptionLeaves[t[0].s]
	}
	if !known {
		p.errf("word 4 is not a trap-options leaf a block takes (one of: %s)", strings.Join(leafNames(), ", "))
		return
	}
	leaf := t[0].s
	var args []string
	for _, a := range t[1:] {
		args = append(args, a.s)
	}
	switch {
	case leaf == trapSourceLeaf:
		if len(t) != 2 || t[1].quoted {
			p.errf("trap-options source-address takes one address, or lo0")
			return
		}
		if why := trapSourceAddress(args[0]); why != "" {
			p.errf("the address of trap-options source-address (word 5) %s", why)
			return
		}
	case !slices.Equal(args, want) || slices.ContainsFunc(t[1:], func(a tok) bool { return a.quoted }):
		p.errf("trap-options %s takes %s", leaf, strings.Join(want, " "))
		return
	}
	for _, o := range p.b.TrapOptions {
		if o.Leaf == leaf {
			o.Lines = append(o.Lines, p.line)
			p.errf("trap-options %s is stated twice", leaf)
			return
		}
	}
	p.b.TrapOptions = append(p.b.TrapOptions, &TrapOption{Leaf: leaf, Args: args, Lines: []int{p.line}})
}

func leafNames() []string {
	out := make([]string, 0, len(trapOptionLeaves))
	for k := range trapOptionLeaves {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (p *parser) parseDelete(t []tok) {
	if len(t) < 2 || !t[0].word("snmp") {
		p.errf("only 'delete snmp community|trap-group|trap-options ...' is accepted (words 2 and 3)")
		return
	}
	nm := NotManaged{Line: p.line}
	switch {
	case t[1].word("community"), t[1].word("trap-group"):
		nm.Kind = t[1].s
		what := "the community string"
		if nm.Kind == "trap-group" {
			what = "the trap group name"
		}
		if len(t) < 3 {
			p.errf("'delete snmp %s' needs %s (word 4)", nm.Kind, what)
			return
		}
		if why := nameProblem(t[2].s); why != "" {
			p.errf("%s (word 4) %s", what, why)
			return
		}
		if why := ownName(what+" (word 4)", t[2].s); why != "" {
			p.errf("%s", why)
			return
		}
		nm.Name = t[2].s
		rest := t[3:]
		if !p.deleteTail(nm.Kind, rest) {
			return
		}
		for _, r := range rest {
			nm.Rest = append(nm.Rest, r.s)
		}
	case t[1].word("trap-options"):
		nm.Kind = "trap-options"
		rest := t[2:]
		if len(rest) > 0 {
			if _, ok := trapOptionLeaves[rest[0].s]; rest[0].quoted || !ok {
				p.errf("word 4 is not a trap-options leaf a block takes (one of: %s)", strings.Join(leafNames(), ", "))
				return
			}
			if len(rest) > 1 {
				p.errf("'delete snmp trap-options %s' takes nothing after the leaf", rest[0].s)
				return
			}
			nm.Rest = []string{rest[0].s}
		}
	default:
		p.errf("word 3 is not one of community, trap-group, trap-options")
		return
	}
	p.b.NotManaged = append(p.b.NotManaged, nm)
}

// deleteTail checks what follows the name of a delete line: nothing (the
// whole object), or one leaf of the grammar, with a value where the leaf
// has one.
func (p *parser) deleteTail(kind string, rest []tok) bool {
	if len(rest) == 0 {
		return true
	}
	fail := func(s string) bool { p.errf("%s", s); return false }
	switch {
	case kind == "community" && rest[0].word("authorization"), kind == "community" && rest[0].word("client-list-name"),
		kind == "trap-group" && rest[0].word("version"):
		if len(rest) == 1 {
			return true
		}
		if len(rest) == 2 {
			if rest[0].word("authorization") && (rest[1].word(AuthReadOnly) || rest[1].word(AuthReadWrite)) {
				return true
			}
			if rest[0].word("version") && (rest[1].word("v1") || rest[1].word("v2")) {
				return true
			}
			if rest[0].word("client-list-name") && nameProblem(rest[1].s) == "" && !names.IsTacctlSNMPName(rest[1].s) {
				return true
			}
		}
		return fail("the leaf after the name takes no value, or a value of the grammar")
	case kind == "community" && rest[0].word("clients"):
		if len(rest) >= 2 && len(rest) <= 3 && (len(rest) == 2 || rest[2].word(RestrictWord)) {
			if _, why := parsePrefix(rest[1].s); why == "" {
				return true
			}
		}
		return fail("'clients' takes an address with a prefix length")
	case kind == "trap-group" && rest[0].word("categories"):
		if len(rest) == 2 && !rest[1].quoted && slices.Contains(TrapCategories, rest[1].s) {
			return true
		}
		return fail("'categories' takes one category of the grammar")
	case kind == "trap-group" && rest[0].word("targets"):
		if len(rest) == 2 {
			if _, why := parseAddr(rest[1].s); why == "" {
				return true
			}
		}
		return fail("'targets' takes one address")
	}
	return fail("the word after the name is not a leaf of the grammar")
}

// parsePrefix is a client of a community: an address with an explicit prefix
// length, in the form Junos prints (network address, canonical text), so the
// block and the device compare equal. The reason holds no input.
func parsePrefix(s string) (netip.Prefix, string) {
	if !strings.Contains(s, "/") {
		return netip.Prefix{}, "needs a prefix length (192.0.2.0/24, or /32 for one host)"
	}
	pfx, err := netip.ParsePrefix(s)
	switch {
	case err != nil:
		return netip.Prefix{}, "is not an IPv4 or IPv6 address with a prefix length"
	case pfx.Addr().Zone() != "" || pfx.Addr().Is4In6():
		return netip.Prefix{}, "is an address form that is not accepted (a zone, or an IPv4-mapped address)"
	case pfx != pfx.Masked():
		return netip.Prefix{}, "has host bits set (write the network: " + pfx.Masked().String() + ")"
	case pfx.String() != s:
		return netip.Prefix{}, "is not in the canonical form " + pfx.String()
	}
	return pfx, ""
}

// parseAddr is a trap target: one IPv4 or IPv6 address in canonical text.
func parseAddr(s string) (netip.Addr, string) {
	a, err := netip.ParseAddr(s)
	switch {
	case err != nil:
		return netip.Addr{}, "is not an IPv4 or IPv6 address"
	case a.Zone() != "" || a.Is4In6():
		return netip.Addr{}, "is an address form that is not accepted (a zone, or an IPv4-mapped address)"
	case a.IsUnspecified() || a.IsMulticast():
		return netip.Addr{}, "is not a host address (unspecified or multicast)"
	case a.String() != s:
		return netip.Addr{}, "is not in the canonical form " + a.String()
	}
	return a, ""
}

// --- checking ---------------------------------------------------------------

// Check is what a parsed block has to answer for in its layer. Errors:
// a community with neither clients nor client-list-name, and, in the default
// layer, any client, client list or target. Notes: a community open to every
// client without restrict, a trap group with no target, the objects that
// become owned, the statements that carry a secret, and the delete lines.
// Findings name an object by its ordinal ('community 2'), never by its
// string.
func Check(b *SNMPBlock, layer Layer) []Finding {
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
	for i, c := range b.Communities {
		n := i + 1
		switch {
		case layer == LayerDefault && (len(c.Clients) > 0 || c.ClientListName != ""):
			add(first(c.Lines), SevError, "community %d: the default block names no client and no client list (a scope or a device does)", n)
		case layer != LayerDefault && len(c.Clients) == 0 && c.ClientListName == "":
			add(first(c.Lines), SevError, "community %d has neither clients nor client-list-name: a community with no client list answers every address", n)
		}
		for _, cl := range c.Clients {
			if cl.Prefix.Bits() == 0 && !cl.Restrict {
				add(first(c.Lines), SevNote, "community %d is open to every client (%s without restrict)", n, cl.Prefix)
			}
		}
		add(first(c.Lines), SevNote, "community %d becomes owned by tacctl: the plan sets its statements and removes the ones this block does not state", n)
		add(first(c.Lines), SevNote, "community %d carries a community string, a secret, on %s", n, lineList(c.Lines))
	}
	for i, g := range b.TrapGroups {
		n := i + 1
		switch {
		case layer == LayerDefault && len(g.Targets) > 0:
			add(first(g.Lines), SevError, "trap-group %d: the default block names no target (a scope or a device does)", n)
		case layer != LayerDefault && len(g.Targets) == 0:
			add(first(g.Lines), SevNote, "trap-group %d has no target: no trap is sent", n)
		}
		add(first(g.Lines), SevNote, "trap-group %d becomes owned by tacctl: the plan sets its statements and removes the ones this block does not state", n)
		add(first(g.Lines), SevNote, "trap-group %d carries a name that is the community string traps are sent with, a secret, on %s", n, lineList(g.Lines))
	}
	for _, o := range b.TrapOptions {
		switch {
		case o.Leaf == trapSourceLeaf && layer == LayerDefault:
			add(first(o.Lines), SevError, "trap-options source-address: the default block names no address (a scope or a device does)")
		case o.Leaf == trapSourceLeaf && layer != LayerDevice && len(o.Args) == 1 && o.Args[0] != "lo0":
			add(first(o.Lines), SevError, "%s", deviceLocalProblem(layer, "trap-options source-address", false))
		case o.Leaf == trapSourceLeaf && layer == LayerScope:
			add(first(o.Lines), SevNote, "trap-options source-address lo0 is the loopback every device of the scope is expected to have: a device without it cannot take it (a device's own block can state another)")
		}
		add(first(o.Lines), SevNote, "trap-options %s becomes owned by tacctl: the plan sets that leaf", o.Leaf)
	}
	for _, d := range b.NotManaged {
		add(d.Line, SevNote, "a delete line: what it names is not managed on this device; it is kept and never rendered")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

func lineList(lines []int) string {
	if len(lines) == 1 {
		return fmt.Sprintf("line %d", lines[0])
	}
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = fmt.Sprint(l)
	}
	return "lines " + strings.Join(parts, ", ")
}

// Lint is Parse then Check: the block and every finding, in line order.
// Check runs only on a block that parsed without error, so one mistake is not
// reported twice.
func Lint(text string, layer Layer) (*SNMPBlock, []Finding) {
	b, fs := Parse(text)
	if HasErrors(fs) {
		return b, fs
	}
	fs = append(fs, Check(b, layer)...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
	return b, fs
}

// --- resolution -------------------------------------------------------------

// Resolve is the block a device is rendered from: the default's objects,
// then the scope's, then the device's, per object (a community by its
// string, a trap group by its name, a trap-options leaf by its keyword): the
// more specific layer's object replaces the less specific one's of the same
// key whole. A delete line of a layer takes the less specific layers' object
// it names out (a whole community, trap group or trap-options leaf; a delete
// of one leaf of an object is only kept). Any of the three may be nil. The
// result is a new block: its objects are in the order of their first
// appearance from the default down, and its NotManaged holds every layer's
// delete lines, the least specific first.
func Resolve(def, scope, dev *SNMPBlock) *SNMPBlock {
	out := &SNMPBlock{}
	for _, l := range []*SNMPBlock{def, scope, dev} {
		if l == nil {
			continue
		}
		for _, d := range l.NotManaged {
			if len(d.Rest) > 0 && d.Kind != "trap-options" {
				continue
			}
			switch d.Kind {
			case "community":
				out.Communities = slices.DeleteFunc(out.Communities, func(c *Community) bool { return c.String == d.Name })
			case "trap-group":
				out.TrapGroups = slices.DeleteFunc(out.TrapGroups, func(g *TrapGroup) bool { return g.Name == d.Name })
			case "trap-options":
				out.TrapOptions = slices.DeleteFunc(out.TrapOptions, func(o *TrapOption) bool {
					return len(d.Rest) == 0 || o.Leaf == d.Rest[0]
				})
			}
		}
		for _, c := range l.Communities {
			cp := *c
			cp.Clients = slices.Clone(c.Clients)
			cp.Lines = slices.Clone(c.Lines)
			if i := slices.IndexFunc(out.Communities, func(o *Community) bool { return o.String == c.String }); i >= 0 {
				out.Communities[i] = &cp
			} else {
				out.Communities = append(out.Communities, &cp)
			}
		}
		for _, g := range l.TrapGroups {
			cp := *g
			cp.Categories = slices.Clone(g.Categories)
			cp.Targets = slices.Clone(g.Targets)
			cp.Lines = slices.Clone(g.Lines)
			if i := slices.IndexFunc(out.TrapGroups, func(o *TrapGroup) bool { return o.Name == g.Name }); i >= 0 {
				out.TrapGroups[i] = &cp
			} else {
				out.TrapGroups = append(out.TrapGroups, &cp)
			}
		}
		for _, o := range l.TrapOptions {
			cp := *o
			cp.Args = slices.Clone(o.Args)
			cp.Lines = slices.Clone(o.Lines)
			if i := slices.IndexFunc(out.TrapOptions, func(x *TrapOption) bool { return x.Leaf == o.Leaf }); i >= 0 {
				out.TrapOptions[i] = &cp
			} else {
				out.TrapOptions = append(out.TrapOptions, &cp)
			}
		}
		for _, d := range l.NotManaged {
			d.Rest = slices.Clone(d.Rest)
			out.NotManaged = append(out.NotManaged, d)
		}
	}
	return out
}

// --- statements, text -------------------------------------------------------

// word is a name as it is written in a statement: quoted when it holds a
// blank.
func word(s string) string {
	if strings.Contains(s, " ") {
		return `"` + s + `"`
	}
	return s
}

// Statements are the 'set' lines of the block in a stable order: the
// communities in the order of their first appearance (authorization, clients
// in the order given, client-list-name), then the trap groups (version,
// categories, targets), then the trap-options leaves. This is what the
// managed snmp section appends after the structured settings.
func Statements(b *SNMPBlock) []string {
	if b == nil {
		return nil
	}
	var out []string
	for _, c := range b.Communities {
		pre := "set snmp community " + word(c.String) + " "
		if c.Authorization != "" {
			out = append(out, pre+"authorization "+c.Authorization)
		}
		for _, cl := range c.Clients {
			s := pre + "clients " + cl.Prefix.String()
			if cl.Restrict {
				s += " " + RestrictWord
			}
			out = append(out, s)
		}
		if c.ClientListName != "" {
			out = append(out, pre+"client-list-name "+word(c.ClientListName))
		}
	}
	for _, g := range b.TrapGroups {
		pre := "set snmp trap-group " + word(g.Name) + " "
		if g.Version != "" {
			out = append(out, pre+"version "+g.Version)
		}
		for _, c := range g.Categories {
			out = append(out, pre+"categories "+c)
		}
		for _, a := range g.Targets {
			out = append(out, pre+"targets "+a.String())
		}
	}
	for _, o := range b.TrapOptions {
		out = append(out, "set snmp trap-options "+o.Leaf+" "+strings.Join(o.Args, " "))
	}
	return out
}

func (d NotManaged) text() string {
	s := "delete snmp " + d.Kind
	if d.Name != "" {
		s += " " + word(d.Name)
	}
	for i, r := range d.Rest {
		// A client list name is a name; every other word is a keyword or a
		// value without blanks.
		if i == 1 && d.Rest[0] == "client-list-name" {
			r = word(r)
		}
		s += " " + r
	}
	return s
}

// Elide is a copy of the block in which every community string is replaced
// by <secret:N> and every trap group name by <group:N>, N counting in the
// order the strings first appear (the communities, then the strings that
// only a delete line names), for the engineers' reads. The marks are local
// to the block: they are not the labels of a device comparison.
func Elide(b *SNMPBlock) *SNMPBlock {
	if b == nil {
		return nil
	}
	secret := map[string]string{}
	group := map[string]string{}
	mark := func(m map[string]string, kind, s string) string {
		if v, ok := m[s]; ok {
			return v
		}
		v := fmt.Sprintf("<%s:%d>", kind, len(m)+1)
		m[s] = v
		return v
	}
	out := &SNMPBlock{}
	for _, c := range b.Communities {
		cp := *c
		cp.String = mark(secret, "secret", c.String)
		cp.Clients = slices.Clone(c.Clients)
		cp.Lines = slices.Clone(c.Lines)
		out.Communities = append(out.Communities, &cp)
	}
	for _, g := range b.TrapGroups {
		cp := *g
		cp.Name = mark(group, "group", g.Name)
		cp.Categories = slices.Clone(g.Categories)
		cp.Targets = slices.Clone(g.Targets)
		cp.Lines = slices.Clone(g.Lines)
		out.TrapGroups = append(out.TrapGroups, &cp)
	}
	for _, o := range b.TrapOptions {
		cp := *o
		cp.Args = slices.Clone(o.Args)
		cp.Lines = slices.Clone(o.Lines)
		out.TrapOptions = append(out.TrapOptions, &cp)
	}
	for _, d := range b.NotManaged {
		cp := d
		cp.Rest = slices.Clone(d.Rest)
		switch d.Kind {
		case "community":
			cp.Name = mark(secret, "secret", d.Name)
		case "trap-group":
			cp.Name = mark(group, "group", d.Name)
		}
		out.NotManaged = append(out.NotManaged, cp)
	}
	return out
}

// String is the block as canonical text: Statements, one per line, then the
// delete lines in the order given; comments and blank lines are not kept. A
// block read back from it is the same block, and its own String is the same
// text. With elided, community strings and trap group names are the marks
// of Elide.
func (b *SNMPBlock) String(elided bool) string {
	if b == nil {
		return ""
	}
	if elided {
		b = Elide(b)
	}
	lines := Statements(b)
	for _, d := range b.NotManaged {
		lines = append(lines, d.text())
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
