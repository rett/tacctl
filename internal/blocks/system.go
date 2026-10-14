package blocks

// The Junos system block (0.2.7, docs/plans/0.2.7-blocks-plan.md B7): Junos
// 'set' statements for the device's own system settings, one statement per
// line, '#' comment lines and blank lines, and one heredoc form for the login
// message:
//
//	set system login message <<'EOF'
//	<line>
//	...
//	EOF
//	set system domain-name <name>
//	set system domain-search <name>
//	set system time-zone <Region/City | UTC | ...>
//	set system name-server <address>
//	set system ntp server <address> [prefer] [version <1-4>] [key <n>] [routing-instance <name>]
//	set system ntp boot-server <address>
//	set system ntp source-address <address>
//	set system ntp authentication-key <n> type md5|sha1|sha256 value <secret>
//	set system ntp trusted-key <n>
//
// The block is additive only: every statement is an object, set when it is
// missing, and what the device holds besides is kept and listed as unmanaged.
// A single-valued statement (login message, domain-name, time-zone,
// boot-server, source-address) replaces the device's value when it differs;
// a list statement adds. A 'delete system ...' line says "not managed here":
// it is kept (SystemNotManaged), never rendered, and in a more specific layer
// it takes the less specific layers' object out of the resolved block.
//
// Everything here is a pure function of text. What a block holds that must
// not be echoed is the login message (a banner, which names a site) and the
// value of an NTP key (a secret): no finding and no message of this package
// ever holds a word of either. They are named by line, column and count.

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The limits of the login message.
const (
	// MaxMessageChars is the longest login message (its characters, the line
	// breaks included): longer is an error.
	MaxMessageChars = 2000
	// MessageNoteChars is the length of the rendered statement from which
	// the plan carries a note: a person pasting the one line into an
	// interactive terminal has it truncated at 1,023 characters, and the
	// note keeps a margin below that.
	MessageNoteChars = 1000
	// MessageTerminator is the line that ends the heredoc of the message.
	MessageTerminator = "EOF"
	// MessageStart is the line that opens it (the quoted form only: no
	// expansion happens).
	MessageStart = "set system login message <<'EOF'"
	// MessageStatement is the head of the rendered one-line statement.
	MessageStatement = "set system login message "
)

// Kinds of a delete line of the system block (SystemNotManaged.Kind).
const (
	SysMessage       = "message"
	SysDomainName    = "domain-name"
	SysDomainSearch  = "domain-search"
	SysTimeZone      = "time-zone"
	SysNameServer    = "name-server"
	SysNTPServer     = "ntp-server"
	SysBootServer    = "boot-server"
	SysSourceAddress = "source-address"
	SysAuthKey       = "authentication-key"
	SysTrustedKey    = "trusted-key"
	SysNTP           = "ntp"
)

// NTPKeyTypes are the types an authentication-key takes.
var NTPKeyTypes = []string{"md5", "sha1", "sha256"}

// MaxKeyNumber is the highest NTP key number Junos takes (1 to 65534).
const MaxKeyNumber = 65534

var reTimeZone = regexp.MustCompile(`^[A-Za-z0-9_+./-]{1,64}$`)

// reLabel is one label of a host name (RFC 1123).
var reLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// reInstance is a routing instance name.
var reInstance = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// LoginMessage is the 'set system login message' object. Body is the text:
// its lines joined by "\n", none after the last. Line is the line of the
// 'set system login message <<'EOF” statement (0 when the block was not read
// from text); the body begins on the next one.
type LoginMessage struct {
	Body string
	Line int
}

// Lines is the number of lines of the message.
func (m *LoginMessage) Lines() int { return strings.Count(m.Body, "\n") + 1 }

// Value is one single word of the block: a host name, a time zone or an
// address, in the text the device prints.
type Value struct {
	Text string
	Line int
}

// NTPServer is one 'set system ntp server <address>' object, with the
// options of its statements. Host is an IPv4 or IPv6 address in canonical
// text, or a host name. Zero Version and Key and an empty RoutingInstance
// are unstated.
type NTPServer struct {
	Host            string
	Prefer          bool
	Version         int
	Key             int
	RoutingInstance string
	Lines           []int
}

// NTPKey is one 'set system ntp authentication-key <n>' object. Value is the
// key, a secret.
type NTPKey struct {
	Number int
	Type   string
	Value  string
	Line   int
}

// KeyRef is one 'set system ntp trusted-key <n>' statement.
type KeyRef struct {
	Number int
	Line   int
}

// SystemNotManaged is one 'delete system ...' line: not managed on this
// device. Kind is one of the Sys* constants; Value names the entry of a list
// (an address, a name, a key number) and is empty for the whole statement
// (the whole list, or for SysNTP the whole ntp hierarchy).
type SystemNotManaged struct {
	Line  int
	Kind  string
	Value string
	// VRF is the vrf an IOS line names ('no ntp server vrf <name> <host>'):
	// the object of that vrf, not the one without it. Empty on Junos.
	VRF string
}

// SystemBlock is a parsed system block. The lists are in the order of their
// first statement.
type SystemBlock struct {
	Message          *LoginMessage
	DomainName       *Value
	DomainSearch     []Value
	TimeZone         *Value
	NameServers      []Value
	NTPServers       []NTPServer
	NTPBootServer    *Value
	NTPSourceAddress *Value
	NTPKeys          []NTPKey
	NTPTrustedKeys   []KeyRef
	NotManaged       []SystemNotManaged
}

// Empty reports a block with no statement and no delete line.
func (b *SystemBlock) Empty() bool {
	return b == nil || (b.Message == nil && b.DomainName == nil && len(b.DomainSearch) == 0 && b.TimeZone == nil &&
		len(b.NameServers) == 0 && len(b.NTPServers) == 0 && b.NTPBootServer == nil && b.NTPSourceAddress == nil &&
		len(b.NTPKeys) == 0 && len(b.NTPTrustedKeys) == 0 && len(b.NotManaged) == 0)
}

// --- the login message on the wire ------------------------------------------

// DeviceMessage is a message body as the one quoted argument of the Junos
// statement: a "\n" between lines and none after the last, every '"' as
// '\"' and every '\' as '\\', leading spaces kept. The result holds its
// outer quotes.
func DeviceMessage(body string) string {
	var sb strings.Builder
	sb.Grow(len(body) + 8)
	sb.WriteByte('"')
	for i := 0; i < len(body); i++ {
		switch c := body[i]; c {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// FromDeviceMessage is the reverse: the text of a device's login message
// (the argument as the device prints it, with or without its outer quotes)
// as the body of the heredoc. DeviceMessage of the result is the argument
// again. The escapes are \n, \", \\ and \t (a tab, which Check refuses); a
// quote that is not escaped, a lone backslash at the end and any other escape
// are errors. The errors name a position, never the text.
func FromDeviceMessage(escaped string) (string, error) {
	s := escaped
	if strings.HasPrefix(s, `"`) {
		// A bare quote is never part of the text, so a leading one is the
		// opening quote; the closing one is the last character, unescaped.
		if len(s) < 2 || !strings.HasSuffix(s, `"`) || trailingBackslashes(s[:len(s)-1])%2 == 1 {
			return "", errors.New("the message starts with a quote that is not closed at the end")
		}
		s = s[1 : len(s)-1]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			return "", fmt.Errorf("a quote at character %d is not escaped", i+1)
		case c != '\\':
			sb.WriteByte(c)
		case i+1 >= len(s):
			return "", fmt.Errorf("a backslash at character %d ends the message", i+1)
		default:
			i++
			switch s[i] {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case '"', '\\':
				sb.WriteByte(s[i])
			default:
				return "", fmt.Errorf("the escape at character %d is not one of \\n \\\" \\\\ \\t", i)
			}
		}
	}
	return sb.String(), nil
}

func trailingBackslashes(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n
}

// messageMark is what an elided block shows in place of a message: counts,
// never text.
func messageMark(m *LoginMessage) string {
	return fmt.Sprintf("<message: %d lines, %d characters>", m.Lines(), len(m.Body))
}

// secretMark is what an elided block shows in place of an NTP key.
const secretMark = "<secret>"

// IsSecretStatement reports whether a rendered statement carries a secret:
// today a 'set system ntp authentication-key <n> type <t> value <secret>'
// line. The plan hides such a statement's value and the report lists it.
func IsSecretStatement(line string) bool {
	f := strings.Fields(line)
	return len(f) >= 4 && f[0] == "set" && f[1] == "system" && f[2] == "ntp" && f[3] == "authentication-key" &&
		slices.Contains(f[4:], "value")
}

// --- parsing ----------------------------------------------------------------

type sysParser struct {
	b        *SystemBlock
	findings []Finding
	line     int
}

func (p *sysParser) errf(format string, a ...any) {
	p.findings = append(p.findings, Finding{p.line, SevError, fmt.Sprintf(format, a...)})
}

// sysLineProblem is why a line of a block outside the heredoc is refused
// before it is read ("" when it is not), and whether it is a comment (which
// may hold a character that is not ASCII).
func sysLineProblem(raw string) (string, bool) {
	comment := strings.HasPrefix(strings.TrimLeft(raw, " "), "#")
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\t':
			return fmt.Sprintf("a tab at column %d (a block is typed with blanks)", i+1), comment
		case c < 0x20 || c == 0x7f:
			return fmt.Sprintf("a control character (0x%02x) at column %d", c, i+1), comment
		case c >= 0x80 && !comment:
			return fmt.Sprintf("a character that is not ASCII at column %d (only a comment may hold one)", i+1), comment
		}
	}
	if comment {
		return "", true
	}
	if strings.TrimSpace(raw) != "" && len(raw) > MaxLine {
		return fmt.Sprintf("the line is longer than %d characters", MaxLine), false
	}
	return "", false
}

// ParseSystem reads a block's text: its statements, and a finding (line
// number, severity, text) for everything that is off the grammar. A block
// with an error finding is partial and must not be used. The content of the
// login message is Check's to judge; Parse takes its lines as they are.
// Findings are in line order.
func ParseSystem(text string) (*SystemBlock, []Finding) {
	p := &sysParser{b: &SystemBlock{}}
	lines := strings.Split(text, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	for i := 0; i < len(lines); {
		p.line = i + 1
		i += p.parseLine(lines, i)
	}
	return p.b, p.findings
}

// parseLine reads the statement at lines[i] and returns how many lines it
// took (more than one for the heredoc).
func (p *sysParser) parseLine(lines []string, i int) int {
	raw := lines[i]
	problem, comment := sysLineProblem(raw)
	if problem != "" {
		p.errf("%s", problem)
		return 1
	}
	if comment || strings.TrimSpace(raw) == "" {
		return 1
	}
	f := strings.Fields(raw)
	switch f[0] {
	case "set":
		if len(f) >= 4 && f[1] == "system" && f[2] == "login" && f[3] == "message" {
			return p.message(f[4:], lines, i)
		}
		if strings.Contains(raw, `"`) {
			p.errf("a quote is not accepted in a system statement (only the login message holds one, as a heredoc)")
			return 1
		}
		p.set(f[1:])
	case "delete":
		if strings.Contains(raw, `"`) {
			p.errf("a quote is not accepted in a system statement (only the login message holds one, as a heredoc)")
			return 1
		}
		p.del(f[1:])
	default:
		p.errf("a block holds 'set' and 'delete' statements only (word 1)")
	}
	return 1
}

// message reads the heredoc whose opening is at lines[i]; rest are the words
// after 'set system login message'.
func (p *sysParser) message(rest []string, lines []string, i int) int {
	switch {
	case len(rest) == 1 && rest[0] == "<<'EOF'":
	case len(rest) >= 1 && strings.HasPrefix(rest[0], "<<"):
		p.errf("the heredoc marker is written <<'EOF' exactly: quoted, so that no expansion happens, with nothing after it")
		return 1
	default:
		p.errf("the login message is a heredoc: %s, its lines, then %s alone on a line", MessageStart, MessageTerminator)
		return 1
	}
	end := -1
	for j := i + 1; j < len(lines); j++ {
		if lines[j] == MessageTerminator {
			end = j
			break
		}
	}
	if end < 0 {
		p.errf("the heredoc of the login message is never closed (%s alone on a line ends it)", MessageTerminator)
		return len(lines) - i
	}
	if p.b.Message != nil {
		p.errf("the login message is stated twice")
	} else {
		p.b.Message = &LoginMessage{Body: strings.Join(lines[i+1:end], "\n"), Line: i + 1}
	}
	return end - i + 1
}

// placeholder reports a <...> word: what an elided read shows in place of a
// value.
func placeholder(s string) bool { return strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") }

const placeholderWhy = "is a placeholder (a block holds the real value; <...> marks are only what an engineer is shown)"

// hostProblem is why s is not a host name ("" when it is): an RFC 1123 name
// of at most 253 characters, no trailing dot, and not an address that does not
// parse (a last label of digits only).
func hostProblem(s string) string {
	switch {
	case placeholder(s):
		return placeholderWhy
	case s == "":
		return "is empty"
	case len(s) > 253:
		return "is longer than 253 characters"
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !reLabel.MatchString(l) {
			return "is not a host name (labels of letters, digits and '-', 1 to 63 characters each, no leading or trailing '-', no empty label)"
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "is not a host name, and does not parse as an address"
	}
	return ""
}

// addrProblem is why s is not one IPv4 or IPv6 address in canonical text.
func addrProblem(s string) string {
	if placeholder(s) {
		return placeholderWhy
	}
	_, why := parseAddr(s)
	return why
}

// hostOrAddrProblem takes an address or a host name.
func hostOrAddrProblem(s string) string {
	if placeholder(s) {
		return placeholderWhy
	}
	if _, err := netip.ParseAddr(s); err == nil || strings.Contains(s, ":") {
		return addrProblem(s)
	}
	return hostProblem(s)
}

func zoneProblem(s string) string {
	switch {
	case placeholder(s):
		return placeholderWhy
	case !reTimeZone.MatchString(s):
		return "is not a time zone name (letters, digits and _ + . / - only, at most 64 characters)"
	}
	return ""
}

// number is a canonical decimal in [lo, hi].
func number(s string, lo, hi int) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || strconv.Itoa(n) != s || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

func (p *sysParser) set(t []string) {
	if len(t) == 0 || t[0] != "system" {
		p.errf("only 'set system ...' statements are accepted in a system block (word 2)")
		return
	}
	if len(t) < 2 {
		p.errf("'set system' needs login, domain-name, domain-search, time-zone, name-server or ntp (word 3)")
		return
	}
	args := t[2:]
	switch t[1] {
	case "login":
		p.errf("only 'set system login message' is accepted under login (word 4)")
	case "domain-name":
		p.single(&p.b.DomainName, "domain-name", args, hostProblem)
	case "domain-search":
		p.list(&p.b.DomainSearch, "domain-search", args, hostProblem, strings.EqualFold)
	case "time-zone":
		p.single(&p.b.TimeZone, "time-zone", args, zoneProblem)
	case "name-server":
		p.list(&p.b.NameServers, "name-server", args, addrProblem, func(a, b string) bool { return a == b })
	case "ntp":
		p.ntp(args)
	default:
		p.errf("word 3 is not one of login, domain-name, domain-search, time-zone, name-server, ntp")
	}
}

// single reads a single-valued statement.
func (p *sysParser) single(dst **Value, what string, args []string, problem func(string) string) {
	if len(args) != 1 {
		p.errf("%s takes one value and nothing else", what)
		return
	}
	if why := problem(args[0]); why != "" {
		p.errf("the value of %s %s", what, why)
		return
	}
	if *dst != nil {
		p.errf("%s is stated twice", what)
		return
	}
	*dst = &Value{args[0], p.line}
}

// list reads one entry of a list statement.
func (p *sysParser) list(dst *[]Value, what string, args []string, problem func(string) string, eq func(a, b string) bool) {
	if len(args) != 1 {
		p.errf("%s takes one value and nothing else", what)
		return
	}
	if why := problem(args[0]); why != "" {
		p.errf("the value of %s %s", what, why)
		return
	}
	if i := slices.IndexFunc(*dst, func(v Value) bool { return eq(v.Text, args[0]) }); i >= 0 {
		p.errf("%s %d is listed twice", what, i+1)
		return
	}
	*dst = append(*dst, Value{args[0], p.line})
}

func (p *sysParser) ntp(t []string) {
	if len(t) == 0 {
		p.errf("'set system ntp' needs server, boot-server, source-address, authentication-key or trusted-key (word 4)")
		return
	}
	args := t[1:]
	switch t[0] {
	case "server":
		p.ntpServer(args)
	case "boot-server":
		p.single(&p.b.NTPBootServer, "ntp boot-server", args, hostOrAddrProblem)
	case "source-address":
		p.single(&p.b.NTPSourceAddress, "ntp source-address", args, addrProblem)
	case "authentication-key":
		p.ntpKey(args)
	case "trusted-key":
		p.trustedKey(args)
	default:
		p.errf("word 4 is not one of server, boot-server, source-address, authentication-key, trusted-key")
	}
}

func (p *sysParser) ntpServer(args []string) {
	if len(args) == 0 {
		p.errf("'set system ntp server' needs an address (word 5)")
		return
	}
	host := args[0]
	if why := hostOrAddrProblem(host); why != "" {
		p.errf("the address of ntp server (word 5) %s", why)
		return
	}
	var opt NTPServer
	for i := 1; i < len(args); i++ {
		w := args[i]
		taken := func(have bool) bool {
			if have {
				p.errf("ntp server: %s is stated twice on the line", w)
			}
			return have
		}
		value := func() (string, bool) {
			if i+1 >= len(args) {
				p.errf("ntp server: %s takes a value", w)
				return "", false
			}
			i++
			return args[i], true
		}
		switch w {
		case "prefer":
			if taken(opt.Prefer) {
				return
			}
			opt.Prefer = true
		case "version":
			if taken(opt.Version != 0) {
				return
			}
			v, ok := value()
			if !ok {
				return
			}
			n, ok := number(v, 1, 4)
			if !ok {
				p.errf("ntp server: version takes 1, 2, 3 or 4")
				return
			}
			opt.Version = n
		case "key":
			if taken(opt.Key != 0) {
				return
			}
			v, ok := value()
			if !ok {
				return
			}
			n, ok := number(v, 1, MaxKeyNumber)
			if !ok {
				p.errf("ntp server: key takes a key number from 1 to %d", MaxKeyNumber)
				return
			}
			opt.Key = n
		case "routing-instance":
			if taken(opt.RoutingInstance != "") {
				return
			}
			v, ok := value()
			if !ok {
				return
			}
			switch {
			case placeholder(v):
				p.errf("ntp server: the routing instance %s", placeholderWhy)
				return
			case !reInstance.MatchString(v):
				p.errf("ntp server: routing-instance takes a name of letters, digits, '_', '.' and '-' (at most 63 characters)")
				return
			}
			opt.RoutingInstance = v
		default:
			p.errf("ntp server: word %d is not one of prefer, version, key, routing-instance", i+5)
			return
		}
	}
	idx := slices.IndexFunc(p.b.NTPServers, func(s NTPServer) bool { return strings.EqualFold(s.Host, host) })
	if idx < 0 {
		opt.Host = host
		opt.Lines = []int{p.line}
		p.b.NTPServers = append(p.b.NTPServers, opt)
		return
	}
	s := &p.b.NTPServers[idx]
	n := idx + 1
	switch {
	case len(args) == 1:
		p.errf("ntp server %d is listed twice", n)
	case opt.Prefer && s.Prefer, opt.Version != 0 && s.Version != 0, opt.Key != 0 && s.Key != 0,
		opt.RoutingInstance != "" && s.RoutingInstance != "":
		p.errf("ntp server %d: an option is stated twice", n)
	default:
		s.Prefer = s.Prefer || opt.Prefer
		if opt.Version != 0 {
			s.Version = opt.Version
		}
		if opt.Key != 0 {
			s.Key = opt.Key
		}
		if opt.RoutingInstance != "" {
			s.RoutingInstance = opt.RoutingInstance
		}
		s.Lines = append(s.Lines, p.line)
	}
}

func (p *sysParser) ntpKey(args []string) {
	if len(args) != 5 || args[1] != "type" || args[3] != "value" {
		p.errf("ntp authentication-key takes <n> type md5|sha1|sha256 value <secret> (words 5 to 9)")
		return
	}
	n, ok := number(args[0], 1, MaxKeyNumber)
	if !ok {
		p.errf("the number of ntp authentication-key (word 5) is a key number from 1 to %d", MaxKeyNumber)
		return
	}
	if !slices.Contains(NTPKeyTypes, args[2]) {
		p.errf("ntp authentication-key %d: the type (word 7) is one of %s", n, strings.Join(NTPKeyTypes, ", "))
		return
	}
	if placeholder(args[4]) {
		p.errf("ntp authentication-key %d: the value (word 9) %s", n, placeholderWhy)
		return
	}
	if why := nameProblem(args[4]); why != "" {
		p.errf("ntp authentication-key %d: the value (word 9) %s", n, why)
		return
	}
	if slices.ContainsFunc(p.b.NTPKeys, func(k NTPKey) bool { return k.Number == n }) {
		p.errf("ntp authentication-key %d is stated twice", n)
		return
	}
	p.b.NTPKeys = append(p.b.NTPKeys, NTPKey{Number: n, Type: args[2], Value: args[4], Line: p.line})
}

func (p *sysParser) trustedKey(args []string) {
	if len(args) != 1 {
		p.errf("ntp trusted-key takes one key number")
		return
	}
	n, ok := number(args[0], 1, MaxKeyNumber)
	if !ok {
		p.errf("ntp trusted-key takes a key number from 1 to %d", MaxKeyNumber)
		return
	}
	if slices.ContainsFunc(p.b.NTPTrustedKeys, func(k KeyRef) bool { return k.Number == n }) {
		p.errf("ntp trusted-key %d is listed twice", n)
		return
	}
	p.b.NTPTrustedKeys = append(p.b.NTPTrustedKeys, KeyRef{n, p.line})
}

func (p *sysParser) del(t []string) {
	if len(t) < 2 || t[0] != "system" {
		p.errf("only 'delete system ...' is accepted (words 2 and 3)")
		return
	}
	nm := SystemNotManaged{Line: p.line}
	bare := func(kind string, args []string) bool {
		if len(args) != 0 {
			p.errf("'delete system %s' takes nothing after it", t[1])
			return false
		}
		nm.Kind = kind
		return true
	}
	entry := func(kind string, args []string, problem func(string) string) bool {
		if len(args) > 1 {
			p.errf("'delete system %s' takes one value, or none for the whole list", strings.Join(t[1:len(t)-len(args)], " "))
			return false
		}
		nm.Kind = kind
		if len(args) == 1 {
			if why := problem(args[0]); why != "" {
				p.errf("the value of the delete line %s", why)
				return false
			}
			nm.Value = args[0]
		}
		return true
	}
	keyProblem := func(s string) string {
		if _, ok := number(s, 1, MaxKeyNumber); !ok {
			return fmt.Sprintf("is not a key number from 1 to %d", MaxKeyNumber)
		}
		return ""
	}
	var ok bool
	switch t[1] {
	case "login":
		if len(t) != 3 || t[2] != "message" {
			p.errf("only 'delete system login message' is accepted under login")
			return
		}
		ok = bare(SysMessage, nil)
	case "domain-name":
		ok = bare(SysDomainName, t[2:])
	case "time-zone":
		ok = bare(SysTimeZone, t[2:])
	case "domain-search":
		ok = entry(SysDomainSearch, t[2:], hostProblem)
	case "name-server":
		ok = entry(SysNameServer, t[2:], addrProblem)
	case "ntp":
		if len(t) == 2 {
			ok = bare(SysNTP, nil)
			break
		}
		args := t[3:]
		switch t[2] {
		case "server":
			ok = entry(SysNTPServer, args, hostOrAddrProblem)
		case "boot-server":
			ok = bare(SysBootServer, args)
		case "source-address":
			ok = bare(SysSourceAddress, args)
		case "authentication-key":
			ok = entry(SysAuthKey, args, keyProblem)
		case "trusted-key":
			ok = entry(SysTrustedKey, args, keyProblem)
		default:
			p.errf("word 4 is not one of server, boot-server, source-address, authentication-key, trusted-key")
		}
	default:
		p.errf("word 3 is not one of login, domain-name, domain-search, time-zone, name-server, ntp")
	}
	if ok {
		p.b.NotManaged = append(p.b.NotManaged, nm)
	}
}

// --- checking ---------------------------------------------------------------

// charProblem is why a line of the login message cannot be installed (""
// when it can).
func charProblem(s string) string {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\t':
			return fmt.Sprintf("a tab at column %d (the message is typed with blanks)", i+1)
		case c < 0x20 || c == 0x7f:
			return fmt.Sprintf("a control character (0x%02x) at column %d", c, i+1)
		case c >= 0x80:
			return fmt.Sprintf("a character that is not ASCII at column %d", i+1)
		}
	}
	return ""
}

// CheckSystem is what a parsed block has to answer for. Errors: a login
// message that is empty, that holds a tab, a control character, a character
// that is not ASCII, a line that is the terminator, a placeholder, or more
// than MaxMessageChars characters. Notes: the length of the rendered message
// statement beyond MessageNoteChars, the statements that carry a secret, a
// key a server or the trusted list names that the block does not define, and
// the delete lines. The layer is not consulted: the system grammar has no
// rule that differs by layer, and the parameter keeps the dispatch the same as
// the snmp block's. Findings never hold the message or a key's value.
func CheckSystem(b *SystemBlock, _ Layer) []Finding {
	var out []Finding
	add := func(line int, sev Severity, format string, a ...any) {
		out = append(out, Finding{line, sev, fmt.Sprintf(format, a...)})
	}
	if m := b.Message; m != nil {
		lines := strings.Split(m.Body, "\n")
		fileLine := func(idx int) int {
			if m.Line == 0 {
				return 0
			}
			return m.Line + 1 + idx
		}
		switch {
		case strings.TrimSpace(m.Body) == "":
			add(m.Line, SevError, "the login message is empty")
		case len(lines) == 1 && strings.HasPrefix(lines[0], "<message:") && strings.HasSuffix(lines[0], ">"):
			add(fileLine(0), SevError, "the login message is a placeholder (a block holds the text; <message: ...> is only what an engineer is shown)")
		default:
			for i, l := range lines {
				if l == MessageTerminator {
					add(fileLine(i), SevError, "line %d of the login message is %s alone, which would end the heredoc", i+1, MessageTerminator)
				}
				if why := charProblem(l); why != "" {
					add(fileLine(i), SevError, "line %d of the login message holds %s", i+1, why)
				}
			}
			stmt := len(MessageStatement) + len(DeviceMessage(m.Body))
			switch {
			case len(m.Body) > MaxMessageChars:
				add(m.Line, SevError, "the login message is %d characters: at most %d", len(m.Body), MaxMessageChars)
			case stmt > MessageNoteChars:
				add(m.Line, SevNote, "the login message is %d lines and %d characters, a statement of %d: a person pasting the one line into an interactive terminal has it truncated at 1,023 characters; plan --plain (the statements for 'load set', through a file) is the form for it",
					m.Lines(), len(m.Body), stmt)
			}
		}
	}
	defined := map[int]bool{}
	for _, k := range b.NTPKeys {
		defined[k.Number] = true
		add(k.Line, SevNote, "ntp authentication-key %d carries a secret, the key value, on line %d: it is shown elided, and typed only where the device lacks it", k.Number, k.Line)
	}
	for _, s := range b.NTPServers {
		if s.Key != 0 && !defined[s.Key] {
			add(s.Lines[0], SevNote, "ntp server uses key %d, which this block does not define: the device must already hold it", s.Key)
		}
	}
	for _, k := range b.NTPTrustedKeys {
		if !defined[k.Number] {
			add(k.Line, SevNote, "ntp trusted-key %d names a key this block does not define: the device must already hold it", k.Number)
		}
	}
	for _, d := range b.NotManaged {
		add(d.Line, SevNote, "a delete line: what it names is not managed on this device; it is kept and never rendered")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// LintSystem is ParseSystem then CheckSystem: the block and every finding, in
// line order. CheckSystem runs only on a block that parsed without error, so
// one mistake is not reported twice.
func LintSystem(text string, layer Layer) (*SystemBlock, []Finding) {
	b, fs := ParseSystem(text)
	if HasErrors(fs) {
		return b, fs
	}
	fs = append(fs, CheckSystem(b, layer)...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
	return b, fs
}

// --- resolution -------------------------------------------------------------

func upsert[T any](dst []T, v T, same func(T) bool) []T {
	if i := slices.IndexFunc(dst, same); i >= 0 {
		dst[i] = v
		return dst
	}
	return append(dst, v)
}

// ResolveSystem is the block a device is rendered from: the default's
// objects, then the scope's, then the device's. A single-valued statement is
// the most specific layer's; the lists are the union in that order (an entry
// of the same value in a more specific layer replaces the less specific one's
// in place; an authentication-key by its number likewise). A delete line of a
// layer takes the less specific layers' object it names out (a value of a
// list, a whole list, the single value, or with 'delete system ntp' every ntp
// statement); a layer's own statements are applied after its delete lines.
// Any of the three may be nil. The result is a new block, and its NotManaged
// holds every layer's delete lines, the least specific first.
func ResolveSystem(def, scope, dev *SystemBlock) *SystemBlock {
	out := &SystemBlock{}
	for _, l := range []*SystemBlock{def, scope, dev} {
		if l == nil {
			continue
		}
		for _, d := range l.NotManaged {
			out.apply(d)
		}
		if l.Message != nil {
			m := *l.Message
			out.Message = &m
		}
		if l.DomainName != nil {
			v := *l.DomainName
			out.DomainName = &v
		}
		if l.TimeZone != nil {
			v := *l.TimeZone
			out.TimeZone = &v
		}
		if l.NTPBootServer != nil {
			v := *l.NTPBootServer
			out.NTPBootServer = &v
		}
		if l.NTPSourceAddress != nil {
			v := *l.NTPSourceAddress
			out.NTPSourceAddress = &v
		}
		for _, v := range l.DomainSearch {
			out.DomainSearch = upsert(out.DomainSearch, v, func(o Value) bool { return strings.EqualFold(o.Text, v.Text) })
		}
		for _, v := range l.NameServers {
			out.NameServers = upsert(out.NameServers, v, func(o Value) bool { return o.Text == v.Text })
		}
		for _, s := range l.NTPServers {
			s.Lines = slices.Clone(s.Lines)
			out.NTPServers = upsert(out.NTPServers, s, func(o NTPServer) bool { return strings.EqualFold(o.Host, s.Host) })
		}
		for _, k := range l.NTPKeys {
			out.NTPKeys = upsert(out.NTPKeys, k, func(o NTPKey) bool { return o.Number == k.Number })
		}
		for _, k := range l.NTPTrustedKeys {
			out.NTPTrustedKeys = upsert(out.NTPTrustedKeys, k, func(o KeyRef) bool { return o.Number == k.Number })
		}
		out.NotManaged = append(out.NotManaged, l.NotManaged...)
	}
	return out
}

// apply takes the object a delete line names out of b.
func (b *SystemBlock) apply(d SystemNotManaged) {
	match := func(s string) bool { return d.Value == "" || strings.EqualFold(s, d.Value) }
	num := func(n int) bool { return d.Value == "" || strconv.Itoa(n) == d.Value }
	switch d.Kind {
	case SysMessage:
		b.Message = nil
	case SysDomainName:
		b.DomainName = nil
	case SysTimeZone:
		b.TimeZone = nil
	case SysDomainSearch:
		b.DomainSearch = slices.DeleteFunc(b.DomainSearch, func(v Value) bool { return match(v.Text) })
	case SysNameServer:
		b.NameServers = slices.DeleteFunc(b.NameServers, func(v Value) bool { return match(v.Text) })
	case SysNTPServer:
		b.NTPServers = slices.DeleteFunc(b.NTPServers, func(s NTPServer) bool { return match(s.Host) })
	case SysBootServer:
		b.NTPBootServer = nil
	case SysSourceAddress:
		b.NTPSourceAddress = nil
	case SysAuthKey:
		b.NTPKeys = slices.DeleteFunc(b.NTPKeys, func(k NTPKey) bool { return num(k.Number) })
	case SysTrustedKey:
		b.NTPTrustedKeys = slices.DeleteFunc(b.NTPTrustedKeys, func(k KeyRef) bool { return num(k.Number) })
	case SysNTP:
		b.NTPServers, b.NTPBootServer, b.NTPSourceAddress, b.NTPKeys, b.NTPTrustedKeys = nil, nil, nil, nil, nil
	}
}

// --- statements, text -------------------------------------------------------

// SystemStatements are the 'set' lines of the block in a stable order: login
// message (the one line, DeviceMessage), domain-name, domain-search,
// time-zone, name-server, then ntp: server, boot-server, source-address,
// authentication-key, trusted-key. This is what the managed system section is
// made of.
func SystemStatements(b *SystemBlock) []string {
	if b == nil {
		return nil
	}
	var out []string
	if b.Message != nil {
		out = append(out, MessageStatement+DeviceMessage(b.Message.Body))
	}
	return append(out, b.statementsBesidesMessage()...)
}

func (b *SystemBlock) statementsBesidesMessage() []string {
	var out []string
	if b.DomainName != nil {
		out = append(out, "set system domain-name "+b.DomainName.Text)
	}
	for _, v := range b.DomainSearch {
		out = append(out, "set system domain-search "+v.Text)
	}
	if b.TimeZone != nil {
		out = append(out, "set system time-zone "+b.TimeZone.Text)
	}
	for _, v := range b.NameServers {
		out = append(out, "set system name-server "+v.Text)
	}
	for _, s := range b.NTPServers {
		l := "set system ntp server " + s.Host
		if s.Prefer {
			l += " prefer"
		}
		if s.Version != 0 {
			l += " version " + strconv.Itoa(s.Version)
		}
		if s.Key != 0 {
			l += " key " + strconv.Itoa(s.Key)
		}
		if s.RoutingInstance != "" {
			l += " routing-instance " + s.RoutingInstance
		}
		out = append(out, l)
	}
	if b.NTPBootServer != nil {
		out = append(out, "set system ntp boot-server "+b.NTPBootServer.Text)
	}
	if b.NTPSourceAddress != nil {
		out = append(out, "set system ntp source-address "+b.NTPSourceAddress.Text)
	}
	for _, k := range b.NTPKeys {
		out = append(out, fmt.Sprintf("set system ntp authentication-key %d type %s value %s", k.Number, k.Type, k.Value))
	}
	for _, k := range b.NTPTrustedKeys {
		out = append(out, fmt.Sprintf("set system ntp trusted-key %d", k.Number))
	}
	return out
}

func (d SystemNotManaged) text() string {
	var s string
	switch d.Kind {
	case SysMessage:
		s = "delete system login message"
	case SysDomainName, SysDomainSearch, SysTimeZone, SysNameServer:
		s = "delete system " + d.Kind
	case SysNTP:
		s = "delete system ntp"
	case SysNTPServer:
		s = "delete system ntp server"
	default:
		s = "delete system ntp " + d.Kind
	}
	if d.Value != "" {
		s += " " + d.Value
	}
	return s
}

// ElideSystem is a copy of the block in which the login message is replaced
// by a mark of its size (<message: N lines, M characters>) and every NTP key
// value by <secret>, for the engineers' reads. The marks are refused when an
// elided text is read back as a block.
func ElideSystem(b *SystemBlock) *SystemBlock {
	if b == nil {
		return nil
	}
	out := *b
	if b.Message != nil {
		m := *b.Message
		m.Body = messageMark(b.Message)
		out.Message = &m
	}
	out.NTPKeys = slices.Clone(b.NTPKeys)
	for i := range out.NTPKeys {
		out.NTPKeys[i].Value = secretMark
	}
	out.DomainSearch = slices.Clone(b.DomainSearch)
	out.NameServers = slices.Clone(b.NameServers)
	out.NTPServers = slices.Clone(b.NTPServers)
	for i := range out.NTPServers {
		out.NTPServers[i].Lines = slices.Clone(out.NTPServers[i].Lines)
	}
	out.NTPTrustedKeys = slices.Clone(b.NTPTrustedKeys)
	out.NotManaged = slices.Clone(b.NotManaged)
	return &out
}

// String is the block as canonical text: the login message as its heredoc,
// then the other statements in the order of SystemStatements, then the delete
// lines in the order given; comments and blank lines are not kept. A block
// read back from it is the same block, and its own String is the same text.
// With elided, the message and the NTP key values are the marks of
// ElideSystem.
func (b *SystemBlock) String(elided bool) string {
	if b == nil {
		return ""
	}
	if elided {
		b = ElideSystem(b)
	}
	var lines []string
	if b.Message != nil {
		lines = append(lines, MessageStart)
		lines = append(lines, strings.Split(b.Message.Body, "\n")...)
		lines = append(lines, MessageTerminator)
	}
	lines = append(lines, b.statementsBesidesMessage()...)
	for _, d := range b.NotManaged {
		lines = append(lines, d.text())
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// --- dispatch by block name -------------------------------------------------

// Doc is what the grammars of the blocks have in common: *SNMPBlock,
// *SystemBlock, *IOSSNMPBlock and *IOSSystemBlock.
type Doc interface {
	Empty() bool
	String(elided bool) string
}

// LintBlock is Lint or LintSystem by the name of the block (BlockSNMP,
// BlockSystem), the Junos grammars; a name that has no grammar is an error.
// The Doc is *SNMPBlock or *SystemBlock.
func LintBlock(block, text string, layer Layer) (Doc, []Finding, error) {
	switch block {
	case BlockSNMP:
		b, fs := Lint(text, layer)
		return b, fs, nil
	case BlockSystem:
		b, fs := LintSystem(text, layer)
		return b, fs, nil
	}
	return nil, nil, fail("Unknown block '" + block + "' (one of: " + strings.Join(KnownBlocks, ", ") + ").")
}

// StatementsOf is the rendered 'set' lines of a block of either grammar.
func StatementsOf(d Doc) []string {
	switch b := d.(type) {
	case *SNMPBlock:
		return Statements(b)
	case *SystemBlock:
		return SystemStatements(b)
	case *IOSSNMPBlock:
		return IOSSNMPStatements(b)
	case *IOSSystemBlock:
		return IOSSystemStatements(b)
	}
	return nil
}
