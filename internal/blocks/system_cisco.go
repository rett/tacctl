package blocks

// The IOS and IOS-XE system block (0.2.7, docs/plans/0.2.7-blocks-plan.md "IOS
// system block and trap-source as built"): configuration lines for the
// device's own system settings, one statement per line, '#' and '!' comment
// lines and blank lines, and one heredoc form for the login banner:
//
//	banner login <<'EOF'
//	<line>
//	...
//	EOF
//	ip domain name <name>
//	ip domain list <name>
//	clock timezone <zone> <hours> [<minutes>]
//	ip name-server <address> [<address> ...]
//	ntp server <address-or-name> [prefer] [version <1-4>] [key <n>] [source <interface>]
//	ntp authentication-key <n> md5 <string>
//	ntp trusted-key <n>
//	ntp authenticate
//	no <statement>
//
// The block is additive only, as the Junos system block is: every statement
// is an object, set when the device lacks it, and what the device holds
// beside it is kept and listed as unmanaged. A single-valued statement
// (banner, domain name, time zone, 'ntp authenticate') replaces the device's
// value when it differs; a list statement adds. A 'no ...' line says "not
// managed here": it is kept (SystemNotManaged), never rendered, and in a more
// specific layer it takes the less specific layers' object out of the
// resolved block.
//
// The login banner is a heredoc in the file so that the text is easy to read
// and edit. It is rendered as IOS's multi-line banner: 'banner login <d>',
// the text lines, '<d>' alone on a line, where <d> is a delimiter character
// chosen per rendering from BannerDelimiters, the first the text does not
// contain.
//
// Everything here is a pure function of text. What a block holds that must
// not be echoed is the banner (it names a site) and an NTP key's value (a
// secret): no finding and no message of this package ever holds a word of
// either; they are named by line, column and count. The VRF forms ('ntp
// server vrf', 'ip name-server vrf', 'ip domain name vrf') are not in the
// grammar: a device's own lines of those forms stay unmanaged.

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The limits of the banner.
const (
	// MaxBannerLines is the most lines of a login banner.
	MaxBannerLines = 20
	// MaxBannerColumns is the longest line of a login banner: well inside what
	// IOS takes on one typed line (255), and what fits a terminal.
	MaxBannerColumns = 80
	// IOSBannerStart is the line that opens the heredoc of the banner.
	IOSBannerStart = "banner login <<'EOF'"
	// IOSBannerHead is the head of the rendered banner's first line.
	IOSBannerHead = "banner login "
)

// BannerDelimiters are the delimiter candidates of a rendered banner, in the
// order they are tried.
var BannerDelimiters = []string{"^", "~", "%", "#", "@", "$", "&"}

// maxIOSKeyNumber is the highest NTP key number IOS takes.
const maxIOSKeyNumber = 4294967295

// maxNTPKeyChars is the longest NTP key string.
const maxNTPKeyChars = 32

// SysAuthenticate is the kind of a 'no ntp authenticate' line.
const SysAuthenticate = "authenticate"

var reZone = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,15}$`)

// IOSTimezone is the 'clock timezone <zone> <hours> [<minutes>]' statement.
// HasMinutes says the minutes were written (a device prints them as 0 or not
// at all, by its version; the compared form always has them).
type IOSTimezone struct {
	Zone       string
	Hours      int
	Minutes    int
	HasMinutes bool
	Line       int
}

// Text is the statement as the block writes it.
func (z *IOSTimezone) Text() string {
	s := "clock timezone " + z.Zone + " " + strconv.Itoa(z.Hours)
	if z.HasMinutes {
		s += " " + strconv.Itoa(z.Minutes)
	}
	return s
}

// IOSNTPServer is one 'ntp server <address-or-name>' object with the options
// of its statement. Host is an IPv4 address in canonical text or a host name
// (as written; compared without case). Zero Version and Key and an empty
// Source are unstated.
type IOSNTPServer struct {
	Host    string
	Prefer  bool
	Version int
	Key     int
	Source  string
	Line    int
}

// Text is the statement as the block writes it: the options in the order of
// the IOS reference (version, key, source, prefer).
func (s IOSNTPServer) Text() string {
	l := "ntp server " + s.Host
	if s.Version != 0 {
		l += " version " + strconv.Itoa(s.Version)
	}
	if s.Key != 0 {
		l += " key " + strconv.Itoa(s.Key)
	}
	if s.Source != "" {
		l += " source " + s.Source
	}
	if s.Prefer {
		l += " prefer"
	}
	return l
}

// IOSSystemBlock is a parsed IOS system block. The lists are in the order of
// their first statement.
type IOSSystemBlock struct {
	Banner      *LoginMessage
	DomainName  *Value
	DomainList  []Value
	Timezone    *IOSTimezone
	NameServers []Value
	NTPServers  []IOSNTPServer
	NTPKeys     []NTPKey
	// NTPTrustedKeys are the 'ntp trusted-key' statements.
	NTPTrustedKeys []KeyRef
	// NTPAuthenticate is the 'ntp authenticate' statement (Text is empty: a
	// bare boolean), nil when not stated.
	NTPAuthenticate *Value
	NotManaged      []SystemNotManaged
}

// BannerBody is the banner's text, "" for none.
func (b *IOSSystemBlock) BannerBody() string {
	if b == nil || b.Banner == nil {
		return ""
	}
	return b.Banner.Body
}

// Empty reports a block with no statement and no 'no' line.
func (b *IOSSystemBlock) Empty() bool {
	return b == nil || (b.Banner == nil && b.DomainName == nil && len(b.DomainList) == 0 && b.Timezone == nil &&
		len(b.NameServers) == 0 && len(b.NTPServers) == 0 && len(b.NTPKeys) == 0 && len(b.NTPTrustedKeys) == 0 &&
		b.NTPAuthenticate == nil && len(b.NotManaged) == 0)
}

// --- the banner on the wire -------------------------------------------------

// BannerDelimiter is the first of BannerDelimiters that the text does not
// contain; ok is false when the text holds every one of them.
func BannerDelimiter(body string) (string, bool) {
	for _, d := range BannerDelimiters {
		if !strings.Contains(body, d) {
			return d, true
		}
	}
	return "", false
}

// IOSBannerLines is the banner as it is typed: 'banner login <d>', the text
// lines, '<d>' alone on a line. nil when no delimiter fits the text.
func IOSBannerLines(body string) []string {
	d, ok := BannerDelimiter(body)
	if !ok {
		return nil
	}
	out := []string{IOSBannerHead + d}
	out = append(out, strings.Split(body, "\n")...)
	return append(out, d)
}

// DeviceBanner reads the banner a device prints from lines, the first of
// which is its 'banner login ...' line (leading blanks trimmed). It returns
// the text (the lines joined by "\n", none after the last, trailing blanks of
// every line trimmed), how many lines the banner took, and whether it was
// read: the delimiter is '^C' (what IOS prints for Ctrl-C) or one printable
// character; the text may begin on the opening line and end on the closing
// one, and one line break after the opening delimiter and one before the
// closing delimiter belong to the delimiters. A banner that is never closed
// takes every line and is not ok.
func DeviceBanner(lines []string) (body string, took int, ok bool) {
	if len(lines) == 0 {
		return "", 0, false
	}
	first := strings.TrimSpace(lines[0])
	rest, found := strings.CutPrefix(first, "banner login")
	if !found || (rest != "" && rest[0] != ' ') {
		return "", 1, false
	}
	rest = strings.TrimLeft(rest, " ")
	if rest == "" {
		return "", 1, false
	}
	delim := rest[:1]
	if strings.HasPrefix(rest, "^C") {
		delim = "^C"
	}
	raw := rest[len(delim):]
	took = 1
	closed := false
	for {
		if i := strings.Index(raw, delim); i >= 0 {
			raw, closed = raw[:i], true
			break
		}
		if took >= len(lines) {
			break
		}
		raw += "\n" + lines[took]
		took++
	}
	if !closed {
		return "", took, false
	}
	// one line break after the opening delimiter and one before the closing
	// one are the delimiters' own
	raw = strings.TrimPrefix(raw, "\n")
	raw = strings.TrimSuffix(raw, "\n")
	ls := strings.Split(raw, "\n")
	for i := range ls {
		ls[i] = strings.TrimRight(ls[i], " \t\r")
	}
	return strings.Join(ls, "\n"), took, true
}

// --- parsing ----------------------------------------------------------------

type iosSysParser struct {
	b        *IOSSystemBlock
	findings []Finding
	line     int
}

func (p *iosSysParser) errf(format string, a ...any) {
	p.findings = append(p.findings, Finding{p.line, SevError, fmt.Sprintf(format, a...)})
}

// iosSysLineProblem is why a line of a block outside the heredoc is refused
// before it is read ("" when it is not), and whether it is a comment (which
// may hold a character that is not ASCII).
func iosSysLineProblem(raw string) (string, bool) {
	t := strings.TrimLeft(raw, " ")
	comment := strings.HasPrefix(t, "#") || strings.HasPrefix(t, "!")
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

// ParseIOSSystem reads a block's text: its statements, and a finding (line
// number, severity, text) for everything that is off the grammar. A block
// with an error finding is partial and must not be used. The content of the
// banner is Check's to judge; Parse takes its lines as they are. Findings are
// in line order.
func ParseIOSSystem(text string) (*IOSSystemBlock, []Finding) {
	p := &iosSysParser{b: &IOSSystemBlock{}}
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
func (p *iosSysParser) parseLine(lines []string, i int) int {
	raw := lines[i]
	problem, comment := iosSysLineProblem(raw)
	if problem != "" {
		p.errf("%s", problem)
		return 1
	}
	if comment || strings.TrimSpace(raw) == "" {
		return 1
	}
	f := strings.Fields(raw)
	if f[0] == "banner" {
		return p.banner(f[1:], lines, i)
	}
	if strings.ContainsAny(raw, `"'`) {
		p.errf("a quote is not accepted in a system statement (only the login banner holds text, as a heredoc)")
		return 1
	}
	switch f[0] {
	case "ip":
		p.ip(f[1:])
	case "clock":
		p.clock(f[1:])
	case "ntp":
		p.ntp(f[1:])
	case "no":
		p.no(f[1:])
	default:
		p.errf("a block holds 'banner login', 'ip', 'clock', 'ntp' and 'no' statements only (word 1)")
	}
	return 1
}

// banner reads the heredoc whose opening is at lines[i]; rest are the words
// after 'banner'.
func (p *iosSysParser) banner(rest []string, lines []string, i int) int {
	switch {
	case len(rest) == 0 || rest[0] != "login":
		p.errf("only 'banner login' is accepted (word 2)")
		return 1
	case len(rest) == 2 && rest[1] == "<<'EOF'":
	case len(rest) >= 2 && strings.HasPrefix(rest[1], "<<"):
		p.errf("the heredoc marker is written <<'EOF' exactly: quoted, so that no expansion happens, with nothing after it")
		return 1
	default:
		p.errf("the login banner is a heredoc: %s, its lines, then %s alone on a line", IOSBannerStart, MessageTerminator)
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
		p.errf("the heredoc of the login banner is never closed (%s alone on a line ends it)", MessageTerminator)
		return len(lines) - i
	}
	if p.b.Banner != nil {
		p.errf("the login banner is stated twice")
	} else {
		body := strings.Join(lines[i+1:end], "\n")
		p.b.Banner = &LoginMessage{Body: body, Line: i + 1}
	}
	return end - i + 1
}

// single reads a single-valued statement of one word.
func (p *iosSysParser) single(dst **Value, what string, args []string, problem func(string) string) {
	if len(args) >= 1 && args[0] == "vrf" {
		p.errf("%s: a vrf form is not accepted in a block (the device's own stays unmanaged)", what)
		return
	}
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
	*dst = &Value{strings.ToLower(args[0]), p.line}
}

func (p *iosSysParser) ip(t []string) {
	if len(t) == 0 {
		p.errf("'ip' needs domain or name-server (word 2)")
		return
	}
	switch t[0] {
	case "domain":
		if len(t) < 2 {
			p.errf("'ip domain' needs name or list (word 3)")
			return
		}
		switch t[1] {
		case "name":
			p.single(&p.b.DomainName, "ip domain name", t[2:], hostProblem)
		case "list":
			p.listOf(&p.b.DomainList, "ip domain list", t[2:], hostProblem)
		default:
			p.errf("word 3 is not name or list (ip domain lookup and the rest are the device's own)")
		}
	case "domain-name":
		p.single(&p.b.DomainName, "ip domain name", t[1:], hostProblem)
	case "domain-list":
		p.listOf(&p.b.DomainList, "ip domain list", t[1:], hostProblem)
	case "name-server":
		p.nameServers(t[1:])
	default:
		p.errf("word 2 is not one of domain, name-server")
	}
}

// listOf reads one entry of a list statement; the text is kept in lower case
// (a host name is no case).
func (p *iosSysParser) listOf(dst *[]Value, what string, args []string, problem func(string) string) {
	if len(args) >= 1 && args[0] == "vrf" {
		p.errf("%s: a vrf form is not accepted in a block (the device's own stays unmanaged)", what)
		return
	}
	if len(args) != 1 {
		p.errf("%s takes one value and nothing else", what)
		return
	}
	if why := problem(args[0]); why != "" {
		p.errf("the value of %s %s", what, why)
		return
	}
	v := strings.ToLower(args[0])
	if i := slices.IndexFunc(*dst, func(x Value) bool { return x.Text == v }); i >= 0 {
		p.errf("%s %d is listed twice", what, i+1)
		return
	}
	*dst = append(*dst, Value{v, p.line})
}

// nameServers reads 'ip name-server <address> [<address> ...]': one object
// per address.
func (p *iosSysParser) nameServers(args []string) {
	if len(args) >= 1 && args[0] == "vrf" {
		p.errf("ip name-server: a vrf form is not accepted in a block (the device's own stays unmanaged)")
		return
	}
	if len(args) == 0 {
		p.errf("'ip name-server' needs at least one address (word 3)")
		return
	}
	var add []Value
	for i, a := range args {
		if why := addrProblem(a); why != "" {
			p.errf("the address %d of ip name-server (word %d) %s", i+1, i+3, why)
			return
		}
		if j := slices.IndexFunc(p.b.NameServers, func(v Value) bool { return v.Text == a }); j >= 0 || slices.ContainsFunc(add, func(v Value) bool { return v.Text == a }) {
			p.errf("ip name-server %d is listed twice", i+1)
			return
		}
		add = append(add, Value{a, p.line})
	}
	p.b.NameServers = append(p.b.NameServers, add...)
}

func (p *iosSysParser) clock(t []string) {
	if len(t) == 0 || t[0] != "timezone" {
		p.errf("only 'clock timezone' is accepted after 'clock' (summer time and the rest are the device's own, word 2)")
		return
	}
	args := t[1:]
	if len(args) < 2 || len(args) > 3 {
		p.errf("clock timezone takes <zone> <hours> [<minutes>]")
		return
	}
	if placeholder(args[0]) {
		p.errf("the zone of clock timezone (word 3) %s", placeholderWhy)
		return
	}
	if !reZone.MatchString(args[0]) {
		p.errf("the zone of clock timezone (word 3) is a name of letters, digits, '_' and '-' (at most 16 characters, starting with a letter)")
		return
	}
	hours, ok := signed(args[1], -23, 23)
	if !ok {
		p.errf("the hours of clock timezone (word 4) are a whole number from -23 to 23")
		return
	}
	z := &IOSTimezone{Zone: args[0], Hours: hours, Line: p.line}
	if len(args) == 3 {
		m, ok := number(args[2], 0, 59)
		if !ok {
			p.errf("the minutes of clock timezone (word 5) are a whole number from 0 to 59")
			return
		}
		z.Minutes, z.HasMinutes = m, true
	}
	if p.b.Timezone != nil {
		p.errf("clock timezone is stated twice")
		return
	}
	p.b.Timezone = z
}

// signed is a canonical decimal in [lo, hi] with an optional leading '+'.
func signed(s string, lo, hi int) (int, bool) {
	t := strings.TrimPrefix(s, "+")
	n, err := strconv.Atoi(t)
	if err != nil || strconv.Itoa(n) != t || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

func (p *iosSysParser) ntp(t []string) {
	if len(t) == 0 {
		p.errf("'ntp' needs server, authentication-key, trusted-key or authenticate (word 2)")
		return
	}
	args := t[1:]
	switch t[0] {
	case "server":
		p.ntpServer(args)
	case "authentication-key":
		p.ntpKey(args)
	case "trusted-key":
		p.trustedKey(args)
	case "authenticate":
		if len(args) != 0 {
			p.errf("'ntp authenticate' takes nothing after it")
			return
		}
		if p.b.NTPAuthenticate != nil {
			p.errf("ntp authenticate is stated twice")
			return
		}
		p.b.NTPAuthenticate = &Value{"", p.line}
	default:
		p.errf("word 2 is not one of server, authentication-key, trusted-key, authenticate (the rest of ntp is the device's own)")
	}
}

func (p *iosSysParser) ntpServer(args []string) {
	if len(args) == 0 {
		p.errf("'ntp server' needs an address or a name (word 3)")
		return
	}
	if args[0] == "vrf" || args[0] == "ip" || args[0] == "ipv6" {
		p.errf("ntp server: '%s' is not in the grammar of a block (write the address or the name; the device's own vrf lines stay unmanaged)", args[0])
		return
	}
	host := args[0]
	if strings.Contains(host, ":") {
		p.errf("ntp server: an IPv6 address is not in the grammar of a block yet (an IPv4 address or a name)")
		return
	}
	if why := hostOrAddrProblem(host); why != "" {
		p.errf("the address of ntp server (word 3) %s", why)
		return
	}
	s := IOSNTPServer{Host: host, Line: p.line}
	for i := 1; i < len(args); i++ {
		w := args[i]
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
			if s.Prefer {
				p.errf("ntp server: prefer is stated twice on the line")
				return
			}
			s.Prefer = true
		case "version":
			if s.Version != 0 {
				p.errf("ntp server: version is stated twice on the line")
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
			s.Version = n
		case "key":
			if s.Key != 0 {
				p.errf("ntp server: key is stated twice on the line")
				return
			}
			v, ok := value()
			if !ok {
				return
			}
			n, ok := number(v, 1, maxIOSKeyNumber)
			if !ok {
				p.errf("ntp server: key takes a key number from 1 to %d", maxIOSKeyNumber)
				return
			}
			s.Key = n
		case "source":
			if s.Source != "" {
				p.errf("ntp server: source is stated twice on the line")
				return
			}
			v, ok := value()
			if !ok {
				return
			}
			if why := InterfaceProblem(v); why != "" {
				p.errf("the interface of ntp server source %s", why)
				return
			}
			s.Source = v
		default:
			p.errf("ntp server: word %d is not one of prefer, version, key, source", i+3)
			return
		}
	}
	if i := slices.IndexFunc(p.b.NTPServers, func(o IOSNTPServer) bool { return strings.EqualFold(o.Host, host) }); i >= 0 {
		p.errf("ntp server %d is listed twice (one line per server)", i+1)
		return
	}
	p.b.NTPServers = append(p.b.NTPServers, s)
}

func (p *iosSysParser) ntpKey(args []string) {
	if len(args) == 0 {
		p.errf("'ntp authentication-key' needs a key number (word 3)")
		return
	}
	n, ok := number(args[0], 1, maxIOSKeyNumber)
	if !ok {
		p.errf("the number of ntp authentication-key (word 3) is a key number from 1 to %d", maxIOSKeyNumber)
		return
	}
	if len(args) != 3 || args[1] != "md5" {
		p.errf("ntp authentication-key %d takes md5 <string> (words 4 and 5)", n)
		return
	}
	switch {
	case placeholder(args[2]):
		p.errf("ntp authentication-key %d: the string (word 5) %s", n, placeholderWhy)
		return
	case len(args[2]) > maxNTPKeyChars:
		p.errf("ntp authentication-key %d: the string (word 5) is longer than %d characters", n, maxNTPKeyChars)
		return
	}
	if why := nameProblem(args[2]); why != "" {
		p.errf("ntp authentication-key %d: the string (word 5) %s", n, why)
		return
	}
	if slices.ContainsFunc(p.b.NTPKeys, func(k NTPKey) bool { return k.Number == n }) {
		p.errf("ntp authentication-key %d is stated twice", n)
		return
	}
	p.b.NTPKeys = append(p.b.NTPKeys, NTPKey{Number: n, Type: "md5", Value: args[2], Line: p.line})
}

func (p *iosSysParser) trustedKey(args []string) {
	if len(args) != 1 {
		p.errf("ntp trusted-key takes one key number")
		return
	}
	n, ok := number(args[0], 1, maxIOSKeyNumber)
	if !ok {
		p.errf("ntp trusted-key takes a key number from 1 to %d", maxIOSKeyNumber)
		return
	}
	if slices.ContainsFunc(p.b.NTPTrustedKeys, func(k KeyRef) bool { return k.Number == n }) {
		p.errf("ntp trusted-key %d is listed twice", n)
		return
	}
	p.b.NTPTrustedKeys = append(p.b.NTPTrustedKeys, KeyRef{n, p.line})
}

// no reads a 'no ...' line: not managed on this device.
func (p *iosSysParser) no(t []string) {
	if len(t) == 0 {
		p.errf("'no' needs a statement (word 2)")
		return
	}
	nm := SystemNotManaged{Line: p.line}
	bare := func(kind string, args []string, what string) bool {
		if len(args) != 0 {
			p.errf("'no %s' takes nothing after it", what)
			return false
		}
		nm.Kind = kind
		return true
	}
	entry := func(kind string, args []string, what string, problem func(string) string) bool {
		if len(args) > 1 {
			p.errf("'no %s' takes one value, or none for the whole list", what)
			return false
		}
		nm.Kind = kind
		if len(args) == 1 {
			if why := problem(args[0]); why != "" {
				p.errf("the value of the no line %s", why)
				return false
			}
			nm.Value = strings.ToLower(args[0])
		}
		return true
	}
	keyProblem := func(s string) string {
		if _, ok := number(s, 1, maxIOSKeyNumber); !ok {
			return fmt.Sprintf("is not a key number from 1 to %d", maxIOSKeyNumber)
		}
		return ""
	}
	var ok bool
	switch t[0] {
	case "banner":
		if len(t) < 2 || t[1] != "login" {
			p.errf("only 'no banner login' is accepted after 'no banner'")
			return
		}
		ok = bare(SysMessage, t[2:], "banner login")
	case "clock":
		if len(t) < 2 || t[1] != "timezone" {
			p.errf("only 'no clock timezone' is accepted after 'no clock'")
			return
		}
		ok = bare(SysTimeZone, t[2:], "clock timezone")
	case "ip":
		if len(t) < 2 {
			p.errf("'no ip' needs domain or name-server (word 3)")
			return
		}
		switch {
		case t[1] == "domain" && len(t) >= 3 && t[2] == "name":
			ok = bare(SysDomainName, t[3:], "ip domain name")
		case t[1] == "domain-name":
			ok = bare(SysDomainName, t[2:], "ip domain name")
		case t[1] == "domain" && len(t) >= 3 && t[2] == "list":
			ok = entry(SysDomainSearch, t[3:], "ip domain list", hostProblem)
		case t[1] == "domain-list":
			ok = entry(SysDomainSearch, t[2:], "ip domain list", hostProblem)
		case t[1] == "name-server":
			ok = entry(SysNameServer, t[2:], "ip name-server", addrProblem)
		default:
			p.errf("a 'no ip' line takes 'domain name', 'domain list' or 'name-server'")
			return
		}
	case "ntp":
		if len(t) == 1 {
			ok = bare(SysNTP, nil, "ntp")
			break
		}
		args := t[2:]
		switch t[1] {
		case "server":
			ok = entry(SysNTPServer, args, "ntp server", hostOrAddrProblem)
		case "authentication-key":
			ok = entry(SysAuthKey, args, "ntp authentication-key", keyProblem)
		case "trusted-key":
			ok = entry(SysTrustedKey, args, "ntp trusted-key", keyProblem)
		case "authenticate":
			ok = bare(SysAuthenticate, args, "ntp authenticate")
		default:
			p.errf("word 3 is not one of server, authentication-key, trusted-key, authenticate")
			return
		}
	default:
		p.errf("a 'no' line takes banner, clock, ip or ntp (word 2)")
		return
	}
	if ok {
		p.b.NotManaged = append(p.b.NotManaged, nm)
	}
}

// --- checking ---------------------------------------------------------------

// CheckIOSSystem is what a parsed block has to answer for. Errors: a banner
// that is empty, that is a placeholder, that holds a tab, a control
// character, a character that is not ASCII, a line that is the terminator, a
// line over MaxBannerColumns, more than MaxBannerLines lines, or every
// delimiter candidate. Notes: the statements that carry a secret, a key a
// server or the trusted list names that the block does not define, keys with
// no 'ntp authenticate', and the no lines. The layer is not consulted: the
// system grammar has no rule that differs by layer. Findings never hold the
// banner or a key's value.
func CheckIOSSystem(b *IOSSystemBlock, _ Layer) []Finding {
	var out []Finding
	add := func(line int, sev Severity, format string, a ...any) {
		out = append(out, Finding{line, sev, fmt.Sprintf(format, a...)})
	}
	if m := b.Banner; m != nil {
		lines := strings.Split(m.Body, "\n")
		fileLine := func(idx int) int {
			if m.Line == 0 {
				return 0
			}
			return m.Line + 1 + idx
		}
		switch {
		case strings.TrimSpace(m.Body) == "":
			add(m.Line, SevError, "the login banner is empty")
		case len(lines) == 1 && strings.HasPrefix(lines[0], "<message:") && strings.HasSuffix(lines[0], ">"):
			add(fileLine(0), SevError, "the login banner is a placeholder (a block holds the text; <message: ...> is only what an engineer is shown)")
		default:
			for i, l := range lines {
				if l == MessageTerminator {
					add(fileLine(i), SevError, "line %d of the login banner is %s alone, which would end the heredoc", i+1, MessageTerminator)
				}
				if why := charProblem(l); why != "" {
					add(fileLine(i), SevError, "line %d of the login banner holds %s", i+1, why)
				}
				if len(l) > MaxBannerColumns {
					add(fileLine(i), SevError, "line %d of the login banner is %d characters: at most %d", i+1, len(l), MaxBannerColumns)
				}
			}
			if len(lines) > MaxBannerLines {
				add(m.Line, SevError, "the login banner is %d lines: at most %d", len(lines), MaxBannerLines)
			}
			if _, ok := BannerDelimiter(m.Body); !ok {
				add(m.Line, SevError, "the login banner holds every delimiter character tacctl can render it with (%s): remove one of them from the text",
					strings.Join(BannerDelimiters, " "))
			}
		}
	}
	defined := map[int]bool{}
	for _, k := range b.NTPKeys {
		defined[k.Number] = true
		add(k.Line, SevNote, "ntp authentication-key %d carries a secret, the key string, on line %d: it is shown elided, and typed only where the device lacks a key of that number", k.Number, k.Line)
	}
	for _, s := range b.NTPServers {
		if s.Key != 0 && !defined[s.Key] {
			add(s.Line, SevNote, "ntp server uses key %d, which this block does not define: the device must already hold it", s.Key)
		}
	}
	for _, k := range b.NTPTrustedKeys {
		if !defined[k.Number] {
			add(k.Line, SevNote, "ntp trusted-key %d names a key this block does not define: the device must already hold it", k.Number)
		}
	}
	if len(b.NTPKeys) > 0 && b.NTPAuthenticate == nil {
		add(b.NTPKeys[0].Line, SevNote, "a key is stated and 'ntp authenticate' is not: a device uses its keys only while 'ntp authenticate' is on (state it here, or the device's own setting stands)")
	}
	if b.NTPAuthenticate != nil && len(b.NTPKeys) == 0 && len(b.NTPTrustedKeys) == 0 {
		add(b.NTPAuthenticate.Line, SevNote, "'ntp authenticate' needs keys and trusted keys on the device: this block states none, so the device must already hold them")
	}
	for _, d := range b.NotManaged {
		add(d.Line, SevNote, "a 'no' line: what it names is not managed on this device; it is kept and never rendered")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// LintIOSSystem is ParseIOSSystem then CheckIOSSystem: the block and every
// finding, in line order. Check runs only on a block that parsed without
// error, so one mistake is not reported twice.
func LintIOSSystem(text string, layer Layer) (*IOSSystemBlock, []Finding) {
	b, fs := ParseIOSSystem(text)
	if HasErrors(fs) {
		return b, fs
	}
	fs = append(fs, CheckIOSSystem(b, layer)...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
	return b, fs
}

// --- resolution -------------------------------------------------------------

// ResolveIOSSystem is the block a device is rendered from: the default's
// objects, then the scope's, then the device's. A single-valued statement is
// the most specific layer's; the lists are the union in that order (an entry
// of the same value in a more specific layer replaces the less specific
// one's in place; a server by its host, a key by its number). A no line of a
// layer takes the less specific layers' object it names out (a value of a
// list, a whole list, the single value, or with 'no ntp' every ntp
// statement); a layer's own statements are applied after its no lines. Any of
// the three may be nil. The result is a new block, and its NotManaged holds
// every layer's no lines, the least specific first.
func ResolveIOSSystem(def, scope, dev *IOSSystemBlock) *IOSSystemBlock {
	out := &IOSSystemBlock{}
	for _, l := range []*IOSSystemBlock{def, scope, dev} {
		if l == nil {
			continue
		}
		for _, d := range l.NotManaged {
			out.apply(d)
		}
		if l.Banner != nil {
			m := *l.Banner
			out.Banner = &m
		}
		if l.DomainName != nil {
			v := *l.DomainName
			out.DomainName = &v
		}
		if l.Timezone != nil {
			z := *l.Timezone
			out.Timezone = &z
		}
		if l.NTPAuthenticate != nil {
			v := *l.NTPAuthenticate
			out.NTPAuthenticate = &v
		}
		for _, v := range l.DomainList {
			out.DomainList = upsert(out.DomainList, v, func(o Value) bool { return o.Text == v.Text })
		}
		for _, v := range l.NameServers {
			out.NameServers = upsert(out.NameServers, v, func(o Value) bool { return o.Text == v.Text })
		}
		for _, s := range l.NTPServers {
			out.NTPServers = upsert(out.NTPServers, s, func(o IOSNTPServer) bool { return strings.EqualFold(o.Host, s.Host) })
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

// apply takes the object a no line names out of b.
func (b *IOSSystemBlock) apply(d SystemNotManaged) {
	match := func(s string) bool { return d.Value == "" || strings.EqualFold(s, d.Value) }
	num := func(n int) bool { return d.Value == "" || strconv.Itoa(n) == d.Value }
	switch d.Kind {
	case SysMessage:
		b.Banner = nil
	case SysDomainName:
		b.DomainName = nil
	case SysTimeZone:
		b.Timezone = nil
	case SysAuthenticate:
		b.NTPAuthenticate = nil
	case SysDomainSearch:
		b.DomainList = slices.DeleteFunc(b.DomainList, func(v Value) bool { return match(v.Text) })
	case SysNameServer:
		b.NameServers = slices.DeleteFunc(b.NameServers, func(v Value) bool { return match(v.Text) })
	case SysNTPServer:
		b.NTPServers = slices.DeleteFunc(b.NTPServers, func(s IOSNTPServer) bool { return match(s.Host) })
	case SysAuthKey:
		b.NTPKeys = slices.DeleteFunc(b.NTPKeys, func(k NTPKey) bool { return num(k.Number) })
	case SysTrustedKey:
		b.NTPTrustedKeys = slices.DeleteFunc(b.NTPTrustedKeys, func(k KeyRef) bool { return num(k.Number) })
	case SysNTP:
		b.NTPServers, b.NTPKeys, b.NTPTrustedKeys, b.NTPAuthenticate = nil, nil, nil, nil
	}
}

// --- statements, text -------------------------------------------------------

// IOSSystemUnits are the statements of the block as groups of lines in the
// order the plan pastes them: the banner (its lines are one group), the
// domain name and list, the time zone, the name servers (one line each), then
// the NTP statements in the order IOS needs them: the keys, the trusted
// keys, the servers, and 'ntp authenticate' last. This is what the managed
// system section is made of; a banner whose text holds every delimiter has no
// unit (Check refuses it).
func IOSSystemUnits(b *IOSSystemBlock) [][]string {
	if b == nil {
		return nil
	}
	var out [][]string
	one := func(s string) { out = append(out, []string{s}) }
	if b.Banner != nil {
		if lines := IOSBannerLines(b.Banner.Body); lines != nil {
			out = append(out, lines)
		}
	}
	if b.DomainName != nil {
		one("ip domain name " + b.DomainName.Text)
	}
	for _, v := range b.DomainList {
		one("ip domain list " + v.Text)
	}
	if b.Timezone != nil {
		one(b.Timezone.Text())
	}
	for _, v := range b.NameServers {
		one("ip name-server " + v.Text)
	}
	for _, k := range b.NTPKeys {
		one(fmt.Sprintf("ntp authentication-key %d md5 %s", k.Number, k.Value))
	}
	for _, k := range b.NTPTrustedKeys {
		one(fmt.Sprintf("ntp trusted-key %d", k.Number))
	}
	for _, s := range b.NTPServers {
		one(s.Text())
	}
	if b.NTPAuthenticate != nil {
		one("ntp authenticate")
	}
	return out
}

// IOSSystemStatements are the lines of the block in the order of
// IOSSystemUnits, flattened (the banner's lines are the lines typed).
func IOSSystemStatements(b *IOSSystemBlock) []string {
	var out []string
	for _, u := range IOSSystemUnits(b) {
		out = append(out, u...)
	}
	return out
}

// IsIOSSecretStatement reports whether a rendered line carries a secret: an
// 'ntp authentication-key <n> md5 <string>' line.
func IsIOSSecretStatement(line string) bool {
	f := strings.Fields(line)
	return len(f) >= 5 && f[0] == "ntp" && f[1] == "authentication-key"
}

// iosText is the line of a no line.
func (d SystemNotManaged) iosText() string {
	var s string
	switch d.Kind {
	case SysMessage:
		s = "no banner login"
	case SysDomainName:
		s = "no ip domain name"
	case SysDomainSearch:
		s = "no ip domain list"
	case SysTimeZone:
		s = "no clock timezone"
	case SysNameServer:
		s = "no ip name-server"
	case SysNTP:
		s = "no ntp"
	case SysNTPServer:
		s = "no ntp server"
	case SysAuthenticate:
		s = "no ntp authenticate"
	default:
		s = "no ntp " + d.Kind
	}
	if d.Value != "" {
		s += " " + d.Value
	}
	return s
}

// ElideIOSSystem is a copy of the block in which the banner is replaced by a
// mark of its size (<message: N lines, M characters>) and every NTP key
// string by <secret>, for the engineers' reads. The marks are refused when an
// elided text is read back as a block.
func ElideIOSSystem(b *IOSSystemBlock) *IOSSystemBlock {
	if b == nil {
		return nil
	}
	out := *b
	if b.Banner != nil {
		m := *b.Banner
		m.Body = messageMark(b.Banner)
		out.Banner = &m
	}
	out.NTPKeys = slices.Clone(b.NTPKeys)
	for i := range out.NTPKeys {
		out.NTPKeys[i].Value = secretMark
	}
	out.DomainList = slices.Clone(b.DomainList)
	out.NameServers = slices.Clone(b.NameServers)
	out.NTPServers = slices.Clone(b.NTPServers)
	out.NTPTrustedKeys = slices.Clone(b.NTPTrustedKeys)
	out.NotManaged = slices.Clone(b.NotManaged)
	return &out
}

// String is the block as canonical text: the banner as its heredoc, then the
// other statements in the order of IOSSystemUnits, then the no lines in the
// order given; comments and blank lines are not kept. A block read back from
// it is the same block, and its own String is the same text. With elided,
// the banner and the NTP key strings are the marks of ElideIOSSystem.
func (b *IOSSystemBlock) String(elided bool) string {
	if b == nil {
		return ""
	}
	if elided {
		b = ElideIOSSystem(b)
	}
	var lines []string
	if b.Banner != nil {
		lines = append(lines, IOSBannerStart)
		lines = append(lines, strings.Split(b.Banner.Body, "\n")...)
		lines = append(lines, MessageTerminator)
	}
	rest := *b
	rest.Banner = nil
	for _, u := range IOSSystemUnits(&rest) {
		lines = append(lines, u...)
	}
	for _, d := range b.NotManaged {
		lines = append(lines, d.iosText())
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// IOSSystemNotManagedLines are the no lines of the block as written.
func IOSSystemNotManagedLines(b *IOSSystemBlock) []string {
	if b == nil {
		return nil
	}
	var out []string
	for _, d := range b.NotManaged {
		out = append(out, d.iosText())
	}
	return out
}
