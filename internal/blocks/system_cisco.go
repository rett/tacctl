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
//	ip domain name [vrf <name>] <name>
//	ip domain list [vrf <name>] <name>
//	clock timezone <zone> <hours> [<minutes>]
//	ip name-server [vrf <name>] <address> [<address> ...]
//	ntp server [vrf <name>] <address-or-name> [prefer] [version <1-4>] [key <n>] [source <interface>]
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
// either; they are named by line, column and count. A VRF form ('ntp server
// vrf V', 'ip name-server vrf V', 'ip domain name|list vrf V') is another
// statement than the one without the vrf: the vrf is part of the identity of
// the object. tacctl does not create a VRF; the device refuses a block that
// names one it lacks.

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

// IOSNTPServer is one 'ntp server [vrf <name>] <address-or-name>' object with
// the options of its statement. Host is an IPv4 address in canonical text or a
// host name (as written; compared without case). VRF is the vrf the server is
// reached in ("" for none; it is part of the object's identity, so one host in
// two vrfs is two objects). Zero Version and Key and an empty Source are
// unstated.
type IOSNTPServer struct {
	VRF     string
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
	l := "ntp server " + vrfWords(s.VRF) + s.Host
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

// IOSDialect is what a train of IOS prints differently from the block's
// text. DefaultNTPVersion is the NTP version the device never prints in an
// 'ntp server' line (0 for none): IOS 12.x stores 'ntp server H version 3'
// as 'ntp server H'.
type IOSDialect struct {
	DefaultNTPVersion int
}

// IOSModern is the syntax of every release after IOS 12.x: the statements
// are stored as typed.
var IOSModern = IOSDialect{}

// IOS12 is the IOS 12.x syntax, in which 'version 3' is the default and is
// not stored.
var IOS12 = IOSDialect{DefaultNTPVersion: 3}

// textIn is Text as the device in dialect d stores it: the version left out
// when it is the dialect's default. Every other option stays as stated.
func (s IOSNTPServer) textIn(d IOSDialect) string {
	if d.DefaultNTPVersion != 0 && s.Version == d.DefaultNTPVersion {
		s.Version = 0
	}
	return s.Text()
}

// IOSVRFValue is a value of a statement stated in a vrf ('ip domain name vrf
// <name> <name>', 'ip domain list vrf <name> <name>', 'ip name-server vrf
// <name> <address>'). Text is the value (a host name in lower case).
type IOSVRFValue struct {
	VRF  string
	Text string
	Line int
}

// vrfWords is 'vrf <name> ' for a vrf, "" for none.
func vrfWords(vrf string) string {
	if vrf == "" {
		return ""
	}
	return "vrf " + vrf + " "
}

// sameServer reports the same object: the same host (without case) in the
// same vrf.
func (s IOSNTPServer) sameServer(o IOSNTPServer) bool {
	return s.VRF == o.VRF && strings.EqualFold(s.Host, o.Host)
}

// IOSSystemBlock is a parsed IOS system block. The lists are in the order of
// their first statement. The statements that name a vrf are in lists of their
// own (a vrf's domain name is one per vrf; the domain name without a vrf is
// DomainName); the NTP servers of every vrf are in NTPServers, told apart by
// IOSNTPServer.VRF.
type IOSSystemBlock struct {
	Banner         *LoginMessage
	DomainName     *Value
	VRFDomainNames []IOSVRFValue
	DomainList     []Value
	VRFDomainList  []IOSVRFValue
	Timezone       *IOSTimezone
	NameServers    []Value
	VRFNameServers []IOSVRFValue
	NTPServers     []IOSNTPServer
	NTPKeys        []NTPKey
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
		len(b.VRFDomainNames) == 0 && len(b.VRFDomainList) == 0 && len(b.VRFNameServers) == 0 &&
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

// reVRFName is a vrf's name: letters, digits, '.', '_' and '-'.
var reVRFName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// vrfProblem is why s cannot be the name of a vrf in a block ("" when it
// can). The reason never holds s.
func vrfProblem(s string) string {
	switch {
	case s == "":
		return "is empty"
	case len(s) > MaxIOSName:
		return fmt.Sprintf("is longer than %d characters", MaxIOSName)
	case !reVRFName.MatchString(s):
		return "holds a character other than letters, digits, '.', '_' and '-'"
	}
	return ""
}

// vrfHead reads the optional 'vrf <name>' that heads args: the vrf ("" for
// none) and the words after it. ok is false when the words are off the
// grammar (reported).
func (p *iosSysParser) vrfHead(what string, args []string) (vrf string, rest []string, ok bool) {
	if len(args) == 0 || args[0] != "vrf" {
		return "", args, true
	}
	if len(args) < 2 {
		p.errf("%s: 'vrf' takes the name of the vrf after it", what)
		return "", nil, false
	}
	if why := vrfProblem(args[1]); why != "" {
		p.errf("the vrf name of %s %s", what, why)
		return "", nil, false
	}
	return args[1], args[2:], true
}

// vrfSingle reads the one value of a single-valued statement of a vrf.
func (p *iosSysParser) vrfSingle(dst *[]IOSVRFValue, what, vrf string, args []string, problem func(string) string) {
	if len(args) != 1 {
		p.errf("%s vrf takes one value and nothing else", what)
		return
	}
	if why := problem(args[0]); why != "" {
		p.errf("the value of %s vrf %s", what, why)
		return
	}
	if slices.ContainsFunc(*dst, func(o IOSVRFValue) bool { return o.VRF == vrf }) {
		p.errf("%s is stated twice for one vrf", what)
		return
	}
	*dst = append(*dst, IOSVRFValue{VRF: vrf, Text: strings.ToLower(args[0]), Line: p.line})
}

// vrfListOf reads one entry of a list statement of a vrf.
func (p *iosSysParser) vrfListOf(dst *[]IOSVRFValue, what, vrf string, args []string, problem func(string) string) {
	if len(args) != 1 {
		p.errf("%s vrf takes one value and nothing else", what)
		return
	}
	if why := problem(args[0]); why != "" {
		p.errf("the value of %s vrf %s", what, why)
		return
	}
	v := strings.ToLower(args[0])
	if slices.ContainsFunc(*dst, func(o IOSVRFValue) bool { return o.VRF == vrf && o.Text == v }) {
		p.errf("%s is listed twice for one vrf", what)
		return
	}
	*dst = append(*dst, IOSVRFValue{VRF: vrf, Text: v, Line: p.line})
}

// single reads a single-valued statement of one word.
func (p *iosSysParser) single(dst **Value, what string, args []string, problem func(string) string) {
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
			p.domainName(t[2:])
		case "list":
			p.domainList(t[2:])
		default:
			p.errf("word 3 is not name or list (ip domain lookup and the rest are the device's own)")
		}
	case "domain-name":
		p.domainName(t[1:])
	case "domain-list":
		p.domainList(t[1:])
	case "name-server":
		p.nameServers(t[1:])
	default:
		p.errf("word 2 is not one of domain, name-server")
	}
}

// domainName reads the words after 'ip domain name': [vrf <name>] <name>.
func (p *iosSysParser) domainName(args []string) {
	vrf, rest, ok := p.vrfHead("ip domain name", args)
	switch {
	case !ok:
	case vrf == "":
		p.single(&p.b.DomainName, "ip domain name", rest, hostProblem)
	default:
		p.vrfSingle(&p.b.VRFDomainNames, "ip domain name", vrf, rest, hostProblem)
	}
}

// domainList reads the words after 'ip domain list': [vrf <name>] <name>.
func (p *iosSysParser) domainList(args []string) {
	vrf, rest, ok := p.vrfHead("ip domain list", args)
	switch {
	case !ok:
	case vrf == "":
		p.listOf(&p.b.DomainList, "ip domain list", rest, hostProblem)
	default:
		p.vrfListOf(&p.b.VRFDomainList, "ip domain list", vrf, rest, hostProblem)
	}
}

// listOf reads one entry of a list statement; the text is kept in lower case
// (a host name is no case).
func (p *iosSysParser) listOf(dst *[]Value, what string, args []string, problem func(string) string) {
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

// nameServers reads 'ip name-server [vrf <name>] <address> [<address> ...]':
// one object per address (and vrf).
func (p *iosSysParser) nameServers(args []string) {
	vrf, args, ok := p.vrfHead("ip name-server", args)
	if !ok {
		return
	}
	base := 3
	if vrf != "" {
		base = 5
	}
	if len(args) == 0 {
		p.errf("'ip name-server' needs at least one address (word %d)", base)
		return
	}
	var add []Value
	for i, a := range args {
		if why := addrProblem(a); why != "" {
			p.errf("the address %d of ip name-server (word %d) %s", i+1, i+base, why)
			return
		}
		dup := false
		if vrf == "" {
			dup = slices.ContainsFunc(p.b.NameServers, func(v Value) bool { return v.Text == a })
		} else {
			dup = slices.ContainsFunc(p.b.VRFNameServers, func(v IOSVRFValue) bool { return v.VRF == vrf && v.Text == a })
		}
		if dup || slices.ContainsFunc(add, func(v Value) bool { return v.Text == a }) {
			p.errf("ip name-server %d is listed twice", i+1)
			return
		}
		add = append(add, Value{a, p.line})
	}
	if vrf == "" {
		p.b.NameServers = append(p.b.NameServers, add...)
		return
	}
	for _, v := range add {
		p.b.VRFNameServers = append(p.b.VRFNameServers, IOSVRFValue{VRF: vrf, Text: v.Text, Line: v.Line})
	}
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
	vrf, args, ok := p.vrfHead("ntp server", args)
	if !ok {
		return
	}
	// the words before the host: 'ntp server' and, with a vrf, 'vrf <name>'
	base := 3
	if vrf != "" {
		base = 5
	}
	if len(args) == 0 {
		p.errf("'ntp server' needs an address or a name (word %d)", base)
		return
	}
	if args[0] == "ip" || args[0] == "ipv6" {
		p.errf("ntp server: '%s' is not in the grammar of a block (write the address or the name)", args[0])
		return
	}
	host := args[0]
	if strings.Contains(host, ":") {
		p.errf("ntp server: an IPv6 address is not in the grammar of a block yet (an IPv4 address or a name)")
		return
	}
	if why := hostOrAddrProblem(host); why != "" {
		p.errf("the address of ntp server (word %d) %s", base, why)
		return
	}
	s := IOSNTPServer{VRF: vrf, Host: host, Line: p.line}
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
			p.errf("ntp server: word %d is not one of prefer, version, key, source", i+base)
			return
		}
	}
	if i := slices.IndexFunc(p.b.NTPServers, func(o IOSNTPServer) bool { return o.sameServer(s) }); i >= 0 {
		p.errf("ntp server %d is listed twice (one line per server and vrf)", i+1)
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
		// a vrf names the object of that vrf: another one than the same
		// statement without it
		inVRF := func(what string, args []string) ([]string, bool) {
			vrf, rest, vok := p.vrfHead("no "+what, args)
			nm.VRF = vrf
			return rest, vok
		}
		switch {
		case t[1] == "domain" && len(t) >= 3 && t[2] == "name",
			t[1] == "domain-name":
			args := t[2:]
			if t[1] == "domain" {
				args = t[3:]
			}
			rest, vok := inVRF("ip domain name", args)
			ok = vok && bare(SysDomainName, rest, "ip domain name")
		case t[1] == "domain" && len(t) >= 3 && t[2] == "list",
			t[1] == "domain-list":
			args := t[2:]
			if t[1] == "domain" {
				args = t[3:]
			}
			rest, vok := inVRF("ip domain list", args)
			ok = vok && entry(SysDomainSearch, rest, "ip domain list", hostProblem)
		case t[1] == "name-server":
			rest, vok := inVRF("ip name-server", t[2:])
			ok = vok && entry(SysNameServer, rest, "ip name-server", addrProblem)
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
			vrf, rest, vok := p.vrfHead("no ntp server", args)
			nm.VRF = vrf
			ok = vok && entry(SysNTPServer, rest, "ntp server", hostOrAddrProblem)
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
// system grammar has one rule that differs by layer (0.2.19): an 'ntp server
// ... source <interface>' in the default or a scope's block is an error unless
// the interface is a loopback by its convention name (a note), since an
// interface is one device's own (deviceLocalProblem). Findings never hold the
// banner or a key's value.
func CheckIOSSystem(b *IOSSystemBlock, layer Layer) []Finding {
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
		if s.Source != "" {
			if why := deviceLocalProblem(layer, "ntp server ... source "+s.Source, isLoopbackName(s.Source)); why != "" {
				add(s.Line, SevError, "%s", why)
			} else if layer != LayerDevice {
				add(s.Line, SevNote, "ntp server source %s is the loopback every device of the scope is expected to have: a device without it cannot take it (a device's own block can state another)", s.Source)
			}
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
	// tacctl creates no vrf: the device refuses a statement that names one
	// it lacks (once per vrf, at its first statement)
	seenVRF := map[string]bool{}
	vrfNote := func(vrf string, line int) {
		if vrf != "" && !seenVRF[vrf] {
			seenVRF[vrf] = true
			add(line, SevNote, "vrf %s must exist on the device: tacctl does not create a vrf, and the device refuses a statement that names one it lacks", vrf)
		}
	}
	for _, v := range b.VRFDomainNames {
		vrfNote(v.VRF, v.Line)
	}
	for _, v := range b.VRFDomainList {
		vrfNote(v.VRF, v.Line)
	}
	for _, v := range b.VRFNameServers {
		vrfNote(v.VRF, v.Line)
	}
	for _, s := range b.NTPServers {
		vrfNote(s.VRF, s.Line)
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
		for _, v := range l.VRFDomainNames {
			out.VRFDomainNames = upsert(out.VRFDomainNames, v, func(o IOSVRFValue) bool { return o.VRF == v.VRF })
		}
		for _, v := range l.DomainList {
			out.DomainList = upsert(out.DomainList, v, func(o Value) bool { return o.Text == v.Text })
		}
		for _, v := range l.VRFDomainList {
			out.VRFDomainList = upsert(out.VRFDomainList, v, func(o IOSVRFValue) bool { return o.VRF == v.VRF && o.Text == v.Text })
		}
		for _, v := range l.NameServers {
			out.NameServers = upsert(out.NameServers, v, func(o Value) bool { return o.Text == v.Text })
		}
		for _, v := range l.VRFNameServers {
			out.VRFNameServers = upsert(out.VRFNameServers, v, func(o IOSVRFValue) bool { return o.VRF == v.VRF && o.Text == v.Text })
		}
		for _, s := range l.NTPServers {
			out.NTPServers = upsert(out.NTPServers, s, func(o IOSNTPServer) bool { return o.sameServer(s) })
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
	// a line of a vrf takes that vrf's objects out, and a line without one
	// only the objects that have none
	inVRF := func(v IOSVRFValue) bool { return v.VRF == d.VRF && match(v.Text) }
	switch d.Kind {
	case SysMessage:
		b.Banner = nil
	case SysDomainName:
		if d.VRF == "" {
			b.DomainName = nil
		} else {
			b.VRFDomainNames = slices.DeleteFunc(b.VRFDomainNames, func(v IOSVRFValue) bool { return v.VRF == d.VRF })
		}
	case SysTimeZone:
		b.Timezone = nil
	case SysAuthenticate:
		b.NTPAuthenticate = nil
	case SysDomainSearch:
		if d.VRF == "" {
			b.DomainList = slices.DeleteFunc(b.DomainList, func(v Value) bool { return match(v.Text) })
		} else {
			b.VRFDomainList = slices.DeleteFunc(b.VRFDomainList, inVRF)
		}
	case SysNameServer:
		if d.VRF == "" {
			b.NameServers = slices.DeleteFunc(b.NameServers, func(v Value) bool { return match(v.Text) })
		} else {
			b.VRFNameServers = slices.DeleteFunc(b.VRFNameServers, inVRF)
		}
	case SysNTPServer:
		b.NTPServers = slices.DeleteFunc(b.NTPServers, func(s IOSNTPServer) bool { return s.VRF == d.VRF && match(s.Host) })
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
// unit (Check refuses it). The 'ntp server' lines are as stated: see
// IOSSystemUnitsIn.
func IOSSystemUnits(b *IOSSystemBlock) [][]string {
	return IOSSystemUnitsIn(b, IOSModern)
}

// IOSSystemUnitsIn is IOSSystemUnits for a device in dialect d: an 'ntp
// server' line is without the version the dialect never prints.
func IOSSystemUnitsIn(b *IOSSystemBlock, d IOSDialect) [][]string {
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
	for _, v := range b.VRFDomainNames {
		one("ip domain name " + vrfWords(v.VRF) + v.Text)
	}
	for _, v := range b.DomainList {
		one("ip domain list " + v.Text)
	}
	for _, v := range b.VRFDomainList {
		one("ip domain list " + vrfWords(v.VRF) + v.Text)
	}
	if b.Timezone != nil {
		one(b.Timezone.Text())
	}
	for _, v := range b.NameServers {
		one("ip name-server " + v.Text)
	}
	for _, v := range b.VRFNameServers {
		one("ip name-server " + vrfWords(v.VRF) + v.Text)
	}
	for _, k := range b.NTPKeys {
		one(fmt.Sprintf("ntp authentication-key %d md5 %s", k.Number, k.Value))
	}
	for _, k := range b.NTPTrustedKeys {
		one(fmt.Sprintf("ntp trusted-key %d", k.Number))
	}
	for _, s := range b.NTPServers {
		one(s.textIn(d))
	}
	if b.NTPAuthenticate != nil {
		one("ntp authenticate")
	}
	return out
}

// IOSSystemStatements are the lines of the block in the order of
// IOSSystemUnits, flattened (the banner's lines are the lines typed).
func IOSSystemStatements(b *IOSSystemBlock) []string {
	return IOSSystemStatementsIn(b, IOSModern)
}

// IOSSystemStatementsIn is IOSSystemStatements for a device in dialect d.
func IOSSystemStatementsIn(b *IOSSystemBlock, d IOSDialect) []string {
	var out []string
	for _, u := range IOSSystemUnitsIn(b, d) {
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
	if d.VRF != "" {
		s += " vrf " + d.VRF
	}
	if d.Value != "" {
		s += " " + d.Value
	}
	return s
}

// ElideIOSSystem is a copy of the block in which the banner is replaced by a
// mark of its size (<message: N lines, M characters>) and every NTP key
// string by <secret>: the form of a summary that prints no text. The marks are
// refused when an elided text is read back as a block. Shown is the form of a
// read.
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
	out.VRFDomainNames = slices.Clone(b.VRFDomainNames)
	out.VRFDomainList = slices.Clone(b.VRFDomainList)
	out.VRFNameServers = slices.Clone(b.VRFNameServers)
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

// Shown is the block as a read prints it (`block show`): every NTP key string
// is <secret>, and the banner is printed as it is, since a device shows it to
// anyone before the login.
func (b *IOSSystemBlock) Shown() string {
	if b == nil {
		return ""
	}
	out := *b
	out.NTPKeys = slices.Clone(b.NTPKeys)
	for i := range out.NTPKeys {
		out.NTPKeys[i].Value = secretMark
	}
	return out.String(false)
}
