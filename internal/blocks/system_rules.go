package blocks

// The closed tables of the simple statements of the system blocks (0.2.19):
// for Junos syslog, the login retry options and the password policy; for IOS
// logging, the login and password policy, the ssh settings and summer time.
// Each rule is a pattern of words:
//
//	a word            itself
//	a|b               one of the words (a value of the statement)
//	<host> <addr> <word> <int:lo-hi> and the other <type>s   a value, checked
//	a trailing *      the word is part of the statement's identity
//	a trailing ~      the word is an option: not part of the identity
//
// The identity of a statement is its rule and the words through the last
// starred one and the literal words after it (the words before the first
// value when none is starred): a more specific layer's statement of the same
// identity replaces the less specific one's, a statement of another identity
// is added, and a delete (Junos) or no (IOS) line naming the identity says it
// is not managed here. Everything else is refused: the table is the whole
// grammar of these hierarchies, and a statement not in it is an error.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// A rule's token kinds.
const (
	rtLit = iota
	rtAlt
	rtHost
	rtAddr
	rtFacility
	rtOverride
	rtLevel
	rtWord
	rtInt
	rtIOSLevel
	rtWeek
	rtDay
	rtMonth
	rtClock
	rtZone
)

type ruleTok struct {
	kind   int
	text   string
	alts   []string
	lo, hi int
	key    bool
	// opt marks a word that is an option of the statement, not part of its
	// identity ("localtime~").
	opt bool
}

// sysRule is one row of a table. Several rows may share an ID: they are forms
// of one statement (with and without an optional word).
type sysRule struct {
	ID      string
	Pattern string
	// DeviceOnly: the statement names the device itself (an address it holds):
	// only the device's own block states it (deviceLocalProblem).
	DeviceOnly bool

	toks []ruleTok
	// keyEnd is how many words make the identity (and a delete line's length).
	keyEnd int
}

// ruleTable is a closed table of statements.
type ruleTable struct {
	rules []sysRule
	// prefix is the words before a statement's arguments in its text ("set
	// system " on Junos, nothing on IOS).
	prefix string
	// twoWordRoot: a statement is the table's when its first two words begin a
	// rule (IOS); otherwise when its first word does ("login" takes two).
	twoWordRoot bool
	roots       map[string][]string
}

// Syslog facilities and levels Junos takes under 'system syslog host', and the
// IOS words of the same kinds.
var (
	sysFacilities = []string{"any", "authorization", "change-log", "conflict-log", "daemon", "external", "firewall", "ftp",
		"interactive-commands", "kernel", "ntp", "pfe", "security", "user"}
	sysLevels = []string{"any", "alert", "critical", "emergency", "error", "info", "none", "notice", "warning"}
	// the facilities a host's facility-override takes
	sysOverrides = []string{"authorization", "daemon", "ftp", "kernel", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "user"}
	// the severity names of IOS logging
	iosLogLevels = []string{"emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging"}
	iosDays      = []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
	iosMonths    = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
)

var (
	reRuleWord = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,62}$`)
	reClockHM  = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):[0-5][0-9]$`)
)

// junosRules is the table of the Junos system block, in the order the
// statements are rendered.
var junosRules = newRuleTable("set system ", false, []sysRule{
	{ID: "syslog-host", Pattern: "syslog host <host>* <facility>* <level>"},
	{ID: "syslog-facility-override", Pattern: "syslog host <host>* facility-override <override>"},
	{ID: "syslog-log-prefix", Pattern: "syslog host <host>* log-prefix <word>"},
	{ID: "syslog-explicit-priority", Pattern: "syslog host <host>* explicit-priority"},
	{ID: "syslog-time-format", Pattern: "syslog time-format year*|millisecond*"},
	{ID: "syslog-source-address", Pattern: "syslog source-address <addr>", DeviceOnly: true},
	{ID: "retry-tries", Pattern: "login retry-options tries-before-disconnect <int:1-10>"},
	{ID: "retry-backoff-threshold", Pattern: "login retry-options backoff-threshold <int:1-3>"},
	{ID: "retry-backoff-factor", Pattern: "login retry-options backoff-factor <int:5-10>"},
	{ID: "retry-minimum-time", Pattern: "login retry-options minimum-time <int:20-60>"},
	{ID: "retry-maximum-time", Pattern: "login retry-options maximum-time <int:20-300>"},
	{ID: "retry-lockout-period", Pattern: "login retry-options lockout-period <int:1-43200>"},
	{ID: "password-minimum-length", Pattern: "login password minimum-length <int:6-20>"},
	{ID: "password-minimum-changes", Pattern: "login password minimum-changes <int:1-128>"},
	{ID: "password-change-type", Pattern: "login password change-type character-sets|set-transitions"},
	{ID: "password-format", Pattern: "login password format md5|sha1|sha256|sha512"},
})

// sysRuleTable is the Junos table's rules.
var sysRuleTable = junosRules.rules

// iosRules is the table of the IOS system block. A rule with several rows is
// one statement with optional words.
var iosRules = newRuleTable("", true, []sysRule{
	{ID: "ios-logging-host", Pattern: "logging host <host>*"},
	{ID: "ios-logging-host-vrf", Pattern: "logging host <host>* vrf <word>*"},
	{ID: "ios-logging-trap", Pattern: "logging trap <ioslevel>"},
	{ID: "ios-logging-buffered", Pattern: "logging buffered <int:4096-2147483647>"},
	{ID: "ios-logging-buffered", Pattern: "logging buffered <int:4096-2147483647> <ioslevel>"},
	{ID: "ios-logging-origin-id", Pattern: "logging origin-id hostname"},
	{ID: "ios-timestamps", Pattern: "service timestamps log*|debug* datetime msec"},
	{ID: "ios-timestamps", Pattern: "service timestamps log*|debug* datetime msec localtime~"},
	{ID: "ios-timestamps", Pattern: "service timestamps log*|debug* datetime msec show-timezone~"},
	{ID: "ios-timestamps", Pattern: "service timestamps log*|debug* datetime msec localtime~ show-timezone~"},
	{ID: "ios-login-on-failure", Pattern: "login on-failure log"},
	{ID: "ios-login-on-failure", Pattern: "login on-failure log every~ <int:1-65535>"},
	{ID: "ios-login-on-success", Pattern: "login on-success log"},
	{ID: "ios-login-on-success", Pattern: "login on-success log every~ <int:1-65535>"},
	{ID: "ios-login-delay", Pattern: "login delay <int:1-10>"},
	{ID: "ios-passwords-min-length", Pattern: "security passwords min-length <int:1-16>"},
	{ID: "ios-auth-failure-rate", Pattern: "security authentication failure rate <int:2-1024> log"},
	{ID: "ios-ssh-version", Pattern: "ip ssh version 2"},
	{ID: "ios-ssh-timeout", Pattern: "ip ssh time-out <int:1-120>"},
	{ID: "ios-ssh-retries", Pattern: "ip ssh authentication-retries <int:0-5>"},
	{ID: "ios-summer-time", Pattern: "clock summer-time <zone> recurring~"},
	{ID: "ios-summer-time", Pattern: "clock summer-time <zone> recurring~ <week> <day> <month> <clock> <week> <day> <month> <clock>"},
	{ID: "ios-summer-time", Pattern: "clock summer-time <zone> recurring~ <week> <day> <month> <clock> <week> <day> <month> <clock> <int:1-1440>"},
})

func newRuleTable(prefix string, twoWord bool, rs []sysRule) *ruleTable {
	t := &ruleTable{rules: buildRules(rs), prefix: prefix, twoWordRoot: twoWord, roots: map[string][]string{}}
	for _, r := range t.rules {
		root := t.rootOfTokens(r.toks)
		if !slices.Contains(t.roots[root], r.Pattern) {
			t.roots[root] = append(t.roots[root], r.Pattern)
		}
	}
	return t
}

func (t *ruleTable) rootOfTokens(toks []ruleTok) string {
	root := toks[0].text
	if len(toks) > 1 && (t.twoWordRoot || root == "login") {
		root += " " + toks[1].text
	}
	return root
}

// rootOf is the key of a statement's first words in the table's roots.
func (t *ruleTable) rootOf(args []string) string {
	if len(args) == 0 {
		return ""
	}
	if len(args) > 1 && (t.twoWordRoot || args[0] == "login") {
		return args[0] + " " + args[1]
	}
	return args[0]
}

// allTables are the tables, for the lookups by a rule's ID.
var allTables = []*ruleTable{junosRules, iosRules}

func buildRules(rs []sysRule) []sysRule {
	for i := range rs {
		r := &rs[i]
		lastKey, firstValue := -1, -1
		for j, w := range strings.Fields(r.Pattern) {
			var t ruleTok
			t.opt = strings.HasSuffix(w, "~")
			w = strings.TrimSuffix(w, "~")
			t.key = strings.HasSuffix(w, "*")
			w = strings.TrimSuffix(w, "*")
			switch {
			case strings.HasPrefix(w, "<int:"):
				t.kind = rtInt
				fmt.Sscanf(strings.TrimSuffix(strings.TrimPrefix(w, "<int:"), ">"), "%d-%d", &t.lo, &t.hi)
			case w == "<host>":
				t.kind = rtHost
			case w == "<addr>":
				t.kind = rtAddr
			case w == "<facility>":
				t.kind = rtFacility
			case w == "<override>":
				t.kind = rtOverride
			case w == "<level>":
				t.kind = rtLevel
			case w == "<ioslevel>":
				t.kind = rtIOSLevel
			case w == "<week>":
				t.kind = rtWeek
			case w == "<day>":
				t.kind = rtDay
			case w == "<month>":
				t.kind = rtMonth
			case w == "<clock>":
				t.kind = rtClock
			case w == "<zone>":
				t.kind = rtZone
			case w == "<word>":
				t.kind = rtWord
			case strings.Contains(w, "|"):
				t.kind = rtAlt
				t.key = t.key || strings.Contains(w, "*")
				for _, a := range strings.Split(w, "|") {
					t.alts = append(t.alts, strings.TrimSuffix(a, "*"))
				}
			default:
				t.kind = rtLit
			}
			t.text = w
			if t.key {
				lastKey = j
			}
			if t.kind != rtLit && firstValue < 0 && !t.key {
				firstValue = j
			}
			r.toks = append(r.toks, t)
		}
		switch {
		case lastKey >= 0:
			// the starred words, and the literal words that follow them: they
			// tell this statement from another of the same host
			r.keyEnd = lastKey + 1
			for r.keyEnd < len(r.toks) && r.toks[r.keyEnd].kind == rtLit && !r.toks[r.keyEnd].opt {
				r.keyEnd++
			}
		case firstValue >= 0:
			r.keyEnd = firstValue
		default:
			r.keyEnd = len(r.toks)
		}
		// the options of a statement are not its identity
		for j, tk := range r.toks {
			if tk.opt && j < r.keyEnd {
				r.keyEnd = j
				break
			}
		}
	}
	return rs
}

// problem is why arg is not a value of the token ("" when it is).
func (t ruleTok) problem(arg string) string {
	switch t.kind {
	case rtLit:
		if arg != t.text {
			return "is not " + t.text
		}
	case rtAlt:
		for _, a := range t.alts {
			if arg == a {
				return ""
			}
		}
		return "is not one of " + strings.Join(t.alts, ", ")
	case rtHost:
		return hostOrAddrProblem(arg)
	case rtAddr:
		return addrProblem(arg)
	case rtFacility:
		if !slices.Contains(sysFacilities, arg) {
			return "is not a syslog facility (one of " + strings.Join(sysFacilities, ", ") + ")"
		}
	case rtOverride:
		if !slices.Contains(sysOverrides, arg) {
			return "is not a facility an override takes (one of " + strings.Join(sysOverrides, ", ") + ")"
		}
	case rtLevel:
		if !slices.Contains(sysLevels, arg) {
			return "is not a syslog level (one of " + strings.Join(sysLevels, ", ") + ")"
		}
	case rtIOSLevel:
		if !slices.Contains(iosLogLevels, arg) {
			return "is not a logging severity (one of " + strings.Join(iosLogLevels, ", ") + ")"
		}
	case rtWeek:
		if _, ok := number(arg, 1, 4); !ok && arg != "first" && arg != "last" {
			return "is not a week (1 to 4, first or last)"
		}
	case rtDay:
		if !slices.Contains(iosDays, arg) {
			return "is not a day name (one of " + strings.Join(iosDays, ", ") + ")"
		}
	case rtMonth:
		if !slices.Contains(iosMonths, arg) {
			return "is not a month name (one of " + strings.Join(iosMonths, ", ") + ")"
		}
	case rtClock:
		if !reClockHM.MatchString(arg) {
			return "is not a time of day (hh:mm)"
		}
	case rtZone:
		if !reZone.MatchString(arg) {
			return "is not a time zone name (letters, digits, '_' and '-', at most 16 characters, starting with a letter)"
		}
	case rtWord:
		if !reRuleWord.MatchString(arg) {
			return "is not a word of letters, digits and . _ : / - (at most 63 characters)"
		}
	case rtInt:
		if _, ok := number(arg, t.lo, t.hi); !ok {
			return fmt.Sprintf("is not a number from %d to %d", t.lo, t.hi)
		}
	}
	return ""
}

// canon is arg in the form the block keeps it: a host name in lower case.
func (t ruleTok) canon(arg string) string {
	if t.kind == rtHost {
		return strings.ToLower(arg)
	}
	return arg
}

// RuleStmt is one statement of a table in a parsed block.
type RuleStmt struct {
	Rule string
	// Head is the identity inside the rule: the words through the last
	// starred one (and the literals after it), lower case.
	Head string
	// Args are the statement's words (after 'set system' on Junos), as the
	// block keeps them.
	Args []string
	Line int
}

// Text is the statement as the device is typed it.
func (r RuleStmt) Text() string {
	if t := tableOf(r.Rule); t != nil {
		return t.prefix + strings.Join(r.Args, " ")
	}
	return strings.Join(r.Args, " ")
}

// tableOf is the table that holds a rule ID.
func tableOf(id string) *ruleTable {
	for _, t := range allTables {
		for _, r := range t.rules {
			if r.ID == id {
				return t
			}
		}
	}
	return nil
}

// ruleByID is the first row of a rule ID.
func ruleByID(id string) *sysRule {
	for _, t := range allTables {
		for i := range t.rules {
			if t.rules[i].ID == id {
				return &t.rules[i]
			}
		}
	}
	return nil
}

// ruleIndex is the place of a rule in its table (the order of rendering).
func ruleIndex(id string) int {
	if t := tableOf(id); t != nil {
		for i := range t.rules {
			if t.rules[i].ID == id {
				return i
			}
		}
	}
	return 1 << 20
}

// match finds the row a statement (its words) is: whole is true for a set
// line (the whole pattern), false for a delete or no line (the identity
// words). claimed says the first words are the table's even when no row fits;
// problem is why the best candidate does not.
func (t *ruleTable) match(args []string, whole bool) (rule *sysRule, canon []string, claimed bool, problem string) {
	pats, ok := t.roots[t.rootOf(args)]
	if !ok {
		return nil, nil, false, ""
	}
	// the reason given is the best candidate's: the row whose literal words
	// the statement shares the most of
	best, bestLits := "", -1
	for i := range t.rules {
		r := &t.rules[i]
		n := len(r.toks)
		if !whole {
			n = r.keyEnd
		}
		if len(args) != n {
			continue
		}
		c := make([]string, n)
		bad, lits := "", 0
		for j := 0; j < n; j++ {
			tk := r.toks[j]
			if tk.kind == rtLit {
				if args[j] != tk.text {
					bad = "literal"
					break
				}
				lits++
			}
			if why := tk.problem(args[j]); why != "" && bad == "" {
				bad = fmt.Sprintf("word %d (%s) %s", j+1+len(strings.Fields(t.prefix)), args[j], why)
			}
			c[j] = tk.canon(args[j])
		}
		switch bad {
		case "":
			return r, c, true, ""
		case "literal":
		default:
			if lits > bestLits {
				best, bestLits = bad, lits
			}
		}
	}
	if best != "" {
		return nil, nil, true, best
	}
	return nil, nil, true, "this statement is not one of: " + strings.Join(pats, "; ")
}

// owns reports whether a statement (its words) begins like a row of the table:
// the leading literal words of some row. The pull sorts a device's statement
// into the system section by it, so that the device's own logging
// destinations, ssh keys and the like are not listed as extras.
func (t *ruleTable) owns(args []string) bool {
	for _, r := range t.rules {
		n := 0
		for n < len(r.toks) && r.toks[n].kind == rtLit && !r.toks[n].opt {
			n++
		}
		if n > 0 && len(args) >= n && slices.Equal(args[:n], func() []string {
			w := make([]string, n)
			for i := range w {
				w[i] = r.toks[i].text
			}
			return w
		}()) {
			return true
		}
	}
	return false
}

// groups are the IDs of the rows whose leading literal words begin the
// statement: the rule groups it could belong to.
func (t *ruleTable) groups(args []string) []string {
	var out []string
	for _, r := range t.rules {
		n := 0
		for n < len(r.toks) && r.toks[n].kind == rtLit && !r.toks[n].opt {
			n++
		}
		if n == 0 || len(args) < n {
			continue
		}
		ok := true
		for i := 0; i < n; i++ {
			ok = ok && args[i] == r.toks[i].text
		}
		if ok && !slices.Contains(out, r.ID) {
			out = append(out, r.ID)
		}
	}
	return out
}

// JunosRuleGroups are the rule groups a Junos statement path (after 'system')
// could belong to: none for a statement the table cannot own. IOSRuleGroups is
// the same for an IOS statement's words. The pull sorts a device's statement
// into the system section only where the block states a statement of the same
// group, so that a device's own logging destinations, ssh settings and the
// like are not listed as extras of a block that says nothing of them.
func JunosRuleGroups(path []string) []string { return junosRules.groups(path) }

// IOSRuleGroups is JunosRuleGroups for an IOS statement's words.
func IOSRuleGroups(words []string) []string { return iosRules.groups(words) }

// JunosTableOwns reports whether a Junos statement path (after 'system') is
// one the system block's table could state: 'syslog host ...', 'syslog
// time-format ...', 'syslog source-address ...', 'login retry-options ...'
// and 'login password ...'.
func JunosTableOwns(path []string) bool { return junosRules.owns(path) }

// IOSTableOwns reports whether an IOS statement (its words) is one the system
// block's table could state.
func IOSTableOwns(words []string) bool { return iosRules.owns(words) }

// ruleStmtOf builds the statement a row and its canonical words are.
func ruleStmtOf(r *sysRule, c []string, line int) RuleStmt {
	return RuleStmt{Rule: r.ID, Head: strings.ToLower(strings.Join(c[:r.keyEnd], " ")), Args: c, Line: line}
}

// rule reads a set statement (the words after 'set system') of the Junos
// table; it reports whether the table claimed it.
func (p *sysParser) rule(t []string) bool {
	r, c, claimed, why := junosRules.match(t, true)
	if !claimed {
		return false
	}
	if r == nil {
		p.errf("%s", why)
		return true
	}
	st := ruleStmtOf(r, c, p.line)
	if i := indexRule(p.b.Rules, st.Rule, st.Head); i >= 0 {
		p.errf("'set system %s' is stated twice (line %d)", strings.Join(c[:r.keyEnd], " "), p.b.Rules[i].Line)
		return true
	}
	p.b.Rules = append(p.b.Rules, st)
	return true
}

// ruleDelete reads a delete line of the Junos table; it reports whether the
// table claimed it.
func (p *sysParser) ruleDelete(t []string) bool {
	r, c, claimed, why := junosRules.match(t, false)
	if !claimed {
		return false
	}
	if r == nil {
		p.errf("a delete line names the statement's identity: %s", why)
		return true
	}
	p.b.NotManaged = append(p.b.NotManaged, SystemNotManaged{Line: p.line, Kind: "rule:" + r.ID, Value: strings.Join(c, " ")})
	return true
}

func indexRule(rs []RuleStmt, id, head string) int {
	for i, r := range rs {
		if r.Rule == id && r.Head == head {
			return i
		}
	}
	return -1
}

// applyRuleDelete takes the statements a delete or no line names out of rs.
func applyRuleDelete(rs []RuleStmt, d SystemNotManaged) []RuleStmt {
	id := strings.TrimPrefix(d.Kind, "rule:")
	r := ruleByID(id)
	if r == nil {
		return rs
	}
	f := strings.Fields(strings.ToLower(d.Value))
	if len(f) < r.keyEnd {
		return rs
	}
	head := strings.Join(f[:r.keyEnd], " ")
	out := rs[:0:0]
	for _, x := range rs {
		if !(x.Rule == id && x.Head == head) {
			out = append(out, x)
		}
	}
	return out
}

// ruleStatements are the statements of a table in a block, in the order of
// the table and then of the block.
func ruleStatements(rs []RuleStmt) []string {
	sorted := append([]RuleStmt(nil), rs...)
	stableByRule(sorted)
	out := make([]string, len(sorted))
	for i, r := range sorted {
		out[i] = r.Text()
	}
	return out
}

func stableByRule(rs []RuleStmt) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && ruleIndex(rs[j].Rule) < ruleIndex(rs[j-1].Rule); j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

// checkRules is what a parsed block's table statements have to answer for
// besides their grammar: a statement that names the device itself only in the
// device's own block, and the login retry times in order.
func checkRules(rs []RuleStmt, layer Layer, add func(line int, sev Severity, format string, a ...any)) {
	var minT, maxT *RuleStmt
	for i := range rs {
		r := &rs[i]
		def := ruleByID(r.Rule)
		if def != nil && def.DeviceOnly {
			if why := deviceLocalProblem(layer, strings.TrimSpace(tableOf(r.Rule).prefix+strings.Join(r.Args[:def.keyEnd], " ")), false); why != "" {
				add(r.Line, SevError, "%s", why)
			}
		}
		switch r.Rule {
		case "retry-minimum-time":
			minT = r
		case "retry-maximum-time":
			maxT = r
		}
	}
	if minT != nil && maxT != nil {
		var a, b int
		fmt.Sscan(minT.Args[len(minT.Args)-1], &a)
		fmt.Sscan(maxT.Args[len(maxT.Args)-1], &b)
		if b < a {
			add(maxT.Line, SevError, "login retry-options maximum-time (%d) is below minimum-time (%d)", b, a)
		}
	}
	for _, r := range rs {
		switch r.Rule {
		case "retry-lockout-period":
			add(r.Line, SevNote, "login retry-options lockout-period locks an account for %s minutes after its failed logins: a mistyped password of a tacctl user or of a local account can lock that account", r.Args[len(r.Args)-1])
		case "ios-login-delay":
			add(r.Line, SevNote, "login delay makes every login wait %s seconds after a failed one, the tacctl server's own logins to the device included", r.Args[len(r.Args)-1])
		}
	}
}
