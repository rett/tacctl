package blocks

// The closed table of the simple statements of the Junos system block
// (0.2.19): syslog, the login retry options and the password policy. Each is a
// pattern of words after 'set system':
//
//	a word            itself
//	a|b               one of the words (a value of the statement)
//	<host> <addr> <facility> <level> <word> <int:lo-hi>   a value, checked
//	a trailing *      the word is part of the statement's identity
//
// The identity of a statement is its rule and the words through the last
// starred one and the literal words after it (the words before the first
// value when none is starred): a more
// specific layer's statement of the same identity replaces the less specific
// one's, a statement of another identity is added, and 'delete system <the
// words of the identity>' says it is not managed here. Everything else is
// refused: the table is the whole grammar of these hierarchies, and a leaf not
// in it ('system syslog file', 'system login password format' with another
// value, 'system login user') is an error.

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
)

type ruleTok struct {
	kind   int
	text   string
	alts   []string
	lo, hi int
	key    bool
}

// sysRule is one row of the table.
type sysRule struct {
	ID      string
	Pattern string
	// DeviceOnly: the statement names the device itself (an address it holds):
	// only the device's own block states it (deviceLocalProblem).
	DeviceOnly bool

	toks []ruleTok
	// keyEnd is how many words make the identity; delLen how many a delete
	// line has (the identity, or the whole pattern of a flag).
	keyEnd, delLen int
}

// Syslog facilities and levels Junos takes under 'system syslog host'.
var (
	sysFacilities = []string{"any", "authorization", "change-log", "conflict-log", "daemon", "external", "firewall", "ftp",
		"interactive-commands", "kernel", "ntp", "pfe", "security", "user"}
	sysLevels = []string{"any", "alert", "critical", "emergency", "error", "info", "none", "notice", "warning"}
	// the facilities a host's facility-override takes
	sysOverrides = []string{"authorization", "daemon", "ftp", "kernel", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "user"}
)

var reRuleWord = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,62}$`)

// sysRuleTable is the table, in the order the statements are rendered.
var sysRuleTable = buildRules([]sysRule{
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

// ruleRoots are the first words of the table's statements: a statement that
// starts with one is the table's to accept or refuse.
func ruleRoots() map[string][]string {
	out := map[string][]string{}
	for _, r := range sysRuleTable {
		root := r.toks[0].text
		if len(r.toks) > 1 && root == "login" {
			root += " " + r.toks[1].text
		}
		out[root] = append(out[root], r.Pattern)
	}
	return out
}

func buildRules(rs []sysRule) []sysRule {
	for i := range rs {
		r := &rs[i]
		lastKey, firstValue := -1, -1
		for j, w := range strings.Fields(r.Pattern) {
			var t ruleTok
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
			for r.keyEnd < len(r.toks) && r.toks[r.keyEnd].kind == rtLit {
				r.keyEnd++
			}
		case firstValue >= 0:
			r.keyEnd = firstValue
		default:
			r.keyEnd = len(r.toks)
		}
		r.delLen = r.keyEnd
	}
	return rs
}

// tokProblem is why arg is not a value of the token ("" when it is).
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

// RuleStmt is one statement of the table in a parsed block.
type RuleStmt struct {
	Rule string
	// Head is the identity inside the rule: the words through the last
	// starred one, lower case.
	Head string
	// Args are the words after 'set system', as the block keeps them.
	Args []string
	Line int
}

// Text is the 'set' statement.
func (r RuleStmt) Text() string { return "set system " + strings.Join(r.Args, " ") }

func ruleByID(id string) *sysRule {
	for i := range sysRuleTable {
		if sysRuleTable[i].ID == id {
			return &sysRuleTable[i]
		}
	}
	return nil
}

// ruleIndex is the place of a rule in the table (the order of rendering).
func ruleIndex(id string) int {
	for i := range sysRuleTable {
		if sysRuleTable[i].ID == id {
			return i
		}
	}
	return len(sysRuleTable)
}

// matchRule finds the rule a statement (the words after 'set system' or
// 'delete system') is: whole is true for a set line (the whole pattern), false
// for a delete line (the identity words, or the flag). claimed says the first
// words are the table's even when no rule fits; problem is why the best
// candidate does not.
func matchRule(args []string, whole bool) (rule *sysRule, canon []string, claimed bool, problem string) {
	root := ""
	if len(args) > 0 {
		root = args[0]
		if root == "login" && len(args) > 1 {
			root += " " + args[1]
		}
	}
	pats, ok := ruleRoots()[root]
	if !ok {
		return nil, nil, false, ""
	}
	// the reason given is the best candidate's: the rule whose literal words
	// the statement shares the most of
	best, bestLits := "", -1
	for i := range sysRuleTable {
		r := &sysRuleTable[i]
		n := len(r.toks)
		if !whole {
			n = r.delLen
		}
		if len(args) != n {
			continue
		}
		c := make([]string, n)
		bad, lits := "", 0
		for j := 0; j < n; j++ {
			t := r.toks[j]
			if t.kind == rtLit {
				if args[j] != t.text {
					bad = "literal"
					break
				}
				lits++
			}
			if why := t.problem(args[j]); why != "" && bad == "" {
				bad = fmt.Sprintf("word %d (%s) %s", j+3, args[j], why)
			}
			c[j] = t.canon(args[j])
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

// rule reads a set statement (the words after 'set system') of the table; it
// reports whether the table claimed it.
func (p *sysParser) rule(t []string) bool {
	r, c, claimed, why := matchRule(t, true)
	if !claimed {
		return false
	}
	if r == nil {
		p.errf("%s", why)
		return true
	}
	head := strings.ToLower(strings.Join(c[:r.keyEnd], " "))
	if i := indexRule(p.b.Rules, r.ID, head); i >= 0 {
		p.errf("'set system %s' is stated twice (line %d)", strings.Join(c[:r.keyEnd], " "), p.b.Rules[i].Line)
		return true
	}
	p.b.Rules = append(p.b.Rules, RuleStmt{Rule: r.ID, Head: head, Args: c, Line: p.line})
	return true
}

// ruleDelete reads a delete line of the table; it reports whether the table
// claimed it.
func (p *sysParser) ruleDelete(t []string) bool {
	r, c, claimed, why := matchRule(t, false)
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

// applyRuleDelete takes the statements a delete line names out of rs.
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

// ruleStatements are the statements of the table in a block, in the order of
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
			if why := deviceLocalProblem(layer, "system "+strings.Join(r.Args[:def.keyEnd], " "), false); why != "" {
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
		if r.Rule == "retry-lockout-period" {
			add(r.Line, SevNote, "login retry-options lockout-period locks an account for %s minutes after its failed logins: a mistyped password of a tacctl user or of a local account can lock that account", r.Args[len(r.Args)-1])
		}
	}
}
