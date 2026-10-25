// Package scrub makes the text a device printed safe to share: what names
// the device, its people or its network is replaced with the standard
// example values (docs/development/README.md, Examples), the same real
// value always with the same example, and what is a secret is removed.
//
// A Scrubber learns first (Learn, LearnFrom over every text of one bundle)
// and applies after (Apply), so a name seen in the third file is replaced in
// the first. Apply replaces in one pass: text it wrote is never read again,
// so an example value can equal another real one without being replaced
// twice. Leaks is the check after it: a learned real value that is still in
// a text.
package scrub

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A Kind is what a value is.
type Kind string

const (
	Host     Kind = "host"
	Domain   Kind = "domain"
	User     Kind = "user"
	Class    Kind = "class"
	Serial   Kind = "serial"
	Addr4    Kind = "ipv4"
	Addr6    Kind = "ipv6"
	MAC      Kind = "mac"
	Mail     Kind = "mail"
	Location Kind = "location"
	Contact  Kind = "contact"
)

// Pair is one replacement, for the map file.
type Pair struct {
	Kind          Kind
	Real, Example string
}

// Removed stands where a secret was.
const Removed = "<removed>"

// kept are names that say nothing about anyone: never replaced.
var kept = map[string]bool{"root": true, "admin": true, "operator": true, "tacctl": true, "none": true, "all": true}

// Scrubber holds what one bundle learned.
type Scrubber struct {
	pairs   []Pair
	byKey   map[string]string // kind+"\x00"+lower(real) -> example
	learned map[string]string // lower(real) -> example, the values found by name
	made    map[string]bool   // examples handed out
	count   map[Kind]int
	re      *regexp.Regexp // the combined pass, rebuilt when learned changes
	dirty   bool
}

// New returns an empty Scrubber.
func New() *Scrubber {
	return &Scrubber{byKey: map[string]string{}, learned: map[string]string{}, made: map[string]bool{}, count: map[Kind]int{}, dirty: true}
}

// Pairs are the replacements made or learned so far, by kind and then real
// value.
func (s *Scrubber) Pairs() []Pair {
	out := append([]Pair(nil), s.pairs...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Real < out[j].Real
	})
	return out
}

var (
	userExamples  = []string{"alice", "bob", "carol", "dave"}
	classExamples = []string{"ops-rw", "ops-ro"}
	locExamples   = []string{"Rack 4, DC1", "Lab rack 2", "Example City, Example State"}
	domExamples   = []string{"example.net", "example.org"}
)

// example is the next example value of a kind.
func (s *Scrubber) example(k Kind, real string) string {
	n := s.count[k]
	s.count[k]++
	switch k {
	case Host:
		return "sw" + strconv.Itoa(n+1)
	case Domain:
		if n < len(domExamples) {
			return domExamples[n]
		}
		return "site" + strconv.Itoa(n-len(domExamples)+1) + ".example.net"
	case User:
		if n < len(userExamples) {
			return userExamples[n]
		}
		return "user" + strconv.Itoa(n+1)
	case Class:
		if n < len(classExamples) {
			return classExamples[n]
		}
		return "class" + strconv.Itoa(n+1)
	case Serial:
		return fmt.Sprintf("SN%06d", n+1)
	case Location:
		if n < len(locExamples) {
			return locExamples[n]
		}
		return "Site " + strconv.Itoa(n-len(locExamples)+1)
	case Contact:
		if n == 0 {
			return "NOC <noc@example.net>"
		}
		return "NOC " + strconv.Itoa(n+1) + " <noc@example.net>"
	case Mail:
		return "user" + strconv.Itoa(n+1) + "@example.net"
	case Addr4:
		// RFC 5737: 192.0.2.0/24, then 198.51.100.0/24, then 203.0.113.0/24
		nets := []string{"192.0.2.", "198.51.100.", "203.0.113."}
		return nets[(n/254)%3] + strconv.Itoa(n%254+1)
	case Addr6:
		return "2001:db8::" + strconv.FormatInt(int64(n+1), 16)
	case MAC:
		return macExample(real, n+1)
	}
	return real
}

// macExample is the example MAC of the form real is written in.
func macExample(real string, n int) string {
	b := fmt.Sprintf("00005e00%04x", 0x5300+n%256)
	switch {
	case strings.Contains(real, "."):
		return b[0:4] + "." + b[4:8] + "." + b[8:12]
	case strings.Contains(real, "-"):
		return strings.Join([]string{b[0:2], b[2:4], b[4:6], b[6:8], b[8:10], b[10:12]}, "-")
	}
	return strings.Join([]string{b[0:2], b[2:4], b[4:6], b[6:8], b[8:10], b[10:12]}, ":")
}

// Learn registers a real value of a kind and returns its example. A value
// already known keeps its example; a value that says nothing (root, an empty
// word) is returned as it is.
func (s *Scrubber) Learn(k Kind, real string) string {
	real = strings.TrimSpace(real)
	if real == "" || kept[strings.ToLower(real)] || len(real) < 2 {
		return real
	}
	key := string(k) + "\x00" + strings.ToLower(real)
	if ex, ok := s.byKey[key]; ok {
		return ex
	}
	var ex string
	switch k {
	case Host:
		// a name with dots is a host and a domain: sw1.corp.net
		if label, dom, ok := strings.Cut(real, "."); ok && label != "" && dom != "" {
			exDom := s.Learn(Domain, dom)
			exLabel := s.Learn(Host, label)
			ex = exLabel + "." + exDom
			s.record(k, real, ex, key, true)
			return ex
		}
		ex = s.example(Host, real)
	case Mail:
		ex = s.example(Mail, real)
	default:
		ex = s.example(k, real)
	}
	byName := k != Addr4 && k != Addr6 && k != MAC && k != Serial && k != Mail
	s.record(k, real, ex, key, byName)
	return ex
}

func (s *Scrubber) record(k Kind, real, ex, key string, byName bool) {
	s.byKey[key] = ex
	s.made[strings.ToLower(ex)] = true
	s.pairs = append(s.pairs, Pair{k, real, ex})
	if byName {
		s.learned[strings.ToLower(real)] = ex
		s.dirty = true
	}
}

var (
	reSecretKeyword = regexp.MustCompile(`(?i)\b(secret|password|passphrase|community|token|key-string|key-hash|authentication-key|encrypted-password|shared-secret|auth-key|priv-key|key)\b((?:\s+(?i:word|string))?(?:\s+\d)?(?:\s*[:=]\s*|\s+))("[^"]*"|\S+)`)
	reHash          = regexp.MustCompile(`\$\d[a-z]?\$[^\s"';]+`)
	reLongToken     = regexp.MustCompile(`\b(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/=_-]{40,})\b`)
	reHistComment   = regexp.MustCompile(`(?m)^(\d+\s+\d{4}-\d{2}-\d{2} .*(?:\n    \S.*)+)`)
	reTZTime        = regexp.MustCompile(`(\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)(\s+)(AKDT|AKST|HDT|HST|PDT|PST|MDT|MST|CDT|CST|EDT|EST|ADT|AST|GMT|BST|IST|CEST|CET|EEST|EET|WEST|WET|MSK|JST|KST|AEST|AEDT|ACST|ACDT|AWST|NZST|NZDT)\b`)
	reTZName        = regexp.MustCompile(`\b(?:Africa|America|Asia|Atlantic|Australia|Europe|Pacific|Indian|Antarctica|Arctic)/[A-Za-z0-9_+/-]+`)
	reClockTZ       = regexp.MustCompile(`(?m)^(\s*clock timezone )\S+(?:\s+-?\d+(?:\s+\d+)?)?`)

	// what the learn step finds by shape
	reLearnHostname = regexp.MustCompile(`(?mi)^\s*(?:hostname|host-name)\s*[:=]?\s*(\S+)\s*$`)
	reLearnJunosHN  = regexp.MustCompile(`(?m)^Hostname:\s*(\S+)\s*$`)
	reLearnBy       = regexp.MustCompile(`\bby (\S+) via\b`)
	reLearnCurrent  = regexp.MustCompile(`Current user: '([^']*)' login: '([^']*)' class '([^']*)'`)
	reLearnDomain   = regexp.MustCompile(`(?mi)^\s*ip domain[- ]name\s+(?:vrf \S+\s+)?(\S+)`)
	reLearnLocation = regexp.MustCompile(`(?mi)^\s*(?:snmp-server location|location|sysLocation(?:\.0)?\s*[:=])\s*(.+?)\s*$`)
	reLearnContact  = regexp.MustCompile(`(?mi)^\s*(?:snmp-server contact|contact|sysContact(?:\.0)?\s*[:=])\s*(.+?)\s*$`)

	// the combined pass
	reMail    = `[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}`
	reMAC     = `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b`
	reV4      = `\b\d{1,3}(?:\.\d{1,3}){3}\b`
	reV6Cand  = `\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3}|::[0-9A-Fa-f:]*`
	reSerial  = `\b[A-Z0-9]{8,14}\b`
	reFQDN    = `\b(?:[A-Za-z0-9-]+\.)+(?:net|com|org|edu|gov|mil|io|local|lan|corp|home|int)\b`
	reExample = regexp.MustCompile(`(?i)(?:^|\.)example\.(?:net|org|com)$`)
)

// LearnFrom learns the names a text holds by their shape: the hostname lines,
// the users and classes of the login and the history, the domain, location
// and contact lines.
func (s *Scrubber) LearnFrom(text string) {
	for _, m := range reLearnJunosHN.FindAllStringSubmatch(text, -1) {
		s.Learn(Host, m[1])
	}
	for _, m := range reLearnHostname.FindAllStringSubmatch(text, -1) {
		s.Learn(Host, m[1])
	}
	for _, m := range reLearnBy.FindAllStringSubmatch(text, -1) {
		s.Learn(User, m[1])
	}
	for _, m := range reLearnCurrent.FindAllStringSubmatch(text, -1) {
		s.Learn(Class, m[1])
		s.Learn(User, m[2])
		s.Learn(Class, m[3])
	}
	for _, m := range reLearnDomain.FindAllStringSubmatch(text, -1) {
		s.Learn(Domain, m[1])
	}
	for _, m := range reLearnLocation.FindAllStringSubmatch(text, -1) {
		s.Learn(Location, strings.Trim(m[1], `"`))
	}
	for _, m := range reLearnContact.FindAllStringSubmatch(text, -1) {
		s.Learn(Contact, strings.Trim(m[1], `"`))
	}
}

// compile builds the combined pass from what is learned.
func (s *Scrubber) compile() {
	if !s.dirty && s.re != nil {
		return
	}
	keys := make([]string, 0, len(s.learned))
	for k := range s.learned {
		keys = append(keys, regexp.QuoteMeta(k))
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	alts := []string{}
	if len(keys) > 0 {
		alts = append(alts, `(?P<learned>(?i:`+strings.Join(keys, "|")+`))`)
	}
	alts = append(alts, `(?P<mail>(?i:`+reMail+`))`, `(?P<mac>(?i:`+reMAC+`))`, `(?P<v4>`+reV4+`)`, `(?P<v6>(?i:`+reV6Cand+`))`,
		`(?P<fqdn>(?i:`+reFQDN+`))`, `(?P<serial>`+reSerial+`)`)
	s.re = regexp.MustCompile(strings.Join(alts, "|"))
	s.dirty = false
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// Apply returns text with the secrets removed and every learned or
// recognised value replaced.
func (s *Scrubber) Apply(text string) string {
	text = reSecretKeyword.ReplaceAllString(text, "$1$2"+Removed)
	text = reHash.ReplaceAllString(text, Removed)
	text = reLongToken.ReplaceAllString(text, Removed)
	text = reHistComment.ReplaceAllStringFunc(text, dropComments)
	text = reTZTime.ReplaceAllString(text, "${1}${2}UTC")
	text = reTZName.ReplaceAllString(text, "UTC")
	text = reClockTZ.ReplaceAllString(text, "${1}UTC 0")
	s.compile()
	names := s.re.SubexpNames()
	var b strings.Builder
	last := 0
	for _, idx := range s.re.FindAllStringSubmatchIndex(text, -1) {
		start, end := idx[0], idx[1]
		if start > 0 && isAlnum(text[start-1]) || end < len(text) && isAlnum(text[end]) {
			continue // inside a longer word
		}
		tok := text[start:end]
		which := ""
		for i := 1; i < len(names); i++ {
			if idx[2*i] >= 0 {
				which = names[i]
				break
			}
		}
		rep, ok := s.replacement(which, tok)
		if !ok {
			continue
		}
		b.WriteString(text[last:start])
		b.WriteString(rep)
		last = end
	}
	b.WriteString(text[last:])
	return b.String()
}

// dropComments keeps the first line of a commit history entry and removes
// the comment lines beneath it, unless tacctl wrote them.
func dropComments(entry string) string {
	lines := strings.Split(entry, "\n")
	out := lines[:1]
	for _, l := range lines[1:] {
		if strings.HasPrefix(strings.TrimSpace(l), "tacctl ") {
			out = append(out, l)
		} else {
			out = append(out, "    <comment removed>")
		}
	}
	return strings.Join(out, "\n")
}

// replacement is the example for a token the combined pass found; false
// leaves the token as it is.
func (s *Scrubber) replacement(which, tok string) (string, bool) {
	switch which {
	case "learned":
		return s.learned[strings.ToLower(tok)], true
	case "mail":
		if reExample.MatchString(tok[strings.IndexByte(tok, '@')+1:]) {
			return "", false
		}
		return s.Learn(Mail, tok), true
	case "mac":
		return s.Learn(MAC, strings.ToLower(tok)), true
	case "v4":
		ip := net.ParseIP(tok)
		if ip == nil || ip.To4() == nil || strings.Contains(tok, "..") {
			return "", false
		}
		o := ip.To4()
		switch {
		case o[0] == 0 || o[0] == 127 || o[0] >= 224, // unspecified, loopback, multicast, masks
			o[0] == 192 && o[1] == 0 && o[2] == 2, o[0] == 198 && o[1] == 51 && o[2] == 100, o[0] == 203 && o[1] == 0 && o[2] == 113:
			return "", false // already an example
		}
		return s.Learn(Addr4, tok), true
	case "v6":
		ip := net.ParseIP(strings.TrimRight(tok, ":."))
		if ip == nil || ip.To4() != nil || !strings.Contains(tok, "::") && strings.Count(tok, ":") != 7 {
			return "", false
		}
		if ip.IsLoopback() || ip.IsUnspecified() || strings.HasPrefix(strings.ToLower(tok), "2001:db8") {
			return "", false
		}
		return s.Learn(Addr6, strings.ToLower(tok)), true
	case "fqdn":
		if reExample.MatchString(tok) {
			return "", false
		}
		return s.Learn(Host, tok), true
	case "serial":
		var digit, letter bool
		for i := 0; i < len(tok); i++ {
			digit = digit || tok[i] >= '0' && tok[i] <= '9'
			letter = letter || tok[i] >= 'A' && tok[i] <= 'Z'
		}
		if !digit || !letter || strings.HasPrefix(tok, "SN0") || strings.Contains(tok, "K9") {
			return "", false
		}
		return s.Learn(Serial, tok), true
	}
	return "", false
}

// ApplyAll learns from every text, then returns each with Apply: a name
// found in a later text is replaced in the earlier ones too, and the values
// Apply recognises are the same in all of them.
func (s *Scrubber) ApplyAll(texts []string) []string {
	for _, t := range texts {
		s.LearnFrom(t)
	}
	for _, t := range texts { // learns the values found by shape
		s.Apply(t)
	}
	out := make([]string, len(texts))
	for i, t := range texts {
		out[i] = s.Apply(t)
	}
	return out
}

// Leaks are the learned real values (by name) that are still in a text and
// are not an example handed out.
func (s *Scrubber) Leaks(text string) []string {
	var out []string
	low := strings.ToLower(text)
	for k := range s.learned {
		if s.made[k] {
			continue
		}
		for from := 0; from < len(low); {
			i := strings.Index(low[from:], k)
			if i < 0 {
				break
			}
			i += from
			end := i + len(k)
			if !(i > 0 && isAlnum(low[i-1]) || end < len(low) && isAlnum(low[end])) {
				out = append(out, k)
				break
			}
			from = i + 1
		}
	}
	sort.Strings(out)
	return out
}
