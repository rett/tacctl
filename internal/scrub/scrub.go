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
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
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
var kept = map[string]bool{"root": true, "remote": true, "admin": true, "operator": true, "tacctl": true, "none": true, "all": true}

// Scrubber holds what one bundle learned.
type Scrubber struct {
	pairs   []Pair
	byKey   map[string]string // kind+"\x00"+lower(real) -> example
	learned map[string]string // lower(real) -> example, the values found by name
	made    map[string]bool   // examples handed out
	models  map[string]bool   // the model names the texts state: never taken for serial numbers
	domains map[string]bool   // the learned domains, lower case: nothing under one is public
	count   map[Kind]int
	re      *regexp.Regexp // the combined pass, rebuilt when learned changes
	dirty   bool
}

// New returns an empty Scrubber.
func New() *Scrubber {
	return &Scrubber{byKey: map[string]string{}, learned: map[string]string{}, made: map[string]bool{}, models: map[string]bool{}, domains: map[string]bool{}, count: map[Kind]int{}, dirty: true}
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
	if k == Domain {
		s.domains[strings.ToLower(real)] = true
	}
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

// learnByName is Learn for a value that the shape of its label gives away,
// replaced wherever it appears (a serial number of digits only).
func (s *Scrubber) learnByName(k Kind, real string) {
	ex := s.Learn(k, real)
	if ex != real {
		s.learned[strings.ToLower(real)] = ex
		s.dirty = true
	}
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
	reSecretKeyword = regexp.MustCompile(`(?i)\b(secret|password|passphrase|community|token|key-string|key-hash|authentication-key|encrypted-password|shared-secret|auth-key|priv-key|key)\b((?:[ \t]+(?:word|string))?(?:[ \t]+(?:ascii-text|hexadecimal|encrypted-password|encrypted|simple-text|plain-text|cleartext|clear|md5|sha256|sha1|sha|\d+))*(?:[ \t]*[:=][ \t]*|[ \t]+))("[^"]*"|(?:[^\s-]|-[^\s-])\S*)`)
	// a Junos permission row ('name -- what it allows') holds words, not values
	rePermissionRow = regexp.MustCompile(`^\s*[\w.-]+\s*-- `)
	reHash          = regexp.MustCompile(`\$\d[a-z]?\$[^\s"';]+`)
	reLongToken     = regexp.MustCompile(`\b(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/=_-]{40,})\b`)
	reHistComment   = regexp.MustCompile(`(?m)^(\d+\s+\d{4}-\d{2}-\d{2} .*(?:\n[ \t]+\S.*)+)`)
	reTZTime        = regexp.MustCompile(`(\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)([ \t]+)([A-Z]{3,5})\b`)
	reTZName        = regexp.MustCompile(`\b(?:Africa|America|Asia|Atlantic|Australia|Europe|Pacific|Indian|Antarctica|Arctic)/[A-Za-z0-9_+/-]+`)
	reClockTZ       = regexp.MustCompile(`(?m)^(\s*clock timezone )\S+(?:\s+-?\d+(?:\s+\d+)?)?`)

	// what the learn step finds by shape
	reLearnHostname = regexp.MustCompile(`(?mi)^[ \t]*(?:hostname|host-name)[ \t]*[:=]?[ \t]*(\S+)[ \t]*$`)
	reLearnJunosHN  = regexp.MustCompile(`(?m)^Hostname:[ \t]*(\S+)[ \t]*$`)
	reLearnBy       = regexp.MustCompile(`\bby (\S+) via\b`)
	reLearnCurrent  = regexp.MustCompile(`Current user: '([^']*)' login: '([^']*)' class '([^']*)'`)
	reLearnUptime   = regexp.MustCompile(`(?m)^(\S+) uptime is `)
	reLearnLastBy   = regexp.MustCompile(`(?m)(?:last configuration change|nvram config last updated).* by (\S+)[ \t]*$`)
	reLearnSerial   = regexp.MustCompile(`(?mi)\bserial(?: number| no\.?)?[ \t]*[:=][ \t]*([^\s,"]+)`)
	reLearnDomain   = regexp.MustCompile(`(?mi)^[ \t]*ip domain[- ]name[ \t]+(?:vrf \S+[ \t]+)?(\S+)`)
	// the model names a text states
	reLearnPID      = regexp.MustCompile(`(?m)\bPID:[ \t]*(.*?)(?:[ \t]{2,}|,|\bVID:|\bSN:|$)`)
	reLearnModel    = regexp.MustCompile(`(?mi)^[ \t]*model(?: number)?[ \t]*[:=][ \t]*(\S+)`)
	reLearnCisco    = regexp.MustCompile(`(?mi)^[ \t]*cisco[ \t]+([A-Za-z0-9][A-Za-z0-9-]*)[ \t]+\([^)\n]*\)[ \t]+processor\b|\bCisco IOS(?: XE)? Software, ([A-Za-z0-9][A-Za-z0-9-]*) Software\b`)
	reLearnLocation = regexp.MustCompile(`(?mi)^[ \t]*(?:snmp-server location|location|sysLocation(?:\.0)?[ \t]*[:=])[ \t]*(\S.*?)[ \t]*$`)
	reLearnContact  = regexp.MustCompile(`(?mi)^[ \t]*(?:snmp-server contact|contact|sysContact(?:\.0)?[ \t]*[:=])[ \t]*(\S.*?)[ \t]*$`)

	// the combined pass
	reMail    = `[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}`
	reMAC     = `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b`
	reV4      = `\b\d{1,3}(?:\.\d{1,3}){3}\b`
	reV6Cand  = `\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3}|::[0-9A-Fa-f:]*`
	reSerial  = `\b[A-Z0-9]{8,14}\b`
	reFQDN    = `\b(?:[A-Za-z0-9-]+\.)+(?:(?:co|com|org|net|ac|gov|edu)\.[a-z]{2}|net|com|org|edu|gov|mil|io|local|lan|corp|home|int|uk|de|fr|nl|se|no|ch|jp|cn|ca|au|ru|br|it|es|eu|us|in|pl|be|at|dk|fi|ie|nz|za|kr|sg|hk|mx)\b`
	reExample = regexp.MustCompile(`(?i)(?:^|\.)example\.(?:net|org|com|edu|invalid|test)$`)

	// what the serial-number shape never reads: the model and the version of a
	// 'show inventory' item, its quoted description, the model of the Model
	// line of Junos, the model of the 'cisco <model> (...) processor' line of
	// IOS; the value only, never the rest of the line
	reKeepPID   = regexp.MustCompile(`(?m)\bPID:[ \t]*(.*?)(?:[ \t]{2,}|,|\bVID:|\bSN:|$)`)
	reKeepVID   = regexp.MustCompile(`\bVID:[ \t]*([^\s,]*)`)
	reKeepDescr = regexp.MustCompile(`\bDESCR:[ \t]*"([^"\n]*)"`)
	reKeepModel = reLearnModel
	reKeepCisco = reLearnCisco
)

// vendorDomains are the registered domains (the last two labels) of vendors
// and standards bodies that texts name in a banner or a URL: the bare domain
// and a few public labels of it (publicLabels) say nothing about the owner,
// so they are kept. A mail address never is: it names a person. A name any
// deeper (acme-corp.hpe.com) is a customer's and is replaced.
var vendorDomains = map[string]bool{
	"cisco.com": true, "juniper.net": true, "hpe.com": true, "hp.com": true, "gnu.org": true,
	"fsf.org": true, "openssl.org": true, "ietf.org": true, "kernel.org": true,
}

// publicLabels are the one label a vendor's public host name may have in
// front of the registered domain: the labels of a download or a web server.
var publicLabels = map[string]bool{"www": true, "tools": true, "ftp": true, "cdn": true, "software": true, "support": true}

// underLearned reports whether name is a learned domain or under one: the
// owner's own name, whatever else it looks like.
func (s *Scrubber) underLearned(name string) bool {
	for d := range s.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// isPublicName reports whether name, a host name, is public: an example
// name, the bare registered domain of a vendor, or one public label of it.
// A name under a learned domain never is.
func (s *Scrubber) isPublicName(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if s.underLearned(name) {
		return false
	}
	if reExample.MatchString(name) {
		return true
	}
	labels := strings.Split(name, ".")
	n := len(labels)
	return n >= 2 && vendorDomains[strings.Join(labels[n-2:], ".")] && (n == 2 || n == 3 && publicLabels[labels[0]])
}

// isExampleMail reports whether the domain of a mail address is an example
// name that is not a learned domain: the only address left as it is.
func (s *Scrubber) isExampleMail(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return !s.underLearned(domain) && reExample.MatchString(domain)
}

// A span is a stretch of a text, [start, end).
type span struct{ start, end int }

// covers reports whether some span holds [start, end).
func covers(spans []span, start, end int) bool {
	for _, sp := range spans {
		if sp.start <= start && end <= sp.end {
			return true
		}
	}
	return false
}

// keepSpans are the stretches of text where the shape of a serial number
// does not make a token one: model names and descriptions.
func keepSpans(text string) []span {
	var out []span
	for _, re := range []*regexp.Regexp{reKeepPID, reKeepVID, reKeepDescr, reKeepModel, reKeepCisco} {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			for i := 2; i+1 < len(m); i += 2 {
				if m[i] >= 0 {
					out = append(out, span{m[i], m[i+1]})
				}
			}
		}
	}
	return out
}

// The serial numbers a text states by their field, whatever their shape: the
// value is group 1.
var reSerialFields = []*regexp.Regexp{
	regexp.MustCompile(`\bSN:[ \t]*([^\s,"]+)`),
	regexp.MustCompile(`\bHw Serial#:[ \t]*([^\s,"]+)`),
	regexp.MustCompile(`\bProcessor board ID[ \t]+([^\s,"]+)`),
	regexp.MustCompile(`(?i)\bSystem serial number[ \t]*:[ \t]*([^\s,"]+)`),
	regexp.MustCompile(`\bSerial ID[ \t]+([^\s,"]+)`),
	reLearnSerial,
}

// A serial column of a table is cut at the position its header gives: the
// headers of 'show chassis hardware' and of Junos 'show virtual-chassis'.
// The cell after the serial column is the one the exempt description starts
// at; the rows of a table with a gap in them are counted from the right.
type serialTable struct {
	head           *regexp.Regexp
	serial, follow string // the header words that start the serial column and the column after it
	fromRight      bool   // a tab-separated row has cells missing before the serial: count them from its end
}

var serialTables = []serialTable{
	{regexp.MustCompile(`^\s*Item\s+Version\s+Part number\s+Serial number\s+Description\b`), "Serial number", "Description", true},
	{regexp.MustCompile(`^\s*Member ID\s+Status\s+Serial No\s+Model\b`), "Serial No", "Model", false},
}

var reNoSerial = regexp.MustCompile(`(?i)^(?:builtin|n/?a|none|unknown|unspecified|not[-_ ]?available|-+)$`)

// isSerialValue reports whether v, the value of a serial field, is a number
// to replace: not empty, not BUILTIN, not an example already.
func isSerialValue(v string) bool {
	return v != "" && !reNoSerial.MatchString(v) && !reExampleSerial.MatchString(v)
}

var reExampleSerial = regexp.MustCompile(`^SN\d{6}$`)

// isTableSerial reports whether v, a word in the serial column of a table, is
// a number to learn: a serial value of the shape of one (four characters or
// more, with a digit), not a status such as Prsnt.
func isTableSerial(v string) bool {
	return len(v) >= 4 && strings.ContainsAny(v, "0123456789") && isSerialValue(v)
}

// reCellSep separates the cells of a row that was cut at tabs, or at two
// blanks or more, instead of at the columns of its header.
var reCellSep = regexp.MustCompile(`\t+| {2,}`)

// cellsAt are the cells of a line, trimmed, with their positions.
func cellsAt(line string) []span {
	var out []span
	add := func(from, to int) {
		for from < to && (line[from] == ' ' || line[from] == '\t') {
			from++
		}
		for to > from && (line[to-1] == ' ' || line[to-1] == '\t') {
			to--
		}
		if from < to {
			out = append(out, span{from, to})
		}
	}
	pos := 0
	for _, sep := range reCellSep.FindAllStringIndex(line, -1) {
		add(pos, sep[0])
		pos = sep[1]
	}
	add(pos, len(line))
	return out
}

// serialSpans are the serial numbers a text states by field, and the
// Description columns of the tables they are cut from (the words there are
// model names and descriptions, whatever their shape). A table ends at a
// blank line, at a 'word:' line, and at the first line with nothing in or
// after the serial column.
func serialSpans(text string) (cells, descr []span) {
	for _, re := range reSerialFields {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			if isSerialValue(text[m[2]:m[3]]) {
				cells = append(cells, span{m[2], m[3]})
			}
		}
	}
	off := 0
	var (
		tb       = -1 // the table of the header seen, -1 outside one
		from, to int  // the serial column and the column after it
		nh, si   int  // the cells of the header, and the one of the serial
	)
	for _, line := range strings.SplitAfter(text, "\n") {
		body := strings.TrimRight(line, "\r\n")
		switch {
		case strings.TrimSpace(body) == "" || strings.HasSuffix(body, ":") && !strings.Contains(body, " "):
			tb = -1
		case headerOf(body) >= 0:
			tb = headerOf(body)
			head := serialTables[tb]
			from, to = strings.Index(body, head.serial), strings.Index(body, head.follow)
			if from < 0 || to <= from {
				tb = -1
				break
			}
			hc := cellsAt(body)
			nh, si = len(hc), slices.IndexFunc(hc, func(c span) bool { return body[c.start:c.end] == head.serial })
		case tb >= 0 && strings.Contains(body, "\t"):
			cs := cellsAt(body)
			idx := si
			if serialTables[tb].fromRight {
				idx = len(cs) - (nh - si)
			}
			if len(cs) < 2 || si < 0 {
				tb = -1
				break
			}
			if idx >= 0 && idx < len(cs) {
				if v := body[cs[idx].start:cs[idx].end]; isTableSerial(v) && !strings.ContainsAny(v, " \t") {
					cells = append(cells, span{off + cs[idx].start, off + cs[idx].end})
				}
			}
			if idx >= 0 && idx+1 < len(cs) {
				descr = append(descr, span{off + cs[idx+1].start, off + len(body)})
			}
		case tb >= 0:
			fields := fieldsAt(body)
			if !slices.ContainsFunc(fields, func(f span) bool { return f.start >= from }) {
				tb = -1 // nothing in or after the serial column: not a row of the table
				break
			}
			for _, f := range fields {
				if f.start >= from && f.start < to && isTableSerial(body[f.start:f.end]) {
					cells = append(cells, span{off + f.start, off + f.end})
				}
			}
			if len(body) > to {
				descr = append(descr, span{off + to, off + len(body)})
			}
		}
		off += len(line)
	}
	return cells, descr
}

// headerOf is the index in serialTables of the table whose header line is
// body, or -1.
func headerOf(body string) int {
	return slices.IndexFunc(serialTables, func(t serialTable) bool {
		return t.head.MatchString(body)
	})
}

// fieldsAt are the blank-separated words of a line, with their positions.
func fieldsAt(line string) []span {
	var out []span
	start := -1
	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ' ' || line[i] == '\t' {
			if start >= 0 {
				out = append(out, span{start, i})
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	return out
}

// learnModels records the model names a text states: the PID of an
// inventory item, the Model line, the model of the 'cisco <model> (...)
// processor' and 'Cisco IOS Software, <model> Software' lines.
func (s *Scrubber) learnModels(text string) {
	add := func(v string) {
		for _, w := range strings.Fields(v) {
			s.models[strings.Trim(w, `",;:()`)] = true
		}
	}
	for _, m := range reLearnPID.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range reLearnModel.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range reLearnCisco.FindAllStringSubmatch(text, -1) {
		add(m[1] + m[2])
	}
}

// LearnFrom learns the names a text holds by their shape: the hostname lines,
// the users and classes of the login and the history, the domain, location
// and contact lines.
func (s *Scrubber) LearnFrom(text string) {
	s.learnModels(text)
	for _, m := range reLearnJunosHN.FindAllStringSubmatch(text, -1) {
		s.Learn(Host, m[1])
	}
	for _, m := range reLearnHostname.FindAllStringSubmatch(text, -1) {
		s.Learn(Host, m[1])
	}
	for _, m := range reLearnUptime.FindAllStringSubmatch(text, -1) {
		s.Learn(Host, m[1])
	}
	for _, m := range reLearnLastBy.FindAllStringSubmatch(strings.ToLower(text), -1) {
		s.Learn(User, m[1])
	}
	cells, _ := serialSpans(text)
	for _, c := range cells {
		if v := text[c.start:c.end]; len(v) >= 4 {
			s.learnByName(Serial, v)
		} else {
			s.Learn(Serial, v)
		}
	}
	for _, m := range reLearnBy.FindAllStringSubmatch(text, -1) {
		s.Learn(User, m[1])
	}
	for _, m := range reLearnCurrent.FindAllStringSubmatch(text, -1) {
		s.Learn(User, m[1])
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
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if !rePermissionRow.MatchString(l) {
			lines[i] = reSecretKeyword.ReplaceAllString(l, "$1$2"+Removed)
		}
	}
	text = strings.Join(lines, "\n")
	text = reHash.ReplaceAllString(text, Removed)
	text = reLongToken.ReplaceAllString(text, Removed)
	text = reHistComment.ReplaceAllStringFunc(text, dropComments)
	text = reTZTime.ReplaceAllString(text, "${1}${2}UTC")
	text = reTZName.ReplaceAllString(text, "UTC")
	text = reClockTZ.ReplaceAllString(text, "${1}UTC 0")
	s.compile()
	cells, descr := serialSpans(text)
	keep := append(keepSpans(text), descr...)
	type edit struct {
		start, end int
		rep        string
		cell       bool // a cell of a table: one blank after it separates the columns
	}
	var edits []edit
	for _, c := range cells {
		if rep := s.Learn(Serial, text[c.start:c.end]); rep != text[c.start:c.end] {
			edits = append(edits, edit{c.start, c.end, rep, true})
		}
	}
	names := s.re.SubexpNames()
	for _, idx := range s.re.FindAllStringSubmatchIndex(text, -1) {
		start, end := idx[0], idx[1]
		if start > 0 && isAlnum(text[start-1]) || end < len(text) && isAlnum(text[end]) {
			continue // inside a longer word
		}
		if slices.ContainsFunc(cells, func(c span) bool { return c.start < end && start < c.end }) {
			continue // a serial number by its field
		}
		tok := text[start:end]
		which := ""
		for i := 1; i < len(names); i++ {
			if idx[2*i] >= 0 {
				which = names[i]
				break
			}
		}
		if which == "v4" && inObjectID(text, start, end) {
			continue // an object identifier, not an address
		}
		if which == "serial" && (s.models[tok] || covers(keep, start, end)) {
			continue
		}
		rep, ok := s.replacement(which, tok)
		if !ok {
			continue
		}
		edits = append(edits, edit{start, end, rep, false})
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var b strings.Builder
	last := 0
	for _, e := range edits {
		if e.start < last {
			continue
		}
		b.WriteString(text[last:e.start])
		rep, skip := keepWidth(text, e.start, e.end, e.rep, e.cell)
		b.WriteString(rep)
		last = e.end + skip
	}
	b.WriteString(text[last:])
	return b.String()
}

// keepWidth keeps the columns after a replacement where the device printed
// them. When rep is shorter than the text[start:end] it replaces and a run of
// blanks follows (two or more, or one in the cell of a table) that is not at
// the end of the line, the missing blanks are added to rep; when it is longer
// and enough blanks follow, as many are skipped (skip), one blank always
// staying. At the end of a line nothing is done.
func keepWidth(text string, start, end int, rep string, cell bool) (string, int) {
	have, want := utf8.RuneCountInString(text[start:end]), utf8.RuneCountInString(rep)
	if have == want {
		return rep, 0
	}
	blanks := 0
	for end+blanks < len(text) && text[end+blanks] == ' ' {
		blanks++
	}
	next := end + blanks
	minRun := 2
	if cell {
		minRun = 1
	}
	if blanks < minRun || next >= len(text) || text[next] == '\n' || text[next] == '\r' {
		return rep, 0
	}
	if have > want {
		return rep + strings.Repeat(" ", have-want), 0
	}
	return rep, min(want-have, blanks-1)
}

// inObjectID reports whether text[start:end], four groups of digits, is part
// of an object identifier: a dotted run of numbers that begins 1.3.6.1.
// (with or without a leading dot). The run is what is left alone; the digits
// around any other address (10.20.30.40.179, ipv4.10.20.30.40) do not make
// it a version string.
func inObjectID(text string, start, end int) bool {
	isRun := func(b byte) bool { return b >= '0' && b <= '9' || b == '.' }
	from, to := start, end
	for from > 0 && isRun(text[from-1]) {
		from--
	}
	for to < len(text) && isRun(text[to]) {
		to++
	}
	return strings.HasPrefix(strings.TrimPrefix(text[from:to], "."), "1.3.6.1.")
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
		if s.isExampleMail(tok[strings.IndexByte(tok, '@')+1:]) {
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
		if s.isPublicName(tok) {
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
			if (i <= 0 || !isAlnum(low[i-1])) && (end >= len(low) || !isAlnum(low[end])) {
				out = append(out, k)
				break
			}
			from = i + 1
		}
	}
	sort.Strings(out)
	return out
}
