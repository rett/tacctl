package devconf

// Cisco IOS and IOS-XE: the text of 'show running-config', and the
// configuration lines devices.Managed renders (a submode's lines indented
// under the line that opens it).
//
// Both sides are put in one form: a statement is its submode context and
// its line joined with " > " ('tacacs server TACACS > address ipv4
// 192.0.2.10'), a line that opens a submode is not a statement of its own
// (only its content is), '!' comments, 'exit', 'end', banners and ACL
// remarks are dropped, the VTY line ranges are merged per statement
// ('line vty 0 4' and 'line vty 5 15' both holding 'access-class X in' is
// 'line vty 0 15 > access-class X in'), and a standard ACL entry is its
// verb and its address ('permit host A', 'permit A 0.0.0.0' and 'permit A'
// are one). Statements are compared as sets, except the entries of an ACL:
// those keep their order, a run of consecutive entries with one action
// being a set (IOS reorders the host entries of a standard ACL, M3).
//
// Nothing here has been seen on a router: the shapes are the vendor
// references' ([A] in the plan, "not lab-tested"). Marked [A] below are the
// behaviours taken from IOS knowledge, not a lab: the parent 'privilege'
// lines IOS adds, 'aaa session-id common', the 'snmp-server user' lines
// that 'show running-config' does not print, and the placement of the
// community in 'snmp-server host'. D62's "'enable' secrets' presence" is
// dropped: Managed does not render an 'enable' secret, so none is
// classified, and 'ip tacacs|radius source-interface' (the operator's
// choice, rendered as a comment) is claimed only when the rendering has it.

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// pathSep joins a submode context to its line.
const pathSep = " > "

var (
	reVTY      = regexp.MustCompile(`^line vty (\d+)(?: (\d+))?$`)
	reSeqNum   = regexp.MustCompile(`^\d+$`)
	reHashWord = regexp.MustCompile(`^\$\d+\$`)
)

// ciscoEntry is one kept line of the text, with its depth.
type ciscoEntry struct {
	indent int
	text   string
	mark   bool
	// path is set for a line already in the joined form (the output of
	// Extract or Normalise read again).
	path []string
}

// ciscoEntries reads the lines: depth by leading blanks, comments, banners
// and the words that carry no configuration dropped.
func ciscoEntries(lines []string, marks []bool) []ciscoEntry {
	var out []ciscoEntry
	for n := 0; n < len(lines); n++ {
		raw := strings.TrimRight(lines[n], " \t\r")
		t := strings.TrimLeft(raw, " \t")
		if t == "" || strings.HasPrefix(t, "!") {
			continue
		}
		if strings.HasPrefix(t, "banner ") {
			// banner <type> <delimiter>text<delimiter>, lines until the
			// delimiter again.
			if f := strings.Fields(t); len(f) >= 3 {
				d := f[2]
				if strings.HasPrefix(d, "^C") {
					d = "^C"
				} else {
					d = d[:1]
				}
				body := strings.TrimPrefix(t, strings.Join(f[:2], " "))
				if strings.Count(body, d) < 2 {
					for n++; n < len(lines) && !strings.Contains(lines[n], d); n++ {
					}
				}
			}
			continue
		}
		fields := strings.Fields(t)
		if fields[0] == "remark" || len(fields) == 1 && slices.Contains([]string{"exit", "end", "quit", "exit-address-family"}, fields[0]) {
			continue
		}
		e := ciscoEntry{indent: len(raw) - len(t), text: strings.Join(fields, " "), mark: markAt(marks, n)}
		if e.indent == 0 && strings.Contains(t, pathSep) {
			e.path = strings.Split(t, pathSep)
			for i := range e.path {
				e.path[i] = strings.Join(strings.Fields(e.path[i]), " ")
			}
		}
		out = append(out, e)
	}
	return out
}

// vtyRange is the lines a 'line vty A [B]' header covers.
func vtyRange(header string) (lo, hi int, ok bool) {
	m := reVTY.FindStringSubmatch(header)
	if m == nil {
		return 0, 0, false
	}
	lo, _ = strconv.Atoi(m[1])
	hi = lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	if hi < lo {
		lo, hi = hi, lo
	}
	return lo, hi, true
}

// ciscoCanon canonicalises running-config text or rendered lines.
func ciscoCanon(lines []string, marks []bool) []stmt {
	entries := ciscoEntries(lines, marks)

	type item struct {
		path []string
		mark bool
		// vty is the index into vtySubs for a merged VTY statement.
		vty int
	}
	type vtySub struct {
		sub  string
		mark bool
		set  map[int]bool
	}
	var items []item
	var subs []vtySub
	subIdx := map[string]int{}

	type frame struct {
		indent int
		text   string
	}
	var stack []frame
	for i, e := range entries {
		if e.path != nil {
			stack = nil
			items = append(items, item{path: e.path, mark: e.mark, vty: -1})
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= e.indent {
			stack = stack[:len(stack)-1]
		}
		// A line that opens a submode is not a statement: the next kept
		// line is deeper.
		if i+1 < len(entries) && entries[i+1].path == nil && entries[i+1].indent > e.indent {
			stack = append(stack, frame{e.indent, e.text})
			continue
		}
		path := make([]string, 0, len(stack)+1)
		for _, f := range stack {
			path = append(path, f.text)
		}
		path = append(path, e.text)
		if len(path) >= 2 {
			if lo, hi, ok := vtyRange(path[0]); ok {
				sub := strings.Join(path[1:], pathSep)
				k, seen := subIdx[sub]
				if !seen {
					k = len(subs)
					subIdx[sub] = k
					subs = append(subs, vtySub{sub: sub, mark: e.mark, set: map[int]bool{}})
					items = append(items, item{vty: k})
				}
				for l := lo; l <= hi; l++ {
					subs[k].set[l] = true
				}
				subs[k].mark = subs[k].mark || e.mark
				continue
			}
		}
		items = append(items, item{path: path, mark: e.mark, vty: -1})
	}

	var out []stmt
	add := func(path []string, mark bool) {
		path = ciscoACLEntry(path)
		if path == nil {
			return
		}
		leaf := strings.Fields(path[len(path)-1])
		stem, secret := ciscoStem(path, leaf, mark)
		x := stmt{text: strings.Join(path, pathSep), secret: secret, path: path}
		x.stem = x.text
		if secret {
			x.stem = strings.Join(append(slices.Clone(path[:len(path)-1]), strings.Join(stem, " ")), pathSep)
		}
		out = append(out, x)
	}
	for _, it := range items {
		if it.vty < 0 {
			add(it.path, it.mark)
			continue
		}
		sub := subs[it.vty]
		var ls []int
		for l := range sub.set {
			ls = append(ls, l)
		}
		slices.Sort(ls)
		for i := 0; i < len(ls); {
			j := i
			for j+1 < len(ls) && ls[j+1] == ls[j]+1 {
				j++
			}
			head := "line vty " + strconv.Itoa(ls[i]) + " " + strconv.Itoa(ls[j])
			add(append([]string{head}, strings.Split(sub.sub, pathSep)...), sub.mark)
			i = j + 1
		}
	}
	return out
}

// ciscoACLEntry puts an ACL entry in its canonical form: no sequence
// number, a standard entry's 'host A' and 'A 0.0.0.0' as 'A'. A path that
// is not an ACL entry is returned unchanged; one that is a remark, nil.
func ciscoACLEntry(path []string) []string {
	var standard bool
	var entry string
	switch {
	case len(path) == 2 && (strings.HasPrefix(path[0], "ip access-list ") || strings.HasPrefix(path[0], "ipv6 access-list ")):
		standard = strings.HasPrefix(path[0], "ip access-list standard ")
		entry = path[1]
	case len(path) == 1 && strings.HasPrefix(path[0], "access-list "):
		f := strings.Fields(path[0])
		if len(f) >= 3 && f[2] == "remark" {
			return nil
		}
		if n, err := strconv.Atoi(f[1]); err == nil && (n < 100 || n >= 1300 && n < 2000) && len(f) >= 3 {
			rest := ciscoStdEntry(f[2:])
			return []string{strings.Join(append(f[:2:2], rest...), " ")}
		}
		return path
	default:
		return path
	}
	f := strings.Fields(entry)
	if len(f) > 1 && reSeqNum.MatchString(f[0]) {
		f = f[1:]
	}
	if len(f) == 0 || f[0] == "remark" {
		return nil
	}
	if standard {
		f = ciscoStdEntry(f)
	}
	return []string{path[0], strings.Join(f, " ")}
}

// ciscoStdEntry is 'permit|deny <address> [wildcard] [log]' with 'host A'
// and 'A 0.0.0.0' as 'A'.
func ciscoStdEntry(f []string) []string {
	if len(f) < 2 || (f[0] != "permit" && f[0] != "deny") {
		return f
	}
	out := []string{f[0]}
	rest := f[1:]
	switch {
	case rest[0] == "host" && len(rest) >= 2:
		out = append(out, rest[1])
		rest = rest[2:]
	case len(rest) >= 2 && rest[1] == "0.0.0.0":
		out = append(out, rest[0])
		rest = rest[2:]
	default:
		out = append(out, rest[0])
		rest = rest[1:]
		if len(rest) > 0 && strings.Count(rest[0], ".") == 3 {
			out = append(out, rest[0])
			rest = rest[1:]
		}
	}
	return append(out, rest...)
}

// isTypeDigit reports a password-type word (0, 5, 6, 7, 8, 9).
func isTypeDigit(s string) bool { return len(s) == 1 && strings.Contains("056789", s) }

// ciscoSecretKeys are the words after which a statement holds a secret:
// the keys and passwords of the shipped syntax, and the broad list of the
// safety net (a statement no rule below knows by name is elided all the
// same).
var ciscoSecretKeys = map[string]bool{
	"key": true, "secret": true, "password": true, "key-string": true, "authentication-key": true,
	"server-key": true, "pre-shared-key": true, "privacy-key": true, "shared-secret": true,
	"passphrase": true, "community": true, "md5": true,
}

// ciscoFreeText are the statements whose words are text, never secrets.
func ciscoFreeText(f []string) bool {
	switch f[0] {
	case "description", "remark", "banner", "alias", "name":
		return true
	case "snmp-server":
		return len(f) >= 2 && slices.Contains([]string{"location", "contact", "chassis-id", "context", "engineID"}, f[1])
	}
	return false
}

// ciscoElide removes the secret that follows the word at f[i]: its
// 'level N', password type and value, as 'key 7 HASH' and 'key VALUE' are
// both 'key'. The value is kept as a mark only when words follow it.
func ciscoElide(f []string, i int) []string {
	out := slices.Clone(f[:i+1])
	j := i + 1
	if j+1 < len(f) && f[j] == "level" {
		out = append(out, f[j], f[j+1])
		j += 2
	}
	if j >= len(f) {
		return out
	}
	if f[j] == secretMark {
		return append(out, f[j:]...)
	}
	if isTypeDigit(f[j]) && j+1 < len(f) {
		j++
	}
	j++ // the value
	if j < len(f) {
		out = append(out, secretMark)
		out = append(out, f[j:]...)
	}
	return out
}

// snmpHostSecret is the index of the community (or v3 user) word of
// 'snmp-server host <addr> [traps|informs] [vrf <v>] [version 1|2c|3
// [auth|noauth|priv]] <community> ...', or -1.
func snmpHostSecret(f []string) int {
	i := 3
	for i < len(f) {
		switch f[i] {
		case "traps", "informs":
			i++
		case "vrf":
			i += 2
		case "version":
			if i+1 < len(f) && f[i+1] == "3" {
				i += 2
				if i < len(f) && slices.Contains([]string{"auth", "noauth", "priv"}, f[i]) {
					i++
				}
			} else {
				i += 2
			}
		default:
			if i < len(f) {
				return i
			}
		}
	}
	return -1
}

// ciscoStem returns a statement's last line without a secret's value, and
// whether it holds one.
func ciscoStem(path, f []string, marked bool) ([]string, bool) {
	if len(f) == 0 {
		return f, false
	}
	if slices.Contains(f, secretMark) {
		// Already elided: a stem read again.
		return f, true
	}
	switch {
	case f[0] == "snmp-server" && len(f) >= 3 && f[1] == "community":
		out := slices.Clone(f)
		out[2] = secretMark
		return out, true
	case f[0] == "snmp-server" && len(f) >= 4 && f[1] == "host":
		// [A] the community follows the version and its options; for v1
		// and for no version, the first word after the host.
		if i := snmpHostSecret(f); i > 0 {
			out := slices.Clone(f)
			out[i] = secretMark
			return out, true
		}
	case f[0] == "snmp-server" && len(f) >= 3 && f[1] == "user":
		// snmp-server user U G v3 auth <alg> <pw> priv <alg> [bits] <pw>
		out := slices.Clone(f)
		found := false
		for i := 0; i < len(out); i++ {
			switch out[i] {
			case "auth":
				if i+2 < len(out) {
					out[i+2], found = secretMark, true
					i += 2
				}
			case "priv":
				// priv <alg> [128|192|256] <pw>: a key length that ends the
				// line belongs to a statement already elided.
				j := i + 2
				if j >= len(out) {
					continue
				}
				if bits := out[j] == "128" || out[j] == "192" || out[j] == "256"; bits {
					if j+1 >= len(out) {
						continue
					}
					j++
				}
				out[j], found = secretMark, true
				i = j
			}
		}
		if found {
			if n := len(out); out[n-1] == secretMark {
				out = out[:n-1]
			}
			return out, true
		}
	case f[0] == "username" && len(f) >= 3:
		for i := 2; i < len(f); i++ {
			if f[i] == "secret" || f[i] == "password" {
				// 'algorithm-type scrypt' names how the value is hashed, not
				// what it is.
				base := slices.Clone(f[:i+1])
				for k := 0; k+1 < len(base); k++ {
					if base[k] == "algorithm-type" {
						base = slices.Delete(base, k, k+2)
						break
					}
				}
				return append(base[:len(base):len(base)], ciscoElide(f, i)[i+1:]...), true
			}
		}
	}
	if !ciscoFreeText(f) {
		out, found := f, false
		for pos := 0; pos < len(out); pos++ {
			if ciscoSecretKeys[out[pos]] {
				out, found = ciscoElide(out, pos), true
			}
		}
		if found {
			return out, true
		}
	}
	// A hash anywhere in a statement no rule knows: the word is elided, the
	// rest of the statement stays.
	var out []string
	for i, w := range f {
		if reHashWord.MatchString(w) {
			if out == nil {
				out = slices.Clone(f)
			}
			out[i] = secretMark
		}
	}
	if out != nil {
		return out, true
	}
	if marked {
		out := slices.Clone(f)
		out[len(out)-1] = secretMark
		return out, true
	}
	return f, false
}

// ciscoACLName is the name of the ACL a statement of 'ip access-list ...'
// or 'access-list N ...' belongs to.
func ciscoACLName(p0 string) (string, bool) {
	f := strings.Fields(p0)
	switch {
	case len(f) >= 3 && (f[0] == "ip" || f[0] == "ipv6") && f[1] == "access-list":
		return f[len(f)-1], true
	case len(f) >= 2 && f[0] == "access-list":
		return f[1], true
	}
	return "", false
}

// ciscoCtx is what classifying the device's statements needs.
type ciscoCtx struct {
	claim map[string]string // stem -> section, the rendered statements'
	acls  map[string]string // ACL name -> section, the rendered ones'
	// device side: the ACLs the VTY lines and SNMP refer to.
	vtyRefs, snmpRefs map[string]bool
}

// defaultACLNames are the names tacctl's ACLs have by default.
var defaultACLNames = map[string]string{"VTY-ACL": SectionMgmtACL, "TACCTL-SNMP": SectionSNMP}

func (c *ciscoCtx) section(x stmt) string {
	if s, ok := c.claim[x.stem]; ok {
		return s
	}
	p := x.path
	if len(p) == 0 {
		return ""
	}
	t := p[0]
	has := func(prefixes ...string) bool {
		for _, q := range prefixes {
			if t == strings.TrimSpace(q) || strings.HasPrefix(t, q) {
				return true
			}
		}
		return false
	}
	switch {
	case t == "aaa session-id common":
		// [A] IOS adds it by itself.
		return ""
	case has("aaa ", "tacacs server ", "radius server ", "tacacs-server ", "radius-server "):
		return SectionAAA
	case has("username "):
		return SectionBreakGlass
	case has("privilege "):
		return SectionRoles
	case has("snmp-server "):
		return SectionSNMP
	case has("netconf-yang ", "netconf "):
		return SectionNetconf
	case strings.HasPrefix(t, "line vty ") && len(p) >= 2:
		if strings.HasPrefix(p[len(p)-1], "access-class ") {
			return SectionMgmtACL
		}
		return ""
	}
	if name, ok := ciscoACLName(t); ok {
		if s, ok := c.acls[name]; ok {
			return s
		}
		switch {
		case c.vtyRefs[name]:
			return SectionMgmtACL
		case c.snmpRefs[name]:
			return SectionSNMP
		}
		return defaultACLNames[name]
	}
	return ""
}

// privilegeParents drops the 'privilege exec level N <word>' lines IOS adds
// for the words leading to a command ('privilege exec level 7 clear' for
// 'privilege exec level 7 clear counters') that the rendering does not
// carry itself. [A] from IOS knowledge, not a lab.
func privilegeParents(in []stmt, claim map[string]string) []stmt {
	isPriv := func(x stmt) []string {
		if len(x.path) != 1 || !strings.HasPrefix(x.path[0], "privilege ") {
			return nil
		}
		return strings.Fields(x.path[0])
	}
	var all [][]string
	for _, x := range in {
		if f := isPriv(x); f != nil {
			all = append(all, f)
		}
	}
	var out []stmt
	for _, x := range in {
		if f := isPriv(x); f != nil {
			if _, claimed := claim[x.stem]; !claimed && isParent(f, all) {
				continue
			}
		}
		out = append(out, x)
	}
	return out
}

// isParent reports whether f is a proper word-prefix of another statement
// of the same mode and level, with at least a mode, level and a word.
func isParent(f []string, all [][]string) bool {
	// privilege <mode> [all] level <n> <word> ...
	lvl := slices.Index(f, "level")
	if lvl < 0 || len(f) <= lvl+2 {
		return false
	}
	for _, g := range all {
		if len(g) > len(f) && slices.Equal(g[:len(f)], f) {
			return true
		}
	}
	return false
}

// refusedAtStart reports an IOS error line ('% Invalid input ...') among
// the first lines of the text, before the configuration (or any banner)
// begins. A '% ' line later is configuration text (a banner's) and fails
// nothing.
func refusedAtStart(lines []string) bool {
	seen := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		switch {
		case strings.HasPrefix(t, "% "):
			return true
		case strings.HasPrefix(t, "version "), strings.HasPrefix(t, "hostname "),
			strings.HasPrefix(t, "Building configuration"), strings.HasPrefix(t, "Current configuration"),
			strings.HasPrefix(t, "!"), strings.HasPrefix(t, "banner "):
			return false
		}
		if seen++; seen > 6 {
			return false
		}
	}
	return false
}

// ciscoExtract is Extract for IOS and IOS-XE.
func ciscoExtract(raw string, expected []devices.Section, visible *bool) (Extracted, error) {
	text := cleanText(raw)
	lines := strings.Split(text, "\n")
	if refusedAtStart(lines) {
		return Extracted{}, fmt.Errorf("%w: the device refused the command", ErrParse)
	}
	configured := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "version ") || strings.HasPrefix(t, "hostname ") ||
			strings.HasPrefix(t, "Building configuration") || strings.HasPrefix(t, "Current configuration") {
			configured = true
			break
		}
	}
	if !configured {
		return Extracted{}, fmt.Errorf("%w: no 'version' or 'hostname' line in the text", ErrParse)
	}

	c := &ciscoCtx{claim: map[string]string{}, acls: map[string]string{},
		vtyRefs: map[string]bool{}, snmpRefs: map[string]bool{}}
	for _, sec := range expected {
		for _, x := range ciscoCanon(sec.Lines, sec.Secret) {
			c.claim[x.stem] = sec.Name
			if name, ok := ciscoACLName(x.path[0]); ok {
				c.acls[name] = sec.Name
			}
		}
	}
	got := privilegeParents(ciscoCanon(lines, nil), c.claim)
	for _, x := range got {
		leaf := strings.Fields(x.path[len(x.path)-1])
		switch {
		case strings.HasPrefix(x.path[0], "line vty ") && len(leaf) >= 2 && leaf[0] == "access-class":
			c.vtyRefs[leaf[1]] = true
		case len(leaf) >= 3 && leaf[0] == "snmp-server" && leaf[1] == "community":
			// snmp-server community <string> [view <v>] [RO|RW] [ipv6 <acl>] [<acl>]
			for i := 3; i < len(leaf); i++ {
				switch leaf[i] {
				case "view", "ipv6":
					i++
				case "RO", "RW", "ro", "rw":
				default:
					c.snmpRefs[leaf[i]] = true
				}
			}
		case len(leaf) >= 2 && leaf[0] == "snmp-server" && (leaf[1] == "group" || leaf[1] == "user"):
			if i := slices.Index(leaf, "access"); i >= 0 && i+1 < len(leaf) {
				c.snmpRefs[leaf[i+1]] = true
			}
		}
	}

	by := map[string][]stmt{}
	for _, x := range got {
		if s := c.section(x); s != "" {
			by[s] = append(by[s], x)
		}
	}
	out := make(map[string]devices.Section, len(SectionNames))
	for _, n := range SectionNames {
		out[n] = toSection(n, uniq(by[n]))
	}
	vis := true
	if visible != nil {
		vis = *visible
	}
	return Extracted{Vendor: FamilyIOS, Sections: out, SecretsVisible: vis}, nil
}
