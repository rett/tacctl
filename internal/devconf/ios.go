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
// community in 'snmp-server host'. 'ip tacacs|radius source-interface' (the
// operator's choice, rendered as a comment) is claimed only when the
// rendering has it.
//
// The 'aaa' section also holds what the device's lines say about logging in
// (D107): the login leaf of every 'line vty' range and of 'line con 0'
// ('line vty 0 4 > login local', 'line con 0 > login authentication
// default'), which the walkthrough renders under the same headers (with
// 'aaa new-model' on, a line with no login statement is on the default
// list, which IOS does not print: withImplicitLogin adds it, and
// alignLogin compares by the lines a range covers), and one marker for the 'enable' secret, by presence only (enableHeld,
// enableNone): Managed renders no 'enable' secret, so the marker is never
// expected, and Compare turns it into a note.

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

// ciscoCanon canonicalises running-config text or rendered lines; lb labels
// a community's name (nil: the bare mark).
func ciscoCanon(lines []string, marks []bool, lb *labels) []stmt {
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
		stem, secret := ciscoStem(path, leaf, mark, lb)
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
// whether it holds one; lb labels a community's name.
func ciscoStem(path, f []string, marked bool, lb *labels) ([]string, bool) {
	if len(f) == 0 {
		return f, false
	}
	if f[0] == "snmp-server" && len(f) >= 3 && f[1] == "community" {
		out := slices.Clone(f)
		out[2] = lb.of(f[2])
		return out, true
	}
	if f[0] == "snmp-server" && len(f) >= 4 && f[1] == "host" {
		// [A] the community follows the version and its options; for v1
		// and for no version, the first word after the host.
		if i := snmpHostSecret(f); i > 0 {
			out := slices.Clone(f)
			out[i] = lb.of(f[i])
			return out, true
		}
	}
	if slices.Contains(f, secretMark) {
		// Already elided: a stem read again.
		return f, true
	}
	if len(path) == 1 && path[0] == enableNone {
		// The marker of an 'enable' secret the device does not have.
		return f, false
	}
	switch {
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

// isLoginLeaf reports a statement that says how a line's login is done:
// 'login', 'login local', 'login authentication <list>' or 'no login'
// under 'line vty <range>' or 'line con 0' (D107). The path is the
// statement's, header first.
func isLoginLeaf(path []string) bool {
	if len(path) != 2 {
		return false
	}
	h := strings.Fields(path[0])
	if len(h) < 3 || h[0] != "line" || !slices.Contains([]string{"vty", "con", "console"}, h[1]) {
		return false
	}
	f := strings.Fields(path[1])
	return len(f) >= 1 && (f[0] == "login" || len(f) >= 2 && f[0] == "no" && f[1] == "login")
}

// loginDefault is the leaf of a line that logs in by the default method
// list: the walkthrough pastes it, and with 'aaa new-model' on a line that
// has no login statement is in that state without printing it ([L] the lab
// 7200: its VTY lines hold only the access class and no 'login' line).
const loginDefault = "login authentication default"

// lineHeader reads the header of a line a login method belongs to: the
// kind ('vty', 'con') and the line numbers it covers.
func lineHeader(h string) (kind string, lines []int, ok bool) {
	if lo, hi, ok := vtyRange(h); ok {
		for l := lo; l <= hi; l++ {
			lines = append(lines, l)
		}
		return "vty", lines, true
	}
	f := strings.Fields(h)
	if len(f) == 3 && f[0] == "line" && (f[1] == "con" || f[1] == "console") {
		if n, err := strconv.Atoi(f[2]); err == nil {
			return "con", []int{n}, true
		}
	}
	return "", nil, false
}

// withImplicitLogin adds, for every console and VTY line of a device that
// has 'aaa new-model' and no login statement of its own, the statement
// 'line vty 0 15 > login authentication default' (consecutive lines in one,
// as the VTY ranges of any statement are): the default method list is in
// force there, IOS omits it from the text, and the compared form says it.
// The statement goes to the sections file like any other, so a comparison
// from a stored record reads the line the same way. A device with no
// 'aaa new-model' gets nothing added: a line without a login statement has
// no method there, and the marker of the 'enable' secret, which every
// extraction of this version leaves, tells a record that has no leaf for a
// line for that reason from one made before the leaves were read.
func withImplicitLogin(got []stmt) []stmt {
	newModel := false
	mentioned := map[string]map[int]bool{"vty": {}, "con": {}}
	explicit := map[string]map[int]bool{"vty": {}, "con": {}}
	for _, x := range got {
		if len(x.path) == 1 && x.path[0] == "aaa new-model" {
			newModel = true
		}
		if len(x.path) == 0 {
			continue
		}
		kind, lines, ok := lineHeader(x.path[0])
		if !ok {
			continue
		}
		for _, l := range lines {
			mentioned[kind][l] = true
			if isLoginLeaf(x.path) {
				explicit[kind][l] = true
			}
		}
	}
	if !newModel {
		return got
	}
	add := func(head string) {
		path := []string{head, loginDefault}
		s := strings.Join(path, pathSep)
		got = append(got, stmt{text: s, stem: s, path: path})
	}
	var vty []int
	for l := range mentioned["vty"] {
		if !explicit["vty"][l] {
			vty = append(vty, l)
		}
	}
	slices.Sort(vty)
	for i := 0; i < len(vty); {
		j := i
		for j+1 < len(vty) && vty[j+1] == vty[j]+1 {
			j++
		}
		add("line vty " + strconv.Itoa(vty[i]) + " " + strconv.Itoa(vty[j]))
		i = j + 1
	}
	var con []int
	for l := range mentioned["con"] {
		if !explicit["con"][l] {
			con = append(con, l)
		}
	}
	slices.Sort(con)
	for _, l := range con {
		add("line con " + strconv.Itoa(l))
	}
	return got
}

// alignLogin makes the device's login statements comparable with the
// rendered ones by the lines they cover: a rendered 'line vty 0 15 > L' is
// there when the device's statements with the leaf L cover every line of
// it ('line vty 0 4' and 'line vty 5 15', the one implicit and the other
// explicit), whatever ranges the device printed. The device's statements
// that are such a part of the rendered one are used up: they are not extra,
// the rendered line is '=' when the lines are covered and '-' while one is
// not (the other leaves of those lines are extra as they are).
func alignLogin(exp, dev []stmt) []stmt {
	used := make([]bool, len(dev))
	var add []stmt
	for _, e := range exp {
		if !isLoginLeaf(e.path) {
			continue
		}
		ek, el, ok := lineHeader(e.path[0])
		if !ok {
			continue
		}
		want := map[int]bool{}
		for _, l := range el {
			want[l] = true
		}
		have := map[int]bool{}
		var part []int
		for i, d := range dev {
			if used[i] || !isLoginLeaf(d.path) || d.path[1] != e.path[1] {
				continue
			}
			dk, dl, ok := lineHeader(d.path[0])
			if !ok || dk != ek || !slices.ContainsFunc(dl, func(l int) bool { return want[l] }) ||
				slices.ContainsFunc(dl, func(l int) bool { return !want[l] }) {
				continue
			}
			part = append(part, i)
			for _, l := range dl {
				have[l] = true
			}
		}
		for _, i := range part {
			used[i] = true
		}
		if len(have) == len(want) && len(part) > 0 {
			add = append(add, stmt{text: e.stem, stem: e.stem, path: e.path})
		}
	}
	var out []stmt
	for i, d := range dev {
		if !used[i] {
			out = append(out, d)
		}
	}
	return append(out, add...)
}

// The 'enable' secret is kept by presence in the aaa section of the
// extraction, as one statement the rendering never has: enableHeld when the
// device sets a secret or password for level 15, enableNone when it does
// not. A section read from a pull of tacctl 0.2.4 has neither, so what the
// device holds is not known from it. Compare takes the statement out of
// the comparison and turns the second into a note.
const (
	enableHeld = "enable secret " + secretMark
	enableNone = "no enable secret"
)

// setsEnableSecret reports a top-level statement that sets the secret or
// password of 'enable' for level 15 ('enable secret 9 <hash>', 'enable
// password <pw>', 'enable algorithm-type scrypt secret <pw>'); a secret
// for another level does not reach 15, and 'enable use-tacacs' and the
// like set none.
func setsEnableSecret(path []string) bool {
	if len(path) != 1 {
		return false
	}
	f := strings.Fields(path[0])
	if len(f) < 2 || f[0] != "enable" || slices.Contains([]string{"use-tacacs", "last-resort", "view"}, f[1]) {
		return false
	}
	for i := 1; i < len(f); i++ {
		if f[i] != "secret" && f[i] != "password" {
			continue
		}
		return i+2 >= len(f) || f[i+1] != "level" || f[i+2] == "15"
	}
	return false
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
	// sourceInterface are the source-interface commands the rendering sets
	// ('ip tacacs source-interface'): only then is the device's own value of
	// the same command a statement of the aaa section. The interface is the
	// operator's choice and the scope may set none (D119): a device's value
	// is then nobody's business.
	sourceInterface map[string]bool
}

// The two source-interface commands (D119).
const (
	ciscoSourceInterfaceTacacs = "ip tacacs source-interface"
	ciscoSourceInterfaceRadius = "ip radius source-interface"
)

// sessionIDCommon is the statement IOS prints by itself and tacctl renders
// (D116): a statement of the aaa section, tolerated where the rendering has
// none (Compare).
const sessionIDCommon = "aaa session-id common"

// enableLocalOnly is the enable list that only names the local secret, which
// is what a device with no list does (Compare).
const enableLocalOnly = "aaa authentication enable default enable"

// isEnableList reports an 'aaa authentication enable default ...' statement.
func isEnableList(x stmt) bool {
	return len(x.path) == 1 && strings.HasPrefix(x.path[0], "aaa authentication enable default ")
}

// isSourceInterface reports a statement that sets the source interface of the
// TACACS+ or RADIUS client.
func isSourceInterface(x stmt) bool {
	return len(x.path) == 1 && (strings.HasPrefix(x.path[0], ciscoSourceInterfaceTacacs+" ") ||
		strings.HasPrefix(x.path[0], ciscoSourceInterfaceRadius+" "))
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
	case strings.HasPrefix(t, ciscoSourceInterfaceTacacs+" "), strings.HasPrefix(t, ciscoSourceInterfaceRadius+" "):
		if c.sourceInterface[strings.Join(strings.Fields(t)[:3], " ")] {
			return SectionAAA
		}
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
	case isLoginLeaf(p):
		// The vty and console login method belongs to aaa (D107), the
		// access-class binding of the same header to mgmt-acl.
		return SectionAAA
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
//
// A parent is the image's own line only while a statement the rendering
// carries is beneath it: when every statement beneath it is an extra (the
// operator lost the command a device was pasted with, so the plan removes
// it), the parent is an extra too, and the plan removes it with them; else
// a device would keep 'privilege exec level 7 clear' and read as different
// after the paste. That holds whenever a rendering was given, with or
// without a rendered 'privilege' line (a site that lowers nothing has none:
// every privilege line on the device, parents included, is an extra the
// plan removes). Only a text extracted with no rendering at all has no
// claim to judge by, and every parent is dropped there, as before.
func privilegeParents(in []stmt, claim map[string]string) []stmt {
	isPriv := func(x stmt) []string {
		if len(x.path) != 1 || !strings.HasPrefix(x.path[0], "privilege ") {
			return nil
		}
		return strings.Fields(x.path[0])
	}
	rendered := len(claim) > 0
	// The commands the rendering lowers, for the residue a 15.x image keeps.
	cmds := map[string]bool{}
	for stem := range claim {
		if strings.HasPrefix(stem, "privilege ") {
			addRenderedCommand(cmds, stem)
		}
	}
	var all [][]string
	for _, x := range in {
		f := isPriv(x)
		if f == nil {
			continue
		}
		if _, claimed := claim[x.stem]; claimed || !rendered {
			all = append(all, f)
		}
	}
	var out []stmt
	for _, x := range in {
		if f := isPriv(x); f != nil {
			if _, claimed := claim[x.stem]; !claimed && (isParent(f, all) || isImageResidue(f, cmds)) {
				continue
			}
		}
		out = append(out, x)
	}
	return out
}

// iosDefaultPrivilege is the level a command has on IOS when no 'privilege'
// line sets it, for the commands tacctl lowers or has lowered (the shipped
// operator and readonly privilege lists of this release and of 0.2.3, which
// internal/policy/previous_defaults.go keeps) and for the words that lead to
// them (the parents the image adds at the command's level and, after a 'no',
// leaves behind at their own).
//
// An IOS 15.x or IOS-XE image does not remove a privilege line when it is
// negated: 'no privilege exec level 7 clear counters' leaves 'privilege exec
// level 15 clear counters', 'no privilege exec all level 7 ping' leaves
// 'privilege exec level 1 ping', and the parents stay at their own levels
// ('level 15 clear ip', 'level 15 monitor', 'level 1 clear', 'level 1
// show'). That line is the image's own and harmless: nobody can remove it,
// so it is never an irregularity (isImageResidue). The table is deliberately
// small and explicit: a command that is not in it is nobody's residue, and
// its line at any level is an extra.
//
// [S: lab IOSv 15.6(2)T and CSR1000v 16.7.1] the entries of the first
// group; [A: IOS knowledge, no capture of the residue] those of the second.
var iosDefaultPrivilege = map[string]string{
	"ping": "1", "traceroute": "1", "show": "1", "clear": "1",
	"clear counters": "15", "clear line": "15", "clear ip": "15", "clear ip arp": "15", "clear arp-cache": "15",
	"monitor": "15", "monitor capture": "15",
	// [A]
	"clear mac address-table dynamic": "15", "undebug": "15", "undebug all": "15", "show running-config": "15",
}

// IOSDefaultPrivilege is the level IOS gives the command (its words, one
// space apart) when no 'privilege' line sets it; ok is false for a command
// outside the table above.
func IOSDefaultPrivilege(words string) (level string, ok bool) {
	level, ok = iosDefaultPrivilege[words]
	return level, ok
}

// execPrivilegeWords splits the fields of 'privilege exec [all] level N
// <words>' into the level, the words and whether it has 'all'. ok is false
// for another mode or a shape without a command.
func execPrivilegeWords(f []string) (level string, words []string, all, ok bool) {
	if len(f) < 5 || f[0] != "privilege" || f[1] != "exec" {
		return "", nil, false, false
	}
	i := 2
	if f[i] == "all" {
		all = true
		i++
	}
	if f[i] != "level" || i+2 >= len(f) {
		return "", nil, false, false
	}
	return f[i+1], f[i+2:], all, true
}

// addRenderedCommand adds to cmds the command a rendered 'privilege exec'
// statement lowers (with or without 'all').
func addRenderedCommand(cmds map[string]bool, stmt string) {
	if _, words, _, ok := execPrivilegeWords(strings.Fields(stmt)); ok {
		cmds[strings.Join(words, " ")] = true
	}
}

// isImageResidue reports whether f, the fields of a device's 'privilege'
// statement, is the line a 15.x image keeps for a command whose privilege
// line was removed: mode exec, no 'all' (an 'all' covers more than the
// default does), the command in iosDefaultPrivilege at exactly its default
// level, and no line of the rendering for that command (cmds, from
// addRenderedCommand): a rendered line for it is the line that should be
// there, and the device's other one is replaced by the paste.
func isImageResidue(f []string, cmds map[string]bool) bool {
	level, words, all, ok := execPrivilegeWords(f)
	if !ok || all {
		return false
	}
	w := strings.Join(words, " ")
	def, known := iosDefaultPrivilege[w]
	return known && def == level && !cmds[w]
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

// iosImplicitQueueLength is the one SNMP line a 12.4 image prints by itself
// beside the first community ([L] the lab 7200, 2026-10-10).
const iosImplicitQueueLength = "snmp-server queue-length 100"

// withoutImplicitIOS drops from the device's statements the lines IOS adds
// to what an operator typed, which the rendering never carries, when the
// rendering has the statement that causes them. It never makes two
// statements equal: the line is left out of the extra ones, and the
// expected statement stays missing if the device lacks it.
//
//   - 'privilege exec level N <words>' where the rendering has a longer
//     'privilege exec [all] level N <words> <more>': an image that does not
//     know the last words stores the ones it knows (no 'capture' in 12.4:
//     'privilege exec all level 7 monitor capture' is stored as
//     'privilege exec level 7 monitor'). The level and the mode are the
//     same, and the device's line has no 'all' (an 'all' there covers more
//     than the rendering says, and stays an extra line).
//   - 'snmp-server queue-length 100' when the rendering has a community:
//     the image prints it beside the first community.
//   - 'privilege exec level L <words>' where <words> is a command of
//     iosDefaultPrivilege at its default level L and the rendering has no
//     line for it: what a 15.x image keeps when a privilege line is removed
//     (isImageResidue). No note: there is nothing to do about it.
//
// The rendered line stays '-' even then (plan D106 would read it as
// equal): the text cannot tell an image that stores the shorter line from a
// device on which the line was removed and its parent left behind, and
// 'equal' would hide the second. The notes say which line the device holds
// instead, for each rendered line it holds only a shorter form of that no
// other rendered line explains (the parent that 'clear counters' leaves
// behind is not the stored form of an unrelated rendered 'clear' line).
func withoutImplicitIOS(exp, dev []stmt) (kept []stmt, notes []string) {
	onDev := map[string]bool{}
	for _, x := range dev {
		onDev[x.stem] = true
	}
	var longer []renderedPrivilege
	community := false
	cmds := map[string]bool{}
	for _, x := range exp {
		if len(x.path) != 1 {
			continue
		}
		f := strings.Fields(x.path[0])
		switch {
		case strings.HasPrefix(x.path[0], "privilege "):
			addRenderedCommand(cmds, x.path[0])
			if i := slices.Index(f, "all"); i >= 0 && i+1 < len(f) && f[i+1] == "level" {
				f = slices.Delete(f, i, i+1)
			}
			longer = append(longer, renderedPrivilege{f, x.stem})
		case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community":
			community = true
		}
	}
	expStem := map[string]bool{}
	for _, x := range exp {
		expStem[x.stem] = true
	}
	// stored are the device's shorter forms, which are left out of kept.
	var stored []stmt
	for _, x := range dev {
		if len(x.path) == 1 && !expStem[x.stem] {
			f := strings.Fields(x.path[0])
			if x.path[0] == iosImplicitQueueLength && community {
				continue
			}
			// what a 15.x image keeps of a privilege line that was removed:
			// nobody can remove it, so it is never reported
			if isImageResidue(f, cmds) {
				continue
			}
			if strings.HasPrefix(x.path[0], "privilege ") && slices.Contains(f, "level") &&
				!slices.Contains(f, "all") && privilegeHasLonger(f, longer) {
				stored = append(stored, x)
				continue
			}
		}
		kept = append(kept, x)
	}
	for _, r := range longer {
		if onDev[r.stem] {
			continue
		}
		// The longest stored form that no other rendered line explains.
		var best *stmt
		var bestWords []string
		for i, x := range stored {
			f := strings.Fields(x.path[0])
			if !r.extends(f) || len(f) <= len(bestWords) {
				continue
			}
			explained := false
			for _, o := range longer {
				if o.stem != r.stem && o.extends(f) {
					explained = true
					break
				}
			}
			if !explained {
				best, bestWords = &stored[i], f
			}
		}
		if best == nil {
			continue
		}
		note := r.stem + ": not on the device, which holds '" + best.stem + "' instead, as an image that does not know '" +
			strings.Join(r.words[len(bestWords):], " ") + "' stores it; a device that lost the line looks the same, so it stays missing"
		if !slices.Contains(notes, note) {
			notes = append(notes, note)
		}
	}
	return kept, notes
}

// renderedPrivilege is a rendered 'privilege' statement: its words without
// the 'all' after the mode, and its compared form.
type renderedPrivilege struct {
	words []string
	stem  string
}

// extends reports whether r has more words than f and begins with them.
func (r renderedPrivilege) extends(f []string) bool {
	return len(r.words) > len(f) && slices.Equal(r.words[:len(f)], f)
}

// privilegeHasLonger reports whether f, a privilege statement with a mode,
// a level and at least one word, is a proper word-prefix of one of longer.
func privilegeHasLonger(f []string, longer []renderedPrivilege) bool {
	lvl := slices.Index(f, "level")
	if lvl < 0 || len(f) <= lvl+2 {
		return false
	}
	for _, g := range longer {
		if g.extends(f) {
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
		vtyRefs: map[string]bool{}, snmpRefs: map[string]bool{}, sourceInterface: map[string]bool{}}
	var rendered []string
	for _, sec := range expected {
		rendered = append(rendered, sec.Lines...)
	}
	lb := newLabels(FamilyIOS, rendered)
	for _, sec := range expected {
		for _, x := range ciscoCanon(sec.Lines, sec.Secret, lb) {
			c.claim[x.stem] = sec.Name
			if isSourceInterface(x) {
				c.sourceInterface[strings.Join(strings.Fields(x.path[0])[:3], " ")] = true
			}
			if name, ok := ciscoACLName(x.path[0]); ok {
				c.acls[name] = sec.Name
			}
		}
	}
	lb.fresh = true
	got := withImplicitLogin(privilegeParents(ciscoCanon(lines, nil, lb), c.claim))
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
	enable := false
	for _, x := range got {
		if setsEnableSecret(x.path) {
			enable = true
		}
		if s := c.section(x); s != "" {
			by[s] = append(by[s], x)
		}
	}
	// By presence only, whatever the secret is (D107): the statement never
	// holds a value, and Managed never renders it.
	marker := stmt{text: enableNone, stem: enableNone, path: []string{enableNone}}
	if enable {
		marker = stmt{text: enableHeld, stem: enableHeld, secret: true, path: []string{enableHeld}}
	}
	by[SectionAAA] = append(by[SectionAAA], marker)
	out := make(map[string]devices.Section, len(SectionNames))
	for _, n := range SectionNames {
		if optionalSection(n) {
			continue
		}
		out[n] = toSection(n, uniq(by[n]))
	}
	vis := true
	if visible != nil {
		vis = *visible
	}
	return Extracted{Vendor: FamilyIOS, Sections: out, SecretsVisible: vis}, nil
}
