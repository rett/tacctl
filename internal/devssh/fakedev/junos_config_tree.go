package fakedev

// The candidate tree of the fake Junos device's configure model
// (junos_config.go): a configuration as ordered 'set' statements, the
// editor that applies set, delete and insert to it, the brace form that
// 'show' and 'show | compare' print, and the diff between two of them.
//
// The list and leaf tables are a copy of the idea of the planner's in-memory
// editor (internal/devconf/plan/simulate.go, which this package must not
// import): the single-valued leaves and the list keywords of the hierarchies
// tacctl manages. A path that no table names is rendered by the generic
// rules below, which is right for a leaf and a plain block and wrong only for
// a list keyword nobody listed.

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
)

// jcfg is a configuration as 'set' statements in order; a statement is its
// path (the words after 'set', unquoted).
type jcfg struct {
	stmts [][]string
}

func (c *jcfg) clone() *jcfg {
	out := &jcfg{stmts: make([][]string, len(c.stmts))}
	for i, s := range c.stmts {
		out.stmts[i] = slices.Clone(s)
	}
	return out
}

// jsplit splits a command line into words as the device reads them: a word
// in double quotes is one word (the quotes dropped, an escape kept), and a
// bracket is a word of its own.
func jsplit(s string) []string {
	var out []string
	var b strings.Builder
	in, has, esc := false, false, false
	flush := func() {
		if has || b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
			has = false
		}
	}
	for _, r := range s {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case in && r == '\\':
			b.WriteRune(r)
			esc = true
		case in:
			if r == '"' {
				in = false
			} else {
				b.WriteRune(r)
			}
		case r == '"':
			in, has = true, true
		case r == ' ' || r == '\t':
			flush()
		case r == '[' || r == ']':
			flush()
			out = append(out, string(r))
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

// jquote writes a word the way the device prints it: bare unless it holds a
// blank, a quote or a character that is structure (a $9$ secret is quoted).
func jquote(t string) string {
	if t == "" || strings.ContainsAny(t, " \t\"'\\;[]{}#$") {
		var b strings.Builder
		b.WriteByte('"')
		for i := 0; i < len(t); i++ {
			switch c := t[i]; {
			case c == '\\' && i+1 < len(t):
				b.WriteByte(c)
				i++
				b.WriteByte(t[i])
			case c == '\\':
				b.WriteString(`\\`)
			case c == '"':
				b.WriteString(`\"`)
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte('"')
		return b.String()
	}
	return t
}

func jjoin(path []string) string {
	parts := make([]string, len(path))
	for i, t := range path {
		parts[i] = jquote(t)
	}
	return strings.Join(parts, " ")
}

// parseSetText reads 'display set' text: the 'set' lines (a bracket list
// expanded to one statement per element); the capture header's comments and
// every other line are dropped.
func parseSetText(text string) *jcfg {
	c := &jcfg{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "set ")
		if !ok {
			continue
		}
		for _, p := range expandBrackets(jsplit(rest)) {
			c.add(p)
		}
	}
	return c
}

// setText is the configuration as 'display set' lines.
func (c *jcfg) setText() string {
	var b strings.Builder
	for _, s := range c.stmts {
		b.WriteString("set " + jjoin(s) + "\n")
	}
	return b.String()
}

func (c *jcfg) equal(o *jcfg) bool {
	if len(c.stmts) != len(o.stmts) {
		return false
	}
	for i := range c.stmts {
		if !slices.Equal(c.stmts[i], o.stmts[i]) {
			return false
		}
	}
	return true
}

// expandBrackets resolves '[ a b ]' lists and splits the one-line forms the
// device prints as one statement per leaf.
func expandBrackets(t []string) [][]string {
	i := slices.Index(t, "[")
	if i < 0 {
		return splitLeaves(t)
	}
	j := slices.Index(t[i:], "]")
	if j < 0 {
		return [][]string{t}
	}
	j += i
	var out [][]string
	for _, item := range t[i+1 : j] {
		next := slices.Concat(t[:i:i], []string{item}, t[j+1:])
		out = append(out, expandBrackets(next)...)
	}
	return out
}

// splitLeaves splits the options of an NTP server and the type and value of
// an NTP key into one statement each, as 'display set' prints them.
func splitLeaves(t []string) [][]string {
	if len(t) < 5 || t[0] != "system" || t[1] != "ntp" {
		return [][]string{t}
	}
	var out [][]string
	switch t[2] {
	case "server":
		if len(t) == 4 {
			return [][]string{t}
		}
		base := t[:4:4]
		for i := 4; i < len(t); {
			n := 1
			if t[i] != "prefer" && i+1 < len(t) {
				n = 2
			}
			out = append(out, slices.Concat(base, t[i:i+n]))
			i += n
		}
	case "authentication-key":
		if len(t) <= 6 {
			return [][]string{t}
		}
		base := t[:4:4]
		for i := 4; i < len(t); i += 2 {
			if i+1 >= len(t) {
				out = append(out, slices.Concat(base, t[i:]))
				break
			}
			out = append(out, slices.Concat(base, t[i:i+2]))
		}
	default:
		return [][]string{t}
	}
	return out
}

// --- the tables ---------------------------------------------------------------------------

// jSingleKeys are the single-valued leaves (the path prefixes whose last
// word is the value): a set of one replaces the value in place. '*' matches
// any word.
var jSingleKeys = []string{
	"snmp location", "snmp contact", "snmp description", "snmp name", "snmp trap-options source-address",
	"system tacplus-server * secret", "system tacplus-server * port", "system tacplus-server * timeout",
	"system tacplus-server * retry", "system tacplus-server * source-address",
	"system radius-server * secret", "system radius-server * port", "system radius-server * timeout",
	"system login user * class", "system login user * uid", "system login user * full-name",
	"system login user * authentication encrypted-password",
	"system login class * idle-timeout",
	"snmp community * authorization", "snmp community * client-list-name",
	"snmp trap-group * version",
	"system host-name", "system accounting destination tacplus server * secret",
	"system login message", "system domain-name", "system time-zone", "system login idle-timeout",
	"system ntp boot-server", "system ntp source-address",
	"system ntp server * version", "system ntp server * key", "system ntp server * routing-instance",
	"system ntp authentication-key * type", "system ntp authentication-key * value",
}

// jListKeys are the keywords whose next word names an entry ('tacplus-server
// 192.0.2.1 { ... }'): the path of the keyword.
var jListKeys = []string{
	"system tacplus-server", "system radius-server", "system login user", "system login class",
	"system ntp server", "system ntp authentication-key", "system name-server", "system syslog user",
	"system syslog file", "system static-host-mapping",
	"snmp community", "snmp trap-group", "snmp client-list", "snmp view",
	"firewall family", "firewall family inet filter", "firewall family inet filter * term",
	"firewall family inet6 filter", "firewall family inet6 filter * term", "firewall policer",
	"policy-options prefix-list", "policy-options policy-statement", "policy-options policy-statement * term",
	"interfaces", "interfaces * unit", "groups", "vlans", "routing-instances", "event-options policy",
}

// jBlockLists are leaf lists that the device prints as a block of one value
// per line rather than as a bracket list.
var jBlockLists = map[string]bool{
	"source-address": true, "destination-address": true, "address": true,
	"source-prefix-list": true, "destination-prefix-list": true, "clients": true,
}

// jSecretLeaves are the leaves the device encrypts when they are set (the
// value is stored as a $9$ string) and marks in the brace form.
var jSecretLeaves = []string{
	"system tacplus-server * secret", "system radius-server * secret",
	"system accounting destination tacplus server * secret",
	"system ntp authentication-key * value",
}

// jFlags are the trailing words of a list entry that are flags of the entry
// ('192.0.2.0/24 restrict'): a node of their own, printed on the entry's line.
var jFlags = map[string]bool{"restrict": true, "except": true}

func jmatch(pat string, path []string) bool {
	kp := strings.Fields(pat)
	if len(kp) != len(path) {
		return false
	}
	for i, t := range kp {
		if t != "*" && t != path[i] {
			return false
		}
	}
	return true
}

func jmatchAny(pats []string, path []string) bool {
	return slices.ContainsFunc(pats, func(p string) bool { return jmatch(p, path) })
}

// singleKeyLen is the length of the key of a single-valued leaf statement
// (path is the whole statement, its last word the value), or -1.
func singleKeyLen(path []string) int {
	for _, k := range jSingleKeys {
		kp := strings.Fields(k)
		if len(path) == len(kp)+1 && jmatch(k, path[:len(kp)]) {
			return len(kp)
		}
	}
	return -1
}

// secretValue encodes a secret the way the device stores it: a $9$ string,
// the same for the same text (the device's differs on every set; a fake that
// is deterministic lets a second apply be 'no change').
func secretValue(v string) string {
	if strings.HasPrefix(v, "$9$") {
		return v
	}
	sum := sha256.Sum256([]byte(v))
	return "$9$" + base64.RawURLEncoding.EncodeToString(sum[:])[:18]
}

// --- the editor ---------------------------------------------------------------------------

// add puts a statement under the deepest node that already holds a sibling
// of it, after that node's last statement; a statement that is there is not
// added twice.
func (c *jcfg) add(s []string) {
	for _, x := range c.stmts {
		if slices.Equal(x, s) {
			return
		}
	}
	at, best := len(c.stmts), 0
	for i, x := range c.stmts {
		k := 0
		for k < len(x) && k < len(s)-1 && x[k] == s[k] {
			k++
		}
		if k > best || k == best && k > 0 {
			best, at = k, i+1
		}
	}
	c.stmts = slices.Insert(c.stmts, at, slices.Clone(s))
}

// set applies one 'set' statement (brackets already expanded).
func (c *jcfg) set(path []string) {
	path = slices.Clone(path)
	if jmatchAny(jSecretLeaves, path[:max(len(path)-1, 0)]) {
		path[len(path)-1] = secretValue(path[len(path)-1])
	}
	// A list entry's flag is a node of its own under the entry, which
	// 'display set' prints as one statement: setting the flagged entry puts
	// the flag on the one the device has, and setting an entry that has its
	// flag already changes nothing.
	if n := len(path); n > 1 && jFlags[path[n-1]] {
		for i, s := range c.stmts {
			if slices.Equal(s, path[:n-1]) {
				c.stmts[i] = path
				return
			}
		}
	} else {
		for _, s := range c.stmts {
			if len(s) == len(path)+1 && jFlags[s[len(path)]] && slices.Equal(s[:len(path)], path) {
				return
			}
		}
	}
	if n := singleKeyLen(path); n > 0 {
		for i, s := range c.stmts {
			if len(s) == n+1 && slices.Equal(s[:n], path[:n]) {
				c.stmts[i] = path
				for j := len(c.stmts) - 1; j > i; j-- {
					if len(c.stmts[j]) == n+1 && slices.Equal(c.stmts[j][:n], path[:n]) {
						c.stmts = slices.Delete(c.stmts, j, j+1)
					}
				}
				return
			}
		}
	}
	c.add(path)
}

// delete removes every statement under path and reports whether any was
// there.
func (c *jcfg) delete(path []string) bool {
	if n := len(path); n > 1 && jFlags[path[n-1]] {
		for i, s := range c.stmts {
			if slices.Equal(s, path) {
				c.stmts[i] = slices.Clone(path[:n-1])
				return true
			}
		}
	}
	found := false
	out := c.stmts[:0:0]
	for _, s := range c.stmts {
		if len(s) >= len(path) && slices.Equal(s[:len(path)], path) {
			found = true
			continue
		}
		out = append(out, s)
	}
	c.stmts = out
	return found
}

// insert handles 'insert <path> [<kw>] B before|after [<kw>] A': the
// statements under the entry B move before or after the entry A's. For
// 'firewall family inet filter F term B before term A' kw is 'term'; for a
// leaf list ('system authentication-order tacplus after password') there is
// none.
func (c *jcfg) insert(t []string) error {
	i := slices.IndexFunc(t, func(w string) bool { return w == "before" || w == "after" })
	if i < 2 || i == len(t)-1 {
		return fmt.Errorf("cannot apply insert %q", strings.Join(t, " "))
	}
	left, right := t[:i], t[i+1:]
	var moved, anchor []string
	switch len(right) {
	case 1:
		moved, anchor = left, slices.Concat(left[:len(left)-1], right)
	case 2:
		if len(left) < 3 || left[len(left)-2] != right[0] {
			return fmt.Errorf("cannot apply insert %q", strings.Join(t, " "))
		}
		moved, anchor = left, slices.Concat(left[:len(left)-1], right[1:])
	default:
		return fmt.Errorf("cannot apply insert %q", strings.Join(t, " "))
	}
	var mv, rest [][]string
	for _, s := range c.stmts {
		if len(s) >= len(moved) && slices.Equal(s[:len(moved)], moved) {
			mv = append(mv, s)
		} else {
			rest = append(rest, s)
		}
	}
	if len(mv) == 0 {
		return fmt.Errorf("insert: no entry %s", moved[len(moved)-1])
	}
	at := -1
	for k, s := range rest {
		if len(s) >= len(anchor) && slices.Equal(s[:len(anchor)], anchor) {
			if t[i] == "before" {
				at = k
				break
			}
			at = k + 1
		}
	}
	if at < 0 {
		return fmt.Errorf("insert: no entry %s", anchor[len(anchor)-1])
	}
	c.stmts = slices.Concat(rest[:at:at], mv, rest[at:])
	return nil
}

// --- the tree and its brace form ---------------------------------------------------------------

type jnode struct {
	tok  string
	kids []*jnode
}

func (n *jnode) child(tok string) *jnode {
	for _, k := range n.kids {
		if k.tok == tok {
			return k
		}
	}
	return nil
}

func (c *jcfg) tree() *jnode {
	root := &jnode{}
	for _, s := range c.stmts {
		n := root
		for _, t := range s {
			k := n.child(t)
			if k == nil {
				k = &jnode{tok: t}
				n.kids = append(n.kids, k)
			}
			n = k
		}
	}
	return root
}

// at is the node at path, or nil.
func (n *jnode) at(path []string) *jnode {
	for _, t := range path {
		if n == nil {
			return nil
		}
		n = n.child(t)
	}
	return n
}

// jitem is one line (or one block) of the brace form of a node.
type jitem struct {
	key    string   // identity for the compare: a changed value pairs with its old one
	head   string   // the text before ';' or '{'
	block  *jnode   // the children of a block; nil for a line
	path   []string // the path of the block
	secret bool
}

func isLeafNode(n *jnode) bool { return len(n.kids) == 0 }

func allLeaves(n *jnode) bool {
	for _, k := range n.kids {
		if !isLeafNode(k) {
			return false
		}
	}
	return len(n.kids) > 0
}

// items are the lines and blocks of the brace form of n (at path).
func items(n *jnode, path []string) []jitem {
	if n == nil {
		return nil
	}
	var out []jitem
	for _, c := range n.kids {
		pc := append(slices.Clone(path), c.tok)
		switch {
		case jmatchAny(jListKeys, pc) && len(c.kids) > 0:
			for _, k := range c.kids {
				head := jquote(c.tok) + " " + jquote(k.tok)
				pk := append(slices.Clone(pc), k.tok)
				if isLeafNode(k) {
					out = append(out, jitem{key: head, head: head})
					continue
				}
				// A flagged entry: 'clients 192.0.2.0/24 restrict' is one line.
				if len(k.kids) == 1 && isLeafNode(k.kids[0]) && jFlags[k.kids[0].tok] {
					h := head + " " + k.kids[0].tok
					out = append(out, jitem{key: head, head: h})
					continue
				}
				out = append(out, jitem{key: head, head: head, block: k, path: pk})
			}
		case singleKeyLen(append(slices.Clone(pc), "?")) > 0 && len(c.kids) == 1 && isLeafNode(c.kids[0]):
			h := jquote(c.tok) + " " + jquote(c.kids[0].tok)
			out = append(out, jitem{key: c.tok, head: h, secret: jmatchAny(jSecretLeaves, pc)})
		case len(c.kids) == 1 && isLeafNode(c.kids[0]) && jFlags[c.kids[0].tok]:
			out = append(out, jitem{key: jquote(c.tok), head: jquote(c.tok) + " " + c.kids[0].tok})
		case isLeafNode(c):
			out = append(out, jitem{key: jquote(c.tok), head: jquote(c.tok)})
		case allLeaves(c) && !jBlockLists[c.tok]:
			var vs []string
			for _, k := range c.kids {
				vs = append(vs, jquote(k.tok))
			}
			h := jquote(c.tok) + " " + vs[0]
			if len(vs) > 1 {
				h = jquote(c.tok) + " [ " + strings.Join(vs, " ") + " ]"
			}
			out = append(out, jitem{key: c.tok, head: h})
		default:
			out = append(out, jitem{key: jquote(c.tok), head: jquote(c.tok), block: c, path: pc})
		}
	}
	return out
}

func render(b *strings.Builder, n *jnode, path []string, indent int) {
	for _, it := range items(n, path) {
		renderItem(b, it, indent)
	}
}

func renderItem(b *strings.Builder, it jitem, indent int) {
	pad := strings.Repeat("    ", indent)
	if it.block == nil {
		b.WriteString(pad + it.head + ";")
		if it.secret {
			b.WriteString(" ## SECRET-DATA")
		}
		b.WriteString("\n")
		return
	}
	b.WriteString(pad + it.head + " {\n")
	render(b, it.block, it.path, indent+1)
	b.WriteString(pad + "}\n")
}

// braceAt is what 'show <path>' prints: the contents of the block at path,
// the line when the path is a leaf, 'user alice {...}' entries when it is a
// list keyword.
func (c *jcfg) braceAt(path []string) string {
	if len(path) == 0 {
		return c.braceText(nil)
	}
	t := c.tree()
	node := t.at(path)
	if node == nil {
		return ""
	}
	pp, last := path[:len(path)-1], path[len(path)-1]
	var b strings.Builder
	if jmatchAny(jListKeys, path) {
		for _, it := range items(t.at(pp), pp) {
			if strings.HasPrefix(it.head, jquote(last)+" ") {
				renderItem(&b, it, 0)
			}
		}
		return b.String()
	}
	for _, it := range items(t.at(pp), pp) {
		if it.key == last || it.key == jquote(last) {
			if it.block == nil {
				renderItem(&b, it, 0)
				return b.String()
			}
			break
		}
	}
	render(&b, node, path, 0)
	return b.String()
}

// braceText is the configuration (or the part of it at path) in the brace
// form 'show' prints.
func (c *jcfg) braceText(path []string) string {
	var b strings.Builder
	render(&b, c.tree().at(path), path, 0)
	return b.String()
}

// under is the statements under path, as a configuration of their own (for
// 'show configuration <path> | display set').
func (c *jcfg) under(path []string) *jcfg {
	out := &jcfg{}
	for _, s := range c.stmts {
		if len(s) >= len(path) && slices.Equal(s[:len(path)], path) {
			out.stmts = append(out.stmts, s)
		}
	}
	return out
}

// --- the compare ----------------------------------------------------------------------------

// compareText is what 'show | compare' prints: for every block with a
// changed line, '[edit <path>]' and the changed lines marked '+' and '-'
// (four columns of indentation per level, the mark in the first), the
// blocks that were added or removed whole as a block. An empty difference is
// the empty text. With context every hunk also prints the unchanged lines
// and blocks beside its changes without a mark, a block collapsed as
// '<head> { ... }', as a device does (live acceptance 2026-10-14: an
// existing trap group collapsed over an added one).
func compareText(old, cur *jcfg, context bool) string {
	var b strings.Builder
	diffNode(&b, old.tree(), cur.tree(), nil, context)
	return b.String()
}

// renderContext is an unchanged item of a hunk as context.
func renderContext(b *strings.Builder, it jitem) {
	switch {
	case it.block != nil:
		b.WriteString("    " + it.head + " { ... }\n")
	case it.secret:
		b.WriteString("    " + it.head + "; ## SECRET-DATA\n")
	default:
		b.WriteString("    " + it.head + ";\n")
	}
}

func renderMarked(b *strings.Builder, mark string, it jitem) {
	var body strings.Builder
	if it.block == nil {
		body.WriteString("    " + it.head + ";")
		if it.secret {
			body.WriteString(" ## SECRET-DATA")
		}
		body.WriteString("\n")
	} else {
		body.WriteString("    " + it.head + " {\n")
		render(&body, it.block, it.path, 2)
		body.WriteString("    }\n")
	}
	for _, line := range strings.SplitAfter(body.String(), "\n") {
		if line == "" {
			continue
		}
		b.WriteString(mark + line[1:])
	}
}

func diffNode(b *strings.Builder, o, n *jnode, path []string, context bool) {
	oi, ni := items(o, path), items(n, path)
	find := func(list []jitem, it jitem) int {
		for i, x := range list {
			if x.key == it.key && (x.block == nil) == (it.block == nil) {
				return i
			}
		}
		return -1
	}
	var lines, ctx strings.Builder
	var nested []jitem
	var nestedOld []*jnode
	done := make([]bool, len(oi))
	flushRemoved := func(upto int) {
		for i := 0; i < upto && i < len(oi); i++ {
			if done[i] {
				continue
			}
			done[i] = true
			if find(ni, oi[i]) < 0 {
				renderMarked(&lines, "-", oi[i])
			}
		}
	}
	for _, it := range ni {
		j := find(oi, it)
		if j >= 0 {
			flushRemoved(j)
			done[j] = true
		}
		switch {
		case j < 0:
			renderMarked(&lines, "+", it)
		case it.block != nil:
			nested = append(nested, it)
			nestedOld = append(nestedOld, oi[j].block)
			renderContext(&ctx, it)
		case it.head != oi[j].head:
			renderMarked(&lines, "-", oi[j])
			renderMarked(&lines, "+", it)
		default:
			renderContext(&ctx, it)
		}
	}
	flushRemoved(len(oi))
	if lines.Len() > 0 {
		b.WriteString("[edit" + joinEditPath(path) + "]\n")
		if context {
			b.WriteString(ctx.String())
		}
		b.WriteString(lines.String())
	}
	for i, it := range nested {
		diffNode(b, nestedOld[i], it.block, it.path, context)
	}
}

// joinEditPath is ' a b c' for the path of a stanza header, ids included
// (the path of a list entry is the keyword and the id).
func joinEditPath(path []string) string {
	if len(path) == 0 {
		return ""
	}
	return " " + jjoin(path)
}

// uidsAssign gives every login user that has none the next free uid, as the
// device does when it commits (2000 and up).
func (c *jcfg) uidsAssign() {
	used := map[int]bool{}
	hasUID := map[string]bool{}
	var order []string
	seen := map[string]bool{}
	for _, s := range c.stmts {
		if len(s) < 4 || s[0] != "system" || s[1] != "login" || s[2] != "user" {
			continue
		}
		if !seen[s[3]] {
			seen[s[3]] = true
			order = append(order, s[3])
		}
		if len(s) == 6 && s[4] == "uid" {
			var n int
			if _, err := fmt.Sscanf(s[5], "%d", &n); err == nil {
				used[n] = true
			}
			hasUID[s[3]] = true
		}
	}
	next := 2000
	for _, u := range order {
		if hasUID[u] {
			continue
		}
		for used[next] {
			next++
		}
		used[next] = true
		c.add([]string{"system", "login", "user", u, "uid", fmt.Sprint(next)})
	}
}
