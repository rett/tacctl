package plan

// The in-memory editors (plan D103): a Junos configuration as 'set'
// statements that a Delta's set, delete and insert lines are applied to, and
// an IOS configuration as the blocks of 'show running-config' that its line
// and no lines are applied to. They are small, pure, and independent of the
// planner's own assumptions where they can be: the single-valued leaves of
// the Junos editor are the schema's, not the planner's table. The property
// test applies a plan to a pulled text with them and compares again.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// --- Junos ----------------------------------------------------------------------------

// jstmt is one statement of a Junos configuration.
type jstmt struct {
	head string // set or deactivate
	path []string
}

func (s jstmt) text() string { return s.head + " " + joinTokens(s.path) }

// JunosConfig is a Junos configuration as 'set' statements in order.
type JunosConfig struct {
	stmts []jstmt
}

// ParseJunos reads 'display set' text: every 'set' and 'deactivate' line, a
// bracket list expanded to one statement per element; other lines (the
// capture header's comments, 'delete', 'groups'...) are kept as they are
// statements of their own hierarchy.
func ParseJunos(text string) *JunosConfig {
	c := &JunosConfig{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		head, rest, _ := strings.Cut(line, " ")
		if head != "set" && head != "deactivate" {
			continue
		}
		for _, p := range expandBrackets(splitTokens(rest)) {
			c.add(jstmt{head: head, path: p})
		}
	}
	return c
}

// expandBrackets resolves '[ a b ]' lists.
func expandBrackets(t []string) [][]string {
	i := slices.Index(t, "[")
	if i < 0 {
		return [][]string{t}
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

func (c *JunosConfig) add(s jstmt) {
	for _, x := range c.stmts {
		if x.head == s.head && slices.Equal(x.path, s.path) {
			return
		}
	}
	// A new statement lands in the tree under the deepest node that
	// already holds a sibling of it, after that node's last statement: a
	// new leaf in a filter term does not move the term, a new term comes
	// last among the filter's terms.
	at := len(c.stmts)
	best := 0
	for i, x := range c.stmts {
		k := 0
		for k < len(x.path) && k < len(s.path)-1 && x.path[k] == s.path[k] {
			k++
		}
		if k > best || k == best && k > 0 {
			best, at = k, i+1
		}
	}
	c.stmts = slices.Insert(c.stmts, at, s)
}

// Text is the configuration as 'display set' lines.
func (c *JunosConfig) Text() string {
	var b strings.Builder
	for _, s := range c.stmts {
		b.WriteString(s.text() + "\n")
	}
	return b.String()
}

// Statements returns the statements as text.
func (c *JunosConfig) Statements() []string {
	out := make([]string, len(c.stmts))
	for i, s := range c.stmts {
		out[i] = s.text()
	}
	return out
}

// Remove drops the statement with exactly this text, reporting whether it
// was there.
func (c *JunosConfig) Remove(text string) bool {
	for i, s := range c.stmts {
		if s.text() == text {
			c.stmts = slices.Delete(c.stmts, i, i+1)
			return true
		}
	}
	return false
}

// Add appends a statement ('set ...').
func (c *JunosConfig) Add(text string) {
	head, rest, _ := strings.Cut(strings.TrimSpace(text), " ")
	for _, p := range expandBrackets(splitTokens(rest)) {
		c.add(jstmt{head: head, path: p})
	}
}

// junosSingleKeys are the Junos schema's single-valued leaves (the
// statement path prefixes whose last token is the value): a set of one
// replaces the value in place. '*' matches any token. This is the editor's
// own knowledge of the device, not the planner's table.
var junosSingleKeys = []string{
	"snmp location", "snmp contact", "snmp description", "snmp name",
	"system tacplus-server * secret", "system tacplus-server * port", "system tacplus-server * timeout",
	"system tacplus-server * retry", "system tacplus-server * source-address",
	"system radius-server * secret", "system radius-server * port", "system radius-server * timeout",
	"system login user * class", "system login user * uid",
	"system login class * idle-timeout",
	"snmp community * authorization",
	"system host-name",
}

func singleKeyLen(path []string) int {
	for _, k := range junosSingleKeys {
		kp := strings.Fields(k)
		if len(path) != len(kp)+1 {
			continue
		}
		ok := true
		for i, t := range kp {
			if t != "*" && t != path[i] {
				ok = false
				break
			}
		}
		if ok {
			return len(kp)
		}
	}
	return -1
}

// Apply applies the lines of a Delta (set, delete, insert) in order.
// Deleting what is not there is a no-op, as the device warns.
func (c *JunosConfig) Apply(lines []Line) error {
	for _, l := range lines {
		t := splitTokens(l.Text)
		if len(t) < 2 {
			return fmt.Errorf("plan: cannot apply %q", l.Shown())
		}
		switch t[0] {
		case "set":
			for _, p := range expandBrackets(t[1:]) {
				c.set(p)
			}
		case "delete":
			c.delete(t[1:])
		case "insert":
			if err := c.insert(t[1:]); err != nil {
				return err
			}
		default:
			return fmt.Errorf("plan: %q is not a set, delete or insert line", l.Shown())
		}
	}
	return nil
}

func (c *JunosConfig) set(path []string) {
	if n := singleKeyLen(path); n > 0 {
		for i, s := range c.stmts {
			if s.head == "set" && len(s.path) == n+1 && slices.Equal(s.path[:n], path[:n]) {
				c.stmts[i].path = slices.Clone(path)
				// drop later duplicates of the key
				for j := len(c.stmts) - 1; j > i; j-- {
					if c.stmts[j].head == "set" && len(c.stmts[j].path) == n+1 && slices.Equal(c.stmts[j].path[:n], path[:n]) {
						c.stmts = slices.Delete(c.stmts, j, j+1)
					}
				}
				return
			}
		}
	}
	c.add(jstmt{head: "set", path: slices.Clone(path)})
}

func (c *JunosConfig) delete(path []string) {
	// A trailing flag of a list entry ('restrict', 'except') is a node of
	// its own: deleting it leaves the entry, as a permit.
	if n := len(path); n > 1 && junosFlags[path[n-1]] {
		for i, s := range c.stmts {
			if s.head == "set" && slices.Equal(s.path, path) {
				c.stmts[i].path = slices.Clone(path[:n-1])
				return
			}
		}
	}
	out := c.stmts[:0:0]
	for _, s := range c.stmts {
		if len(s.path) >= len(path) && slices.Equal(s.path[:len(path)], path) {
			continue
		}
		out = append(out, s)
	}
	c.stmts = out
}

// insert handles 'firewall family inet filter F term B before|after term A'.
func (c *JunosConfig) insert(t []string) error {
	// t: firewall family inet filter F term B (before|after) term A
	if len(t) != 10 || t[0] != "firewall" || t[5] != "term" || t[7] != "before" && t[7] != "after" || t[8] != "term" {
		return fmt.Errorf("plan: cannot apply insert %q", strings.Join(t, " "))
	}
	pfx := slices.Clone(t[:5])
	termB := append(slices.Clone(pfx), "term", t[6])
	termA := append(slices.Clone(pfx), "term", t[9])
	var moved, rest []jstmt
	for _, s := range c.stmts {
		if len(s.path) >= len(termB) && slices.Equal(s.path[:len(termB)], termB) {
			moved = append(moved, s)
		} else {
			rest = append(rest, s)
		}
	}
	if len(moved) == 0 {
		return fmt.Errorf("plan: insert: no term %s", t[6])
	}
	at := -1
	for i, s := range rest {
		if len(s.path) >= len(termA) && slices.Equal(s.path[:len(termA)], termA) {
			if t[7] == "before" {
				at = i
				break
			}
			at = i + 1
		}
	}
	if at < 0 {
		return fmt.Errorf("plan: insert: no term %s", t[9])
	}
	c.stmts = slices.Concat(rest[:at:at], moved, rest[at:])
	return nil
}

// --- IOS ------------------------------------------------------------------------------

// iosBlk is a top-level line with its indented children, or a line of text
// that is none of that ('!' separators, banner text).
type iosBlk struct {
	lines []string
}

// IOSConfig is a running configuration as blocks, kept as it was read so
// everything not edited is emitted verbatim.
type IOSConfig struct {
	blocks []iosBlk
}

// ParseIOS reads 'show running-config' text.
func ParseIOS(text string) *IOSConfig {
	c := &IOSConfig{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimLeft(l, " \t")
		switch {
		case strings.HasPrefix(t, "banner ") && indentOf(l) == 0:
			blk := iosBlk{lines: []string{l}}
			if f := strings.Fields(t); len(f) >= 3 {
				d := f[2]
				if strings.HasPrefix(d, "^C") {
					d = "^C"
				} else {
					d = d[:1]
				}
				body := strings.TrimPrefix(t, strings.Join(f[:2], " "))
				if strings.Count(body, d) < 2 {
					for i++; i < len(lines); i++ {
						blk.lines = append(blk.lines, lines[i])
						if strings.Contains(lines[i], d) {
							break
						}
					}
				}
			}
			c.blocks = append(c.blocks, blk)
		case t == "" || strings.HasPrefix(t, "!") || indentOf(l) == 0 || len(c.blocks) == 0:
			c.blocks = append(c.blocks, iosBlk{lines: []string{l}})
		default:
			last := &c.blocks[len(c.blocks)-1]
			if t2 := strings.TrimLeft(last.lines[0], " \t"); t2 == "" || strings.HasPrefix(t2, "!") {
				c.blocks = append(c.blocks, iosBlk{lines: []string{l}})
			} else {
				last.lines = append(last.lines, l)
			}
		}
	}
	return c
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }

// Text is the configuration again.
func (c *IOSConfig) Text() string {
	var b strings.Builder
	for _, blk := range c.blocks {
		for _, l := range blk.lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

func norm(s string) string { return strings.Join(strings.Fields(s), " ") }

// endIndex is where a new top-level block goes: before the final 'end'.
func (c *IOSConfig) endIndex() int {
	for i := len(c.blocks) - 1; i >= 0; i-- {
		if norm(c.blocks[i].lines[0]) == "end" {
			return i
		}
	}
	return len(c.blocks)
}

func (c *IOSConfig) insertBlock(blk iosBlk) {
	at := c.endIndex()
	c.blocks = slices.Insert(c.blocks, at, blk)
}

// blockFor finds the block whose header is the text.
func (c *IOSConfig) blockFor(header string) *iosBlk {
	for i := range c.blocks {
		if norm(c.blocks[i].lines[0]) == header {
			return &c.blocks[i]
		}
	}
	return nil
}

// Apply applies a Delta's lines: a 'line' types a line (replacing the one
// with the same key in place, as IOS does), a 'no' removes the line, or the
// whole block when it is a block's header.
func (c *IOSConfig) Apply(lines []Line) error {
	// Nothing under 'aaa' exists on IOS until 'aaa new-model' is set (the
	// spike's "Legacy IOS 12.4"): an 'aaa ...' statement or an 'aaa group
	// server' block typed before it is rejected, and so is the paste.
	modelOn := slices.ContainsFunc(c.blocks, func(b iosBlk) bool { return norm(b.lines[0]) == "aaa new-model" })
	for _, l := range lines {
		text := norm(l.Text)
		if l.Op == OpLine && len(l.Context) == 0 && text == "aaa new-model" {
			modelOn = true
		}
		if l.Op == OpNo && len(l.Context) == 0 && text == "aaa new-model" {
			modelOn = false
		}
		if l.Op == OpLine && !modelOn && (len(l.Context) == 0 && strings.HasPrefix(text, "aaa ") ||
			len(l.Context) > 0 && strings.HasPrefix(norm(l.Context[0]), "aaa group server ")) {
			return fmt.Errorf("plan: %q is typed before 'aaa new-model': IOS has no such command until it is set", l.Shown())
		}
		// 'login authentication <list>' is a line command only once 'aaa
		// new-model' is set: typed before it the line is refused
		if l.Op == OpLine && !modelOn && len(l.Context) == 1 && isLoginLeafPath([]string{l.Context[0], text}) &&
			strings.HasPrefix(text, "login authentication ") {
			return fmt.Errorf("plan: %q under %q is typed before 'aaa new-model': IOS has no such line command until it is set", l.Shown(), l.Context[0])
		}
		switch {
		case l.Op == OpLine && len(l.Context) == 0:
			c.typeGlobal(text)
		case l.Op == OpLine:
			if isLoginLeafPath([]string{l.Context[0], text}) {
				c.replaceLogin(l.Context[0])
			}
			blk := c.blockFor(l.Context[0])
			if blk == nil {
				c.insertBlock(iosBlk{lines: []string{l.Context[0]}})
				blk = c.blockFor(l.Context[0])
			}
			typeChild(blk, l.Context, text)
		case l.Op == OpNo && len(l.Context) == 0:
			c.noGlobal(text)
		case l.Op == OpNo:
			if blk := c.blockFor(l.Context[0]); blk != nil {
				noChild(blk, l.Context[0], text)
			}
		default:
			return fmt.Errorf("plan: cannot apply %q", l.Shown())
		}
	}
	return nil
}

// replaceLogin models what typing a login method under 'line vty A B' does:
// the lines of the range have one method, so the login leaves of the blocks
// whose lines it covers are gone (their other leaves stay).
func (c *IOSConfig) replaceLogin(header string) {
	for i := range c.blocks {
		b := &c.blocks[i]
		h := norm(b.lines[0])
		if h == header || !within(h, header) {
			continue
		}
		kept := b.lines[:1:1]
		for _, l := range b.lines[1:] {
			if !isLoginLeafPath([]string{h, norm(l)}) {
				kept = append(kept, l)
			}
		}
		b.lines = kept
	}
}

func (c *IOSConfig) typeGlobal(text string) {
	key, hasKey := iosKey([]string{text})
	first := -1
	for i := 0; i < len(c.blocks); i++ {
		b := c.blocks[i]
		if len(b.lines) != 1 {
			if norm(b.lines[0]) == text {
				return
			}
			continue
		}
		t := norm(b.lines[0])
		if t == text {
			return
		}
		if hasKey {
			if k, ok := iosKey([]string{t}); ok && k == key {
				if first < 0 {
					first = i
					c.blocks[i].lines[0] = text
				} else {
					c.blocks = slices.Delete(c.blocks, i, i+1)
					i--
				}
			}
		}
	}
	if first >= 0 {
		return
	}
	c.insertBlock(iosBlk{lines: []string{text}})
}

func (c *IOSConfig) noGlobal(text string) {
	for i := 0; i < len(c.blocks); i++ {
		h := norm(c.blocks[i].lines[0])
		// 'no aaa new-model' takes every aaa line and group with it (the lines
		// that name the list on the vty lines stay: the lab, lock-out 2)
		if text == "aaa new-model" && strings.HasPrefix(h, "aaa ") {
			c.blocks = slices.Delete(c.blocks, i, i+1)
			i--
			continue
		}
		if h == text || strings.HasPrefix(h, text+" ") {
			c.blocks = slices.Delete(c.blocks, i, i+1)
			i--
		}
	}
}

// childKey is how a child line of a block is compared with a typed one: an
// access list's entry by its canonical form (no sequence number, 'host A'
// and 'A 0.0.0.0' as 'A'), another line as it is.
func childKey(header, child string) string {
	child = norm(child)
	if strings.HasPrefix(header, "ip access-list ") || strings.HasPrefix(header, "ipv6 access-list ") {
		if st, err := devconf.Elide("cisco", []string{header, " " + child}, nil); err == nil && len(st) == 1 {
			return st[0]
		}
	}
	return child
}

func typeChild(blk *iosBlk, ctx []string, text string) {
	path := append(slices.Clone(ctx), text)
	key, hasKey := iosKey(path)
	want := childKey(ctx[0], text)
	first := -1
	for i := 1; i < len(blk.lines); i++ {
		t := norm(blk.lines[i])
		if childKey(ctx[0], t) == want {
			return
		}
		if hasKey {
			if k, ok := iosKey(append(slices.Clone(ctx), t)); ok && k == key {
				if first < 0 {
					first = i
					blk.lines[i] = " " + text
				} else {
					blk.lines = slices.Delete(blk.lines, i, i+1)
					i--
				}
			}
		}
	}
	if first < 0 {
		blk.lines = append(blk.lines, " "+text)
	}
}

func noChild(blk *iosBlk, header, text string) {
	want := childKey(header, text)
	for i := 1; i < len(blk.lines); i++ {
		t := norm(blk.lines[i])
		if childKey(header, t) == want || t == text || strings.HasPrefix(t, text+" ") {
			blk.lines = slices.Delete(blk.lines, i, i+1)
			i--
		}
	}
}
