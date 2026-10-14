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

// expandBrackets resolves '[ a b ]' lists, and splits the one-line forms the
// device prints as one statement per leaf (splitLeaves).
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

// splitLeaves puts a statement of several leaves as 'display set' prints it:
// the options of an NTP server and the type and value of an NTP key one
// statement each (the system block renders them on one line).
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
	"snmp location", "snmp contact", "snmp description", "snmp name", "snmp trap-options source-address",
	"system tacplus-server * secret", "system tacplus-server * port", "system tacplus-server * timeout",
	"system tacplus-server * retry", "system tacplus-server * source-address",
	"system radius-server * secret", "system radius-server * port", "system radius-server * timeout",
	"system login user * class", "system login user * uid",
	"system login class * idle-timeout",
	"snmp community * authorization", "snmp community * client-list-name",
	"snmp trap-group * version",
	"system host-name",
	"system login message", "system domain-name", "system time-zone",
	"system ntp boot-server", "system ntp source-address",
	"system ntp server * version", "system ntp server * key", "system ntp server * routing-instance",
	"system ntp authentication-key * type", "system ntp authentication-key * value",
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
	// A list entry's flag ('restrict', 'except') is a node of its own under
	// the entry, which 'display set' prints as one statement: setting the
	// flagged entry puts the flag on the one the device has, and setting an
	// entry that has its flag already changes nothing.
	if n := len(path); n > 1 && junosFlags[path[n-1]] {
		for i, s := range c.stmts {
			if s.head == "set" && slices.Equal(s.path, path[:n-1]) {
				c.stmts[i].path = slices.Clone(path)
				return
			}
		}
	} else {
		for _, s := range c.stmts {
			if s.head == "set" && len(s.path) == len(path)+1 && junosFlags[s.path[len(path)]] && slices.Equal(s.path[:len(path)], path) {
				return
			}
		}
	}
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
	// D117 (amended): IOS silently refuses a second server entry with the
	// same address and key; the block the paste creates and the device
	// refuses is gone, and what the paste then types under its header is
	// typed into nothing. created and dropped are per paste.
	created, dropped := map[string]bool{}, map[string]bool{}
	dangling := c.danglingGroupEntries()
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
		case l.Op == OpLine && len(l.Context) == 0 && strings.HasPrefix(l.Text, "banner login ") && strings.Contains(l.Text, "\n"):
			// a login banner: its lines replace the device's banner, or are
			// added before 'end'
			c.typeBanner(l.Text)
		case l.Op == OpLine && len(l.Context) == 0:
			if e, ok := hostLineEntry(text); ok && c.duplicateOf("", e) {
				continue // refused, silently
			}
			c.typeGlobal(text)
		case l.Op == OpLine:
			hdr := l.Context[0]
			if dropped[hdr] {
				continue
			}
			if isLoginLeafPath([]string{hdr, text}) {
				c.replaceLogin(hdr)
			}
			blk := c.blockFor(hdr)
			if blk == nil {
				c.insertBlock(iosBlk{lines: []string{hdr}})
				blk = c.blockFor(hdr)
				created[hdr] = true
			}
			if f := strings.Fields(text); serverBlockKind(hdr) != "" && len(f) > 0 && (f[0] == "address" || f[0] == "key") {
				cp := iosBlk{lines: slices.Clone(blk.lines)}
				typeChild(&cp, l.Context, text)
				if e, ok := blockServerEntry(serverBlockKind(hdr), cp.lines[1:]); ok && c.duplicateOf(hdr, e) {
					if created[hdr] {
						c.removeBlock(hdr)
						dropped[hdr] = true
					}
					continue
				}
				blk.lines = cp.lines
				continue
			}
			typeChild(blk, l.Context, text)
			// a group's 'server name X' is a block the device has
			if f := strings.Fields(text); len(f) == 3 && f[0] == "server" && f[1] == "name" {
				if kind := groupKind(hdr); kind != "" && c.blockFor(kind+" server "+f[2]) == nil {
					return fmt.Errorf("plan: %q under %q names no %s server block %q: the group would name a block that does not exist", l.Shown(), hdr, kind, f[2])
				}
			}
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
	for g := range c.danglingGroupEntries() {
		if !dangling[g] {
			return fmt.Errorf("plan: the group entry %q names a server block that does not exist after the paste", g)
		}
	}
	return nil
}

// --- the server entries the device refuses (D117, amended) -------------------------------

// iosServerEntry is what makes two server entries the same to IOS: the
// protocol, the address, the ports (RADIUS) and the key.
type iosServerEntry struct {
	kind, addr, ports, key string
}

// serverBlockKind is "tacacs" or "radius" for a 'tacacs server N' or 'radius
// server N' header, "" for any other.
func serverBlockKind(header string) string {
	h := norm(header)
	switch {
	case strings.HasPrefix(h, "tacacs server "):
		return "tacacs"
	case strings.HasPrefix(h, "radius server "):
		return "radius"
	}
	return ""
}

// groupKind is "tacacs" or "radius" for an 'aaa group server tacacs+|radius
// G' header.
func groupKind(header string) string {
	h := norm(header)
	switch {
	case strings.HasPrefix(h, "aaa group server tacacs+ "):
		return "tacacs"
	case strings.HasPrefix(h, "aaa group server radius "):
		return "radius"
	}
	return ""
}

// type7 is the table of the 'key 7' encoding, which is reversible: two
// devices hold the same key when their decoded values are the same.
const type7 = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254kfg87"

// keyValue reads the words after 'key' as the value IOS compares: a plain or
// 'key 0' value as it is, 'key 7' decoded, any other encryption type as an
// opaque value of its own type.
func keyValue(w []string) string {
	if len(w) == 0 {
		return ""
	}
	if len(w) >= 2 {
		switch w[0] {
		case "0":
			return w[1]
		case "7":
			if v, ok := decodeType7(w[1]); ok {
				return v
			}
		case "6", "8", "9":
			return "type" + w[0] + ":" + w[1]
		}
	}
	return w[0]
}

func decodeType7(h string) (string, bool) {
	if len(h) < 4 || len(h)%2 != 0 {
		return "", false
	}
	seed := 0
	for _, r := range h[:2] {
		if r < '0' || r > '9' {
			return "", false
		}
		seed = seed*10 + int(r-'0')
	}
	var out []byte
	for i := 2; i+1 < len(h); i += 2 {
		var b byte
		for _, r := range h[i : i+2] {
			switch {
			case r >= '0' && r <= '9':
				b = b<<4 | byte(r-'0')
			case r >= 'A' && r <= 'F':
				b = b<<4 | byte(r-'A'+10)
			case r >= 'a' && r <= 'f':
				b = b<<4 | byte(r-'a'+10)
			default:
				return "", false
			}
		}
		out = append(out, b^type7[(seed+len(out))%len(type7)])
	}
	return string(out), true
}

// portsOf reads the ports of a RADIUS entry (the defaults when not given) and
// the port of a TACACS+ one.
func portsOf(kind string, w []string) string {
	val := func(kw, def string) string {
		if i := slices.Index(w, kw); i >= 0 && i+1 < len(w) {
			return w[i+1]
		}
		return def
	}
	if kind == "radius" {
		return val("auth-port", "1812") + "/" + val("acct-port", "1813")
	}
	return val("port", "49")
}

// blockServerEntry reads the address, ports and key of a block's leaves; ok
// is false while the block lacks the address or the key.
func blockServerEntry(kind string, leaves []string) (iosServerEntry, bool) {
	e := iosServerEntry{kind: kind}
	for _, l := range leaves {
		w := strings.Fields(l)
		switch {
		case len(w) >= 3 && w[0] == "address" && w[1] == "ipv4":
			e.addr, e.ports = w[2], portsOf(kind, w[3:])
		case len(w) >= 2 && w[0] == "key":
			e.key = keyValue(w[1:])
		}
	}
	if e.ports == "" {
		e.ports = portsOf(kind, nil)
	}
	return e, e.addr != "" && e.key != ""
}

// hostLineEntry reads a global 'tacacs-server host A ... key K' or
// 'radius-server host A ... key K' line.
func hostLineEntry(text string) (iosServerEntry, bool) {
	w := strings.Fields(text)
	if len(w) < 3 || w[1] != "host" || (w[0] != "tacacs-server" && w[0] != "radius-server") {
		return iosServerEntry{}, false
	}
	kind := strings.TrimSuffix(w[0], "-server")
	e := iosServerEntry{kind: kind, addr: w[2], ports: portsOf(kind, w[3:])}
	if i := slices.Index(w, "key"); i >= 0 {
		e.key = keyValue(w[i+1:])
	}
	return e, e.key != ""
}

// duplicateOf reports whether another entry of the device (a named block other
// than self, or a global host line) is the same server as e.
func (c *IOSConfig) duplicateOf(self string, e iosServerEntry) bool {
	for _, b := range c.blocks {
		h := norm(b.lines[0])
		if self != "" && h == norm(self) {
			continue
		}
		var o iosServerEntry
		var ok bool
		if k := serverBlockKind(h); k != "" {
			o, ok = blockServerEntry(k, b.lines[1:])
		} else if len(b.lines) == 1 && self != "" {
			o, ok = hostLineEntry(h)
		}
		if ok && o.kind == e.kind && o.addr == e.addr && o.ports == e.ports && o.key == e.key {
			return true
		}
	}
	return false
}

// removeBlock drops the block with the header.
func (c *IOSConfig) removeBlock(header string) {
	for i := range c.blocks {
		if norm(c.blocks[i].lines[0]) == norm(header) {
			c.blocks = slices.Delete(c.blocks, i, i+1)
			return
		}
	}
}

// danglingGroupEntries are the 'server name X' entries of the groups that
// name a server block the device does not have, as 'header > entry'.
func (c *IOSConfig) danglingGroupEntries() map[string]bool {
	out := map[string]bool{}
	for _, b := range c.blocks {
		kind := groupKind(b.lines[0])
		if kind == "" {
			continue
		}
		for _, l := range b.lines[1:] {
			w := strings.Fields(l)
			if len(w) == 3 && w[0] == "server" && w[1] == "name" && c.blockFor(kind+" server "+w[2]) == nil {
				out[norm(b.lines[0])+" > "+norm(l)] = true
			}
		}
	}
	return out
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

// typeBanner types a login banner (its lines: 'banner login <d>', the text,
// '<d>'): it replaces the device's login banner in place, else it is added.
func (c *IOSConfig) typeBanner(text string) {
	blk := iosBlk{lines: strings.Split(text, "\n")}
	for i := range c.blocks {
		if strings.HasPrefix(norm(c.blocks[i].lines[0]), "banner login ") {
			c.blocks[i] = blk
			return
		}
	}
	c.insertBlock(blk)
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
	// a trap host is an entry of its address, vrf, kind, udp-port and
	// community: 'no' takes that entry away whatever its version and types,
	// and never an entry of another kind or port (lab, IOS 15.6 and 16.7)
	hostKey, isHost := "", false
	if strings.HasPrefix(text, "snmp-server host ") {
		hostKey, isHost = iosKey([]string{text})
	}
	for i := 0; i < len(c.blocks); i++ {
		h := norm(c.blocks[i].lines[0])
		if isHost && len(c.blocks[i].lines) == 1 && strings.HasPrefix(h, "snmp-server host ") {
			if k, ok := iosKey([]string{h}); ok && k == hostKey {
				c.blocks = slices.Delete(c.blocks, i, i+1)
				i--
			}
			continue
		}
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
