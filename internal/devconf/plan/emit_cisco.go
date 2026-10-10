package plan

// The IOS region and its after-steps (plan §4b, D100, D106, D108, D109).

import (
	"slices"
	"strings"
)

// iosPrivilegeResidue follows the privilege 'no' lines of a back-out. [S: lab
// IOSv 15.6(2)T: 'no privilege exec level 7 <cmd>' leaves an explicit line at
// the command's default level in the running configuration.]
const iosPrivilegeResidue = "!   (on IOS 15.x a removed privilege line may stay as 'privilege exec level <default> <cmd>'\n" +
	"!    (the command's own default level): harmless)\n"

// iosCursor remembers the submode the last written line was in, so a
// header is written once for consecutive lines.
type iosCursor struct{ ctx []string }

// writeIOSLine writes one line of a Delta (or an undo) as typed: submode
// headers once, the leaf indented under them, 'no ' in front of a removal.
// leader is a comment leader for the back-out block ('!   ').
func writeIOSLine(b *strings.Builder, l Line, leader string, c *iosCursor) {
	if l.Op == OpComment {
		// a back-out step that is no line: a note, in parentheses
		b.WriteString(leader + "(" + l.Text + ")\n")
		return
	}
	same := len(c.ctx) == len(l.Context)
	for i := 0; same && i < len(l.Context); i++ {
		same = c.ctx[i] == l.Context[i]
	}
	if !same {
		for i, h := range l.Context {
			b.WriteString(leader + strings.Repeat(" ", i) + h + "\n")
		}
		c.ctx = append([]string(nil), l.Context...)
	}
	text := l.Text
	if l.Op == OpNo {
		text = "no " + text
	}
	b.WriteString(leader + strings.Repeat(" ", len(l.Context)) + text + "\n")
}

// DECISION: the back-out is the delta's undo lines in reverse paste order
// (the brief); the plan's §4b sample lists the roles lines in paste order
// after the server line. With 'aaa new-model' added, 'no aaa new-model' comes
// first (the lines it removes need no 'no' of their own: every 'aaa ...'
// line and every 'aaa group server' block, not the server line or block,
// which keep their 'no'), then what puts a login method back on the console
// and VTY lines (WP13.1b: the leaves the paste replaced are typed again as
// the extraction carried them, one statement per range it printed, and a
// range that was on 'login authentication <list>' and that the paste did not
// touch gets 'login local', so no line is left with no method). A line that
// replaced another in place is undone by typing the old line again, a block
// that did not exist before by one 'no <header>'.
//
// iosBackout is the 'no'-line block that undoes the delta, in reverse order,
// as lines (not comments).
func iosBackout(d Delta) []Line {
	var out []Line
	push := func(u Line) {
		if len(out) > 0 && sameLine(out[len(out)-1], u) {
			return
		}
		out = append(out, u)
	}
	isLine := func(u Line) bool {
		return len(u.Context) > 0 && (strings.HasPrefix(u.Context[0], "line vty ") || strings.HasPrefix(u.Context[0], "line con "))
	}
	subsumed := func(l Line) bool {
		if !d.AddsAAA || l.Section != "aaa" {
			return false
		}
		return strings.HasPrefix(l.Text, "aaa ") && len(l.Context) == 0 || len(l.Context) > 0 && strings.HasPrefix(l.Context[0], "aaa ")
	}
	if d.AddsAAA {
		push(Line{Op: OpNo, Text: "aaa new-model"})
		var touched []string
		for i := len(d.Lines) - 1; i >= 0; i-- {
			for _, u := range d.Lines[i].Undo {
				if isLine(u) {
					push(u)
					touched = append(touched, u.Context[0])
				}
			}
		}
		for _, lg := range d.Login {
			if !strings.HasPrefix(lg.Text, "login authentication") {
				continue
			}
			if slices.ContainsFunc(touched, func(h string) bool { return overlaps(h, lg.Line) }) {
				continue
			}
			push(Line{Op: OpLine, Context: []string{lg.Line}, Text: "login local"})
		}
	}
	for i := len(d.Lines) - 1; i >= 0; i-- {
		l := d.Lines[i]
		if subsumed(l) {
			continue
		}
		for _, u := range l.Undo {
			if d.AddsAAA && isLine(u) {
				continue // already first
			}
			push(u)
		}
	}
	return out
}

// overlaps reports whether two line headers share a line.
func overlaps(a, b string) bool {
	ka, alo, ahi, ok := lineRange(a)
	kb, blo, bhi, ok2 := lineRange(b)
	return ok && ok2 && ka == kb && alo <= bhi && blo <= ahi
}

func sameLine(a, b Line) bool {
	if a.Op != b.Op || a.Text != b.Text || len(a.Context) != len(b.Context) {
		return false
	}
	for i := range a.Context {
		if a.Context[i] != b.Context[i] {
			return false
		}
	}
	return true
}

// iosRegion is 'configure terminal', the statements by section under one
// label each, and 'end'. The command-authorization lines of the aaa unit are
// the last statements (Opus HIGH 5). Nothing that saves or leaves is in it:
// the change is live at 'end' and 'write memory' is typed afterwards.
func iosRegion(d Delta) []RegionLine {
	out := []RegionLine{{Text: "configure terminal", Line: -1}}
	cur := ""
	var c iosCursor
	for i, l := range d.Lines {
		sec := l.Section
		if l.Late {
			sec = "late"
		}
		if sec != cur {
			cur = sec
			c = iosCursor{}
			label := ""
			if l.Late {
				label = "! aaa: command authorization, last on purpose"
			} else {
				why, _, _ := strings.Cut(d.Of(l.Section).Why, "; ")
				if why == "" {
					why = "the lines tacctl renders"
				}
				label = "! " + l.Section + ": " + why
			}
			out = append(out, RegionLine{Text: label, Comment: true, Line: -1})
		}
		// headers once for consecutive lines of one submode
		same := len(c.ctx) == len(l.Context)
		for ci := 0; same && ci < len(l.Context); ci++ {
			same = c.ctx[ci] == l.Context[ci]
		}
		if !same {
			for ci, h := range l.Context {
				out = append(out, RegionLine{Text: strings.Repeat(" ", ci) + h, Line: -1})
			}
			c.ctx = append([]string(nil), l.Context...)
		}
		text := l.Text
		if l.Op == OpNo {
			text = "no " + text
		}
		text = strings.Repeat(" ", len(l.Context)) + text
		if l.Secret && !l.HasValue && strings.Contains(l.Text, "<SECRET>") {
			out = append(out, RegionLine{Text: "! " + secretLinePrefix + strings.TrimSpace(text), Comment: true, Line: i})
			continue
		}
		out = append(out, RegionLine{Text: text, Line: i})
	}
	out = append(out, RegionLine{Text: "end", Line: -1})
	return out
}

// iosAfter is what follows the region: how to read the echo, the check, the
// one line to type, the back-out as comments, what not to do.
func iosAfter(d Delta, h Header, w Wrapper) string {
	var b strings.Builder
	c := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString("! " + l + "\n")
		}
	}
	b.WriteString("!\n")
	c("If any line printed \"% Invalid\" or \"% Error\", stop and paste the back-out below.")
	b.WriteString("!\n")
	c("Check now (nothing rolls this back by itself):")
	b.WriteString("!   From the tacctl server:   tacctl device config pull " + h.Device + " --diff     (" + joinAnd(d.Planned()) + ": ok)\n")
	b.WriteString("!   In the second terminal:   open a NEW ssh session to " + h.Device + " as yourself, then: terminal length 0, show privilege (must say 15)\n")
	c("If both are fine, type this in the pasting session:")
	b.WriteString("write memory\n")
	b.WriteString("!\n")
	c("To undo (paste in the second terminal, in configuration mode, before 'write memory' or after):")
	cur := &iosCursor{}
	lines := iosBackout(d)
	lastPriv := -1
	for i, l := range lines {
		if l.Op == OpNo && len(l.Context) == 0 && strings.HasPrefix(l.Text, "privilege ") {
			lastPriv = i
		}
	}
	for i, l := range lines {
		writeIOSLine(&b, l, "!   ", cur)
		if i == lastPriv {
			b.WriteString(iosPrivilegeResidue)
		}
	}
	b.WriteString("!   end\n")
	if d.AddsAAA {
		b.WriteString("!   ('no aaa new-model' drops every aaa line but does not restore the login method of the lines:\n")
		b.WriteString("!    the lines after it do.)\n")
	}
	c("Do not: 'write memory' before the check; paste outside the banners; paste into another device; paste on a console more than twenty lines at a time; keep this output in a file after the paste when it holds a secret.")
	return b.String()
}

// removableHeader reports a submode header that is an object of its own,
// which 'no <header>' removes whole: a server block, a group, an access
// list. A line header is not one.
func removableHeader(h string) bool {
	for _, p := range []string{"tacacs server ", "radius server ", "aaa group server ", "ip access-list ", "ipv6 access-list "} {
		if strings.HasPrefix(h, p) {
			return true
		}
	}
	return false
}

// pastedLines counts the lines a person pastes for a section's delta: the
// leaves, and a submode's header once for consecutive lines (the plan's
// "11 lines" of §4b counts the group's header).
func pastedLines(lines []Line) int {
	n := 0
	c := &iosCursor{}
	for _, l := range lines {
		same := len(c.ctx) == len(l.Context)
		for i := 0; same && i < len(l.Context); i++ {
			same = c.ctx[i] == l.Context[i]
		}
		if !same {
			n += len(l.Context)
			c.ctx = append([]string(nil), l.Context...)
		}
		n++
	}
	return n
}
