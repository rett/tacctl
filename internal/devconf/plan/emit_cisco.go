package plan

// The IOS region and its after-steps (plan §4b, D100, D106, D108, D109).

import (
	"slices"
	"strings"
)

// iosPrivilegeResidue follows the privilege 'no' lines of a back-out. [S: lab
// IOSv 15.6(2)T: 'no privilege exec level 7 <cmd>' leaves an explicit line at
// the command's default level in the running configuration.]
var iosPrivilegeResidue = []string{
	"! (on IOS 15.x a removed privilege line may stay as 'privilege exec level <default> <cmd>'",
	"!  (the command's own default level): harmless)",
}

// iosCursor remembers the submode the last written line was in, so a
// header is written once for consecutive lines.
type iosCursor struct{ ctx []string }

// emitIOSLine appends one line of a Delta (or an undo) as typed: the
// submode headers once for consecutive lines, the leaf indented under them,
// 'no ' in front of a removal. idx is the line's index in Delta.Lines (-1
// for a back-out line).
func emitIOSLine(out *[]RegionLine, c *iosCursor, l Line, idx int) {
	same := len(c.ctx) == len(l.Context)
	for i := 0; same && i < len(l.Context); i++ {
		same = c.ctx[i] == l.Context[i]
	}
	if !same {
		for i, h := range l.Context {
			*out = append(*out, RegionLine{Text: strings.Repeat(" ", i) + h, Line: -1})
		}
		c.ctx = append([]string(nil), l.Context...)
	}
	text := l.Text
	if l.Op == OpNo {
		text = "no " + text
	}
	text = strings.Repeat(" ", len(l.Context)) + text
	if l.Secret && !l.HasValue && strings.Contains(l.Text, "<SECRET>") {
		*out = append(*out, RegionLine{Text: "! " + secretLinePrefix + strings.TrimSpace(text), Comment: true, Line: idx})
		return
	}
	// a login banner is one statement of several lines (the opening line, the
	// text, the closing delimiter): they are consecutive lines of the region,
	// the first of them the line of the plan
	if lines := strings.Split(text, "\n"); len(lines) > 1 {
		for i, bl := range lines {
			at := idx
			if i > 0 {
				at = -1
			}
			*out = append(*out, RegionLine{Text: bl, Line: at})
		}
		return
	}
	*out = append(*out, RegionLine{Text: text, Line: idx})
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
		var touched []string
		// A leaf the paste typed on a line that had none (the console's
		// CONSOLE list) is taken off first, while AAA is still on and the
		// command is there to type: with AAA off a 'login authentication'
		// is not a command of the line any more.
		for i := len(d.Lines) - 1; i >= 0; i-- {
			for _, u := range d.Lines[i].Undo {
				if isLine(u) && u.Op == OpNo {
					push(u)
					touched = append(touched, u.Context[0])
				}
			}
		}
		push(Line{Op: OpNo, Text: "aaa new-model"})
		for i := len(d.Lines) - 1; i >= 0; i-- {
			for _, u := range d.Lines[i].Undo {
				if isLine(u) && u.Op != OpNo {
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
	out := []RegionLine{{Text: "configure terminal", Wrapper: true, Line: -1}}
	cur := ""
	var c iosCursor
	for i, l := range d.Lines {
		sec := l.Section
		switch {
		case l.Late:
			sec = "late"
		case l.Leaf:
			sec = "leaf"
		}
		if sec != cur {
			cur = sec
			c = iosCursor{}
			label := ""
			switch {
			case l.Late:
				label = "! aaa: command authorization, last on purpose"
			case l.Leaf:
				label = "! aaa: the login method of the console and vty lines"
			default:
				why, _, _ := strings.Cut(d.Of(l.Section).Why, "; ")
				if why == "" {
					why = "the lines tacctl renders"
				}
				label = "! " + l.Section + ": " + why
			}
			out = append(out, RegionLine{Text: label, Comment: true, Line: -1})
		}
		emitIOSLine(&out, &c, l, i)
	}
	out = append(out, RegionLine{Text: "end", Wrapper: true, Line: -1})
	return out
}

// iosBackoutRegion is the back-out as a region: 'configure terminal', the
// undo lines (plain, executable: no line of it is a comment but the notes),
// 'end'.
func iosBackoutRegion(d Delta) []RegionLine {
	out := []RegionLine{{Text: "configure terminal", Wrapper: true, Line: -1},
		{Text: "! back-out: the lines as the pull showed them", Comment: true, Line: -1}}
	var c iosCursor
	lines := iosBackout(d)
	lastPriv := -1
	for i, l := range lines {
		if l.Op == OpNo && len(l.Context) == 0 && strings.HasPrefix(l.Text, "privilege ") {
			lastPriv = i
		}
	}
	for i, l := range lines {
		if l.Op == OpComment {
			// a step that is no line: a note, in parentheses
			out = append(out, RegionLine{Text: "! (" + l.Text + ")", Comment: true, Line: -1})
			continue
		}
		emitIOSLine(&out, &c, l, -1)
		if i == lastPriv {
			for _, r := range iosPrivilegeResidue {
				out = append(out, RegionLine{Text: r, Comment: true, Line: -1})
			}
		}
	}
	if d.AddsAAA {
		out = append(out, RegionLine{Text: "! ('no aaa new-model' drops every aaa line but does not restore the login method of the lines: the line vty and line con lines of this back-out do)", Comment: true, Line: -1})
	}
	out = append(out, RegionLine{Text: "end", Wrapper: true, Line: -1})
	return out
}

// iosAfter is what follows the region: how to read the echo, the check, the
// one line to type (a comment line: a copy of the whole output must not save
// before the check, review H1), where the back-out is, what not to do.
func iosAfter(d Delta, h Header, w Wrapper) string {
	var b strings.Builder
	c := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString("! " + l + "\n")
		}
	}
	undo := "tacctl device config plan " + h.Device + " --backout"
	b.WriteString("!\n")
	if HasBackout(d) {
		c("If any line printed \"% Invalid\" or \"% Error\", stop and undo it: " + undo + "     (its own region, to paste in the second terminal).")
	} else {
		c("If any line printed \"% Invalid\" or \"% Error\", stop and undo it by hand: tacctl has no lines of its own to undo this plan.")
	}
	b.WriteString("!\n")
	c("Check now (nothing rolls this back by itself):")
	b.WriteString("!   From the tacctl server:   tacctl device config pull " + h.Device + " --diff     (" + joinAnd(d.Planned()) + ": ok)\n")
	b.WriteString("!   In the second terminal:   open a NEW ssh session to " + h.Device + " as yourself, then: terminal length 0, show privilege (must say 15)\n")
	b.WriteString("! When both checks are fine, type this one command yourself:  write memory\n")
	b.WriteString("!\n")
	if HasBackout(d) {
		c("To undo: " + undo + "     (tacctl keeps this plan's back-out: after the check pull has replaced the picture, the command still prints this plan's, and says which pull it undoes, until the next plan with changes)")
	}
	if d.restoreShown() {
		// the restore block is above the region; here is where to go back with it
		if HasBackout(d) {
			c("Restore point: " + d.Restore.Name(h) + " (the block above the region). The back-out names it as an alternative to its 'no' lines: 'configure replace' with the file.")
		} else {
			b.WriteString("!\n")
			c("Restore point: " + d.Restore.Name(h) + " (the block above the region). There are no lines of tacctl's to undo this plan, so the way back is the file.")
			restoreAlternative(d, h, "", c, func(s string) { b.WriteString("!   " + s + "\n") })
		}
	}
	c("Do not: 'write memory' before the check; paste outside the banners; paste into another device; paste on a console more than twenty lines at a time; keep this output in a file after the paste when it holds a secret.")
	b.WriteString(lockoutHelp(d, h))
	return b.String()
}

// iosBackoutAfter is what follows the back-out region: comments only.
func iosBackoutAfter(d Delta, h Header, w Wrapper) string {
	var b strings.Builder
	c := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString("! " + l + "\n")
		}
	}
	b.WriteString("!\n")
	c("If any line printed \"% Invalid\" or \"% Error\", stop and read the echo line by line.")
	b.WriteString("!\n")
	c("Check now (nothing undoes this by itself):")
	b.WriteString("!   From the tacctl server:   tacctl device config pull " + h.Device + " --diff     (the differences of the plan are back)\n")
	b.WriteString("!   In the second terminal:   open a NEW ssh session to " + h.Device + " as yourself, then: terminal length 0, show privilege (must say 15)\n")
	b.WriteString("! When both checks are fine, type this one command yourself:  write memory\n")
	c("If the plan was saved with write memory, this undo is saved only when you type it again.")
	b.WriteString("!\n")
	c("A value that tacctl does not hold (an original secret) is a line marked with ! inside the region: put it back by hand.")
	if d.restoreShown() {
		b.WriteString("!\n")
		restoreAlternative(d, h, "Or, ", c, func(s string) { b.WriteString("!   " + s + "\n") })
		b.WriteString("!\n")
	}
	c("Do not: 'write memory' before the check; paste outside the banners; paste into another device; paste on a console more than twenty lines at a time; keep this output in a file after the paste when it holds a secret.")
	b.WriteString(lockoutHelp(d, h))
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
		n += strings.Count(l.Text, "\n") + 1
	}
	return n
}
