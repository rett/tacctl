package plan

// The Junos region and its after-steps (plan §3, D96, D108, D109).

import (
	"strconv"
	"strings"
)

// junosCommitConfirmed is the last line of the region and the only commit it
// holds. [A: lab check L3 was not run (a commit needs a separate go-ahead):
// the 'commit confirmed <minutes> comment "..."' syntax is the Junos
// reference's, and the 0.2.4 spike (d) confirmed the CLI's 'commit confirmed
// N' and its expiry.]
func junosCommitConfirmed(minutes int, h Header) string {
	return "commit confirmed " + strconv.Itoa(minutes) + " comment \"tacctl plan " + commentSafe(h.Device) + " " +
		fmtStamp(h.Now) + " by " + commentSafe(h.User) + "\""
}

// junosVerifyHierarchy is the 'show configuration' argument that shows a
// statement's hierarchy.
func junosVerifyHierarchy(text string) string {
	t := splitTokens(text)
	if len(t) > 0 && (t[0] == "set" || t[0] == "delete" || t[0] == "insert" || t[0] == "deactivate") {
		t = t[1:]
	}
	switch {
	case len(t) == 0:
		return ""
	case t[0] == "system" && len(t) >= 2:
		return "system " + t[1]
	case t[0] == "snmp":
		return "snmp"
	case t[0] == "firewall" && len(t) >= 5:
		return joinTokens(t[:5])
	}
	return t[0]
}

// junosRegion is `configure private`, one label per section and its
// statements, `show | compare | no-more` (the one line that prints; the
// pager would swallow what follows), `commit check`, and the confirmed
// commit as the last line. [S: lab check L2: '#' lines are accepted in
// configuration mode; L5: a refused `configure private` leaves every later
// line an unknown operational command.]
func junosRegion(d Delta, h Header, w Wrapper) []RegionLine {
	out := []RegionLine{{Text: "configure private", Line: -1}}
	cur := ""
	for i, l := range d.Lines {
		if l.Section != cur {
			cur = l.Section
			why, _, _ := strings.Cut(d.Of(cur).Why, "; ")
			if why == "" {
				why = "the statements tacctl renders"
			}
			out = append(out, RegionLine{Text: "# " + cur + ": " + why, Comment: true, Line: -1})
		}
		if l.Secret && !l.HasValue && strings.Contains(l.Text, "<SECRET>") {
			out = append(out, RegionLine{Text: "# " + secretLinePrefix + l.Text, Comment: true, Line: i})
			continue
		}
		out = append(out, RegionLine{Text: l.Text, Line: i})
	}
	out = append(out,
		RegionLine{Text: "show | compare | no-more", Line: -1},
		RegionLine{Text: "commit check", Line: -1},
		RegionLine{Text: junosCommitConfirmed(confirmMinutes(w), h), Line: -1})
	return out
}

// junosAfter is what follows the region: the refused-configure note, the
// check, the one line to type, the back-out, what not to do. Everything is a
// comment line but the one word.
func junosAfter(d Delta, h Header, w Wrapper) string {
	var b strings.Builder
	n := confirmMinutes(w)
	c := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString("# " + l + "\n")
		}
	}
	b.WriteString("#\n")
	c("If the first line printed \"Users currently editing the configuration\" or \"error: shared configuration database modified\": nothing happened; ask that person to commit or roll back, then paste again. If any line printed \"error:\", stop and type:  rollback 0")
	b.WriteString("#\n")
	c("Check now. In " + strconv.Itoa(n) + " minutes the switch undoes this by itself unless you type one word.")
	b.WriteString("#   From the tacctl server:   tacctl device config pull " + h.Device + " --diff     (" + joinAnd(d.Planned()) + ": ok)\n")
	b.WriteString("#   In a second terminal:     ssh " + h.Device + ", then: show cli authorization | no-more\n")
	var shown []string
	for _, l := range d.Lines {
		if v := junosVerifyHierarchy(l.Shown()); v != "" && !containsStr(shown, v) {
			shown = append(shown, v)
		}
	}
	for _, v := range shown {
		b.WriteString("#                             show configuration " + v + " | no-more\n")
	}
	c("If both are fine, type this one word in the pasting session, before the " + strconv.Itoa(n) + " minutes end:")
	b.WriteString("commit\n")
	b.WriteString("#\n")
	c("If your session drops before that, the switch still rolls back when the time runs out (a dropped CLI session does not roll back at once): log in again and paste again. To undo after the commit: show system commit, then rollback <n> of the entry just before the one commented \"tacctl plan " + commentSafe(h.Device) + "\" (the newest entry is that commit itself), then commit.")
	c("Do not: type commit before the check; paste anything outside the banners; paste this into another device; use configure exclusive; keep this output in a file after the paste when it holds a secret.")
	return b.String()
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
