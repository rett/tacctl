package plan

// The Junos region and its after-steps (plan §3, D96, D108, D109).

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The words of an apply (0.2.9 plan D131 and §3.1): every line the driver
// types beside the delta's own statements. They are data and not execution:
// the driver sends them, and its command log is asserted to hold nothing but
// the statements Allow passes and these (IsApplyWord). [A: the texts of
// the device's answers are WP14.0's L1/L2/L5 captures; the words typed are
// the helper's and the Junos reference's.]
const (
	// ApplyConfigure is the throwaway shared session of the gate (step 3).
	ApplyConfigure = "configure"
	// ApplyConfigureExclusive is the held session of the transaction
	// (step 4); there is no private one: a private session refuses `commit
	// confirmed` (lab L5).
	ApplyConfigureExclusive = "configure exclusive"
	// ApplyCompare is the candidate against the committed configuration
	// (steps 3 and 6; the pager would swallow what follows without no-more).
	ApplyCompare = "show | compare | no-more"
	// ApplyCommitCheck is step 7; it ends a check.
	ApplyCommitCheck = "commit check"
	// ApplyRollback0 discards the candidate; ApplyRollback1 loads the
	// previous configuration, which Cancel commits (D131).
	ApplyRollback0 = "rollback 0"
	ApplyRollback1 = "rollback 1"
	// ApplyExit leaves configuration mode, ApplyQuit the session.
	ApplyExit = "exit"
	ApplyQuit = "quit"
	// The reads of the pre-flight (step 1) and the verification (step 9).
	ApplyShowVersion       = "show version"
	ApplyShowCommit        = "show system commit"
	ApplyShowAuthorization = "show cli authorization"
	// ApplyLandedCompare is the landed compare of step 9: the committed
	// configuration against rollback 1, in operational mode (lab L3; `show |
	// compare rollback 1` in configure mode).
	ApplyLandedCompare = "show configuration | compare rollback 1 | no-more"
)

// ApplyRollbackCompare is the settle's read (D132): the configuration
// against rollback n, in operational mode. It is empty exactly when the
// configuration is the one commit n of the history produced.
func ApplyRollbackCompare(n int) string {
	return "show configuration | compare rollback " + strconv.Itoa(n) + " | no-more"
}

// MaxRollback is the highest rollback a Junos device keeps.
const MaxRollback = 49

var reApplyRollbackCompare = regexp.MustCompile(`^show configuration \| compare rollback ([0-9]|[1-4][0-9]) \| no-more$`)

// The phrases an apply requires of the device's output ([S: the helper];
// a text the driver does not know is a failure).
const (
	// ApplyCheckOK is what `commit check` prints (step 7).
	ApplyCheckOK = "configuration check succeeds"
	// ApplyCommitComplete is what the confirming `commit` prints (step 11).
	ApplyCommitComplete = "commit complete"
)

// ApplyConfirmedNote is the line `commit confirmed N` prints (step 8),
// between `configuration check succeeds` and `commit complete` [lab L1;
// `1 minutes` for N=1].
func ApplyConfirmedNote(minutes int) string {
	return "commit confirmed will be automatically rolled back in " + strconv.Itoa(confirmMinutes(Wrapper{ConfirmMinutes: minutes})) + " minutes unless confirmed"
}

// ApplyCommitConfirmed is step 8: the confirmed commit with its comment.
// minutes is clamped to 1-60 (5 when 0); id and user are made safe for the
// comment's quotes.
func ApplyCommitConfirmed(minutes int, id, user string) string {
	return "commit confirmed " + strconv.Itoa(confirmMinutes(Wrapper{ConfirmMinutes: minutes})) +
		" comment \"tacctl apply " + commentSafe(id) + " by " + commentSafe(user) + "\""
}

// ApplyConfirm is step 11: the commit that confirms, in the session that
// committed.
func ApplyConfirm(id, user string) string {
	return "commit comment \"tacctl apply confirm " + commentSafe(id) + " by " + commentSafe(user) + "\""
}

// ApplyCancel is the commit that follows `rollback 1` after a failure
// past step 8 (D131 Cancel).
func ApplyCancel(id string) string {
	return "commit comment \"tacctl apply cancel " + commentSafe(id) + "\""
}

// applyFixed are the words that are typed as they are, with the variants
// the pager asks for.
var applyFixed = []string{
	ApplyConfigure, ApplyConfigureExclusive,
	ApplyCompare, ApplyCommitCheck, ApplyRollback0, ApplyRollback1,
	ApplyExit, ApplyQuit,
	ApplyShowVersion, ApplyShowVersion + " | no-more",
	ApplyShowCommit, ApplyShowCommit + " | no-more",
	ApplyShowAuthorization, ApplyShowAuthorization + " | no-more",
	ApplyLandedCompare, "show configuration | compare rollback 1",
}

// ApplyWords returns the fixed words of an apply, sorted. The commit
// lines carry an id and a user and are ApplyCommitConfirmed,
// ApplyConfirm and ApplyCancel.
func ApplyWords() []string {
	out := slices.Clone(applyFixed)
	sort.Strings(out)
	return out
}

const safeWord = `[A-Za-z0-9._@:/_-]+`

var (
	reApplyConfirmed = regexp.MustCompile(`^commit confirmed ([1-9]|[1-5][0-9]|60) comment "tacctl apply ` + safeWord + ` by ` + safeWord + `"$`)
	reApplyConfirm   = regexp.MustCompile(`^commit comment "tacctl apply confirm ` + safeWord + ` by ` + safeWord + `"$`)
	reApplyCancel    = regexp.MustCompile(`^commit comment "tacctl apply cancel ` + safeWord + `"$`)
)

// IsApplyWord reports whether a line is one of the apply's own words (a
// fixed word or one of the three commit lines) and not a statement.
func IsApplyWord(line string) bool {
	return slices.Contains(applyFixed, line) || reApplyRollbackCompare.MatchString(line) ||
		reApplyConfirmed.MatchString(line) || reApplyConfirm.MatchString(line) || reApplyCancel.MatchString(line)
}

// junosCommitWord is the last line of a region and the only commit it holds;
// word names what it commits ('plan', 'backout', 'cleanup'). [A: lab check
// L3 was not run (a commit needs a separate go-ahead): the 'commit confirmed
// <minutes> comment "..."' syntax is the Junos reference's, and the 0.2.4
// spike (d) confirmed the CLI's 'commit confirmed N' and its expiry.]
func junosCommitWord(word string, minutes int, h Header) string {
	return "commit confirmed " + strconv.Itoa(minutes) + " comment \"tacctl " + word + " " + commentSafe(h.Device) + " " +
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
	case t[0] == "system" && len(t) >= 3 && t[1] == "login" && (t[2] == "message" || t[2] == "announcement"):
		return "system login " + t[2]
	case t[0] == "system" && len(t) >= 2:
		return "system " + t[1]
	case t[0] == "snmp":
		return "snmp"
	case t[0] == "firewall" && len(t) >= 5:
		return joinTokens(t[:5])
	}
	return t[0]
}

// junosRegion is `configure exclusive`, one label per section and its
// statements, `show | compare | no-more` (the one line that prints; the
// pager would swallow what follows), `commit check`, and the confirmed
// commit as the last line. [S: lab check L2: '#' lines are accepted in
// configuration mode; 0.2.9 lab L5: a private session refuses `commit
// confirmed`, an exclusive one takes it; a refused `configure exclusive`
// leaves every later line an unknown operational command.]
func junosRegion(d Delta, h Header, w Wrapper) []RegionLine {
	return junosRegionWord(d, h, w, "plan")
}

// junosRegionWord is junosRegion for the region word of the commit comment:
// 'plan' for the plan's region, 'cleanup' for the --converge region.
func junosRegionWord(d Delta, h Header, w Wrapper, word string) []RegionLine {
	out := []RegionLine{{Text: ApplyConfigureExclusive, Wrapper: true, Line: -1}}
	cur, from := "", ""
	for i, l := range d.Lines {
		if l.Section != cur {
			cur, from = l.Section, ""
			why, _, _ := strings.Cut(d.Of(cur).Why, "; ")
			if why == "" {
				why = "the statements tacctl renders"
			}
			out = append(out, RegionLine{Text: "# " + cur + ": " + why, Comment: true, Line: -1})
		}
		if o := d.originOf(l); o != "" && o != from {
			from = o
			out = append(out, RegionLine{Text: "# from " + o, Comment: true, Line: -1})
		}
		if l.Secret && !l.HasValue && strings.Contains(l.Text, "<SECRET>") {
			out = append(out, RegionLine{Text: "# " + secretLinePrefix + l.Text, Comment: true, Line: i})
			continue
		}
		out = append(out, RegionLine{Text: l.Text, Line: i})
	}
	out = append(out,
		RegionLine{Text: "show | compare | no-more", Wrapper: true, Line: -1},
		RegionLine{Text: "commit check", Wrapper: true, Line: -1},
		RegionLine{Text: junosCommitWord(word, confirmMinutes(w), h), Wrapper: true, Line: -1})
	return out
}

// junosBackoutRegion is the back-out as a region: the same wrapper as the
// plan's, the lines that put the pulled statements back, the confirmed
// commit last. A line that holds the placeholder of --no-secrets, or that
// is a note, is a comment.
func junosBackoutRegion(d Delta, h Header, w Wrapper) []RegionLine {
	out := []RegionLine{{Text: ApplyConfigureExclusive, Wrapper: true, Line: -1},
		{Text: "# back-out: the statements as the pull showed them", Comment: true, Line: -1}}
	for _, l := range d.Backout {
		switch {
		case l.Op == OpComment:
			out = append(out, RegionLine{Text: "# " + l.Text, Comment: true, Line: -1})
		case l.Secret && !l.HasValue && strings.Contains(l.Text, "<SECRET>"):
			out = append(out, RegionLine{Text: "# " + secretLinePrefix + l.Text, Comment: true, Line: -1})
		default:
			out = append(out, RegionLine{Text: l.Text, Line: -1})
		}
	}
	out = append(out,
		RegionLine{Text: "show | compare | no-more", Wrapper: true, Line: -1},
		RegionLine{Text: "commit check", Wrapper: true, Line: -1},
		RegionLine{Text: junosCommitWord("backout", confirmMinutes(w), h), Wrapper: true, Line: -1})
	return out
}

// junosBackoutAfter is what follows the back-out region: comments only.
func junosBackoutAfter(d Delta, h Header, w Wrapper) string {
	var b strings.Builder
	n := confirmMinutes(w)
	c := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString("# " + l + "\n")
		}
	}
	b.WriteString("#\n")
	c("If the first line printed \"error: configuration database modified\" or \"error: configuration database locked by\": nothing happened (see the note above the region); paste again once it is cleared. If any line printed \"error:\": do not type commit; the switch undoes this by itself in " + strconv.Itoa(n) + " minutes.")
	b.WriteString("#\n")
	c("Check now. In " + strconv.Itoa(n) + " minutes the switch undoes this by itself unless you type one word.")
	b.WriteString("#   From the tacctl server:   tacctl device config pull " + h.Device + " --diff     (the differences of the plan are back)\n")
	b.WriteString("#   In a second terminal:     ssh " + h.Device + ", then: show cli authorization | no-more\n")
	b.WriteString("# When both checks are fine, type this one word yourself:  commit     (before the " + strconv.Itoa(n) + " minutes end)\n")
	c("Then type exit: the session holds the configuration lock until you do.")
	b.WriteString("#\n")
	c("A value that tacctl does not hold (an original secret) is a line marked with # inside the region: put it back by hand.")
	c("Do not: type commit before the check; paste anything outside the banners; paste this into another device; keep this output in a file after the paste when it holds a secret.")
	b.WriteString(lockoutHelp(d, h))
	return b.String()
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
	c("If the first line printed \"error: configuration database modified\" or \"error: configuration database locked by\": nothing happened (see the note above the region); paste again once it is cleared. If any line printed \"error:\": do not type commit; the switch undoes this by itself in " + strconv.Itoa(n) + " minutes.")
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
	// a comment line, never a plain one: a copy of the whole output must not
	// confirm the commit before the check (review H1)
	b.WriteString("# When both checks are fine, type this one word yourself:  commit     (before the " + strconv.Itoa(n) + " minutes end)\n")
	c("Then type exit: the session holds the configuration lock until you do.")
	b.WriteString("#\n")
	c("If your session drops before that, the switch still rolls back when the time runs out (a dropped CLI session does not roll back at once): log in again and paste again.")
	if HasBackout(d) {
		c("To undo it after the commit: tacctl device config plan " + h.Device + " --backout     (its own region to paste; tacctl keeps this plan's back-out: after the check pull has replaced the picture, the command still prints this plan's, and says which pull it undoes, until the next plan with changes). Without tacctl: show system commit, then rollback <n> of the entry just before the one commented \"tacctl plan " + commentSafe(h.Device) + "\" (the newest entry is that commit itself), then commit.")
	} else {
		c("To undo it after the commit: show system commit, then rollback <n> of the entry just before the one commented \"tacctl plan " + commentSafe(h.Device) + "\" (the newest entry is that commit itself), then commit. tacctl has no lines of its own to undo this plan.")
	}
	c("Do not: type commit before the check; paste anything outside the banners; paste this into another device; keep this output in a file after the paste when it holds a secret.")
	b.WriteString(lockoutHelp(d, h))
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

// junosSessionNote is the comment block above a Junos region: the region
// opens `configure exclusive`, the session holds the configuration lock until
// `exit`, and what a refusal means (0.2.9 lab L1: `error: configuration
// database modified` for another session's uncommitted shared changes,
// `error: configuration database locked by: <holder>` for another exclusive
// session).
const junosSessionNote = "The region opens configure exclusive: the session holds the configuration lock until you type exit " +
	"(after commit, to confirm). If it printed \"error: configuration database modified\", another session has " +
	"uncommitted changes: have that person commit or discard them, then paste again. If it printed " +
	"\"error: configuration database locked by\", another session holds the exclusive lock: wait for it to exit, then paste again. " +
	"Either way nothing happened (every later line is an unknown command)."
