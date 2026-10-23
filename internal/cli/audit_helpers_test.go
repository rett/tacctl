package cli

import (
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/execx/fake"
)

// The audit lines of a run, read from the fake runner's record of the
// logger calls (docs/plans/0.2.17-plan.md D255 item 8). A line carries the
// process's session id as its last key (internal/audit); the helpers cut it,
// so a test asserts the content that the verb wrote and is not tied to the
// id or to how many calls a run made. auditSID says what the cut part was.

// auditCall is one logger call: its tag, priority and message, the message
// without the session id (Line) and the id (SID, "" when the message has
// none).
type auditCall struct {
	Tag, Priority, Line, SID string
}

var reAuditSID = regexp.MustCompile(` sid=([a-z0-9]{8})$`)

// cutAuditSID is msg without its trailing ' sid=<id>' and the id.
func cutAuditSID(msg string) (line, sid string) {
	if m := reAuditSID.FindStringSubmatch(msg); m != nil {
		return strings.TrimSuffix(msg, m[0]), m[1]
	}
	return msg, ""
}

// auditCalls are the logger calls of the run, in order, of every tag.
func auditCalls(r *fake.Runner) []auditCall {
	var out []auditCall
	for _, c := range r.Calls() {
		if c.Name != "logger" || len(c.Args) != 5 || c.Args[0] != "-t" || c.Args[2] != "-p" {
			continue
		}
		line, sid := cutAuditSID(c.Args[4])
		out = append(out, auditCall{Tag: c.Args[1], Priority: c.Args[3], Line: line, SID: sid})
	}
	return out
}

// auditLines are the lines the run's tacctl command wrote (tag tacctl, not
// the console's own), without the session id.
func auditLines(r *fake.Runner) []string {
	var out []string
	for _, c := range auditCalls(r) {
		if c.Tag == "tacctl" {
			out = append(out, c.Line)
		}
	}
	return out
}

// auditLine is the first line of the run that starts with prefix, "" if
// none.
func auditLine(r *fake.Runner, prefix string) string {
	for _, l := range auditLines(r) {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

// hasAudit reports whether the run wrote exactly line at priority.
func hasAudit(r *fake.Runner, priority, line string) bool { return auditCount(r, priority, line) > 0 }

// auditCount is how many times the run wrote exactly line at priority.
func auditCount(r *fake.Runner, priority, line string) int {
	n := 0
	for _, c := range auditCalls(r) {
		if c.Tag == "tacctl" && c.Priority == priority && c.Line == line {
			n++
		}
	}
	return n
}

// hasAuditPrefix reports whether the run wrote a line that starts with
// prefix at priority ("" for any priority).
func hasAuditPrefix(r *fake.Runner, priority, prefix string) bool {
	for _, c := range auditCalls(r) {
		if c.Tag == "tacctl" && (priority == "" || c.Priority == priority) && strings.HasPrefix(c.Line, prefix) {
			return true
		}
	}
	return false
}

// hasAuditMatch reports whether the run wrote a line that the regular
// expression matches at priority ("" for any priority); the expression
// sees the line without the session id, so '$' ends it.
func hasAuditMatch(r *fake.Runner, priority, pattern string) bool {
	re := regexp.MustCompile(pattern)
	for _, c := range auditCalls(r) {
		if c.Tag == "tacctl" && (priority == "" || c.Priority == priority) && re.MatchString(c.Line) {
			return true
		}
	}
	return false
}

// wroteAudit reports whether the run wrote any line at all (of any tag).
func wroteAudit(r *fake.Runner) bool { return len(auditCalls(r)) > 0 }

// auditSID is the session id the run's lines share: "" when it wrote none;
// the test fails (through ok false) when two lines carry different ids.
func auditSID(r *fake.Runner) (sid string, ok bool) {
	for _, c := range auditCalls(r) {
		if sid == "" {
			sid = c.SID
		} else if c.SID != sid {
			return sid, false
		}
	}
	return sid, true
}

// nonAuditArgvs are the commands the run started other than logger.
func nonAuditArgvs(r *fake.Runner) []string {
	var out []string
	for _, c := range r.Calls() {
		if c.Name != "logger" {
			out = append(out, c.Name+" "+strings.Join(c.Args, " "))
		}
	}
	return out
}
