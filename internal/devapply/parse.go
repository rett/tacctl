package devapply

// The fail-closed parsers of the Junos answers. Each takes the text of one
// command and returns what it means or an error; a text it does not know is
// an error, never an empty or a successful answer.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devssh"
)

// lines splits an answer into lines without their trailing blanks.
func lines(out string) []string {
	out = strings.ReplaceAll(out, "\r", "")
	ls := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimRight(l, " \t")
	}
	if len(ls) == 1 && ls[0] == "" {
		return nil
	}
	return ls
}

// nonBlank drops the empty lines.
func nonBlank(ls []string) []string {
	var out []string
	for _, l := range ls {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// configAnswer is the answer of a command typed in configuration mode: the
// lines before the location line ('[edit]', '{master:0}[edit]') that ends
// it. No location line at the end means the session is not in configuration
// mode (or the device printed something the parser does not know): ok is
// false.
//
// A pending commit's banner right before the location line is the prompt's
// and not the answer's (devssh drops it as the device prints it before
// every prompt; one whose minutes changed between two prompts stays): it is
// dropped too.
func configAnswer(out string) (body []string, ok bool) {
	ls := lines(out)
	for len(ls) > 0 && strings.TrimSpace(ls[len(ls)-1]) == "" {
		ls = ls[:len(ls)-1]
	}
	if len(ls) == 0 || !devssh.LocationLine(strings.TrimSpace(ls[len(ls)-1])) {
		return nonBlank(ls), false
	}
	return trimPromptArea(ls[:len(ls)-1]), true
}

// trimPromptArea drops what the device prints before a prompt from the end
// of an answer: blank lines, the banner of a pending commit and a switch's
// '{master:0}' line.
func trimPromptArea(ls []string) []string {
	for len(ls) > 0 {
		t := strings.TrimSpace(ls[len(ls)-1])
		if t != "" && !reBanner.MatchString(t) && !reSwitchLine.MatchString(t) {
			break
		}
		ls = ls[:len(ls)-1]
	}
	return ls
}

// parseBanner reads the prompt area of a shell session (devssh.PromptArea):
// blank lines, a switch's '{master:0}' line and the banner of a pending
// confirmed commit. Any other line is an error (fail closed: a prompt area
// tacctl does not know is never read as 'nothing pending').
func parseBanner(area []string) (pending bool, minutes int, err error) {
	for _, l := range area {
		t := strings.TrimSpace(l)
		switch m := reBanner.FindStringSubmatch(t); {
		case t == "" || reSwitchLine.MatchString(t):
		case m != nil:
			n, _ := strconv.Atoi(m[1])
			if pending && n != minutes {
				return false, 0, fmt.Errorf("the prompt: two banners %q: %w", cut(t), ErrUnrecognised)
			}
			pending, minutes = true, n
		default:
			return false, 0, fmt.Errorf("the prompt: a line %q: %w", cut(t), ErrUnrecognised)
		}
	}
	return pending, minutes, nil
}

// exactly reports whether the non-blank lines are want, in order.
func exactly(body []string, want ...string) bool {
	got := nonBlank(body)
	if len(got) != len(want) {
		return false
	}
	for i, w := range want {
		if strings.TrimSpace(got[i]) != w {
			return false
		}
	}
	return true
}

// parseVersion reads 'show version': one hostname, one release (a virtual
// chassis prints the block per member; the members must agree). A line of
// the error table is a refusal.
func parseVersion(out string) (Identity, error) {
	ls := lines(out)
	if row := classify(ls); row != "" {
		return Identity{}, answerError("show version", ls, nil)
	}
	var id Identity
	set := func(dst *string, v string) error {
		if *dst != "" && *dst != v {
			return fmt.Errorf("show version: two values %q and %q: %w", cut(*dst), cut(v), ErrUnrecognised)
		}
		*dst = v
		return nil
	}
	for _, l := range ls {
		m := reVersionField.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		var err error
		switch m[1] {
		case "Hostname":
			err = set(&id.Hostname, m[2])
		case "Model":
			err = set(&id.Model, m[2])
		case "Junos":
			err = set(&id.Release, m[2])
		}
		if err != nil {
			return Identity{}, err
		}
	}
	if id.Hostname == "" || id.Release == "" {
		return Identity{}, fmt.Errorf("show version: no Hostname or Junos line: %w", ErrUnrecognised)
	}
	return id, nil
}

// parseHistory reads 'show system commit'. Every non-blank line is an entry
// or the indented comment of the entry before it; anything else is an
// error. The rescue line a saved rescue configuration adds is a marker, no
// entry: it is accepted only after the numbered entries, once, and the
// comment below it is its own. Entry 0 must be complete (a tail the parser does not know there
// makes the pending state unknowable, so it is an error); a later entry's
// unknown tail is kept as it is.
func parseHistory(out string) (History, error) {
	ls := lines(out)
	if row := classify(ls); row != "" {
		return nil, answerError("show system commit", ls, nil)
	}
	var h History
	rescue := false
	for _, l := range ls {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if reHistoryRescue.MatchString(l) {
			if len(h) == 0 || rescue {
				return nil, fmt.Errorf("show system commit: a line %q: %w", cut(strings.TrimSpace(l)), ErrUnrecognised)
			}
			rescue = true
			continue
		}
		if rescue && reHistoryEntry.MatchString(l) {
			return nil, fmt.Errorf("show system commit: entry after the rescue line: %w", ErrUnrecognised)
		}
		if m := reHistoryEntry.FindStringSubmatch(l); m != nil {
			seq, _ := strconv.Atoi(m[1])
			if seq != len(h) {
				return nil, fmt.Errorf("show system commit: entry %d where %d was expected: %w", seq, len(h), ErrUnrecognised)
			}
			e := CommitEntry{Seq: seq, TimeText: m[2], User: m[3], Via: m[4]}
			for _, layout := range historyTimeLayouts {
				if t, err := time.Parse(layout, m[2]); err == nil {
					e.Time = t
					break
				}
			}
			if e.Time.IsZero() {
				return nil, fmt.Errorf("show system commit: a time %q: %w", cut(m[2]), ErrUnrecognised)
			}
			if tail := strings.TrimSpace(m[5]); tail != "" {
				if r := reRollbackIn.FindStringSubmatch(tail); r != nil {
					e.RollbackIn, _ = strconv.Atoi(r[1])
				} else if seq == 0 {
					return nil, fmt.Errorf("show system commit: entry 0 ends %q: %w", cut(tail), ErrUnrecognised)
				}
			}
			h = append(h, e)
			continue
		}
		if (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")) && len(h) > 0 {
			if rescue {
				continue
			}
			c := strings.TrimSpace(l)
			if h[len(h)-1].Comment != "" {
				h[len(h)-1].Comment += " " + c
			} else {
				h[len(h)-1].Comment = c
			}
			continue
		}
		return nil, fmt.Errorf("show system commit: a line %q: %w", cut(strings.TrimSpace(l)), ErrUnrecognised)
	}
	if len(h) == 0 {
		return nil, fmt.Errorf("show system commit: no entry: %w", ErrUnrecognised)
	}
	return h, nil
}

// parseAuthorization reads 'show cli authorization': the class from the
// first line, the permissions from the indented lines under
// 'Permissions:'.
func parseAuthorization(out string) (Login, error) {
	ls := nonBlank(lines(out))
	if row := classify(ls); row != "" {
		return Login{}, answerError("show cli authorization", ls, nil)
	}
	if len(ls) == 0 {
		return Login{}, fmt.Errorf("show cli authorization: no answer: %w", ErrUnrecognised)
	}
	m := reAuthClass.FindStringSubmatch(ls[0])
	if m == nil {
		return Login{}, fmt.Errorf("show cli authorization: no class on %q: %w", cut(ls[0]), ErrUnrecognised)
	}
	lg := Login{Class: m[1]}
	if u := reAuthUser.FindStringSubmatch(ls[0]); u != nil {
		lg.User, lg.Name = u[1], u[2]
	}
	in := false
	seen := false
	for _, l := range ls[1:] {
		t := strings.TrimSpace(l)
		switch {
		case t == "Permissions:":
			in, seen = true, true
		case in && (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")):
			for _, w := range strings.Fields(t) {
				if !slices.Contains(lg.Permissions, w) {
					lg.Permissions = append(lg.Permissions, w)
				}
			}
		default:
			in = false
		}
	}
	if !seen {
		return Login{}, fmt.Errorf("show cli authorization: no Permissions block: %w", ErrUnrecognised)
	}
	return lg, nil
}

// lockedBy reads the holder from the answer of a refused 'configure
// exclusive': the first word of the line after the refusal [C: '  admin
// terminal pts/0 (pid 84557) on since 2026-10-13 20:02:28 AKDT'].
func lockedBy(body []string) string {
	body = nonBlank(body)
	for i, l := range body {
		if strings.Contains(l, textLocked) && i+1 < len(body) {
			if f := strings.Fields(body[i+1]); len(f) > 0 {
				return cut(f[0])
			}
		}
	}
	return ""
}

// exclusiveEditor reads the editors a shared 'configure' listed: the user
// of an editor whose mode line begins 'exclusive' [C: '      exclusive
// {master:0}[edit]'], ok false when none holds the lock.
func exclusiveEditor(body []string) (user string, ok bool) {
	body = nonBlank(body)
	in := false
	for i, l := range body {
		f := strings.Fields(l)
		switch {
		case strings.Contains(l, textUsersEditing):
			in = true
		case in && i > 0 && len(f) > 0 && f[0] == "exclusive":
			if p := strings.Fields(body[i-1]); len(p) > 0 {
				return cut(p[0]), true
			}
			return "", true
		}
	}
	return "", false
}
