package devrollout

// The device texts of the Junos command line and the error table (0.2.9 plan
// §5, D131 steps 3-11), in one place so that the lab spike (WP14.0, L1, L2,
// L5) corrects them here and nowhere else.
//
// [L] Every text below that is not marked [S] is the helper script's
// observed phrase or the Junos reference's, NOT confirmed on a device by
// tacctl: the prompts' location line, the refusals of 'configure
// exclusive', the answers to 'rollback N', the layout of 'show system
// commit' (the time, 'by <user> via <how>', the indented comment), the
// expiry's history entry ('by root via other'), the layout of 'show cli
// authorization' and of 'show version'. Each parser fails closed, so a
// text that differs on a device is a failure that names the text, never a
// success.

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// The answers the transport requires or recognises.
const (
	// textEnterConfig is the answer to 'configure', 'configure exclusive'
	// and 'configure private'.
	textEnterConfig = "Entering configuration mode"
	// textExitConfig is the answer to 'exit' in configuration mode.
	textExitConfig = "Exiting configuration mode"
	// textLoadComplete is the answer to 'rollback 0' and 'rollback 1'.
	textLoadComplete = "load complete"
	// textNotFound is the one tolerated answer, to a 'delete' of an absent
	// node (D131 step 5).
	textNotFound = "warning: statement not found"
	// textUsersEditing heads the list of the other editors after a shared
	// 'configure' (the gate).
	textUsersEditing = "Users currently editing the configuration"
	// textNotCommitted is a shared candidate's staged change.
	textNotCommitted = "The configuration has been changed but not committed"
	// textLocked is the refusal of 'configure' under another session's
	// exclusive lock; the next line names the holder.
	textLocked = "error: configuration database locked by"
	// textModified is the refusal of 'configure exclusive' over a staged
	// change.
	textModified = "error: configuration database modified"
	// textNoConfirmedPrivate is the private session's refusal of 'commit
	// confirmed' on some releases (the helper's phrase is the prefix).
	textNoConfirmedPrivate = "error: commit confirmed not supported for private"
	// textExpiryUser and textExpiryVia are the history entry of the
	// device's own rollback at the end of a confirmed commit's window.
	textExpiryUser = "root"
	textExpiryVia  = "other"
)

// The success phrases are the plan package's [S].
var (
	textCheckOK        = plan.RolloutCheckOK
	textCommitComplete = plan.RolloutCommitComplete
)

// reHistoryEntry is one entry of 'show system commit':
// '0   2026-10-13 14:12:01 UTC by alice via cli commit confirmed, rollback in 10mins'.
var reHistoryEntry = regexp.MustCompile(`^(\d+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?: [A-Za-z][A-Za-z0-9+-]*)?) by (\S+) via (\S+)(?:\s+(.*))?$`)

// reRollbackIn is the tail of a confirmed commit's entry.
var reRollbackIn = regexp.MustCompile(`^commit confirmed, rollback in (\d+) ?mins?$`)

// historyTimeLayouts are the layouts of an entry's time (with a zone
// abbreviation, or without one).
var historyTimeLayouts = []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05"}

// reAuthClass finds the class on the first line of 'show cli authorization'
// ('Current user: alice login: alice class: super-user', quotes optional).
var reAuthClass = regexp.MustCompile(`\bclass:?\s+'?([A-Za-z0-9_.@-]+)'?`)

// reVersionField is a 'Hostname: x', 'Model: y' or 'Junos: z' line of 'show
// version'.
var reVersionField = regexp.MustCompile(`^(Hostname|Model|Junos):\s+(\S+)\s*$`)

// ErrorRow is one row of the error table: an answer line that matches
// Pattern is a refusal named Name.
type ErrorRow struct {
	Name    string
	Pattern *regexp.Regexp
}

// errorTable is the helper's ERROR_WORDS as data (plan §5). It is matched
// against one command's own answer, never against a compare or a read.
var errorTable = []ErrorRow{
	{"error", regexp.MustCompile(`(?i)^\s*error:`)},
	{"syntax error", regexp.MustCompile(`(?i)syntax error`)},
	{"unknown command", regexp.MustCompile(`(?i)unknown command`)},
	{"missing argument", regexp.MustCompile(`(?i)missing argument`)},
	{"invalid", regexp.MustCompile(`(?i)invalid (command|value)`)},
	{"not authorized", regexp.MustCompile(`(?i)not authorized`)},
	{"permission denied", regexp.MustCompile(`(?i)permission denied`)},
	{"database locked", regexp.MustCompile(`(?i)configuration database locked`)},
	{"database modified", regexp.MustCompile(`(?i)configuration database modified`)},
	{"users editing", regexp.MustCompile(`(?i)users currently editing`)},
	{"not committed", regexp.MustCompile(`(?i)changed but not committed`)},
}

// ErrorTable returns the rows of the error table.
func ErrorTable() []ErrorRow { return append([]ErrorRow(nil), errorTable...) }

// classify names the first row of the error table a line of the answer
// matches ("" none).
func classify(lines []string) string {
	for _, l := range lines {
		for _, r := range errorTable {
			if r.Pattern.MatchString(l) {
				return r.Name
			}
		}
	}
	return ""
}

// The typed errors of a transport. A caller tells them apart with errors.Is
// and errors.As, never by text.
var (
	// ErrRefused: the device answered with a line of the error table.
	ErrRefused = errors.New("the device refused")
	// ErrUnrecognised: the device answered with a text the parser does not
	// know (fail closed: never taken for success).
	ErrUnrecognised = errors.New("the device's answer is not recognised")
	// ErrSessionLost: the held session (or the connection) ended; nothing
	// more can be typed in it.
	ErrSessionLost = errors.New("the held session is lost")
	// ErrNotSent: the transport refused to send a line (not a rollout word,
	// not an allowed statement, or not in the right state).
	ErrNotSent = errors.New("not sent")
)

// AnswerError is a command whose answer was a refusal or not recognised.
// Cmd is the command as it may be shown (a secret's value elided), Lines the
// answer's lines (cut short, a secret's value elided), Row the error table's
// row ("" for an answer no row names).
type AnswerError struct {
	Cmd   string
	Lines []string
	Row   string
	base  error
}

func (e *AnswerError) Error() string {
	msg := strings.Join(e.Lines, "; ")
	if msg == "" {
		msg = "no answer"
	}
	return fmt.Sprintf("%s: %s", e.Cmd, msg)
}

// Unwrap is ErrRefused or ErrUnrecognised.
func (e *AnswerError) Unwrap() error { return e.base }

// Message is the answer as one line.
func (e *AnswerError) Message() string {
	if len(e.Lines) == 0 {
		return "no answer"
	}
	return strings.Join(e.Lines, "; ")
}

// LockedError is a configuration database another session holds or has
// changed: 'configure' or 'configure exclusive' was refused.
type LockedError struct {
	// By is the holder of the exclusive lock ("" when the device did not
	// name one).
	By string
	// Modified is set for a staged change in the shared candidate.
	Modified bool
}

func (e *LockedError) Error() string {
	if e.Modified {
		return "the configuration database is modified (a staged change)"
	}
	if e.By == "" {
		return "the configuration database is locked"
	}
	return "the configuration database is locked by " + e.By
}

// Unwrap is ErrRefused.
func (e *LockedError) Unwrap() error { return ErrRefused }

// maxAnswerLines is how many lines of an answer an error carries; maxLine
// the longest line.
const (
	maxAnswerLines = 6
	maxLine        = 200
)

// answerError builds the error of an answer; m elides the secrets of cmd.
func answerError(cmd string, lines []string, m *masker) *AnswerError {
	row := classify(lines)
	base := ErrUnrecognised
	if row != "" {
		base = ErrRefused
	}
	var kept []string
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if len(kept) == maxAnswerLines {
			kept = append(kept, "...")
			break
		}
		kept = append(kept, cut(m.text(strings.TrimSpace(l))))
	}
	return &AnswerError{Cmd: m.text(cmd), Lines: kept, Row: row, base: base}
}

// cut shortens a line and replaces its control characters.
func cut(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxLine {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
