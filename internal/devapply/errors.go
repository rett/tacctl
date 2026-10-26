package devapply

// The device texts of the Junos command line and the error table (0.2.9 plan
// §5, D131 steps 3-11), in one place.
//
// [C] marks a text the lab spike captured on Junos 25.4
// (docs/plans/0.2.9-lab.md, tests/fixtures/devconf/juniper/apply/
// texts.txt). The others are the helper script's observed phrases or the
// Junos reference's, not confirmed on a device by tacctl: the gate's editor
// texts, 'database modified', 'statement not found', the layout of 'show
// cli authorization' and of 'show version'. Each parser fails closed, so a
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
	// textEnterConfig is the answer to 'configure' and, after
	// textExclusiveWarning, to 'configure exclusive' [C].
	textEnterConfig = "Entering configuration mode"
	// textExclusiveWarning is the first line of the answer to 'configure
	// exclusive' [C].
	textExclusiveWarning = "warning: uncommitted changes will be discarded on exit"
	// textExitConfig is the answer to 'exit' in configuration mode [C].
	textExitConfig = "Exiting configuration mode"
	// textLoadComplete is the answer to 'rollback 0' and 'rollback 1' [C].
	textLoadComplete = "load complete"
	// textNotFound is the one tolerated answer, to a 'delete' of an absent
	// node (D131 step 5).
	textNotFound = "warning: statement not found"
	// textUsersEditing heads the list of the other editors after a shared
	// 'configure' (the gate).
	textUsersEditing = "Users currently editing the configuration"
	// textNotCommitted is a shared candidate's staged change.
	textNotCommitted = "The configuration has been changed but not committed"
	// textLocked is the refusal of 'configure exclusive' under another
	// session's exclusive lock [C]; the next line names the holder ('  admin
	// terminal pts/0 (pid 84557) on since ...'), the one after it its mode
	// ('      exclusive {master:0}[edit]'). A shared 'configure' enters
	// instead and lists the holder among the editors [C].
	textLocked = "error: configuration database locked by"
	// textModified is the refusal of 'configure exclusive' over a staged
	// change.
	textModified = "error: configuration database modified"
	// textExpiryUser and textExpiryVia are the history entry of the
	// device's own rollback at the end of a confirmed commit's window [C].
	textExpiryUser = "root"
	textExpiryVia  = "other"
)

// reBanner is the line a Junos device prints before the prompt of every
// session while a confirmed commit is pending, the minutes left in it [C:
// '# commit confirmed will be rolled back in 2 minutes'; '1 minute' for one].
var reBanner = regexp.MustCompile(`^# commit confirmed will be rolled back in ([1-9][0-9]{0,4}) minutes?$`)

// reSwitchLine is the '{master:0}' line a switch prints before its
// operational prompt [C].
var reSwitchLine = regexp.MustCompile(`^\{[a-z-]+(?::[a-z0-9]+)?\}$`)

// The success phrases are the plan package's [S].
var (
	textCheckOK        = plan.ApplyCheckOK
	textCommitComplete = plan.ApplyCommitComplete
)

// reHistoryEntry is one entry of 'show system commit':
// '0   2026-10-13 14:12:01 UTC by alice via cli commit confirmed, rollback in 10mins'.
var reHistoryEntry = regexp.MustCompile(`^(\d+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?: [A-Za-z][A-Za-z0-9+-]*)?) by (\S+) via (\S+)(?:\s+(.*))?$`)

// reHistoryRescue is the line 'show system commit' ends with when a rescue
// configuration is saved [C: 'rescue 2024-01-04 11:42:38 UTC by root via
// cli']. It is a marker, no entry of the history.
var reHistoryRescue = regexp.MustCompile(`^rescue\s+\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+ by \S+ via \S+(\s.*)?$`)

// reRollbackIn is the tail of a confirmed commit's entry.
var reRollbackIn = regexp.MustCompile(`^commit confirmed, rollback in (\d+) ?mins?$`)

// historyTimeLayouts are the layouts of an entry's time (with a zone
// abbreviation, or without one).
var historyTimeLayouts = []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05"}

// reAuthClass finds the class on the first line of 'show cli authorization'
// ('Current user: alice login: alice class: super-user'; a TACACS+ login
// [C]: "Current user: 'EN-CLASS' login: 'gotesteng' class 'EN-CLASS'", the
// template account, the person, the class).
var reAuthClass = regexp.MustCompile(`(?:^|\s)class:?\s+'?([A-Za-z0-9_.@-]+)'?\s*$`)

// reAuthUser finds the current user and the login on that line.
var reAuthUser = regexp.MustCompile(`^\s*Current user:\s+'?([A-Za-z0-9_.@-]+)'?\s+login:\s+'?([A-Za-z0-9_.@-]+)'?\s`)

// reVersionField is a 'Hostname: x', 'Model: y' or 'Junos: z' line of 'show
// version'.
var reVersionField = regexp.MustCompile(`^(Hostname|Model|Junos):\s+(\S+)\s*$`)

// reVersionOld is the release line of a Junos that prints no 'Junos:' line
// (before 14.1, and the SRX and MX trains): 'JUNOS Base OS boot [12.3R12-S15.1]'
// or 'JUNOS Software Release [12.1X46-D40.2]'.
var reVersionOld = regexp.MustCompile(`^JUNOS (?:Base OS boot|Software Release) \[(\S+)\]\s*$`)

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
	// ErrNotSent: the transport refused to send a line (not an apply word,
	// not an allowed statement, or not in the right state).
	ErrNotSent = errors.New("not sent")
	// ErrPending: the device's prompt shows a pending confirmed commit
	// where the transport must not act on one (a 'commit check' would
	// confirm it).
	ErrPending = errors.New("a confirmed commit is pending")
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
// changed: 'configure exclusive' was refused, or the gate's shared
// 'configure' listed an exclusive editor.
type LockedError struct {
	// By is the user that holds the exclusive lock, the first word of the
	// holder's line ("" when the device did not name one).
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
