package devrollout

// The Junos command-line transport (D131): reads over exec channels, as the
// pull makes them, and one shell session held from 'configure exclusive' to
// the confirming 'commit'. Every line it sends passes send's guard: a
// rollout word (plan.IsRolloutWord), the pull's read command on an exec
// channel, or a statement the allow-list given to Open passes.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
)

// JunosCLI is the Junos command line of one login. Its methods are for one
// goroutine at a time.
type JunosCLI struct {
	client *devssh.Client
	read   string
	// newShell opens a shell session (the client's, or a test's).
	newShell func() (devssh.CLISession, error)
	newExec  func() (devssh.CLISession, error)

	mu       sync.Mutex
	exec     devssh.CLISession
	held     devssh.CLISession
	inConfig bool
	allow    func(string) error
	login    *Login
	log      []string
	m        *masker
}

// NewJunosCLI is the transport over an authenticated client. The client
// must have been dialled with a context that outlives the job's
// cancellation (context.WithoutCancel of it, with the transaction's own
// deadline), so that the driver can still type the discard or the cancel
// after the second interrupt; closing the transport closes the client.
func NewJunosCLI(c *devssh.Client) *JunosCLI {
	_, read, _ := devconf.Commands(devssh.VendorJuniper)
	return &JunosCLI{
		client: c,
		read:   read,
		newShell: func() (devssh.CLISession, error) {
			return c.CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
		},
		newExec: func() (devssh.CLISession, error) {
			return c.CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeExec))
		},
		m: &masker{},
	}
}

// DialJunos dials the device and returns its transport (the password comes
// from t.Password, the injected source).
func DialJunos(ctx context.Context, t devssh.Target) (*JunosCLI, error) {
	c, err := devssh.Dial(ctx, t)
	if err != nil {
		return nil, err
	}
	return NewJunosCLI(c), nil
}

// Vendor is the registry's word.
func (j *JunosCLI) Vendor() string { return devssh.VendorJuniper }

// RollsBackOnClose is false: over the command line only the window's end
// rolls a confirmed commit back (D132).
func (j *JunosCLI) RollsBackOnClose() bool { return false }

// LocalAddr is the local end of the connection.
func (j *JunosCLI) LocalAddr() net.IP {
	if j.client == nil {
		return nil
	}
	return j.client.LocalAddr()
}

// Confirms reports whether the login's class may commit (read by Login).
func (j *JunosCLI) Confirms() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.login != nil && j.login.CanCommit()
}

// Log is what was typed, a secret's value elided.
func (j *JunosCLI) Log() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.log...)
}

// Held reports whether the held session is in configuration mode.
func (j *JunosCLI) Held() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.held != nil && j.inConfig
}

// Close closes the sessions and the connection. An exclusive or private
// candidate that was not committed goes with its session.
func (j *JunosCLI) Close() error {
	j.mu.Lock()
	held := j.held
	j.held, j.inConfig = nil, false
	j.mu.Unlock()
	if held != nil {
		_ = held.Close()
	}
	if j.client != nil {
		return j.client.Close()
	}
	return nil
}

// dropHeld closes the held session after a failure: nothing more is typed
// in it.
func (j *JunosCLI) dropHeld() {
	j.mu.Lock()
	held := j.held
	j.held, j.inConfig = nil, false
	j.mu.Unlock()
	if held != nil {
		_ = held.Close()
	}
}

// --- the guard ---------------------------------------------------------------------------

// isStatement reports whether a line begins with a statement verb.
func isStatement(line string) bool {
	verb, _, _ := strings.Cut(line, " ")
	return verb == "set" || verb == "delete" || verb == "insert"
}

// guardWord refuses a line that is not one of the rollout's own words.
func guardWord(line string) error {
	if !plan.IsRolloutWord(line) {
		return fmt.Errorf("%w: %q is not a rollout word", ErrNotSent, cut(line))
	}
	return nil
}

// guardStatement refuses a statement the allow-list does not pass.
func (j *JunosCLI) guardStatement(l plan.Line) error {
	if !isStatement(l.Text) || plan.IsRolloutWord(l.Text) {
		return fmt.Errorf("%w: not a statement: %s", ErrNotSent, cut(l.Shown()))
	}
	if strings.ContainsAny(l.Text, "?\n\r") {
		return fmt.Errorf("%w: a statement with '?' or a line break cannot be typed in a shell: %s", ErrNotSent, cut(l.Shown()))
	}
	j.mu.Lock()
	allow := j.allow
	j.mu.Unlock()
	if allow == nil {
		return fmt.Errorf("%w: no allow-list: %s", ErrNotSent, cut(l.Shown()))
	}
	if err := allow(l.Text); err != nil {
		return fmt.Errorf("%w: %v", ErrNotSent, err)
	}
	return nil
}

// --- the reads ------------------------------------------------------------------------------

// runExec runs a read on an exec channel; cmd must be a rollout word or the
// pull's read command.
func (j *JunosCLI) runExec(ctx context.Context, cmd string) (string, error) {
	if cmd != j.read {
		if err := guardWord(cmd); err != nil {
			return "", err
		}
	}
	j.mu.Lock()
	if j.exec == nil {
		s, err := j.newExec()
		if err != nil {
			j.mu.Unlock()
			return "", err
		}
		j.exec = s
	}
	ex := j.exec
	j.log = append(j.log, cmd)
	j.mu.Unlock()
	out, err := ex.Run(ctx, cmd)
	var ce devssh.CommandError
	if errors.As(err, &ce) {
		return "", answerError(cmd, lines(out), j.m)
	}
	return out, err
}

// Identity runs 'show version'.
func (j *JunosCLI) Identity(ctx context.Context) (Identity, error) {
	out, err := j.runExec(ctx, plan.RolloutShowVersion)
	if err != nil {
		return Identity{}, err
	}
	return parseVersion(out)
}

// History runs 'show system commit'.
func (j *JunosCLI) History(ctx context.Context) (History, error) {
	out, err := j.runExec(ctx, plan.RolloutShowCommit)
	if err != nil {
		return nil, err
	}
	return parseHistory(out)
}

// Login runs 'show cli authorization'.
func (j *JunosCLI) Login(ctx context.Context) (Login, error) {
	out, err := j.runExec(ctx, plan.RolloutShowAuthorization)
	if err != nil {
		return Login{}, err
	}
	lg, err := parseAuthorization(out)
	if err != nil {
		return Login{}, err
	}
	j.mu.Lock()
	j.login = &lg
	j.mu.Unlock()
	return lg, nil
}

// Read runs the pull's read command.
func (j *JunosCLI) Read(ctx context.Context) (string, error) {
	out, err := j.runExec(ctx, j.read)
	if err != nil {
		return "", err
	}
	// 'display set' prints statements and nothing else: any other line (a
	// refusal, a banner) is not a configuration
	for _, l := range nonBlank(lines(out)) {
		if !strings.HasPrefix(l, "set ") && !strings.HasPrefix(l, "deactivate ") {
			return "", answerError(j.read, []string{l}, j.m)
		}
	}
	return out, nil
}

// LandedCompare runs 'show system rollback compare 1 0'.
// An exec channel's output is whole only when the channel ended with its exit
// status (devssh: anything else is an error), so a cut text never parses.
func (j *JunosCLI) LandedCompare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	out, err := j.runExec(ctx, plan.RolloutLandedCompare)
	if err != nil {
		return plan.CompareText{}, err
	}
	c, err := plan.ParseCompareFor(out, d)
	if err != nil {
		return plan.CompareText{}, fmt.Errorf("%s: %w: %v", plan.RolloutLandedCompare, ErrUnrecognised, j.m.text(err.Error()))
	}
	return c, nil
}

// --- the held session -------------------------------------------------------------------------

// runHeld types a line in the held session; shown is the line as it is
// logged. A failure of the session itself drops it (ErrSessionLost).
func (j *JunosCLI) runHeld(ctx context.Context, line, shown string) (string, error) {
	j.mu.Lock()
	held := j.held
	if held == nil {
		j.mu.Unlock()
		return "", fmt.Errorf("%w: %s", ErrSessionLost, shown)
	}
	j.log = append(j.log, shown)
	j.mu.Unlock()
	out, err := held.Run(ctx, line)
	if err != nil {
		j.dropHeld()
		return "", fmt.Errorf("%w: %s: %v", ErrSessionLost, shown, j.m.text(err.Error()))
	}
	return out, nil
}

// word types a rollout word in configuration mode and returns the answer's
// lines before the location line; a missing location line is an
// unrecognised answer (the session is not where the transport thinks).
func (j *JunosCLI) word(ctx context.Context, line string) ([]string, error) {
	if err := guardWord(line); err != nil {
		return nil, err
	}
	if !j.Held() {
		return nil, fmt.Errorf("%w: %s: not in configuration mode", ErrSessionLost, line)
	}
	out, err := j.runHeld(ctx, line, line)
	if err != nil {
		return nil, err
	}
	body, ok := configAnswer(out)
	if !ok {
		return nil, answerError(line, body, j.m)
	}
	return body, nil
}

// SharedDirty is the gate: a throwaway shell, 'configure' (shared), 'show |
// compare | no-more', and the session closed. No 'exit' is typed: in a
// shared session with a stranger's staged change the device asks a question
// at 'exit' that a read never ends, and closing the session leaves the
// shared candidate as it was.
func (j *JunosCLI) SharedDirty(ctx context.Context) (Dirty, error) {
	s, err := j.newShell()
	if err != nil {
		return Dirty{}, err
	}
	defer func() { _ = s.Close() }()
	run := func(cmd string) (string, error) {
		if err := guardWord(cmd); err != nil {
			return "", err
		}
		j.mu.Lock()
		j.log = append(j.log, cmd)
		j.mu.Unlock()
		return s.Run(ctx, cmd)
	}
	out, err := run(plan.RolloutConfigure)
	if err != nil {
		return Dirty{}, err
	}
	body, ok := configAnswer(out)
	if !ok {
		if l := lockedBy(body); l != "" || containsLine(body, textLocked) {
			return Dirty{}, &LockedError{By: l}
		}
		return Dirty{}, answerError(plan.RolloutConfigure, body, j.m)
	}
	var d Dirty
	if len(nonBlank(body)) == 0 || strings.TrimSpace(nonBlank(body)[0]) != textEnterConfig {
		return Dirty{}, answerError(plan.RolloutConfigure, body, j.m)
	}
	for _, l := range nonBlank(body)[1:] {
		switch {
		case strings.Contains(l, textUsersEditing):
			d.Editors = true
		case strings.Contains(l, textNotCommitted):
			d.Staged = true
		}
	}
	if extra := nonBlank(body)[1:]; len(extra) > 0 && !d.Editors && !d.Staged {
		return Dirty{}, answerError(plan.RolloutConfigure, body, j.m)
	}
	out, err = run(plan.RolloutCompare)
	if err != nil {
		return Dirty{}, err
	}
	body, ok = configAnswer(out)
	if !ok {
		return Dirty{}, answerError(plan.RolloutCompare, body, j.m)
	}
	c, err := plan.ParseCompare(strings.Join(body, "\n"))
	if err != nil {
		return Dirty{}, fmt.Errorf("%s: %w: %v", plan.RolloutCompare, ErrUnrecognised, err)
	}
	if !c.Empty() {
		d.Staged = true
	}
	return d, nil
}

func containsLine(body []string, s string) bool {
	for _, l := range body {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// Open opens the held session and enters configuration mode. Any answer but
// 'Entering configuration mode' and the location line fails, and the
// session is closed without another word.
func (j *JunosCLI) Open(ctx context.Context, mode OpenMode, allow func(string) error) error {
	if allow == nil {
		return fmt.Errorf("%w: Open needs the allow-list", ErrNotSent)
	}
	j.mu.Lock()
	if j.held != nil {
		j.mu.Unlock()
		return fmt.Errorf("%w: the held session is open already", ErrNotSent)
	}
	j.mu.Unlock()
	cmd := plan.RolloutConfigureExclusive
	if mode == OpenPrivate {
		cmd = plan.RolloutConfigurePrivate
	}
	s, err := j.newShell()
	if err != nil {
		return err
	}
	j.mu.Lock()
	j.held, j.allow = s, allow
	j.mu.Unlock()
	out, err := j.runHeld(ctx, cmd, cmd)
	if err != nil {
		return err
	}
	body, ok := configAnswer(out)
	if !ok || !exactly(body, textEnterConfig) {
		j.dropHeld()
		switch {
		case containsLine(body, textModified):
			return &LockedError{Modified: true}
		case containsLine(body, textLocked):
			return &LockedError{By: lockedBy(body)}
		}
		return answerError(cmd, body, j.m)
	}
	j.mu.Lock()
	j.inConfig = true
	j.mu.Unlock()
	return nil
}

// Load types one statement; the answer must be nothing, or for a delete the
// tolerated 'statement not found'.
func (j *JunosCLI) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	if err := j.guardStatement(l); err != nil {
		return Loaded{}, err
	}
	if !j.Held() {
		return Loaded{}, fmt.Errorf("%w: not in configuration mode", ErrSessionLost)
	}
	j.mu.Lock()
	j.m.add(l)
	j.mu.Unlock()
	out, err := j.runHeld(ctx, l.Text, l.Shown())
	if err != nil {
		return Loaded{}, err
	}
	body, ok := configAnswer(out)
	switch {
	case !ok:
	case len(nonBlank(body)) == 0:
		return Loaded{}, nil
	case l.Op == plan.OpDelete && exactly(body, textNotFound):
		return Loaded{NotFound: true}, nil
	}
	return Loaded{}, answerError(l.Text, body, j.m)
}

// Compare runs 'show | compare | no-more' in the held session. The answer is
// whole only when devssh saw it end at the configure prompt (a read that
// ended by its context, a closed channel or a prompt count that does not
// add up is an error there) and the location line stands right before that
// prompt (word: configAnswer); only then is it parsed, so an answer cut at a
// block boundary never reads as a smaller compare.
func (j *JunosCLI) Compare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	body, err := j.word(ctx, plan.RolloutCompare)
	if err != nil {
		return plan.CompareText{}, err
	}
	// no error table here: a compare may hold a login message with any
	// words; the parser refuses every line that is not a compare's
	c, err := plan.ParseCompareFor(strings.Join(body, "\n"), d)
	if err != nil {
		return plan.CompareText{}, fmt.Errorf("%s: %w: %v", plan.RolloutCompare, ErrUnrecognised, j.m.text(err.Error()))
	}
	return c, nil
}

// Check runs 'commit check'; the answer must be the success phrase alone.
func (j *JunosCLI) Check(ctx context.Context) error {
	body, err := j.word(ctx, plan.RolloutCommitCheck)
	if err != nil {
		return err
	}
	if !exactly(body, textCheckOK) {
		return answerError(plan.RolloutCommitCheck, body, j.m)
	}
	return nil
}

// CommitConfirmed types the confirmed commit; the answer must be the
// window's line and 'commit complete', nothing else.
func (j *JunosCLI) CommitConfirmed(ctx context.Context, minutes int, id, user string) error {
	line := plan.RolloutCommitConfirmed(minutes, id, user)
	body, err := j.word(ctx, line)
	if err != nil {
		return err
	}
	if !exactly(body, plan.RolloutConfirmedNote(minutes), textCommitComplete) {
		return answerError(line, body, j.m)
	}
	return nil
}

// Confirm types the confirming commit; the answer must be 'commit
// complete'.
func (j *JunosCLI) Confirm(ctx context.Context, id, user string) error {
	line := plan.RolloutConfirm(id, user)
	body, err := j.word(ctx, line)
	if err != nil {
		return err
	}
	if !exactly(body, textCommitComplete) {
		return answerError(line, body, j.m)
	}
	return nil
}

// Cancel types 'rollback 1' and, only when it answered 'load complete', the
// cancel's commit. A 'rollback 1' that did not load is discarded with
// 'rollback 0' and the session closed: nothing is committed.
func (j *JunosCLI) Cancel(ctx context.Context, id string) error {
	body, err := j.word(ctx, plan.RolloutRollback1)
	if err != nil {
		return err
	}
	if !exactly(body, textLoadComplete) {
		j.dropHeld()
		return answerError(plan.RolloutRollback1, body, j.m)
	}
	line := plan.RolloutCancel(id)
	body, err = j.word(ctx, line)
	if err != nil {
		return err
	}
	if !exactly(body, textCommitComplete) {
		return answerError(line, body, j.m)
	}
	return nil
}

// Discard types 'rollback 0' and, only when it answered 'load complete',
// 'exit' (an exit over a candidate with changes asks a question no read
// ends). Any other answer closes the held session, which drops an exclusive
// or private candidate all the same; the error says so.
func (j *JunosCLI) Discard(ctx context.Context) error {
	defer j.dropHeld()
	body, err := j.word(ctx, plan.RolloutRollback0)
	if err != nil {
		return err
	}
	if !exactly(body, textLoadComplete) {
		return answerError(plan.RolloutRollback0, body, j.m)
	}
	if err := guardWord(plan.RolloutExit); err != nil {
		return err
	}
	out, err := j.runHeld(ctx, plan.RolloutExit, plan.RolloutExit)
	if err != nil {
		return err
	}
	if !exactly(lines(out), textExitConfig) {
		return answerError(plan.RolloutExit, lines(out), j.m)
	}
	return nil
}
