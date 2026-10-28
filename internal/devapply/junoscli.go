package devapply

// The Junos command-line transport (D131): reads over exec channels, as the
// pull makes them, and one shell session held from 'configure exclusive' to
// the confirming 'commit'. Every line it sends passes send's guard: a
// apply word (plan.IsApplyWord), the pull's read command on an exec
// channel, or a statement the allow-list given to Open passes.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

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

	mu   sync.Mutex
	exec devssh.CLISession
	// op is the operational-mode shell session State reads in (the banner
	// of a pending commit stands only in a shell's prompt).
	op       devssh.CLISession
	held     devssh.CLISession
	inConfig bool
	// area is the held session's prompt area after its last command, and
	// areaOK whether it was read (devssh.PromptArea).
	area   []string
	areaOK bool
	allow  func(string) error
	login  *Login
	log    []string
	m      *masker
	// committed is the held session's last compare (and its delta): the
	// change a confirmed commit after it commits, which Cancel undoes.
	committed      *plan.CompareText
	committedDelta plan.Delta
	// release ends the connection's own context (DialJunos).
	release context.CancelFunc
	// closeExec: the exec reads go through a session of their own that
	// Close closes (NewJunosCLIWith).
	closeExec bool
}

// DefaultConnLifetime bounds the connection of a transport DialJunos made
// when the job's context has no deadline: the longest window and the
// verification's margin.
const DefaultConnLifetime = (MaxConfirmMinutes + 10) * time.Minute

// NewJunosCLI is the transport over an authenticated client. The client
// must have been dialled with a context that outlives the job's
// cancellation (context.WithoutCancel of it, with the transaction's own
// deadline), so that the driver can still type the discard or the cancel
// after the second interrupt; DialJunos does that. Closing the transport
// closes the client.
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

// NewJunosCLIWith is NewJunosCLI with every session of the transport opened
// with opts: with devssh.WithCommand (the root login of D136, whose csh
// starts the CLI through a wrapper command) the reads that are otherwise an
// exec channel per command go through one shell session as well, since an
// exec request of a root login is a csh command line.
func NewJunosCLIWith(c *devssh.Client, opts ...devssh.CLIOption) *JunosCLI {
	j := NewJunosCLI(c)
	if len(opts) == 0 {
		return j
	}
	shell := append([]devssh.CLIOption{devssh.WithMode(devssh.ModeShell)}, opts...)
	j.newShell = func() (devssh.CLISession, error) { return c.CLI(devssh.VendorJuniper, shell...) }
	j.newExec = j.newShell
	j.closeExec = true
	return j
}

// DialJunosWith is DialJunos with the sessions of NewJunosCLIWith.
func DialJunosWith(ctx context.Context, t devssh.Target, opts ...devssh.CLIOption) (*JunosCLI, error) {
	j, err := DialJunos(ctx, t)
	if err != nil || len(opts) == 0 {
		return j, err
	}
	w := NewJunosCLIWith(j.client, opts...)
	w.release = j.release
	return w, nil
}

// DialJunos dials the device and returns its transport (the password comes
// from t.Password, the injected source). ctx is the job's context: it ends
// the dial, but not the connection. The connection lives in
// context.WithoutCancel(ctx) with its own deadline, the job's deadline and
// DefaultGrace (or DefaultConnLifetime when the job has none), so the driver
// can still type the discard or the cancel after the second interrupt
// whatever context the caller holds; Close ends it.
func DialJunos(ctx context.Context, t devssh.Target) (*JunosCLI, error) {
	c, release, err := dialLife(ctx, t)
	if err != nil {
		return nil, err
	}
	j := NewJunosCLI(c)
	j.release = release
	return j, nil
}

// dialLife dials with the lifetime DialJunos describes and returns the
// client and the function that ends its context.
func dialLife(ctx context.Context, t devssh.Target) (*devssh.Client, context.CancelFunc, error) {
	deadline := time.Now().Add(DefaultConnLifetime)
	if d, ok := ctx.Deadline(); ok && d.Add(DefaultGrace).Before(deadline) {
		deadline = d.Add(DefaultGrace)
	}
	life, release := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	// the dial itself ends with the job's context
	stop := context.AfterFunc(ctx, release)
	c, err := devssh.Dial(life, t)
	if !stop() && err == nil {
		_ = c.Close()
		err = ctx.Err()
	}
	if err != nil {
		release()
		return nil, nil, err
	}
	return c, release, nil
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

// Close closes the sessions and the connection. An exclusive candidate
// that was not committed goes with its session.
func (j *JunosCLI) Close() error {
	j.mu.Lock()
	held, op := j.held, j.op
	j.held, j.inConfig, j.op = nil, false, nil
	j.area, j.areaOK = nil, false
	var ex devssh.CLISession
	if j.closeExec {
		ex, j.exec = j.exec, nil
	}
	j.mu.Unlock()
	if ex != nil {
		_ = ex.Close()
	}
	if held != nil {
		_ = held.Close()
	}
	if op != nil {
		_ = op.Close()
	}
	if j.release != nil {
		defer j.release()
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
	j.area, j.areaOK = nil, false
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

// guardWord refuses a line that is not one of the apply's own words.
func guardWord(line string) error {
	if !plan.IsApplyWord(line) {
		return fmt.Errorf("%w: %q is not an apply word", ErrNotSent, cut(line))
	}
	return nil
}

// guardStatement refuses a statement the allow-list does not pass.
func (j *JunosCLI) guardStatement(l plan.Line) error {
	j.mu.Lock()
	allow := j.allow
	j.mu.Unlock()
	return checkStatement(allow, l)
}

// checkStatement is the guard both transports apply to every statement
// before anything is sent: a statement, not an apply word, nothing a shell
// would take for more than one line, and a statement the allow-list passes.
func checkStatement(allow func(string) error, l plan.Line) error {
	if !isStatement(l.Text) || plan.IsApplyWord(l.Text) {
		return fmt.Errorf("%w: not a statement: %s", ErrNotSent, cut(l.Shown()))
	}
	if strings.ContainsAny(l.Text, "?\n\r") {
		return fmt.Errorf("%w: a statement with '?' or a line break cannot be typed in a shell: %s", ErrNotSent, cut(l.Shown()))
	}
	if allow == nil {
		return fmt.Errorf("%w: no allow-list: %s", ErrNotSent, cut(l.Shown()))
	}
	if err := allow(l.Text); err != nil {
		return fmt.Errorf("%w: %v", ErrNotSent, err)
	}
	return nil
}

// --- the reads ------------------------------------------------------------------------------

// runExec runs a read on an exec channel; cmd must be an apply word or the
// pull's read command.
func (j *JunosCLI) runExec(ctx context.Context, cmd string) (string, error) {
	if cmd != j.read && cmd != devconf.PlainCommand(devssh.VendorJuniper) {
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
	out, err := j.runExec(ctx, plan.ApplyShowVersion)
	if err != nil {
		return Identity{}, err
	}
	return parseVersion(out)
}

// History runs 'show system commit'.
func (j *JunosCLI) History(ctx context.Context) (History, error) {
	out, err := j.runExec(ctx, plan.ApplyShowCommit)
	if err != nil {
		return nil, err
	}
	return parseHistory(out)
}

// State runs 'show system commit | no-more' in the operational-mode shell
// session (opened at the first call, kept) and reads the pending marker
// from the prompt area the device printed after the answer (lab L2: the
// banner stands before the prompt of every session while a confirmed
// commit is pending; an exec channel has no prompt). The history and the
// banner come from one answer. A session that cannot tell its prompt area,
// or a prompt area with a line tacctl does not know, is an error; a failed
// read closes the session.
func (j *JunosCLI) State(ctx context.Context) (CommitState, error) {
	cmd := plan.ApplyShowCommit + " | no-more"
	out, area, err := j.runOp(ctx, cmd)
	if err != nil {
		return CommitState{}, err
	}
	pending, minutes, err := parseBanner(area)
	if err != nil {
		j.dropOp()
		return CommitState{}, err
	}
	h, err := parseHistory(strings.Join(trimPromptArea(lines(out)), "\n"))
	if err != nil {
		return CommitState{}, err
	}
	return CommitState{History: h, Pending: pending, Minutes: minutes}, nil
}

// runOp types an apply word in the operational-mode shell session (opened
// at the first call, kept) and returns the answer and the prompt area after
// it. A session that cannot tell its prompt area is an error; a failed read
// closes the session.
func (j *JunosCLI) runOp(ctx context.Context, cmd string) (string, []string, error) {
	if err := guardWord(cmd); err != nil {
		return "", nil, err
	}
	j.mu.Lock()
	if j.op == nil {
		s, err := j.newShell()
		if err != nil {
			j.mu.Unlock()
			return "", nil, err
		}
		j.op = s
	}
	op := j.op
	j.log = append(j.log, cmd)
	j.mu.Unlock()
	out, err := op.Run(ctx, cmd)
	if err != nil {
		j.dropOp()
		return "", nil, fmt.Errorf("%s: %w", cmd, err)
	}
	area, ok := promptArea(op)
	if !ok {
		j.dropOp()
		return "", nil, fmt.Errorf("%s: %w: %s", cmd, ErrUnrecognised, noPromptArea(op))
	}
	return out, area, nil
}

// dropOp closes the operational-mode shell session.
func (j *JunosCLI) dropOp() {
	j.mu.Lock()
	op := j.op
	j.op = nil
	j.mu.Unlock()
	if op != nil {
		_ = op.Close()
	}
}

// RollbackCompare runs 'show configuration | compare rollback n | no-more'
// in the operational-mode shell session State reads in (the settle's
// compares, D132): empty exactly when the configuration is the one commit n
// of the history produced. The answer must end at a prompt whose area
// tacctl knows (a pending commit's banner there is the prompt's); its text
// is parsed fail closed and never quoted: an error gives the line number
// and why only.
func (j *JunosCLI) RollbackCompare(ctx context.Context, n int) (plan.CompareText, error) {
	if n < 0 || n > plan.MaxRollback {
		return plan.CompareText{}, fmt.Errorf("%w: rollback %d is not one a device keeps", ErrNotSent, n)
	}
	cmd := plan.ApplyRollbackCompare(n)
	out, area, err := j.runOp(ctx, cmd)
	if err != nil {
		return plan.CompareText{}, err
	}
	if _, _, err := parseBanner(area); err != nil {
		j.dropOp()
		return plan.CompareText{}, err
	}
	c, err := plan.ParseCompare(strings.Join(trimPromptArea(lines(out)), "\n"))
	if err != nil {
		var le *plan.CompareLineError
		if errors.As(err, &le) {
			return plan.CompareText{}, fmt.Errorf("%s: %w: compare line %d: %s (not quoted)", cmd, ErrUnrecognised, le.Line, le.Why)
		}
		return plan.CompareText{}, fmt.Errorf("%s: %w: the answer is not a compare (not quoted)", cmd, ErrUnrecognised)
	}
	return c, nil
}

// textNoPromptArea is why a shell session that completed a command did not
// tell its prompt area (devssh.PromptArea): the device answered the empty
// line typed ahead without echoing it, so both prompts stood on one line.
// The banner is the only pending marker, so the state cannot be read
// (fail closed).
const textNoPromptArea = "the device did not echo the empty line typed ahead (both prompts on one line), " +
	"so the banner of a pending confirmed commit cannot be read: apply cannot run on this device"

// noPromptArea is why the session told no prompt area.
func noPromptArea(s devssh.CLISession) string {
	if _, ok := s.(devssh.PromptArea); !ok {
		return "the session tells no prompt area"
	}
	return textNoPromptArea
}

// promptArea is a session's prompt area after its last command.
func promptArea(s devssh.CLISession) ([]string, bool) {
	pa, ok := s.(devssh.PromptArea)
	if !ok {
		return nil, false
	}
	return pa.PromptArea()
}

// heldPending reads the held session's prompt area after its last command:
// whether it showed the banner of a pending commit. A prompt area that was
// not read or not known is an error.
func (j *JunosCLI) heldPending() (bool, error) {
	j.mu.Lock()
	area, ok := j.area, j.areaOK
	j.mu.Unlock()
	if !ok {
		return false, fmt.Errorf("%w: the held session: %s", ErrUnrecognised, textNoPromptArea)
	}
	pending, _, err := parseBanner(area)
	return pending, err
}

// Login runs 'show cli authorization'.
func (j *JunosCLI) Login(ctx context.Context) (Login, error) {
	out, err := j.runExec(ctx, plan.ApplyShowAuthorization)
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

// plainRunner is the transport's exec channel as devconf's Runner, for the
// plain view's one command.
type plainRunner struct{ j *JunosCLI }

func (p plainRunner) Run(ctx context.Context, cmd string) (string, error) {
	return p.j.runExec(ctx, cmd)
}

// ReadPlain reads the plain view, the configuration without the groups'
// inheritance applied (devconf.PlainCommand), which the planner tells a
// group's statements from the device's own by (D97). It is best effort, as
// the pull's: "" when the device gives none, and the planner then says the
// inheritance was not checked. The text is the caller's planner's input and
// is not kept.
func (j *JunosCLI) ReadPlain(ctx context.Context) string {
	return devconf.ReadPlain(ctx, plainRunner{j}, devssh.VendorJuniper)
}

// LandedCompare runs 'show configuration | compare rollback 1 | no-more'
// (lab L3: the committed configuration against the one before, the text
// of the candidate's 'show | compare').
// An exec channel's output is whole only when the channel ended with its exit
// status (devssh: anything else is an error), so a cut text never parses.
func (j *JunosCLI) LandedCompare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	out, err := j.runExec(ctx, plan.ApplyLandedCompare)
	if err != nil {
		return plan.CompareText{}, err
	}
	c, err := plan.ParseCompareFor(out, d)
	if err != nil {
		return plan.CompareText{}, fmt.Errorf("%s: %w: %v", plan.ApplyLandedCompare, ErrUnrecognised, j.m.text(err.Error()))
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
	j.area, j.areaOK = nil, false
	j.mu.Unlock()
	out, err := held.Run(ctx, line)
	if err != nil {
		j.dropHeld()
		return "", fmt.Errorf("%w: %s: %v", ErrSessionLost, shown, j.m.text(err.Error()))
	}
	area, ok := promptArea(held)
	j.mu.Lock()
	if j.held == held {
		j.area, j.areaOK = area, ok
	}
	j.mu.Unlock()
	return out, nil
}

// word types an apply word in configuration mode and returns the answer's
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
	out, err := run(plan.ApplyConfigure)
	if err != nil {
		return Dirty{}, err
	}
	body, ok := configAnswer(out)
	if !ok {
		if l := lockedBy(body); l != "" || containsLine(body, textLocked) {
			return Dirty{}, &LockedError{By: l}
		}
		return Dirty{}, answerError(plan.ApplyConfigure, body, j.m)
	}
	var d Dirty
	if len(nonBlank(body)) == 0 || strings.TrimSpace(nonBlank(body)[0]) != textEnterConfig {
		return Dirty{}, answerError(plan.ApplyConfigure, body, j.m)
	}
	// a shared session enters under another's exclusive lock and lists
	// the holder (lab L1): the lock is named, not just 'other editors'
	if by, ok := exclusiveEditor(body); ok {
		return Dirty{}, &LockedError{By: by}
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
		return Dirty{}, answerError(plan.ApplyConfigure, body, j.m)
	}
	out, err = run(plan.ApplyCompare)
	if err != nil {
		return Dirty{}, err
	}
	// the shared candidate's compare is a stranger's staged work: an error
	// about it never quotes it, it gives a line number or a count
	body, ok = configAnswer(out)
	if !ok {
		base := ErrUnrecognised
		if classify(body) != "" {
			base = ErrRefused
		}
		return Dirty{}, &AnswerError{Cmd: plan.ApplyCompare, base: base,
			Lines: []string{fmt.Sprintf("%d line(s) without the location line (the shared candidate's, not quoted)", len(nonBlank(body)))}}
	}
	c, err := plan.ParseCompare(strings.Join(body, "\n"))
	if err != nil && d.Staged {
		// 'configure' said a change is staged: that is the gate's reason,
		// whatever the compare holds (the gate fails either way)
		return d, nil
	}
	if err != nil {
		var le *plan.CompareLineError
		if errors.As(err, &le) {
			return Dirty{}, fmt.Errorf("%s: %w: compare line %d: %s (the shared candidate's, not quoted)", plan.ApplyCompare, ErrUnrecognised, le.Line, le.Why)
		}
		return Dirty{}, fmt.Errorf("%s: %w: %v", plan.ApplyCompare, ErrUnrecognised, err)
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

// Open opens the held session and enters configuration mode with
// 'configure exclusive' (the only mode: a private session refuses 'commit
// confirmed', lab L5). Any answer but the captured one (the warning that
// uncommitted changes are discarded on exit, 'Entering configuration mode'
// and the location line) fails, and the session is closed without another
// word; another session's lock is a *LockedError with its holder.
func (j *JunosCLI) Open(ctx context.Context, allow func(string) error) error {
	if allow == nil {
		return fmt.Errorf("%w: Open needs the allow-list", ErrNotSent)
	}
	j.mu.Lock()
	if j.held != nil {
		j.mu.Unlock()
		return fmt.Errorf("%w: the held session is open already", ErrNotSent)
	}
	j.mu.Unlock()
	cmd := plan.ApplyConfigureExclusive
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
	if !ok || !exactly(body, textExclusiveWarning, textEnterConfig) {
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
	body, err := j.word(ctx, plan.ApplyCompare)
	if err != nil {
		return plan.CompareText{}, err
	}
	// no error table here: a compare may hold a login message with any
	// words; the parser refuses every line that is not a compare's
	c, err := plan.ParseCompareFor(strings.Join(body, "\n"), d)
	if err != nil {
		return plan.CompareText{}, fmt.Errorf("%s: %w: %v", plan.ApplyCompare, ErrUnrecognised, j.m.text(err.Error()))
	}
	j.mu.Lock()
	j.committed, j.committedDelta = &c, d
	j.mu.Unlock()
	return c, nil
}

// Check runs 'commit check'; the answer must be the success phrase alone.
// It is not typed when the held session's last prompt showed a pending
// confirmed commit, which the check would confirm (ErrPending), or did not
// tell its prompt.
func (j *JunosCLI) Check(ctx context.Context) error {
	if err := guardWord(plan.ApplyCommitCheck); err != nil {
		return err
	}
	if !j.Held() {
		return fmt.Errorf("%w: %s: not in configuration mode", ErrSessionLost, plan.ApplyCommitCheck)
	}
	pending, err := j.heldPending()
	switch {
	case err != nil:
		return fmt.Errorf("%w: %s: %v", ErrNotSent, plan.ApplyCommitCheck, err)
	case pending:
		return fmt.Errorf("%w: %s: %w: the held session's prompt shows it", ErrNotSent, plan.ApplyCommitCheck, ErrPending)
	}
	body, err := j.word(ctx, plan.ApplyCommitCheck)
	if err != nil {
		return err
	}
	if ok, why := checkAnswer(body); !ok {
		return answerErrorWhy(plan.ApplyCommitCheck, body, j.m, why)
	}
	return nil
}

// committedAnswer reports whether a commit's answer is want, after the
// check's 'configuration check succeeds' that a commit prints first [C] (or
// without it), or the same for each member of a device that has several
// (readCommitted).
func committedAnswer(body []string, want ...string) bool {
	ok, _ := readCommitted(body, want...)
	return ok
}

// commitRefusal is the error of a commit's answer that is not want: the
// answer's lines, led by the member and the text that cannot be read when
// the answer has members.
func (j *JunosCLI) commitRefusal(line string, body []string, want ...string) error {
	_, why := readCommitted(body, want...)
	return answerErrorWhy(line, body, j.m, why)
}

// CommitConfirmed types the confirmed commit; the answer must be the
// window's line and 'commit complete' [C], nothing else, and the prompt
// after it must show the banner of the pending commit.
func (j *JunosCLI) CommitConfirmed(ctx context.Context, minutes int, id, user string) error {
	line := plan.ApplyCommitConfirmed(minutes, id, user)
	body, err := j.word(ctx, line)
	if err != nil {
		return err
	}
	if !committedAnswer(body, plan.ApplyConfirmedNote(minutes), textCommitComplete) {
		return j.commitRefusal(line, body, plan.ApplyConfirmedNote(minutes), textCommitComplete)
	}
	pending, err := j.heldPending()
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w", line, err)
	case !pending:
		return fmt.Errorf("%s: %w: the prompt after it shows no pending commit", line, ErrUnrecognised)
	}
	return nil
}

// Confirm types the confirming commit; the answer must be 'commit
// complete' [C].
func (j *JunosCLI) Confirm(ctx context.Context, id, user string) error {
	line := plan.ApplyConfirm(id, user)
	body, err := j.word(ctx, line)
	if err != nil {
		return err
	}
	if !committedAnswer(body, textCommitComplete) {
		return j.commitRefusal(line, body, textCommitComplete)
	}
	return nil
}

// Cancel types 'rollback 1', 'show | compare | no-more' and, only when the
// prompt after 'rollback 1' still showed the banner of the pending commit
// and the compare is exactly the inverse of the held session's last compare
// (the change the confirmed commit committed), the cancel's commit (lab L2:
// it ends the window at once and is a normal entry). Anything else commits
// nothing: 'rollback 1' typed after the device's own rollback loads the
// change itself, and committing it would keep it. A 'rollback 1' that did
// not load closes the session; a missing banner or a compare that is not
// the inverse (or does not parse) is discarded ('rollback 0', 'exit'), and
// the device's expiry is the cancel.
func (j *JunosCLI) Cancel(ctx context.Context, id string) error {
	return j.undo(ctx, id, true)
}

// Revert is Cancel for a commit that something confirmed before tacctl's
// confirm: the same words and the same inverse compare, and the prompt
// after 'rollback 1' must show no banner (one that stands is a pending
// commit the driver did not see, and is not committed over).
func (j *JunosCLI) Revert(ctx context.Context, id string) error {
	return j.undo(ctx, id, false)
}

// undo is Cancel (banner true: the banner must stand after 'rollback 1')
// and Revert (false: it must not).
func (j *JunosCLI) undo(ctx context.Context, id string, banner bool) error {
	j.mu.Lock()
	committed, d := j.committed, j.committedDelta
	j.mu.Unlock()
	if committed == nil {
		return fmt.Errorf("%w: no compare of the commit to undo", ErrNotSent)
	}
	body, err := j.word(ctx, plan.ApplyRollback1)
	if err != nil {
		return err
	}
	if !exactly(body, textLoadComplete) {
		j.dropHeld()
		return answerError(plan.ApplyRollback1, body, j.m)
	}
	if pending, err := j.heldPending(); err != nil || pending != banner {
		why := "the prompt after 'rollback 1' shows no pending commit (the window may have ended)"
		if !banner {
			why = "the prompt after 'rollback 1' shows a pending commit"
		}
		if err != nil {
			why = "the prompt after 'rollback 1': " + j.m.text(err.Error())
		}
		if derr := j.Discard(ctx); derr != nil {
			why += "; the discard did not answer as it must, the held session was closed"
		} else {
			why += "; it was discarded"
		}
		return fmt.Errorf("%w: %s: nothing was committed", ErrUnrecognised, why)
	}
	body, err = j.word(ctx, plan.ApplyCompare)
	if err != nil {
		j.dropHeld()
		return err
	}
	c, err := plan.ParseCompareFor(strings.Join(body, "\n"), d)
	if err != nil || !c.Equal(committed.Inverse()) {
		why := "the candidate 'rollback 1' loaded is not the inverse of the commit (the window may have ended)"
		if err != nil {
			why = fmt.Sprintf("the candidate 'rollback 1' loaded: %v", j.m.text(err.Error()))
		}
		if derr := j.Discard(ctx); derr != nil {
			why += "; the discard did not answer as it must, the held session was closed"
		} else {
			why += "; it was discarded"
		}
		return fmt.Errorf("%w: %s: nothing was committed", ErrUnrecognised, why)
	}
	line := plan.ApplyCancel(id)
	body, err = j.word(ctx, line)
	if err != nil {
		return err
	}
	if !committedAnswer(body, textCommitComplete) {
		return j.commitRefusal(line, body, textCommitComplete)
	}
	return nil
}

// Discard types 'rollback 0' and, only when it answered 'load complete',
// 'exit' (an exit over a candidate with changes asks a question no read
// ends). Any other answer closes the held session, which drops an exclusive
// candidate all the same; the error says so.
func (j *JunosCLI) Discard(ctx context.Context) error {
	defer j.dropHeld()
	body, err := j.word(ctx, plan.ApplyRollback0)
	if err != nil {
		return err
	}
	if !exactly(body, textLoadComplete) {
		return answerError(plan.ApplyRollback0, body, j.m)
	}
	if err := guardWord(plan.ApplyExit); err != nil {
		return err
	}
	out, err := j.runHeld(ctx, plan.ApplyExit, plan.ApplyExit)
	if err != nil {
		return err
	}
	if ls := trimPromptArea(lines(out)); !exactly(ls, textExitConfig) {
		return answerError(plan.ApplyExit, ls, j.m)
	}
	return nil
}
