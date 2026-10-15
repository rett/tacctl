package devapply

// The Junos NETCONF transport (0.2.10 plan D149): the second implementation
// of Transport, over devssh.NetconfSession. The driver is the one the command
// line uses; what differs is the way in and three properties of the device:
//
//   - A confirmed commit that the session which made it closes without
//     confirming is rolled back at once (0.2.4 spike (d)): RollsBackOnClose is
//     true and Cancel is the close of the held session. Nothing but the held
//     session can confirm (no 'persist'), so Revert is never reached.
//   - There is no prompt, so no banner: a pending confirmed commit is read
//     from the history's own label ('commit confirmed, rollback in Nmins' on
//     entry 0), which is the fail-closed reading: a label that a 'commit
//     check' of someone else left behind is taken for pending until the next
//     commit (the CLI transport tells the two apart by the banner).
//   - The session mode is private first; a device that refuses 'commit
//     confirmed' in a private session (as the command line does, 0.2.9 lab
//     L5) gives a typed error (ErrPrivateConfirmRefused) and RetryExclusive,
//     and the caller runs the whole transaction again with ModeExclusive. The
//     mode is never switched in the middle of a transaction.
//
// Every read is a <command> RPC of the apply word the command-line reader
// types, parsed by the same parsers, so both transports yield the same typed
// values. Reads go through a session of their own (never the held one), as
// the command line's exec channel does, so they show the committed
// configuration whatever the held session has loaded. Log() holds the apply
// word of each step where one exists and 'netconf: ...' for the RPCs that
// have none; a statement is logged as its shown form, a secret elided.

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
)

// NetconfMode is the kind of edit session a NETCONF transaction opens.
type NetconfMode int

// The modes. ModeAuto is ModePrivate with RetryExclusive (see the package
// comment): a refusal of the confirmed commit is reported, never worked
// around inside the transaction.
const (
	ModeAuto NetconfMode = iota
	ModePrivate
	ModeExclusive
)

// ErrPrivateConfirmRefused: the device refused 'commit confirmed' in a
// private session. Nothing was committed; the caller runs the transaction
// again in ModeExclusive (JunosNetconf.RetryExclusive).
var ErrPrivateConfirmRefused = errors.New("the device refuses a confirmed commit in a private session")

// ErrNotApplicable: the method has no meaning for this transport.
var ErrNotApplicable = errors.New("not applicable for this transport")

const (
	capCandidate = "urn:ietf:params:netconf:capability:candidate:1.0"
	capConfirmed = "urn:ietf:params:netconf:capability:confirmed-commit:1.0"
	// capConfirmed11 is the second revision, which a device that offers it
	// offers beside the first; either makes a confirmed commit.
	capConfirmed11 = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"

	// textNoConfirmedPrivate is what a device says to a confirmed commit in
	// a private session [C: 0.2.9 lab L5].
	textNoConfirmedPrivate = "commit confirmed not supported for private configuration"
)

// JunosNetconf is the Junos NETCONF subsystem of one login. Its methods are
// for one goroutine at a time.
type JunosNetconf struct {
	client *devssh.Client
	mode   NetconfMode
	read   string

	mu sync.Mutex
	// rd is the reads' session (opened at the first read).
	rd devssh.NetconfSession
	// held is the transaction's session; open is set while it has the
	// configuration open.
	held  devssh.NetconfSession
	open  bool
	allow func(string) error
	login *Login
	log   []string
	m     *masker
	// own is set from the confirmed commit's answer to the confirming
	// commit: this session has a commit pending that only it can confirm.
	own bool
	// retry is set when the device refused the confirmed commit in a
	// private session.
	retry   bool
	release context.CancelFunc
}

// NewJunosNetconf is the transport over an authenticated client (dialled as
// NewJunosCLI's is: with a context that outlives the job's cancellation).
// Closing the transport closes the client.
func NewJunosNetconf(c *devssh.Client, mode NetconfMode) *JunosNetconf {
	_, read, _ := devconf.Commands(devssh.VendorJuniper)
	return &JunosNetconf{client: c, mode: mode, read: read, m: &masker{}}
}

// DialJunosNetconf dials the device and returns its NETCONF transport, with
// the connection lifetime DialJunos gives the command line's.
func DialJunosNetconf(ctx context.Context, t devssh.Target, mode NetconfMode) (*JunosNetconf, error) {
	c, release, err := dialLife(ctx, t)
	if err != nil {
		return nil, err
	}
	j := NewJunosNetconf(c, mode)
	j.release = release
	return j, nil
}

// Vendor is the registry's word.
func (j *JunosNetconf) Vendor() string { return devssh.VendorJuniper }

// RollsBackOnClose is true: a confirmed commit whose session closes without
// confirming is rolled back at once (0.2.4 spike (d)).
func (j *JunosNetconf) RollsBackOnClose() bool { return true }

// LocalAddr is the local end of the connection.
func (j *JunosNetconf) LocalAddr() net.IP {
	if j.client == nil {
		return nil
	}
	return j.client.LocalAddr()
}

// Mode is the mode the transport opens its session in.
func (j *JunosNetconf) Mode() NetconfMode { return j.mode }

// RetryExclusive reports whether the device refused a confirmed commit in a
// private session: the transaction committed nothing and is to be run again
// in ModeExclusive.
func (j *JunosNetconf) RetryExclusive() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.retry
}

// Confirms reports whether an apply can commit and confirm through this
// transport: the hello offers the candidate and a confirmed commit, and the
// login's class may commit (read by Login).
func (j *JunosNetconf) Confirms() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.login == nil || !j.login.CanCommit() || j.rd == nil {
		return false
	}
	var cand, conf bool
	for _, c := range j.rd.Capabilities() {
		switch c {
		case capCandidate:
			cand = true
		case capConfirmed, capConfirmed11:
			conf = true
		}
	}
	return cand && conf
}

// Log is what was sent, a secret's value elided.
func (j *JunosNetconf) Log() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.log...)
}

// Held reports whether the held session has the configuration open.
func (j *JunosNetconf) Held() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.held != nil && j.open
}

// Close closes the sessions and the connection. A private or exclusive
// candidate that was not committed goes with its session, and so does a
// confirmed commit that was not confirmed (it is rolled back).
func (j *JunosNetconf) Close() error {
	j.mu.Lock()
	held, rd := j.held, j.rd
	j.held, j.rd, j.open, j.own = nil, nil, false, false
	j.mu.Unlock()
	if held != nil {
		_ = held.Close()
	}
	if rd != nil {
		_ = rd.Close()
	}
	if j.release != nil {
		defer j.release()
	}
	if j.client != nil {
		return j.client.Close()
	}
	return nil
}

// dropHeld closes the held session after a failure: nothing more is sent
// in it, and the device rolls back what it had not confirmed.
func (j *JunosNetconf) dropHeld() {
	j.mu.Lock()
	held := j.held
	j.held, j.open, j.own = nil, false, false
	j.mu.Unlock()
	if held != nil {
		_ = held.Close()
	}
}

func (j *JunosNetconf) logf(s string) {
	j.mu.Lock()
	j.log = append(j.log, s)
	j.mu.Unlock()
}

// --- the answer ---------------------------------------------------------------------------

// rpcMsg is one <rpc-error> of a reply.
type rpcMsg struct {
	Severity, Tag, Message, Path, Bad string
}

// text is the message as one line with the masker's elisions, the way an
// answer line of the command line reads ('error: ...').
func (e rpcMsg) text(m *masker) string {
	sev := e.Severity
	if sev == "" {
		sev = "error"
	}
	msg := e.Message
	if msg == "" {
		msg = e.Tag
	}
	return cut(m.text(sev + ": " + strings.TrimSpace(msg)))
}

// rpcReply is what the dispatch reads of a reply: its rpc-errors of every
// severity and the names of the elements it holds outside them.
type rpcReply struct {
	Errs []rpcMsg
	Seen map[string]bool
}

// parseReply reads a reply document. A document that is not XML is an
// error (fail closed).
func parseReply(reply string) (rpcReply, error) {
	r := rpcReply{Seen: map[string]bool{}}
	d := xml.NewDecoder(strings.NewReader(reply))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var cur *rpcMsg
	var field string
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return r, nil
		}
		if err != nil {
			return r, fmt.Errorf("%w: the reply is not XML", ErrUnrecognised)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			switch {
			case name == "rpc-error":
				cur = &rpcMsg{}
			case cur != nil:
				field = name
			default:
				r.Seen[name] = true
			}
		case xml.EndElement:
			if t.Name.Local == "rpc-error" && cur != nil {
				r.Errs = append(r.Errs, *cur)
				cur = nil
			}
			field = ""
		case xml.CharData:
			if cur == nil {
				continue
			}
			s := string(t)
			switch field {
			case "error-severity":
				cur.Severity += strings.TrimSpace(s)
			case "error-tag":
				cur.Tag += strings.TrimSpace(s)
			case "error-message":
				cur.Message += s
			case "error-path":
				cur.Path += strings.TrimSpace(s)
			case "bad-element":
				cur.Bad += strings.TrimSpace(s)
			}
		}
	}
}

// --- the guard and the reads -----------------------------------------------------------------

// readSession is the reads' session, opened at the first read. A session
// that failed is dropped so that the next read opens another.
func (j *JunosNetconf) readSession() (devssh.NetconfSession, error) {
	j.mu.Lock()
	rd := j.rd
	j.mu.Unlock()
	if rd != nil {
		return rd, nil
	}
	s, err := j.client.NETCONF()
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	if j.rd == nil {
		j.rd = s
	} else {
		_ = s.Close()
		s = j.rd
	}
	j.mu.Unlock()
	return s, nil
}

func (j *JunosNetconf) dropRead(s devssh.NetconfSession) {
	j.mu.Lock()
	if j.rd == s {
		j.rd = nil
	}
	j.mu.Unlock()
	_ = s.Close()
}

// runCmd runs an operational command as a <command> RPC and returns its
// text; cmd must be an apply word or the pull's read command (the guard of
// the command line's exec channel).
func (j *JunosNetconf) runCmd(ctx context.Context, cmd string) (string, error) {
	if cmd != j.read && cmd != devconf.PlainCommand(devssh.VendorJuniper) {
		if err := guardWord(cmd); err != nil {
			return "", err
		}
	}
	s, err := j.readSession()
	if err != nil {
		return "", err
	}
	j.logf(cmd)
	reply, err := s.RPC(ctx, devssh.CommandRPC(cmd))
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		return "", answerError(cmd, []string{rpcMsg{Severity: re.Severity, Tag: re.Tag, Message: re.Message}.text(j.m)}, j.m)
	case err != nil:
		j.dropRead(s)
		return "", err
	}
	out, err := devssh.ReplyText(reply)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %v", cmd, ErrUnrecognised, j.m.text(err.Error()))
	}
	return out, nil
}

// Identity runs 'show version'.
func (j *JunosNetconf) Identity(ctx context.Context) (Identity, error) {
	out, err := j.runCmd(ctx, plan.ApplyShowVersion)
	if err != nil {
		return Identity{}, err
	}
	return parseVersion(out)
}

// History runs 'show system commit'.
func (j *JunosNetconf) History(ctx context.Context) (History, error) {
	out, err := j.runCmd(ctx, plan.ApplyShowCommit)
	if err != nil {
		return nil, err
	}
	return parseHistory(out)
}

// State reads the history and says a confirmed commit is pending when entry
// 0 carries a window ('commit confirmed, rollback in Nmins'): over NETCONF
// there is no prompt and so no banner (see the package comment). Minutes is
// the entry's window, which is an upper bound of the minutes left.
func (j *JunosNetconf) State(ctx context.Context) (CommitState, error) {
	h, err := j.History(ctx)
	if err != nil {
		return CommitState{}, err
	}
	st := CommitState{History: h}
	if h[0].RollbackIn > 0 {
		st.Pending, st.Minutes = true, h[0].RollbackIn
	}
	return st, nil
}

// Login runs 'show cli authorization'.
func (j *JunosNetconf) Login(ctx context.Context) (Login, error) {
	out, err := j.runCmd(ctx, plan.ApplyShowAuthorization)
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
func (j *JunosNetconf) Read(ctx context.Context) (string, error) {
	out, err := j.runCmd(ctx, j.read)
	if err != nil {
		return "", err
	}
	for _, l := range nonBlank(lines(out)) {
		if !strings.HasPrefix(l, "set ") && !strings.HasPrefix(l, "deactivate ") {
			return "", answerError(j.read, []string{l}, j.m)
		}
	}
	return out, nil
}

// ReadPlain reads the plain view as JunosCLI.ReadPlain does.
func (j *JunosNetconf) ReadPlain(ctx context.Context) string {
	return devconf.ReadPlain(ctx, netconfRunner{j}, devssh.VendorJuniper)
}

type netconfRunner struct{ j *JunosNetconf }

func (r netconfRunner) Run(ctx context.Context, cmd string) (string, error) {
	return r.j.runCmd(ctx, cmd)
}

// LandedCompare runs 'show configuration | compare rollback 1 | no-more'.
func (j *JunosNetconf) LandedCompare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	out, err := j.runCmd(ctx, plan.ApplyLandedCompare)
	if err != nil {
		return plan.CompareText{}, err
	}
	c, err := plan.ParseCompareFor(out, d)
	if err != nil {
		return plan.CompareText{}, fmt.Errorf("%s: %w: %v", plan.ApplyLandedCompare, ErrUnrecognised, j.m.text(err.Error()))
	}
	return c, nil
}

// RollbackCompare runs 'show configuration | compare rollback n | no-more'.
func (j *JunosNetconf) RollbackCompare(ctx context.Context, n int) (plan.CompareText, error) {
	if n < 0 || n > plan.MaxRollback {
		return plan.CompareText{}, fmt.Errorf("%w: rollback %d is not one a device keeps", ErrNotSent, n)
	}
	cmd := plan.ApplyRollbackCompare(n)
	out, err := j.runCmd(ctx, cmd)
	if err != nil {
		return plan.CompareText{}, err
	}
	c, err := plan.ParseCompare(out)
	if err != nil {
		var le *plan.CompareLineError
		if errors.As(err, &le) {
			return plan.CompareText{}, fmt.Errorf("%s: %w: compare line %d: %s (not quoted)", cmd, ErrUnrecognised, le.Line, le.Why)
		}
		return plan.CompareText{}, fmt.Errorf("%s: %w: the answer is not a compare (not quoted)", cmd, ErrUnrecognised)
	}
	return c, nil
}

// --- the gate -------------------------------------------------------------------------------------

// SharedDirty is the gate, in a throwaway session that is closed after it:
// the shared candidate's compare against the committed configuration (a
// staged change) and a lock attempt on the shared candidate, released at
// once (another session's lock or its changes refuse it). Editors that
// changed nothing are not visible over NETCONF and are never reported.
func (j *JunosNetconf) SharedDirty(ctx context.Context) (Dirty, error) {
	s, err := j.client.NETCONF()
	if err != nil {
		return Dirty{}, err
	}
	defer func() { _ = s.Close() }()
	rpc := func(body string) (rpcReply, error) {
		reply, err := s.RPC(ctx, body)
		if err != nil {
			var re devssh.RPCError
			if errors.As(err, &re) {
				return rpcReply{Errs: []rpcMsg{{Severity: re.Severity, Tag: re.Tag, Message: re.Message}}}, err
			}
			return rpcReply{}, err
		}
		return parseReply(reply)
	}
	var d Dirty
	j.logf("netconf: get-configuration compare rollback 0 (shared candidate)")
	reply, err := s.RPC(ctx, `<get-configuration compare="rollback" rollback="0" format="text"/>`)
	if err != nil {
		return Dirty{}, j.gateError(err, plan.ApplyCompare)
	}
	out, err := devssh.ReplyText(reply)
	if err != nil {
		return Dirty{}, fmt.Errorf("%s: %w: the shared candidate's compare (not quoted)", plan.ApplyCompare, ErrUnrecognised)
	}
	c, perr := plan.ParseCompare(out)
	switch {
	case perr == nil && !c.Empty():
		d.Staged = true
	case perr != nil && strings.TrimSpace(out) != "":
		// a stranger's staged work: never quoted
		d.Staged = true
	}
	j.logf("netconf: lock candidate (the gate)")
	_, err = rpc(`<lock><target><candidate/></target></lock>`)
	if err != nil {
		var re devssh.RPCError
		if !errors.As(err, &re) {
			return Dirty{}, err
		}
		switch {
		case re.Tag == "lock-denied":
			return Dirty{}, &LockedError{By: holderOf(re.Message)}
		case strings.Contains(re.Message, "modified"):
			d.Staged = true
			return d, nil
		}
		return Dirty{}, answerError("lock candidate", []string{rpcMsg{Severity: re.Severity, Tag: re.Tag, Message: re.Message}.text(j.m)}, j.m)
	}
	j.logf("netconf: unlock candidate (the gate)")
	if _, err := rpc(`<unlock><target><candidate/></target></unlock>`); err != nil {
		var re devssh.RPCError
		if errors.As(err, &re) {
			// closing the throwaway session releases the lock all the same
			return d, nil
		}
		return Dirty{}, err
	}
	return d, nil
}

// gateError names a failure of the gate's own RPC.
func (j *JunosNetconf) gateError(err error, cmd string) error {
	var re devssh.RPCError
	if errors.As(err, &re) {
		return answerError(cmd, []string{rpcMsg{Severity: re.Severity, Tag: re.Tag, Message: re.Message}.text(j.m)}, j.m)
	}
	return err
}

// holderOf is the first word after 'locked by' in a lock-denied message
// ("" when there is none).
func holderOf(msg string) string {
	_, rest, ok := strings.Cut(msg, "locked by")
	if !ok {
		return ""
	}
	rest = strings.TrimLeft(rest, ": \t\r\n")
	if f := strings.Fields(rest); len(f) > 0 {
		return cut(f[0])
	}
	return ""
}

// --- the held session ----------------------------------------------------------------------

// Open opens the held session and the configuration in the transport's mode:
// private, or exclusive. allow is the allow-list every statement Load is
// given must pass. Another session's lock is a *LockedError with its holder;
// a private session opened under another's exclusive lock (the device
// answers with a warning that nothing can be committed) is refused the same
// way.
func (j *JunosNetconf) Open(ctx context.Context, allow func(string) error) error {
	if allow == nil {
		return fmt.Errorf("%w: Open needs the allow-list", ErrNotSent)
	}
	j.mu.Lock()
	if j.held != nil {
		j.mu.Unlock()
		return fmt.Errorf("%w: the held session is open already", ErrNotSent)
	}
	j.mu.Unlock()
	s, err := j.client.NETCONF()
	if err != nil {
		return err
	}
	j.mu.Lock()
	j.held, j.allow = s, allow
	j.mu.Unlock()
	child, word := "<private/>", "private"
	if j.mode == ModeExclusive {
		child, word = "<exclusive/>", "exclusive"
	}
	j.logf("netconf: open-configuration " + word)
	reply, err := s.RPC(ctx, "<open-configuration>"+child+"</open-configuration>")
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		j.dropHeld()
		switch {
		case re.Tag == "lock-denied":
			return &LockedError{By: holderOf(re.Message)}
		case strings.Contains(re.Message, "modified"):
			return &LockedError{Modified: true}
		}
		return answerError("open-configuration "+word, []string{rpcMsg{Severity: re.Severity, Tag: re.Tag, Message: re.Message}.text(j.m)}, j.m)
	case err != nil:
		j.dropHeld()
		return fmt.Errorf("%w: open-configuration: %v", ErrSessionLost, j.m.text(err.Error()))
	}
	r, err := parseReply(reply)
	if err != nil {
		j.dropHeld()
		return err
	}
	for _, e := range r.Errs {
		if strings.Contains(e.Message, "exclusive") {
			j.dropHeld()
			return &LockedError{}
		}
		j.dropHeld()
		return answerError("open-configuration "+word, []string{e.text(j.m)}, j.m)
	}
	if !r.Seen["ok"] {
		j.dropHeld()
		return answerError("open-configuration "+word, []string{"no <ok/>"}, j.m)
	}
	j.mu.Lock()
	j.open = true
	j.mu.Unlock()
	return nil
}

// rpcHeld sends one RPC in the held session and returns the parsed reply; a
// refusal is returned as the device's rpc-error (reply parsed, err a
// devssh.RPCError), a failure of the session itself drops it
// (ErrSessionLost).
func (j *JunosNetconf) rpcHeld(ctx context.Context, body, shown string) (rpcReply, error) {
	j.mu.Lock()
	held := j.held
	j.mu.Unlock()
	if held == nil {
		return rpcReply{}, fmt.Errorf("%w: %s", ErrSessionLost, shown)
	}
	reply, err := held.RPC(ctx, body)
	var re devssh.RPCError
	if errors.As(err, &re) {
		r, perr := parseReply(reply)
		if perr != nil || len(r.Errs) == 0 {
			r.Errs = []rpcMsg{{Severity: re.Severity, Tag: re.Tag, Message: re.Message}}
		}
		return r, err
	}
	if err != nil {
		j.dropHeld()
		return rpcReply{}, fmt.Errorf("%w: %s: %v", ErrSessionLost, shown, j.m.text(err.Error()))
	}
	return parseReply(reply)
}

// firstError is the answer error of a reply's rpc-errors, the command
// shown as cmd.
func (j *JunosNetconf) firstError(cmd string, r rpcReply) error {
	var ls []string
	for _, e := range r.Errs {
		ls = append(ls, e.text(j.m))
	}
	if len(ls) == 0 {
		ls = []string{"error: refused"}
	}
	return answerError(cmd, ls, j.m)
}

func (j *JunosNetconf) mustHold(shown string) error {
	if !j.Held() {
		return fmt.Errorf("%w: %s: no configuration is open", ErrSessionLost, shown)
	}
	return nil
}

// Load sends one statement as a <load-configuration> in set format; the
// answer must be its <ok/> alone, or for a delete the tolerated 'statement
// not found' warning.
func (j *JunosNetconf) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	j.mu.Lock()
	allow := j.allow
	j.mu.Unlock()
	if err := checkStatement(allow, l); err != nil {
		return Loaded{}, err
	}
	if err := j.mustHold(l.Shown()); err != nil {
		return Loaded{}, err
	}
	j.mu.Lock()
	j.m.add(l)
	j.mu.Unlock()
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(l.Text))
	j.logf(l.Shown())
	r, err := j.rpcHeld(ctx, `<load-configuration action="set" format="text"><configuration-set>`+b.String()+
		`</configuration-set></load-configuration>`, l.Shown())
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		return Loaded{}, j.firstError(l.Text, r)
	case err != nil:
		return Loaded{}, err
	}
	if len(r.Errs) == 0 && r.Seen["ok"] {
		return Loaded{}, nil
	}
	if r.Seen["ok"] && len(r.Errs) == 1 && l.Op == plan.OpDelete && r.Errs[0].Severity == "warning" &&
		strings.Contains(r.Errs[0].Message, "statement not found") {
		return Loaded{NotFound: true}, nil
	}
	return Loaded{}, j.firstError(l.Text, r)
}

// Compare asks for the candidate's difference against the committed
// configuration ('show | compare').
func (j *JunosNetconf) Compare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	if err := j.mustHold(plan.ApplyCompare); err != nil {
		return plan.CompareText{}, err
	}
	j.logf(plan.ApplyCompare)
	j.mu.Lock()
	held := j.held
	j.mu.Unlock()
	reply, err := held.RPC(ctx, `<get-configuration compare="rollback" rollback="0" format="text"/>`)
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		return plan.CompareText{}, answerError(plan.ApplyCompare, []string{rpcMsg{Severity: re.Severity, Tag: re.Tag, Message: re.Message}.text(j.m)}, j.m)
	case err != nil:
		j.dropHeld()
		return plan.CompareText{}, fmt.Errorf("%w: %s: %v", ErrSessionLost, plan.ApplyCompare, j.m.text(err.Error()))
	}
	out, err := devssh.ReplyText(reply)
	if err != nil {
		return plan.CompareText{}, fmt.Errorf("%s: %w: %v", plan.ApplyCompare, ErrUnrecognised, j.m.text(err.Error()))
	}
	c, err := plan.ParseCompareFor(out, d)
	if err != nil {
		return plan.CompareText{}, fmt.Errorf("%s: %w: %v", plan.ApplyCompare, ErrUnrecognised, j.m.text(err.Error()))
	}
	return c, nil
}

// Check is the commit check; the answer must be its success element. It is
// not sent while this session has a confirmed commit pending (ErrPending).
func (j *JunosNetconf) Check(ctx context.Context) error {
	if err := guardWord(plan.ApplyCommitCheck); err != nil {
		return err
	}
	if err := j.mustHold(plan.ApplyCommitCheck); err != nil {
		return err
	}
	j.mu.Lock()
	own := j.own
	j.mu.Unlock()
	if own {
		return fmt.Errorf("%w: %s: %w: this session's own confirmed commit", ErrNotSent, plan.ApplyCommitCheck, ErrPending)
	}
	j.logf(plan.ApplyCommitCheck)
	r, err := j.rpcHeld(ctx, `<commit-configuration><check/></commit-configuration>`, plan.ApplyCommitCheck)
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		for _, e := range r.Errs {
			if e.Tag == "lock-denied" {
				return &LockedError{By: holderOf(e.Message)}
			}
		}
		return j.firstError(plan.ApplyCommitCheck, r)
	case err != nil:
		return err
	}
	if !r.Seen["commit-check-success"] || len(r.Errs) > 0 {
		return j.firstError(plan.ApplyCommitCheck, r)
	}
	return nil
}

// reCommitWord splits the apply's own commit line into its minutes and its
// comment: the NETCONF RPCs carry what the command line's words do, from the
// same constructors, so the clamp and the safe characters are the plan's.
var reCommitWord = regexp.MustCompile(`^commit(?: confirmed ([0-9]+))? comment "(.*)"$`)

func commitParts(line string) (minutes int, comment string, err error) {
	m := reCommitWord.FindStringSubmatch(line)
	if m == nil {
		return 0, "", fmt.Errorf("%w: %q is not a commit word", ErrNotSent, cut(line))
	}
	if m[1] != "" {
		minutes, _ = strconv.Atoi(m[1])
	}
	return minutes, m[2], nil
}

// CommitConfirmed sends the confirmed commit with tacctl's comment as its
// log. A device that refuses it in a private session gives
// ErrPrivateConfirmRefused (and RetryExclusive): nothing was committed.
func (j *JunosNetconf) CommitConfirmed(ctx context.Context, minutes int, id, user string) error {
	line := plan.ApplyCommitConfirmed(minutes, id, user)
	if err := guardWord(line); err != nil {
		return err
	}
	if err := j.mustHold(line); err != nil {
		return err
	}
	n, comment, err := commitParts(line)
	if err != nil {
		return err
	}
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(comment))
	j.logf(line)
	r, err := j.rpcHeld(ctx, "<commit><confirmed/><confirm-timeout>"+strconv.Itoa(n)+"</confirm-timeout><log>"+b.String()+"</log></commit>", line)
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		for _, e := range r.Errs {
			switch {
			case strings.Contains(e.Message, textNoConfirmedPrivate):
				if j.mode != ModeExclusive {
					j.mu.Lock()
					j.retry = true
					j.mu.Unlock()
				}
				return fmt.Errorf("%w: %w", ErrPrivateConfirmRefused, j.firstError(line, r))
			case e.Tag == "lock-denied":
				return &LockedError{By: holderOf(e.Message)}
			}
		}
		return j.firstError(line, r)
	case err != nil:
		return err
	}
	if !r.Seen["ok"] && !r.Seen["commit-success"] || len(r.Errs) > 0 {
		return j.firstError(line, r)
	}
	j.mu.Lock()
	j.own = true
	j.mu.Unlock()
	return nil
}

// Confirm is the confirming commit, in the session that committed.
func (j *JunosNetconf) Confirm(ctx context.Context, id, user string) error {
	line := plan.ApplyConfirm(id, user)
	if err := guardWord(line); err != nil {
		return err
	}
	if err := j.mustHold(line); err != nil {
		return err
	}
	_, comment, err := commitParts(line)
	if err != nil {
		return err
	}
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(comment))
	j.logf(line)
	r, err := j.rpcHeld(ctx, "<commit><log>"+b.String()+"</log></commit>", line)
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		return j.firstError(line, r)
	case err != nil:
		return err
	}
	if !r.Seen["ok"] && !r.Seen["commit-success"] || len(r.Errs) > 0 {
		return j.firstError(line, r)
	}
	j.mu.Lock()
	j.own = false
	j.mu.Unlock()
	return nil
}

// Cancel closes the held session without confirming: the device rolls the
// confirmed commit back at once (0.2.4 spike (d)). The driver reads the
// state afterwards and names what happened; nothing is committed by the
// transport.
func (j *JunosNetconf) Cancel(ctx context.Context, id string) error {
	_ = ctx
	j.mu.Lock()
	held := j.held
	j.mu.Unlock()
	if held == nil {
		return fmt.Errorf("%w: cancel %s", ErrSessionLost, cut(id))
	}
	j.logf("netconf: close-session (cancel " + cut(id) + ")")
	j.dropHeld()
	return nil
}

// Revert is not applicable: nothing but the held session confirms a NETCONF
// commit, so a commit that "something else confirmed" cannot happen to it.
func (j *JunosNetconf) Revert(ctx context.Context, id string) error {
	_, _ = ctx, id
	return fmt.Errorf("%w: a NETCONF confirmed commit is confirmed by its own session only", ErrNotApplicable)
}

// Discard drops the candidate and ends the held session: a discard-changes
// (an exclusive candidate has the changes of nobody else), the configuration
// closed, then the session. A device that does not answer closes the session
// all the same.
func (j *JunosNetconf) Discard(ctx context.Context) error {
	defer j.dropHeld()
	if err := j.mustHold("discard"); err != nil {
		return err
	}
	j.logf("netconf: discard-changes")
	r, err := j.rpcHeld(ctx, "<discard-changes/>", "discard-changes")
	var re devssh.RPCError
	switch {
	case errors.As(err, &re):
		return j.firstError("discard-changes", r)
	case err != nil:
		return err
	}
	if !r.Seen["ok"] {
		return j.firstError("discard-changes", r)
	}
	j.logf("netconf: close-configuration")
	r, err = j.rpcHeld(ctx, "<close-configuration/>", "close-configuration")
	switch {
	case errors.As(err, &re):
		return j.firstError("close-configuration", r)
	case err != nil:
		return err
	}
	if !r.Seen["ok"] {
		return j.firstError("close-configuration", r)
	}
	return nil
}
