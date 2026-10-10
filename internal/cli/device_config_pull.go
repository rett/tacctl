package cli

// 'device config pull' (docs/plans/0.2.4-plan.md D61, D65-D69 and section
// 9): read the managed sections of devices over NETCONF or the ssh command
// line as the invoking user, compare them with what tacctl renders for each
// device (devices.Managed), keep a record per device and print one line per
// device. The selection is device_config_select.go, the runner is
// internal/devconf/batch, the progress is device_config_view.go.
//
// The device password is resolved once, before any connection, through
// devicePasswords: the terminal prompt today, the shell's password cache
// where WP11.6 plugs it in (cachedDevicePassword is the one place a cached
// password is consulted). Nothing here writes it anywhere, and no worker
// ever prompts.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/ui"
)

// The transports of a pull (device.config.transport, --transport).
const (
	transportAuto    = "auto"
	transportNetconf = "netconf"
	transportSSH     = "ssh"
)

// The NETCONF probe states of a record and of 'device check' (D61).
const (
	netconfHelloOK    = "hello ok"
	netconfPortClosed = "port closed"
	netconfNoHello    = "no hello"
	netconfNotProbed  = "not probed"
)

// wtiUnsupported is what a WTI unit's pull says (D71).
const wtiUnsupported = "WTI units are not read in this release"

// pullArgs are the options of a pull, as 'device config pull' and 'device
// config diff --pull' take them.
type pullArgs struct {
	transport   string
	concurrency int
	timeout     time.Duration
	maxFailures int
	showDiff    bool
	json        bool
	render      managedOptions
}

// deviceSettings are the device.config.* settings in force.
type deviceSettings struct {
	maxConcurrency int
	transport      string
	timeout        time.Duration
}

// deviceConfigSettings reads device.config.* (D68); a value the schema
// would not accept (a hand-edited file that 'config validate' reports) is
// the default.
func (inv *invocation) deviceConfigSettings() deviceSettings {
	s := deviceSettings{maxConcurrency: 8, transport: transportAuto, timeout: 90 * time.Second}
	if n, err := atoiIn(inv.confGet("device.config.max_concurrency", "8"), 1, 64); err == nil {
		s.maxConcurrency = n
	}
	switch t := inv.confGet("device.config.transport", transportAuto); t {
	case transportAuto, transportNetconf, transportSSH:
		s.transport = t
	}
	if n, err := atoiIn(inv.confGet("device.config.timeout", "90"), 10, 600); err == nil {
		s.timeout = time.Duration(n) * time.Second
	}
	return s
}

// pullOutcome is what one device's pull found, handed from the worker to
// the view and the printing through batch.Result.Value. The worker is done
// with it when it returns the result.
type pullOutcome struct {
	Name, Scope, Vendor string
	// Result is the record's result (devconf.Result*); "" when nothing was
	// attempted (no expected configuration could be made).
	Result string
	// Transport is what read the configuration; Netconf the probe's answer
	// (netconfNotProbed when none was made).
	Transport, Netconf string
	// Fallback says why NETCONF was not used under 'auto' ("netconf: port
	// closed").
	Fallback string
	Duration time.Duration
	// Sections are the comparison of a successful pull.
	Sections       []devconf.SectionResult
	SecretsVisible bool
	// Reason is the failure in words; Hint what to do about it.
	Reason, Hint string
	// Offered is the host key a device presented that is not pinned
	// ('<type> <base64>'): the pull raises the hostkey notice from it.
	Offered string
}

// differs are the sections that differ from what tacctl renders (differs or
// missing: a statement tacctl renders is absent), in order.
func differingSections(rs []devconf.SectionResult) []string {
	var out []string
	for _, r := range rs {
		if r.State == devconf.StateDiffers || r.State == devconf.StateMissing {
			out = append(out, r.Name)
		}
	}
	return out
}

// pullArgsOf reads the options a pull and a diff --pull share: the
// transport, the concurrency (never above the configured cap), the
// per-device timeout, the failure budget and --server and --source.
func (inv *invocation) pullArgsOf(p Parsed, verb string) (pullArgs, error) {
	st := inv.deviceConfigSettings()
	usage := "Usage: tacctl device config " + deviceConfigUse(verb)
	a := pullArgs{transport: st.transport, timeout: st.timeout, showDiff: p.Has("--diff"), json: p.Has("--json")}
	if p.Has("--transport") {
		switch t := p.Value("--transport"); t {
		case transportAuto, transportNetconf, transportSSH:
			a.transport = t
		default:
			return a, inv.argErr("--transport takes auto, netconf or ssh: '"+t+"'", usage)
		}
	}
	if p.Has("--concurrency") {
		n, err := atoiIn(p.Value("--concurrency"), 1, 1<<20)
		if err != nil {
			return a, inv.argErr("--concurrency takes a number of devices, 1 or more: '"+p.Value("--concurrency")+"'", usage)
		}
		if n > st.maxConcurrency {
			return a, inv.argErr("--concurrency "+strconv.Itoa(n)+" is above device.config.max_concurrency ("+strconv.Itoa(st.maxConcurrency)+").",
				"A superuser raises that limit with: tacctl config devices max-concurrency <n> (at most 64)")
		}
		a.concurrency = n
	}
	if p.Has("--timeout") {
		n, err := atoiIn(p.Value("--timeout"), 10, 600)
		if err != nil {
			return a, inv.argErr("--timeout takes seconds per device, 10 to 600: '"+p.Value("--timeout")+"'", usage)
		}
		a.timeout = time.Duration(n) * time.Second
	}
	if p.Has("--max-failures") {
		n, err := atoiIn(p.Value("--max-failures"), 1, 1<<20)
		if err != nil {
			return a, inv.argErr("--max-failures takes a number of failed devices, 1 or more: '"+p.Value("--max-failures")+"'", usage)
		}
		a.maxFailures = n
	}
	if p.Has("--server") {
		addr, name, err := inv.deviceServerFlag(p.Value("--server"))
		if err != nil {
			// Its refusal is printed; as every wrong argument of these verbs
			// it ends with the status of a wrong argument.
			var ee *ExitError
			if errors.As(err, &ee) && ee.Err == nil && ee.Code == 1 {
				return a, exit(batch.ExitUsage)
			}
			return a, err
		}
		a.render.AuthServer, a.render.AuthName = addr, name
	}
	if p.Has("--source") {
		norm, err := devreg.NormalizeAddress(p.Value("--source"))
		if err != nil || strings.Contains(norm, ":") || strings.Contains(p.Value("--source"), "/") {
			return a, inv.argErr("--source takes the IPv4 address tacctl reaches the devices from (a single address, no prefix length): '" + p.Value("--source") + "'")
		}
		a.render.SourceIP = norm
	}
	return a, nil
}

// --- the password -------------------------------------------------------------

// devicePasswords is where a pull gets the device login password and what
// it tells the source of it (D70, plan section 6). The pull resolves the
// password once, before any connection; it never reaches argv, the
// environment, a file or a log line. WP11.6 plugs the shell's password
// cache in through this interface: Accepted is where a prompted password is
// stored (never one that came from the cache, so the maximum lifetime
// cannot be extended by use), Rejected where the cache forgets.
type devicePasswords interface {
	// Password returns the password for user. The caller zeroes it when
	// the run ends.
	Password(ctx context.Context, user string) ([]byte, error)
	// Accepted is called once, after the first device accepted the
	// password.
	Accepted()
	// Rejected is called once, after the first device rejected it.
	Rejected()
}

// newDevicePasswords is the source of the invocation's password; tests
// replace it. The process is marked not dumpable first (a password it
// prompted for will live in its memory) and the session's password cache
// variable is read, once, and taken out of the environment
// (password_cache.go).
var newDevicePasswords = func(inv *invocation) devicePasswords {
	_ = setNotDumpable()
	return &terminalPasswords{inv: inv, client: inv.takeAskpass()}
}

// passwordPrompt reads a line from a terminal without echo (tests replace
// it).
var passwordPrompt = askpass.Prompt

// errNoPassword is a pull with no terminal and no cached password.
var errNoPassword = errors.New("a password is needed and no terminal or cached password is available")

// terminalPasswords is the default source: the session's password cache
// first, then the terminal.
type terminalPasswords struct {
	inv *invocation
	// client asks the shell's password cache (nil: this line has none).
	client *askpass.Client

	mu sync.Mutex
	// secret is a private copy of a password typed for this run (nil: none,
	// or it came from the cache, or it was already stored or dropped). The
	// slice Password returns is the caller's to zero; this one is zeroed by
	// Accepted, Rejected and Done.
	secret []byte
	// rejected: a device refused the password; nothing is stored after it.
	rejected bool
}

// cachedDevicePassword is the one place a cached password is consulted:
// the password the user's console session holds, or nil. The agent answers
// once per line and only while the line runs.
func (t *terminalPasswords) cachedDevicePassword(ctx context.Context, _ string) []byte {
	if t.client == nil {
		return nil
	}
	pw, err := t.client.Get(ctx)
	if err != nil {
		return nil
	}
	return pw
}

// typed remembers a private copy of a password the person typed.
func (t *terminalPasswords) typed(pw []byte) {
	t.mu.Lock()
	t.secret = append([]byte(nil), pw...)
	t.mu.Unlock()
}

func (t *terminalPasswords) Password(ctx context.Context, user string) ([]byte, error) {
	if pw := t.cachedDevicePassword(ctx, user); len(pw) > 0 {
		return pw, nil
	}
	// A test build has no terminal: the knob supplies the password.
	if pw := t.inv.app.Knobs.DevicePassword(); pw != "" {
		b := []byte(pw)
		t.typed(b)
		return b, nil
	}
	tty, closeTTY := t.inv.passwordTerminal()
	if tty == nil {
		return nil, errNoPassword
	}
	defer closeTTY()
	pw, err := passwordPrompt(tty, "Password for "+user+" (device login): ")
	if err != nil {
		if errors.Is(err, askpass.ErrCancelled) {
			return nil, ui.ErrInterrupted
		}
		if errors.Is(err, askpass.ErrNoTerminal) {
			return nil, errNoPassword
		}
		if errors.Is(err, askpass.ErrBadSecret) {
			return nil, errors.New("the password is empty or has a line break or is too long; nothing was tried")
		}
		return nil, err
	}
	t.typed(pw)
	return pw, nil
}

// Accepted stores the password in the session's cache when the person
// typed it for this run: a password that came from the cache is not stored
// again, so its maximum lifetime cannot be stretched by use. A cache that
// cannot be reached is no failure of the pull. The lock is held across the
// store and Rejected holds it across the forget, so a store never lands
// after a forget in the same run, whichever worker gets there first.
func (t *terminalPasswords) Accepted() {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.secret
	t.secret = nil
	if len(s) == 0 {
		return
	}
	defer askpass.Zero(s)
	if t.rejected || t.client == nil {
		return
	}
	_ = t.client.Store(context.Background(), s)
}

// Rejected makes the cache forget at once, whichever way the password came
// (one wrong password must not be tried again, here or on the next line),
// and keeps a later Accepted from storing it.
func (t *terminalPasswords) Rejected() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rejected = true
	askpass.Zero(t.secret)
	t.secret = nil
	if t.client != nil {
		_ = t.client.Forget(context.Background())
	}
}

// Done drops what the source still holds (a run no device accepted or
// rejected).
func (t *terminalPasswords) Done() {
	t.mu.Lock()
	defer t.mu.Unlock()
	askpass.Zero(t.secret)
	t.secret = nil
}

// passwordTerminal is the terminal a password is typed at: stdin when it
// is one, else the controlling terminal; nil when there is none. The close
// function releases a terminal it opened.
func (inv *invocation) passwordTerminal() (*os.File, func()) {
	if f, ok := inv.app.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return f, func() {}
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, func() {}
	}
	if !term.IsTerminal(int(f.Fd())) {
		_ = f.Close()
		return nil, func() {}
	}
	return f, func() { _ = f.Close() }
}

// --- the dial ------------------------------------------------------------------

// deviceDialOverride replaces the TCP dial of every device in tests (the
// in-process fake device); nil dials the device's own address. A test build
// can also set the knob TACCTL_TEST_DEVICE_DIAL.
var deviceDialOverride devssh.Dialer

// deviceDialer is the dialer of this invocation's device sessions: the
// knob's loopback address (test builds) or the tests' override, else nil
// (the device's own address).
func (inv *invocation) deviceDialer() devssh.Dialer {
	if addr := inv.app.Knobs.DeviceDial(); addr != "" {
		return func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	return deviceDialOverride
}

// deviceTarget is where and how to log in to a registered device.
func (inv *invocation) deviceTarget(e devreg.Entry, user string, pw devssh.PasswordSource) devssh.Target {
	host, _ := devreg.SSHTarget(e)
	return devssh.Target{
		Host: host, Port: e.SSHPort(), User: user, HostKeys: e.HostKeys, Legacy: e.LegacySSH,
		Password: pw, ConnectTimeout: devssh.DefaultConnectTimeout, Dialer: inv.deviceDialer(),
	}
}

// --- reading -------------------------------------------------------------------

// deviceRead is what reading one device's configuration returned.
type deviceRead struct {
	Raw string
	// Transport is netconf or ssh; Netconf the probe's state, "" when no
	// probe was made.
	Transport, Netconf string
	// Fallback is why NETCONF was not used under auto ("" when it was, or
	// was not tried).
	Fallback string
}

// errNetconfNotRead is --transport netconf for a vendor that has no NETCONF
// read (D61: IOS-XE reads go over the command line).
var errNetconfNotRead = errors.New("NETCONF is not read for Cisco devices; use --transport ssh (or auto)")

// netconfRunner runs a CLI command as a NETCONF <command> RPC and returns
// the text of the reply: the same text the command line gives (D61).
type netconfRunner struct{ s devssh.NetconfSession }

func (r netconfRunner) Run(ctx context.Context, cmd string) (string, error) {
	reply, err := r.s.RPC(ctx, devssh.CommandRPC(cmd))
	if err != nil {
		return "", err
	}
	// devssh's own reader of a reply: it takes the XML declaration a Junos
	// reply starts with (encoding="us-ascii"), which devconf.UnwrapNetconf
	// (a decoder without a charset reader) does not.
	return devssh.ReplyText(reply)
}

// readDeviceConfig reads a device's configuration through the logged-in
// client: over NETCONF where the mode and the vendor allow it and the
// device answers, over the command line otherwise ('auto' falls back with
// the reason; 'netconf' and 'ssh' never do).
func readDeviceConfig(ctx context.Context, c *devssh.Client, vendor, mode string) (deviceRead, error) {
	var out deviceRead
	read, err := devconf.Reader(vendor)
	if err != nil {
		return out, err
	}
	fam, _ := devconf.Family(vendor)
	junos := fam == devconf.FamilyJunos
	if mode == transportNetconf && !junos {
		return out, errNetconfNotRead
	}
	if junos && mode != transportSSH {
		ns, nerr := c.NETCONF()
		if nerr == nil {
			out.Netconf = netconfHelloOK
			raw, rerr := func() (string, error) {
				defer func() { _ = ns.Close() }()
				return read(ctx, netconfRunner{ns})
			}()
			if rerr == nil {
				out.Raw, out.Transport = raw, transportNetconf
				return out, nil
			}
			if mode == transportNetconf || ctx.Err() != nil {
				return out, rerr
			}
			out.Fallback = "netconf: " + shortReason(rerr)
		} else {
			switch {
			case errors.Is(nerr, devssh.ErrNoSubsystem):
				out.Netconf = netconfPortClosed
			default:
				out.Netconf = netconfNoHello
			}
			if mode == transportNetconf {
				return out, nerr
			}
			if ctx.Err() != nil {
				return out, nerr
			}
			out.Fallback = "netconf: " + out.Netconf
		}
	}
	s, err := c.CLI(vendor)
	if err != nil {
		return out, err
	}
	defer func() { _ = s.Close() }()
	raw, err := read(ctx, s)
	if err != nil {
		return out, err
	}
	out.Raw, out.Transport = raw, transportSSH
	return out, nil
}

// shortReason is an error's first line, cut short.
func shortReason(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

// resultOf derives the record's result and the words for a failure from the
// typed errors (never by parsing text), and a hint where one helps.
func resultOf(ctx context.Context, name string, err error) (result, reason, hint string) {
	var hk devssh.ErrHostKey
	var rpc devssh.RPCError
	switch {
	case errors.As(err, &hk):
		if hk.Unpinned() {
			return devconf.ResultHostKeyMismatch, "no host key is pinned for the device",
				"tacctl device hostkey " + name + " accept"
		}
		return devconf.ResultHostKeyMismatch, hk.Error(), "tacctl device hostkey " + name + " show"
	case errors.Is(err, devssh.ErrAuth):
		return devconf.ResultAuthFailed, "authentication failed", ""
	case errors.Is(err, context.Canceled) || (ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded)):
		return devconf.ResultInterrupted, "interrupted", ""
	case errors.Is(err, devssh.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return devconf.ResultTimeout, "timed out", ""
	case errors.Is(err, devssh.ErrUnreachable):
		return devconf.ResultUnreachable, shortReason(err), ""
	case errors.Is(err, devssh.ErrHandshake):
		return devconf.ResultUnreachable, shortReason(err), "tacctl device legacy-ssh " + name + " enable (an old IOS needs its legacy algorithms)"
	case errors.Is(err, devssh.ErrNoSubsystem):
		return devconf.ResultUnreachable, "NETCONF is not enabled on the device", ""
	case errors.Is(err, errNetconfNotRead):
		return devconf.ResultUnsupported, err.Error(), ""
	case errors.Is(err, devconf.ErrParse), errors.Is(err, devssh.ErrProtocol), errors.Is(err, devssh.ErrOutputTooLarge),
		errors.As(err, &rpc):
		return devconf.ResultParseFailed, shortReason(err), ""
	case errors.Is(err, devssh.ErrClosed):
		return devconf.ResultUnreachable, shortReason(err), ""
	}
	return devconf.ResultUnreachable, shortReason(err), ""
}

// --- the batch -------------------------------------------------------------------

// pullRun is one pull: what the jobs share. The password and the records
// store are the only mutable things, and both are guarded.
type pullRun struct {
	inv      *invocation
	user     string
	mode     string
	render   *managedRender
	store    devconf.Store
	passwd   devicePasswords
	password string // the login password as ssh takes it (a Go string)

	acceptOnce, rejectOnce sync.Once
}

// pullJob is the batch job of one registered device.
func (r *pullRun) pullJob(e devreg.Entry) batch.Job {
	return batch.Job{Name: e.Name, Do: func(ctx context.Context) batch.Result {
		start := r.inv.app.Knobs.Now()
		o := &pullOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Netconf: netconfNotProbed}
		res := r.pullDevice(ctx, e, o)
		o.Duration = r.inv.app.Knobs.Now().Sub(start)
		res.Value = o
		return res
	}}
}

// pullDevice is one device's pull: render, connect, read, compare, record.
func (r *pullRun) pullDevice(ctx context.Context, e devreg.Entry, o *pullOutcome) batch.Result {
	inv := r.inv
	fail := func(status batch.Status, reason, hint string) batch.Result {
		o.Reason, o.Hint = reason, hint
		return batch.Result{Status: status, Reason: reason}
	}
	if e.Vendor == "wti" {
		o.Result = devconf.ResultUnsupported
		r.record(o, e)
		return fail(batch.StatusFailed, wtiUnsupported, "")
	}
	// --transport netconf does not read a Cisco device (D61): refused before
	// any login, and the record is left as it was (nothing was attempted).
	if r.mode == transportNetconf && e.Vendor == "cisco" {
		return fail(batch.StatusFailed, errNetconfNotRead.Error(), "")
	}
	expected, err := r.render.Expected(e)
	if err != nil {
		return fail(batch.StatusFailed, "cannot build the expected configuration: "+err.Error(), "")
	}
	client, err := devssh.Dial(ctx, inv.deviceTarget(e, r.user, func() (string, error) { return r.password, nil }))
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	defer func() { _ = client.Close() }()
	r.acceptOnce.Do(r.passwd.Accepted)

	rd, err := readDeviceConfig(ctx, client, e.Vendor, r.mode)
	if rd.Netconf != "" {
		o.Netconf = rd.Netconf
	}
	o.Fallback = rd.Fallback
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	o.Transport = rd.Transport
	ext, err := devconf.ExtractWith(e.Vendor, rd.Raw, devconf.Options{Expected: expected})
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	results, err := devconf.CompareAll(expected, ext)
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	o.Result, o.Sections, o.SecretsVisible = devconf.ResultOK, results, ext.SecretsVisible
	if err := r.recordSuccess(o, e, ext, results); err != nil {
		o.Result = ""
		return fail(batch.StatusFailed, "cannot record the result: "+strings.Join(msgs(err), " "), "")
	}
	return batch.Result{Status: batch.StatusOK, Differs: differingSections(results)}
}

// failed turns an error into the outcome and the batch status, and keeps
// the record of the attempt.
func (r *pullRun) failed(ctx context.Context, e devreg.Entry, o *pullOutcome, err error) batch.Result {
	result, reason, hint := resultOf(ctx, e.Name, err)
	o.Result, o.Reason, o.Hint = result, reason, hint
	var hk devssh.ErrHostKey
	if errors.As(err, &hk) {
		o.Offered = hk.Offered
	}
	if errors.Is(err, devssh.ErrAuth) {
		r.rejectOnce.Do(r.passwd.Rejected)
	}
	r.record(o, e)
	st := batch.StatusFailed
	if result == devconf.ResultAuthFailed {
		st = batch.StatusAuthFailed
	}
	return batch.Result{Status: st, Reason: reason, Err: err}
}

// now is the clock of the records.
func (r *pullRun) now() time.Time { return r.inv.app.Knobs.Now() }

// record keeps a failed attempt: the record's result is the attempt's and
// the sections and times of the last good pull stay (they are what 'diff'
// compares). A record that cannot be written is not the pull's failure: the
// device line already says what happened.
func (r *pullRun) record(o *pullOutcome, e devreg.Entry) {
	unlock, err := r.store.Lock()
	if err != nil {
		return
	}
	defer unlock()
	recs, _ := r.store.Load()
	var rec devconf.Record
	if old, ok := recs.Of(e.Name); ok {
		rec = *old
	}
	rec.Address, rec.Vendor, rec.Result = e.Address, e.Vendor, o.Result
	if o.Netconf != "" && o.Netconf != netconfNotProbed {
		rec.Netconf, rec.NetconfAt = o.Netconf, r.now()
	}
	recs.Put(e.Name, rec)
	recs.Updated = r.now()
	_ = r.store.Save(recs)
}

// recordSuccess keeps a successful pull: the sections file, then the
// record, under the store's lock.
func (r *pullRun) recordSuccess(o *pullOutcome, e devreg.Entry, ext devconf.Extracted, results []devconf.SectionResult) error {
	unlock, err := r.store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	recs, _ := r.store.Load()
	var rec devconf.Record
	if old, ok := recs.Of(e.Name); ok {
		rec = *old
	}
	now := r.now()
	rec.Address, rec.Vendor, rec.Transport = e.Address, e.Vendor, o.Transport
	if o.Netconf != "" && o.Netconf != netconfNotProbed {
		rec.Netconf, rec.NetconfAt = o.Netconf, now
	}
	rec.Pulled, rec.By, rec.Result = now, r.user, devconf.ResultOK
	rec.DurationMS = o.Duration.Milliseconds()
	rec.SecretsVisible = ext.SecretsVisible
	if err := rec.SetSections(ext, results); err != nil {
		return err
	}
	if err := r.store.SaveSections(e.Name, e.Vendor, ext.Sections); err != nil {
		return err
	}
	recs.Put(e.Name, rec)
	recs.Updated = now
	return r.store.Save(recs)
}

// configStore is the records store of this invocation.
func (inv *invocation) configStore() devconf.Store {
	return devconf.Store{Records: inv.app.Paths.ConfigRecords, Dir: inv.app.Paths.ConfigDir}
}

// interruptSource, when a test sets it, is the source of the operator's
// interrupts instead of the process's signals: the channel each Ctrl-C
// arrives on, so a test delivers them without a signal that any other code
// of the process could see.
var interruptSource func() <-chan struct{}

// batchInterrupts wires the operator's Ctrl-C to the runner: the first
// SIGINT stops new devices from starting, the second cancels the running
// ones; SIGTERM and SIGHUP cancel at once. The context is not the
// invocation's (whose cancellation is the first SIGINT).
func (inv *invocation) batchInterrupts() (ctx context.Context, interrupts <-chan struct{}, stop func()) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(inv.ctx))
	if interruptSource != nil {
		return ctx, interruptSource(), cancel
	}
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	ints := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-ch:
				if s == syscall.SIGINT {
					select {
					case ints <- struct{}{}:
					default:
					}
					continue
				}
				cancel()
			case <-done:
				return
			}
		}
	}()
	return ctx, ints, func() {
		signal.Stop(ch)
		close(done)
		cancel()
	}
}

// pullBatch is what runPull needs and returns.
type pullBatch struct {
	entries []devreg.Entry
	render  *managedRender
	args    pullArgs
	user    string
	view    batch.View
}

// runPull resolves the password, runs the pool over the entries and
// returns the summary with each device's outcome in the order of the
// entries (nil for a device that was not started).
func (inv *invocation) runPull(b pullBatch) (batch.Summary, []*pullOutcome, error) {
	settings := inv.deviceConfigSettings()
	run := &pullRun{inv: inv, user: b.user, mode: b.args.transport, render: b.render, store: inv.configStore(),
		passwd: newDevicePasswords(inv)}
	// The password, once, before any connection and only when a device will
	// be dialled: a WTI-only selection never asks.
	if needsLogin(b.entries) {
		pw, err := run.passwd.Password(inv.ctx, b.user)
		if err != nil {
			return batch.Summary{}, nil, err
		}
		run.password = string(pw)
		askpass.Zero(pw)
	}
	jobs := make([]batch.Job, len(b.entries))
	for i, e := range b.entries {
		jobs[i] = run.pullJob(e)
	}
	ctx, interrupts, stop := inv.batchInterrupts()
	defer stop()
	sum := batch.Run(ctx, batch.Options{
		Concurrency: b.args.concurrency, Cap: settings.maxConcurrency, Timeout: b.args.timeout,
		MaxFailures: b.args.maxFailures, StopOnAuthFailure: true, Interrupts: interrupts, Clock: inv.app.Knobs.Now,
	}, jobs, b.view)
	run.password = ""
	if d, ok := run.passwd.(interface{ Done() }); ok {
		d.Done()
	}
	outs := make([]*pullOutcome, len(sum.Entries))
	for i, en := range sum.Entries {
		if o, ok := en.Result.Value.(*pullOutcome); ok {
			outs[i] = o
		}
	}
	inv.noteHostKeys(b.entries, outs)
	return sum, outs, nil
}

// noteHostKeys records the host key a device offered that is not the pinned
// one in the seen cache, as a host-key scan does, so the hostkey notice
// comes up ('device notices'; 'device hostkey <name> accept' re-pins after
// verifying). Nothing is pinned here and nothing is prompted.
func (inv *invocation) noteHostKeys(entries []devreg.Entry, outs []*pullOutcome) {
	type offer struct {
		e    devreg.Entry
		keys []devreg.HostKey
	}
	var offers []offer
	for i, o := range outs {
		if o == nil || o.Offered == "" {
			continue
		}
		if k, err := devreg.ParseHostKey(o.Offered); err == nil {
			offers = append(offers, offer{entries[i], []devreg.HostKey{k}})
		}
	}
	if len(offers) == 0 {
		return
	}
	path := inv.app.Paths.SeenCache
	unlock, err := devreg.LockSeen(path)
	if err != nil {
		return
	}
	defer unlock()
	seen := inv.seenLoad()
	now := inv.app.Knobs.Now()
	for _, of := range offers {
		seen.RecordKeyScan(of.e.Name, of.e.Address, of.e.SSHPort(), of.keys, now)
	}
	_ = seen.Save(path)
}

// needsLogin reports whether any entry is dialled (WTI units are not).
func needsLogin(entries []devreg.Entry) bool {
	for _, e := range entries {
		if e.Vendor != "wti" {
			return true
		}
	}
	return false
}

// pullAuditLine is the audit line of one device's pull (D69): the user, the
// device, the transport, the result and the time, never a credential.
func pullAuditLine(user string, o *pullOutcome, r batch.Result) string {
	result := o.Result
	if result == "" {
		result = r.Status.String()
	}
	transport := o.Transport
	if transport == "" {
		transport = "-"
	}
	return fmt.Sprintf("device config pull user=%s device=%s transport=%s result=%s duration=%s",
		user, o.Name, transport, result, seconds(o.Duration))
}

// seconds is a duration as 0.0 seconds, for log lines.
func seconds(d time.Duration) string { return fmt.Sprintf("%.1f", d.Seconds()) }

// --- the verb --------------------------------------------------------------------

// deviceConfigPull is 'device config pull'.
func (inv *invocation) deviceConfigPull(args []string) error {
	p, err := inv.deviceConfigParse("pull", args)
	if err != nil {
		return err
	}
	if err := inv.deviceConfigAllowed("pull"); err != nil {
		return err
	}
	user, err := inv.configLogin("device config pull")
	if err != nil {
		return err
	}
	pa, err := inv.pullArgsOf(p, "pull")
	if err != nil {
		return err
	}
	sel, err := inv.parseSelection(p, "pull")
	if err != nil {
		return err
	}
	chosen, err := inv.chooseDevices(sel, user, true, "pull", pa.render)
	if err != nil {
		return err
	}
	if len(chosen.entries) == 0 {
		return inv.nothingSelected(chosen, pa.json, false)
	}
	if err := inv.refuseNetconfForCisco(chosen.entries, pa.transport); err != nil {
		return err
	}
	view := inv.newPullView(chosen.entries, pa.json, user, false)
	sum, outs, err := inv.runPull(pullBatch{entries: chosen.entries, render: chosen.render, args: pa, user: user, view: view})
	if err != nil {
		return err
	}
	return inv.finishPull(sum, outs, chosen, pa, view)
}

// finishPull prints the summary, the notes and, with --diff, the
// differences, then returns the exit status.
func (inv *invocation) finishPull(sum batch.Summary, outs []*pullOutcome, chosen *chosenDevices, pa pullArgs, view *pullView) error {
	code := sum.ExitCode(false)
	if pa.json {
		view.printSummaryJSON(sum, chosen, code)
	} else {
		inv.echo("")
		inv.echo("  " + sum.Line())
		if l := sum.StopLine(); l != "" {
			inv.echo("  " + l)
		}
		for i, o := range outs {
			if o != nil && o.Hint != "" && sum.Entries[i].Result.Status.Failure() {
				inv.echo("  " + o.Name + ": " + o.Hint)
			}
		}
		chosen.printSkipped(inv)
		if pa.showDiff {
			for _, o := range outs {
				if o != nil && len(differingSections(o.Sections)) > 0 {
					inv.printDeviceDiff(o.Name, o.Scope, o.Vendor, o.Sections, nil, o.SecretsVisible, deviceDiffMeta{})
				}
			}
		}
		inv.echo("")
	}
	if code != 0 {
		return exit(code)
	}
	return nil
}
