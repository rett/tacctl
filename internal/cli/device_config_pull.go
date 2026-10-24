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
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devconf/wti"
	"github.com/rett/tacctl/internal/devices"
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
	// OS is the version line a Cisco device answered (D113) and Syntax the
	// configuration syntax the comparison was made in ("" where the syntax
	// is of no consequence). ImageSyntax is the syntax the line derives to
	// when it is not the setting's: the pull was compared as set (the
	// setting wins), and the view says the line contradicts it.
	OS, Syntax  string
	ImageSyntax string
	// Unit is what a WTI unit's read learned beside its pages (its command
	// menu version is OS); nil for every other vendor. Warning is a pull that
	// is ok all the same but did less than asked (the user directory was not
	// read), in words.
	Unit    *devconf.WTIReadInfo
	Warning string
	// Facts are the release, model and serial number the pull read (the
	// record keeps them; any may be empty).
	Facts devconf.Facts
	// Reason is the failure in words; Hint what to do about it.
	Reason, Hint string
	// Offered is the host key a device presented that is not pinned
	// ('<type> <base64>'): the pull raises the hostkey notice from it.
	Offered string
	// Login is "local:<account>" for a pull made as a local account of the
	// device ('--login', D136), "" for the invoking user's own login.
	Login string
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
	// 'apply' has a --transport of its own (auto, cli or netconf: how it
	// writes, D150); the reads of a pull are the settings'.
	if p.Has("--transport") && verb != "apply" {
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

// The source of the invocation's password is hooks.newDevicePasswords
// (hooks.go).

// errNoPassword is a pull with no terminal and no cached password.
var errNoPassword = errors.New("a password is needed and no terminal or cached password is available")

// A local account's password source ('--login', 'device onboard', D136) is
// hooks.newLocalPasswords (hooks.go).

// terminalPasswords is the default source: the session's password cache
// first, then the terminal.
//
// With local set it is a local account's source instead (D136): the
// terminal (or a test build's local knob) only, never the cache, whatever
// client holds; Accepted and Rejected do nothing (the cache holds the
// invoking user's password, which a local account's refusal says nothing
// about), and Done zeroes the bytes Password returned.
type terminalPasswords struct {
	inv *invocation
	// client asks the shell's password cache (nil: this line has none).
	client *askpass.Client
	// local is the device's local account ("" the invoking user's login)
	// and where the device, both for the prompt.
	local, where string

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
	if t.local != "" {
		return t.localPassword()
	}
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
	pw, err := t.inv.hooks.prompt(tty, "Password for "+user+" (device login): ")
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

// localPassword is a local account's password: a test build's knob, else the
// terminal. The source keeps the very slice it returns (no copy) and zeroes
// it at Done; the caller must not keep it past Done.
func (t *terminalPasswords) localPassword() ([]byte, error) {
	var pw []byte
	if k := t.inv.app.Knobs.LocalPassword(); k != "" {
		pw = []byte(k)
	} else {
		tty, closeTTY := t.inv.passwordTerminal()
		if tty == nil {
			return nil, errNoLocalPassword
		}
		defer closeTTY()
		var err error
		pw, err = t.inv.hooks.prompt(tty, "Password of "+t.local+" on "+t.where+" (a local account; asked once, never kept): ")
		switch {
		case errors.Is(err, askpass.ErrCancelled):
			return nil, ui.ErrInterrupted
		case errors.Is(err, askpass.ErrNoTerminal):
			return nil, errNoLocalPassword
		case errors.Is(err, askpass.ErrBadSecret):
			return nil, errors.New("the password is empty or has a line break or is too long; nothing was tried")
		case err != nil:
			return nil, err
		}
	}
	t.mu.Lock()
	askpass.Zero(t.secret)
	t.secret = pw
	t.mu.Unlock()
	return pw, nil
}

// errNoLocalPassword is a local login with no terminal to ask on.
var errNoLocalPassword = errors.New("the password of a local account is asked on a terminal, and there is none; nothing was sent")

// Accepted stores the password in the session's cache when the person
// typed it for this run: a password that came from the cache is not stored
// again, so its maximum lifetime cannot be stretched by use. A cache that
// cannot be reached is no failure of the pull. The lock is held across the
// store and Rejected holds it across the forget, so a store never lands
// after a forget in the same run, whichever worker gets there first.
func (t *terminalPasswords) Accepted() {
	if t.local != "" {
		// a local account's password is never stored (D136)
		return
	}
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
	if t.local != "" {
		// the cache holds the invoking user's password, not this one: it is
		// not told anything
		return
	}
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

// deviceDialer is the dialer of this invocation's device sessions: the
// knob's loopback address (test builds) or the tests' override
// (hooks.deviceDial), else nil (the device's own address).
func (inv *invocation) deviceDialer() devssh.Dialer {
	if addr := inv.app.Knobs.DeviceDial(); addr != "" {
		return func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	return inv.hooks.dialer()
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
	// Version is the device's version line (devconf.VersionLine; Cisco
	// only, "" when it answered none).
	Version string
	// Plain is the same configuration without the groups' inheritance applied
	// (Junos; devconf.ReadPlain), "" when the device has none or did not
	// answer: the planner then cannot tell a group's statements from the
	// device's own, and says so.
	Plain string
	// Unit is what the walk of a WTI unit learned beside the document (nil
	// for the other vendors); Version is then its command menu's.
	Unit *devconf.WTIReadInfo
	// Facts are what the device reported about itself in the same session
	// (release, model, serial number; any may be empty). A fact the device
	// did not give is no failure of the read.
	Facts devconf.Facts
}

// errNetconfNotRead is --transport netconf for a vendor that has no NETCONF
// read (D61: IOS-XE reads go over the command line), errNetconfNotReadWTI the
// same for a WTI unit, which has no NETCONF at all, and errNetconfNotReadMixed
// for a selection of both.
var (
	errNetconfNotRead      = errors.New("NETCONF is not read for Cisco devices; use --transport ssh (or auto)")
	errNetconfNotReadWTI   = errors.New("NETCONF is not read for WTI units (they have none); use --transport ssh (or auto)")
	errNetconfNotReadMixed = errors.New("NETCONF is not read for Cisco devices or WTI units; use --transport ssh (or auto)")
)

// netconfRefusal is the refusal of --transport netconf for a vendor, nil for
// one that is read over NETCONF.
func netconfRefusal(vendor string) error {
	switch vendor {
	case "cisco":
		return errNetconfNotRead
	case "wti":
		return errNetconfNotReadWTI
	}
	return nil
}

// netconfRunner runs a CLI command as a NETCONF <command> RPC and returns
// the text of the reply: the same text the command line gives (D61).
type netconfRunner struct{ s devssh.NetconfSession }

func (r netconfRunner) Run(ctx context.Context, cmd string) (string, error) {
	// NETCONF never pages: the pipe that keeps the command line from it is
	// not part of the command a device is asked.
	cmd = strings.TrimSuffix(cmd, " | no-more")
	reply, err := r.s.RPC(ctx, devssh.CommandRPC(cmd))
	if err != nil {
		return "", err
	}
	// devssh's own reader of a reply: it takes the XML declaration a Junos
	// reply starts with (encoding="us-ascii"), which devconf.UnwrapNetconf
	// (a decoder without a charset reader) does not.
	return devssh.ReplyText(reply)
}

// readFacts is devconf.ReadFacts within the facts limit (hooks.factsLimit).
func readFacts(ctx context.Context, limit time.Duration, r devconf.Runner, vendor string, f devconf.Facts) devconf.Facts {
	fctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return devconf.ReadFacts(fctx, r, vendor, f)
}

// readDeviceConfig reads a device's configuration through the logged-in
// client: over NETCONF where the mode and the vendor allow it and the
// device answers, over the command line otherwise ('auto' falls back with
// the reason; 'netconf' and 'ssh' never do).
//
// A WTI unit has no command that prints its configuration: its pages are
// walked in a terminal session (readWTI), and second dials the unit again
// for the user directory's session (nil: the directory is not read).
//
// opts open the command-line session (a root login's wrapper, D136); with
// them the session is a shell.
func readDeviceConfig(ctx context.Context, c *devssh.Client, vendor, mode string, factsLimit time.Duration, second func(context.Context) (*devssh.Client, error), opts ...devssh.CLIOption) (deviceRead, error) {
	var out deviceRead
	if fam, _ := devconf.Family(vendor); fam == devconf.FamilyWTI {
		return readWTI(ctx, c, mode, second)
	}
	read, err := devconf.ReaderWithFacts(vendor)
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
			raw, plain, facts, rerr := func() (string, string, devconf.Facts, error) {
				defer func() { _ = ns.Close() }()
				text, _, facts, err := read(ctx, netconfRunner{ns})
				if err != nil {
					return "", "", facts, err
				}
				plain := devconf.ReadPlain(ctx, netconfRunner{ns}, vendor)
				// last: what the pull needs is read first
				return text, plain, readFacts(ctx, factsLimit, netconfRunner{ns}, vendor, facts), nil
			}()
			if rerr == nil {
				out.Raw, out.Plain, out.Facts, out.Transport = raw, plain, facts, transportNetconf
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
	s, err := c.CLI(vendor, opts...)
	if err != nil {
		return out, err
	}
	defer func() { _ = s.Close() }()
	raw, version, facts, err := read(ctx, s)
	if err != nil {
		return out, err
	}
	out.Raw, out.Version, out.Transport = raw, version, transportSSH
	out.Plain = devconf.ReadPlain(ctx, s, vendor)
	out.Facts = readFacts(ctx, factsLimit, s, vendor, facts)
	return out, nil
}

// clientTerm is a terminal session that ends its connection with it: a WTI
// unit frees the session of a connection that went away on a page (the
// tested-safe exit of a read), and nothing is left open between the first
// session and the second.
type clientTerm struct {
	devssh.TermSession
	c *devssh.Client
}

func (t clientTerm) Close() error {
	err := t.TermSession.Close()
	if cerr := t.c.Close(); err == nil {
		err = cerr
	}
	return err
}

// readWTI reads a WTI unit over its text interface on the logged-in client
// (devconf.ReadWTI): the version, the access level and the pages of the
// tables, and, in a second connection with the same password, the user
// directory (a top-level menu is left only by a save, so '/N' and '/F' do
// not share a session). The raw text it returns is the captured screens;
// nothing of it is kept or logged by the caller but its extraction.
func readWTI(ctx context.Context, c *devssh.Client, mode string, second func(context.Context) (*devssh.Client, error)) (deviceRead, error) {
	var out deviceRead
	if mode == transportNetconf {
		return out, errNetconfNotReadWTI
	}
	term, err := c.Terminal(ctx)
	if err != nil {
		return out, err
	}
	var opts devconf.WTIReadOptions
	if second != nil {
		opts.Users = func(ctx context.Context) (devconf.WTITerminal, error) {
			c2, err := second(ctx)
			if err != nil {
				return nil, err
			}
			t2, err := c2.Terminal(ctx)
			if err != nil {
				_ = c2.Close()
				return nil, err
			}
			return clientTerm{t2, c2}, nil
		}
	}
	raw, info, err := devconf.ReadWTI(ctx, clientTerm{term, c}, opts)
	if err != nil {
		return out, err
	}
	out.Raw, out.Version, out.Transport, out.Unit = raw, info.Version, transportSSH, &info
	// The command menu's version is the unit's release; the menu prints no
	// model and no serial number, so there is nothing more to read.
	out.Facts = devconf.CleanFacts(devconf.Facts{Release: info.Version})
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
	var denied *devconf.WTIDeniedError
	var version *devconf.WTIVersionError
	var page *devconf.WTIPageError
	switch {
	case errors.As(err, &denied):
		return devconf.ResultDenied, deniedReason(denied.Level), ""
	case errors.As(err, &version):
		return devconf.ResultUnsupported, "command menu version " + version.Version + "; tables are verified for " + wti.Version, ""
	case errors.As(err, &page):
		return devconf.ResultParseFailed, pageReason(page), ""
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
		return devconf.ResultUnreachable, shortReason(err), "tacctl device legacy-ssh " + name + " enable (a device that offers only the SHA-1 key exchange, CBC ciphers or ssh-rsa needs them)"
	case errors.Is(err, devssh.ErrNoSubsystem):
		return devconf.ResultUnreachable, "NETCONF is not enabled on the device", ""
	case errors.Is(err, errNetconfNotRead), errors.Is(err, errNetconfNotReadWTI), errors.Is(err, errNetconfNotReadMixed):
		return devconf.ResultUnsupported, err.Error(), ""
	case errors.Is(err, devconf.ErrParse), errors.Is(err, devssh.ErrProtocol), errors.Is(err, devssh.ErrOutputTooLarge),
		errors.As(err, &rpc):
		return devconf.ResultParseFailed, shortReason(err), ""
	case errors.Is(err, devssh.ErrClosed):
		return devconf.ResultUnreachable, shortReason(err), ""
	}
	return devconf.ResultUnreachable, shortReason(err), ""
}

// deniedReason is the words of a WTI login whose level cannot configure the
// unit: the level the unit's help showed, and what is needed.
func deniedReason(level string) string {
	label := map[string]string{wti.LevelViewOnly: "ViewOnly", wti.LevelUser: "User",
		wti.LevelSuperUser: "SuperUser", wti.LevelAdministrator: "Administrator"}[level]
	if label == "" {
		return "the login's WTI level cannot configure the unit; SuperUser or Administrator is needed"
	}
	return "the login's WTI level is " + label + "; SuperUser or Administrator is needed"
}

// pageReason is the words of a page of a WTI unit the walk could not take:
// the page's path and its title line, which is all of a screen an error
// holds, and the fixed phrase of the reader.
func pageReason(e *devconf.WTIPageError) string {
	var b strings.Builder
	b.WriteString("WTI unit")
	if e.Path != "" {
		b.WriteString(", page " + e.Path)
	}
	if e.Title != "" {
		fmt.Fprintf(&b, " (title %q)", e.Title)
	}
	b.WriteString(": " + e.Detail)
	return b.String()
}

// usersWarning is the line of a pull that read the unit's pages but not its
// user directory: the breakglass section is not compared.
func usersWarning(info *devconf.WTIReadInfo) string {
	why := "the list is longer than a pull reads or holds a name it does not type"
	if info.UsersErr != nil {
		why = strings.TrimPrefix(shortReason(info.UsersErr), "devconf: ")
	}
	return "the user directory was not read, so the breakglass section is not compared (" + why + ")"
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
	// group is the invoking user's group, which a WTI level is set on (the
	// hint of a login whose level cannot configure a unit).
	group string
	// local is the one-shot local login of '--login' (nil: the invoking
	// user's own login).
	local *localLogin

	acceptOnce, rejectOnce sync.Once
}

// account is the device account a pull logs in as: the local account of
// --login, else the invoking user.
func (r *pullRun) account() string {
	if r.local != nil {
		return r.local.account
	}
	return r.user
}

// source is the pull's password source for ssh: the run's password, or a
// local account's, handed over once in the whole run (one device, one
// connection; a second request is refused).
func (r *pullRun) source() devssh.PasswordSource {
	if r.local == nil {
		return func() (string, error) { return r.password, nil }
	}
	return r.local.sendOnce()
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
	// --transport netconf does not read a Cisco device (D61) nor a WTI unit:
	// refused before any login, and the record is left as it was (nothing was
	// attempted).
	if err := netconfRefusal(e.Vendor); r.mode == transportNetconf && err != nil {
		return fail(batch.StatusFailed, err.Error(), "")
	}
	// A device whose syntax is unknown (D113) is rendered after the read, in
	// the syntax its version line says; the refusals that need no device
	// (a RADIUS scope that is not enabled) are the same for both syntaxes.
	_, syntaxKnown := r.render.syntaxFor(e)
	var expected []devices.Section
	var err error
	if syntaxKnown {
		expected, err = r.render.Expected(e)
	} else {
		expected, err = r.render.ExpectedAs(e, false)
	}
	if err != nil {
		return fail(batch.StatusFailed, "cannot build the expected configuration: "+err.Error(), "")
	}
	if r.local != nil {
		o.Login = devconf.LocalLoginPrefix + r.local.account
	}
	target := inv.deviceTarget(e, r.account(), r.source())
	client, err := devssh.Dial(ctx, target)
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	defer func() { _ = client.Close() }()
	r.acceptOnce.Do(r.passwd.Accepted)

	// The second connection of a WTI read (the user directory) is the same
	// login: same target, host keys and password, in memory. A local login
	// is one connection: it has none (--login is Junos only).
	second := func(ctx context.Context) (*devssh.Client, error) { return devssh.Dial(ctx, target) }
	var opts []devssh.CLIOption
	mode := r.mode
	if r.local != nil {
		second = nil
		opts = r.local.cliOptions()
		if len(opts) > 0 {
			// root's CLI is a wrapper on a shell channel: no NETCONF
			mode = transportSSH
		}
	}
	rd, err := readDeviceConfig(ctx, client, e.Vendor, mode, inv.hooks.factsLimit(), second, opts...)
	if rd.Netconf != "" {
		o.Netconf = rd.Netconf
	}
	o.Fallback = rd.Fallback
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	o.Transport, o.Facts = rd.Transport, rd.Facts
	if rd.Unit != nil {
		o.OS, o.Unit = rd.Version, rd.Unit
		if !rd.Unit.UsersRead {
			o.Warning = usersWarning(rd.Unit)
		}
	}
	// The comparison is made in the syntax the device is in now: the
	// setting, else what its version line says, else the record's. A device
	// that says nothing and has no record of it cannot be compared.
	if r.render.inv.syntaxMatters(e) {
		o.OS = rd.Version
		var old *devconf.Record
		if r.render.recs != nil {
			old, _ = r.render.recs.Of(e.Name)
		}
		syn := devconf.SyntaxFromRead(e.ConfigSyntax, rd.Version, old)
		if syn == "" {
			// Nothing is recorded: the pull's own output is the only place
			// that says why (the list keeps showing 'needs pull').
			if strings.TrimSpace(rd.Version) != "" {
				return fail(batch.StatusFailed, "the device's version line \""+cleanLine(rd.Version)+
					"\" is not an image tacctl maps to a configuration syntax (IOS 12.x, 15.2 and later, 16.x, 17.x, IOS-XE), so its configuration syntax is unknown",
					"tacctl device config-syntax "+e.Name+" ios12|modern")
			}
			return fail(batch.StatusFailed, "the device's IOS version was not read ('"+devconf.VersionCommand+
				"' answered no image line), so its configuration syntax is unknown",
				"tacctl device config-syntax "+e.Name+" ios12|modern")
		}
		o.Syntax = syn
		// An explicit setting that the line contradicts wins; the pull says so.
		if img, conflict := devconf.ConflictOf(e.ConfigSyntax, rd.Version); conflict {
			o.ImageSyntax = img
		}
		expected, err = r.render.ExpectedAs(e, syn == devconf.SyntaxIOS12)
		if err != nil {
			return fail(batch.StatusFailed, "cannot build the expected configuration: "+err.Error(), "")
		}
	} else if e.Vendor == "cisco" {
		o.OS = rd.Version
	}
	ext, err := devconf.ExtractWith(e.Vendor, rd.Raw, devconf.Options{Expected: expected})
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	results, err := devconf.CompareAll(expected, ext)
	if err != nil {
		return r.failed(ctx, e, o, err)
	}
	o.Result, o.Sections, o.SecretsVisible = devconf.ResultOK, results, ext.SecretsVisible
	// The plain view, extracted the same way, tells the planner which
	// statements a group supplies (D97). A view that does not extract is no
	// view: the pull is not refused for it.
	var plain map[string]devices.Section
	if rd.Plain != "" {
		if pe, perr := devconf.ExtractWith(e.Vendor, rd.Plain, devconf.Options{Expected: expected}); perr == nil {
			plain = pe.Sections
		}
	}
	if err := r.recordSuccess(o, e, ext, results, plain); err != nil {
		o.Result = ""
		return fail(batch.StatusFailed, "cannot record the result: "+strings.Join(msgs(err), " "), "")
	}
	return batch.Result{Status: batch.StatusOK, Differs: differingSections(results)}
}

// failed turns an error into the outcome and the batch status, and keeps
// the record of the attempt.
func (r *pullRun) failed(ctx context.Context, e devreg.Entry, o *pullOutcome, err error) batch.Result {
	result, reason, hint := resultOf(ctx, e.Name, err)
	if result == devconf.ResultDenied {
		g := r.group
		if g == "" {
			g = "<group>"
		}
		hint = "raise the WTI level of the login's group: tacctl group edit " + g + " wti-level superuser"
	}
	o.Result, o.Reason, o.Hint = result, reason, hint
	var hk devssh.ErrHostKey
	if errors.As(err, &hk) {
		o.Offered = hk.Offered
	}
	if errors.Is(err, devssh.ErrAuth) {
		r.rejectOnce.Do(r.passwd.Rejected)
		if r.local != nil {
			o.Reason = "the device refused the password of its local account '" + r.local.account + "'"
		}
	}
	r.record(o, e)
	st := batch.StatusFailed
	if result == devconf.ResultAuthFailed {
		st = batch.StatusAuthFailed
	}
	return batch.Result{Status: st, Reason: o.Reason, Err: err}
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
	rec.Address, rec.Result = e.Address, o.Result
	// The vendor is the one the stored sections were read for: a failed
	// attempt keeps the last good pull's (0.2.17 D260, VendorChanged).
	rec.SetVendorUnlessPulled(e.Vendor)
	if o.Netconf != "" && o.Netconf != netconfNotProbed {
		rec.Netconf, rec.NetconfAt = o.Netconf, r.now()
	}
	recs.Put(e.Name, rec)
	recs.Updated = r.now()
	_ = r.store.Save(recs)
}

// recordSuccess keeps a successful pull: the sections file, then the
// record, under the store's lock.
func (r *pullRun) recordSuccess(o *pullOutcome, e devreg.Entry, ext devconf.Extracted, results []devconf.SectionResult, plain map[string]devices.Section) error {
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
	// read before the pull's own fields replace the old ones
	asUser := rec.PulledAsUser()
	rec.Address, rec.Vendor, rec.Transport = e.Address, e.Vendor, o.Transport
	if o.Netconf != "" && o.Netconf != netconfNotProbed {
		rec.Netconf, rec.NetconfAt = o.Netconf, now
	}
	rec.Pulled, rec.By, rec.Result = now, r.user, devconf.ResultOK
	// how it logged in (D136): a local account's pull keeps whether the
	// device was ever pulled as the invoking user's own login
	if o.Login != "" {
		rec.UserPulled = asUser
		rec.Login = o.Login
	} else {
		rec.Login, rec.UserPulled = "", true
	}
	rec.DurationMS = o.Duration.Milliseconds()
	// The image of a Cisco device (D113): the version line and the syntax
	// derived from it (not the registry's setting, which overrides it
	// without changing what the device says). A pull that read no line
	// keeps the record's under auto, and forgets them under a setting: the
	// device was compared without them.
	if e.Vendor == "cisco" {
		switch {
		case o.OS != "":
			rec.OS = o.OS
			rec.Syntax = devconf.DeriveSyntax(o.OS)
		case e.ConfigSyntax != "":
			rec.OS, rec.Syntax = "", ""
		}
	}
	// A WTI unit: the command menu's version, and what the read saw beside
	// the pages (the unit's own Site ID, how many others were logged in, no
	// name).
	rec.Unit = nil
	if e.Vendor == "wti" {
		rec.OS = o.OS
		if o.Unit != nil {
			rec.Unit = &devconf.UnitFacts{SiteID: o.Unit.SiteID, OtherSessions: o.Unit.OtherSessions, UsersRead: o.Unit.UsersRead}
		}
	}
	// the file system of an IOS device's archive path, for the plan's restore
	// point; every other vendor, and a pull that read none, keeps nothing
	rec.ArchiveFS = ""
	if e.Vendor == "cisco" {
		rec.ArchiveFS = ext.ArchiveFS
	}
	// What the device reported about itself: replaced on every good pull, so
	// a fact this pull did not read is not the last one's.
	rec.Release, rec.Model, rec.Serial = o.Facts.Release, o.Facts.Model, o.Facts.Serial
	// the device's own name (Junos), which 'device sync' fills the registry
	// from
	rec.Hostname = ext.Hostname
	rec.SecretsVisible = ext.SecretsVisible
	if err := rec.SetSections(ext, results); err != nil {
		return err
	}
	if err := r.store.SaveSections(e.Name, e.Vendor, ext.Sections); err != nil {
		return err
	}
	// The plain view of this pull, or none: the last pull's must not outlive
	// it (the planner would compare two different pulls).
	if err := r.store.SavePlain(e.Name, e.Vendor, plain, now); err != nil {
		return err
	}
	recs.Put(e.Name, rec)
	recs.Updated = now
	return r.store.Save(recs)
}

// configStore is the records store of this invocation.
func (inv *invocation) configStore() devconf.Store {
	return devconf.Store{Records: inv.app.Paths.ConfigRecords, Dir: inv.app.Paths.ConfigDir, Touch: inv.app.Audit().Touch}
}

// batchInterrupts wires the operator's Ctrl-C to the runner: the first
// SIGINT stops new devices from starting, the second cancels the running
// ones; SIGTERM and SIGHUP cancel at once. The context is not the
// invocation's (whose cancellation is the first SIGINT).
func (inv *invocation) batchInterrupts() (ctx context.Context, interrupts <-chan struct{}, stop func()) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(inv.ctx))
	if src := inv.hooks.interrupts(); src != nil {
		return ctx, src(), cancel
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
	// local is the one-shot local login of '--login' (D136): one device,
	// its password from the terminal only and never from or into the cache.
	local *localLogin
}

// runPull resolves the password, runs the pool over the entries and
// returns the summary with each device's outcome in the order of the
// entries (nil for a device that was not started).
func (inv *invocation) runPull(b pullBatch) (batch.Summary, []*pullOutcome, error) {
	settings := inv.deviceConfigSettings()
	run := &pullRun{inv: inv, user: b.user, mode: b.args.transport, render: b.render, store: inv.configStore(), local: b.local}
	if b.local != nil {
		// A local account (D136): the terminal only, never the cache; the
		// bytes stay the source's and are zeroed at Done, the string is made
		// at the single send.
		if len(b.entries) != 1 {
			return batch.Summary{}, nil, errors.New("a local login reads one device")
		}
		src := inv.hooks.newLocalPasswords(inv, b.local.account, b.entries[0].Name+" ("+b.entries[0].Address+")")
		run.passwd = src
		pw, err := src.Password(inv.ctx, b.local.account)
		if err != nil {
			src.Done()
			return batch.Summary{}, nil, err
		}
		b.local.secret = pw
		inv.app.Audit().Raw("auth.info", fmt.Sprintf("device config pull user=%s device=%s login=%s%s",
			b.user, b.entries[0].Name, devconf.LocalLoginPrefix, b.local.account))
	} else {
		run.passwd = inv.hooks.newDevicePasswords(inv)
		// The password, once, before any connection.
		pw, err := run.passwd.Password(inv.ctx, b.user)
		if err != nil {
			return batch.Summary{}, nil, err
		}
		run.password = string(pw)
		askpass.Zero(pw)
	}
	// The group a WTI level is set on, read before the workers start.
	if slices.ContainsFunc(b.entries, func(e devreg.Entry) bool { return e.Vendor == "wti" }) {
		if m, err := inv.model(); err == nil {
			if u := m.User(b.user); u != nil {
				run.group = u.Group
			}
		}
	}
	jobs := make([]batch.Job, len(b.entries))
	for i, e := range b.entries {
		jobs[i] = run.pullJob(e)
	}
	// The start line of the audit is written here, on the command's own
	// goroutine: the workers write the records, and audit.strict refuses by
	// a panic that only this goroutine recovers (audit.Writer.Touch).
	inv.app.Audit().Touch()
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
	if b.local != nil {
		b.local.secret = nil
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
	login := ""
	if o.Login != "" {
		login = " login=" + o.Login
	}
	return fmt.Sprintf("device config pull user=%s device=%s transport=%s result=%s duration=%s%s",
		user, o.Name, transport, result, seconds(o.Duration), login)
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
	if err := inv.localLoginGate(p, "pull"); err != nil {
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
	local, err := inv.localLoginOf(p, "pull", sel, true)
	if err != nil {
		return err
	}
	chosen, err := inv.chooseDevices(sel, user, local == nil, "pull", pa.render)
	if err != nil {
		return err
	}
	if local != nil {
		if err := inv.localLoginDevice(local, chosen); err != nil {
			return err
		}
	}
	if len(chosen.entries) == 0 {
		return inv.nothingSelected(chosen, pa.json, false)
	}
	if err := inv.refuseNetconfForCisco(chosen.entries, pa.transport); err != nil {
		return err
	}
	view := inv.newPullView(chosen.entries, pa.json, user, false)
	sum, outs, err := inv.runPull(pullBatch{entries: chosen.entries, render: chosen.render, args: pa, user: user, view: view, local: local})
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
