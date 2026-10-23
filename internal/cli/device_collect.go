package cli

// 'device collect <address>... | --discovered [--login <local-user>]
// [--register]' (docs/plans/0.2.9-rollout-plan.md D137, D141): the login
// before the registration. For each address no registry entry holds, one
// login (the invoking user's own, or the device's local account of --login:
// the one-shot password of D136, never cached), the host keys scanned and
// shown with their fingerprints and trusted by ONE question (or --host-key),
// 'show version' and the pull's read command in one session, and nothing
// else. The result is one table; --register runs the 'device add' of each
// (the registry's own registration code, with every key shown pinned) and
// keeps the read as that device's first pull record, so 'device sync' and
// 'device config plan' have a record at once. A device that is not Junos is
// listed and its session closed; the first refusal of the password ends the
// run, so a wrong password reaches one address only.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// collectUse is the usage line of the verb.
const collectUse = "Usage: tacctl device collect <address>... | --discovered [--login <local-user>] [--host-key SHA256:<fp>] [--register [-y]] [--json]"

// The results of one address.
const (
	collectOK         = "collected"
	collectNotJunos   = "not-junos"
	collectAuthFailed = "auth-failed"
	collectNoKey      = "no-key"
	collectFailed     = "failed"
	collectNotTried   = "not-tried"
)

// collectRow is one address of the run.
type collectRow struct {
	Address string
	Result  string
	// Reason is the words of a result that is not collected; Note one more
	// line about a collected one (why it is not registered).
	Reason, Note string
	Banner       string
	Hostname     string
	Model        string
	Release      string
	AuthOrder    []string
	Tacplus      int
	Radius       int
	ENClass      bool
	Netconf      bool
	Lo0Filter    []string
	Legacy       bool
	// Name is the name it would be registered as ("" when none is usable);
	// Registered is set once it is.
	Name       string
	Registered bool

	keys []devreg.HostKey
	id   devapply.Identity
	raw  string
}

// collect is one run.
type collect struct {
	inv  *invocation
	user string
	pr   *ui.Prompter

	addrs                 []string
	discovered            bool
	hostKey               string
	register, yes, asJSON bool
	local                 *localLogin
	src                   *terminalPasswords
	tp                    devicePasswords
	rows                  []*collectRow
	stopped               bool
	collectOnce
}

// deviceCollect is 'device collect'.
func (inv *invocation) deviceCollect(args []string) error {
	p, err := Parse(deviceSpecs["collect"], args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.argErr(msg, collectUse)
	}
	if err := inv.deviceVerbAllowed("device", "collect", tier.Superuser); err != nil {
		return err
	}
	user, err := inv.configLogin("device collect")
	if err != nil {
		return err
	}
	c := &collect{inv: inv, user: user, pr: inv.app.Prompter(), hostKey: p.Value("--host-key"), discovered: p.Has("--discovered"),
		register: p.Has("--register"), yes: p.Has("-y"), asJSON: p.Has("--json")}
	if err := c.args(p); err != nil {
		return err
	}
	saved := inv.app.Out.Stdout
	if c.asJSON {
		// the progress goes to standard error, the object to standard output
		inv.app.Out.Stdout = inv.app.Out.Stderr
	}
	code, err := c.run()
	inv.app.Out.Stdout = saved
	c.done()
	if err != nil {
		c.audit()
		return err
	}
	c.audit()
	if c.asJSON {
		c.printJSON(code)
	}
	if code != 0 {
		return exit(code)
	}
	return nil
}

// args checks what needs no device and no registry (exit 2).
func (c *collect) args(p Parsed) error {
	inv := c.inv
	seen := map[string]bool{}
	for _, a := range p.Args {
		addr, err := devreg.NormalizeAddress(a)
		if err != nil {
			return inv.argErr(strings.Join(msgs(err), " "), collectUse)
		}
		if !seen[addr] {
			seen[addr] = true
			c.addrs = append(c.addrs, addr)
		}
	}
	switch {
	case c.discovered && len(c.addrs) > 0:
		return inv.argErr("Name the addresses, or give --discovered, not both.", collectUse)
	case !c.discovered && len(c.addrs) == 0:
		return inv.argErr("Name the addresses to collect from, or give --discovered (the addresses 'tacctl device discover' lists).", collectUse)
	}
	if p.Has("--login") {
		acct, err := inv.localAccountOf(p.Value("--login"), collectUse)
		if err != nil {
			return err
		}
		c.local = &localLogin{account: acct}
	}
	if p.Has("--host-key") {
		switch {
		case !devreg.ValidFingerprint(c.hostKey):
			return inv.argErr("Invalid --host-key '"+c.hostKey+"': expected SHA256:<fingerprint> as ssh prints it.", collectUse)
		case c.discovered || len(c.addrs) != 1:
			return inv.argErr("--host-key names the key of ONE device: give one address (a list is trusted at the terminal, key by key shown).", collectUse)
		}
	}
	switch {
	case !c.pr.Interactive() && c.hostKey == "":
		return inv.argErr("No terminal to answer the identity question on: the keys of an address nobody registered are trusted by a person. "+
			"Give --host-key SHA256:<fp> with one address (the fingerprint read on the device's console). Nothing was sent.", collectUse)
	case c.register && !c.pr.Interactive() && !c.yes:
		return inv.argErr("No terminal to answer the registration question on: --register without one needs -y. Nothing was sent.", collectUse)
	}
	return nil
}

// done drops what the run still holds of a password.
func (c *collect) done() {
	if c.src != nil {
		c.src.Done()
	}
	if c.local != nil {
		c.local.mu.Lock()
		c.local.secret = nil
		c.local.mu.Unlock()
	}
	if d, ok := c.tp.(interface{ Done() }); ok {
		d.Done()
	}
}

// loginWord is the audit line's and the JSON's word for the login.
func (c *collect) loginWord() string {
	if c.local != nil {
		return localLoginText(c.local.account)
	}
	return "own"
}

// run is the whole collect; the code is the exit status (an error is a
// refusal before anything was sent, already printed).
func (c *collect) run() (int, error) {
	inv := c.inv
	if err := c.admissible(); err != nil {
		return 0, err
	}
	if len(c.rows) == 0 {
		inv.app.Out.Info("No unregistered address has authenticated: nothing to collect from. 'tacctl device discover' reads the logs for them.")
		return batch.ExitOK, nil
	}
	// 1. Identity: every address's keys, scanned and shown; nothing is sent.
	c.scan()
	keyed := c.keyed()
	if len(keyed) == 0 {
		c.names()
		c.print()
		return batch.ExitFailed, nil
	}
	if err := c.identity(keyed); err != nil {
		return 0, err
	}
	// 2. The password, once; then one address at a time.
	if err := c.password(); err != nil {
		return 0, err
	}
	base, interrupts, stop := inv.batchInterrupts()
	defer stop()
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-interrupts:
			cancel()
		case <-finished:
		}
	}()
	for _, r := range keyed {
		switch {
		case c.stopped:
			r.Result, r.Reason = collectNotTried, "an earlier address refused the password; nothing was sent here"
		case ctx.Err() != nil:
			r.Result, r.Reason = collectNotTried, "interrupted"
		default:
			c.one(ctx, r)
		}
	}
	interrupted := ctx.Err() != nil
	c.names()
	c.print()
	code := batch.ExitOK
	for _, r := range c.rows {
		if r.Result != collectOK {
			code = batch.ExitFailed
		}
	}
	if c.register && !interrupted {
		if rc := c.registerAll(ctx); rc != 0 {
			code = rc
		}
	}
	if interrupted {
		code = batch.ExitInterrupted
	}
	return code, nil
}

// admissible is what is refused before anything is scanned or sent: an
// address a registry entry holds (it is reached by the normal flow), an
// address no scope answers, a break-glass hold, a caller who is no active
// tacctl user. One refusal ends the run: the person named the address.
func (c *collect) admissible() error {
	inv := c.inv
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if c.discovered {
		for _, u := range res.Unregistered(false) {
			c.addrs = append(c.addrs, u.Address)
		}
	}
	var refuse []string
	for _, addr := range c.addrs {
		if e, ok := res.Lookup(addr, devreg.ScopeFilter{}); ok && e.Address == addr {
			kind := "a device"
			if e.Source == devreg.SourceHost {
				kind = "an enrolled Linux host"
			}
			refuse = append(refuse, addr+" is registered as '"+e.Name+"' ("+kind+"): it is reached by the normal flow (tacctl device config pull "+e.Name+")")
			continue
		}
		info, covered := m.LookupAddr(addr)
		switch {
		case !covered:
			refuse = append(refuse, "No scope answers "+addr+": no scope's prefixes cover it. Add them first: tacctl scope prefixes <scope> add <cidr>")
			continue
		case c.local == nil:
			if msg := loginProblem(m, c.user, info.Scope); msg != "" {
				refuse = append(refuse, addr+": "+msg)
				continue
			}
		}
		if h, held := inv.holdAt(addr); held {
			refuse = append(refuse, holdRefusal(h.Device)+": release it first")
			continue
		}
		c.rows = append(c.rows, &collectRow{Address: addr})
	}
	if len(refuse) > 0 {
		for _, l := range refuse {
			inv.app.Out.ErrorE(l)
		}
		return inv.usageErr("Nothing was scanned or sent.")
	}
	return nil
}

// scan reads each address's host keys (ssh-keyscan, and for a device that
// gives none, tacctl's own client with the legacy algorithms): nothing is
// authenticated and nothing is sent.
func (c *collect) scan() {
	inv := c.inv
	for _, r := range c.rows {
		keys, err := inv.scanDevice(r.Address, devssh.DefaultPort, false)
		if errors.Is(err, devreg.ErrNoAnswer) && inv.ctx.Err() == nil {
			if k2, err2 := inv.scanDevice(r.Address, devssh.DefaultPort, true); err2 == nil && len(k2) > 0 {
				keys, err, r.Legacy = k2, nil, true
			}
		}
		switch {
		case inv.ctx.Err() != nil:
			r.Result, r.Reason = collectNotTried, "interrupted"
		case errors.Is(err, devreg.ErrNoAnswer):
			r.Result, r.Reason = collectNoKey, "no ssh host key could be read (ssh-keyscan): not reachable on port 22"
		case err != nil:
			r.Result, r.Reason = collectNoKey, cleanLine(strings.Join(msgs(err), " "))
		case len(keys) == 0:
			r.Result, r.Reason = collectNoKey, "no ssh host key could be read"
		default:
			r.keys = keys
		}
	}
}

// keyed are the rows whose keys were read.
func (c *collect) keyed() []*collectRow {
	var out []*collectRow
	for _, r := range c.rows {
		if r.Result == "" && len(r.keys) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// identity shows every key and trusts them: --host-key names the one key
// of the one address (no question), otherwise ONE question before any
// login.
func (c *collect) identity(rows []*collectRow) error {
	inv := c.inv
	for _, r := range rows {
		inv.echo("  " + r.Address + " offers:")
		inv.echoKeys("    ", r.keys)
		if r.Legacy {
			inv.echo("    (it needs the legacy algorithms; registered --legacy-ssh)")
		}
	}
	if c.hostKey != "" {
		r := rows[0]
		k, ok := devreg.MatchFingerprint(r.keys, c.hostKey)
		if !ok {
			return inv.usageErr("No host key "+r.Address+" offers matches "+c.hostKey+". Nothing was sent.",
				"Check the fingerprint on the device console: "+devreg.VerifyHint(devssh.VendorJuniper)+".")
		}
		r.keys = []devreg.HostKey{k}
		inv.echo("  " + c.hostKey + " matches --host-key.")
		return nil
	}
	who := "the password of '" + c.user + "' (your tacctl password)"
	if c.local != nil {
		who = "the local password of '" + c.local.account + "'"
	}
	where := rows[0].Address
	if len(rows) > 1 {
		where = fmt.Sprintf("these %d addresses, one attempt at each", len(rows))
	}
	inv.echo("  Nobody registered " + where + ": compare the keys with each device's console (" + devreg.VerifyHint(devssh.VendorJuniper) + ").")
	if !c.pr.Confirm("Trust these keys and send " + who + " to " + where + "? [y/N] ") {
		return inv.usageErr("Not trusted. Nothing was sent.")
	}
	return nil
}

// password resolves the one password of the run before any connection.
func (c *collect) password() error {
	inv := c.inv
	if c.local != nil {
		c.src = inv.hooks.newLocalPasswords(inv, c.local.account, fmt.Sprintf("%d address(es) nobody registered", len(c.keyed())))
		if len(c.keyed()) == 1 {
			c.src.where = c.keyed()[0].Address
		}
		pw, err := c.src.Password(inv.ctx, c.local.account)
		if err != nil {
			return err
		}
		c.local.mu.Lock()
		c.local.secret = pw
		c.local.mu.Unlock()
		return nil
	}
	c.tp = inv.hooks.newDevicePasswords(inv)
	pw, err := c.tp.Password(inv.ctx, c.user)
	if err != nil {
		return err
	}
	secret := string(pw)
	askpass.Zero(pw)
	c.own = func() (string, error) { return secret, nil }
	return nil
}

// target is the login at one address with the keys of the identity step.
func (c *collect) target(r *collectRow, legacy bool) devssh.Target {
	user := c.user
	pw := c.own
	if c.local != nil {
		user, pw = c.local.account, c.local.eachConnection()
	}
	return devssh.Target{Host: r.Address, Port: devssh.DefaultPort, User: user, HostKeys: devreg.KeyStrings(r.keys), Legacy: legacy,
		Password: pw, ConnectTimeout: devssh.DefaultConnectTimeout, Dialer: c.inv.deviceDialer()}
}

// one is one address: the login, 'show version', the read, nothing else.
func (c *collect) one(ctx context.Context, r *collectRow) {
	inv := c.inv
	dctx, cancel := context.WithTimeout(ctx, inv.deviceConfigSettings().timeout)
	defer cancel()
	client, err := devssh.Dial(dctx, c.target(r, r.Legacy))
	var ae devssh.AlgorithmError
	if err != nil && !r.Legacy && errors.As(err, &ae) {
		r.Legacy = true
		client, err = devssh.Dial(dctx, c.target(r, true))
	}
	if err != nil {
		c.dialFailed(ctx, r, err)
		return
	}
	r.Banner = cleanLine(client.ServerVersion())
	if c.tp != nil {
		c.acceptOnce.Do(c.tp.Accepted)
	}
	var opts []devssh.CLIOption
	if c.local != nil {
		opts = c.local.cliOptions()
	}
	j := devapply.NewJunosCLIWith(client, opts...)
	defer func() { _ = j.Close() }()
	id, err := j.Identity(dctx)
	if err != nil {
		// anything but a Junos answer to 'show version' closes the session
		// at once: no read, nothing more typed
		r.Result, r.Reason = collectNotJunos, "not a Junos device ("+cleanLine(shortReason(err))+"); the session was closed"
		return
	}
	raw, err := j.Read(dctx)
	if err != nil {
		result, reason, _ := resultOf(dctx, r.Address, err)
		r.Result, r.Reason = collectFailed, "the configuration was not read ("+result+": "+cleanLine(reason)+")"
		return
	}
	r.id, r.raw = id, raw
	r.fill(raw)
	r.Result = collectOK
}

// dialFailed is a login that did not come up, in words; a refused password
// ends the run.
func (c *collect) dialFailed(ctx context.Context, r *collectRow, err error) {
	var hk devssh.ErrHostKey
	switch {
	case errors.Is(err, devssh.ErrAuth):
		r.Result, r.Reason = collectAuthFailed, "the device refused the password"
		if c.local != nil {
			r.Reason = "the device refused the password of its local account '" + c.local.account + "' " +
				"(a device whose authentication-order is tacplus only refuses local accounts while the server answers)"
		}
		c.stopped = true
		if c.tp != nil {
			c.rejectOnce.Do(c.tp.Rejected)
		}
	case errors.As(err, &hk):
		r.Result, r.Reason = collectFailed, "it presented a host key that is not the trusted one ("+cleanLine(hk.Error())+"); compare the keys with its console"
	default:
		_, reason, _ := resultOf(ctx, r.Address, err)
		r.Result, r.Reason = collectFailed, "the login failed: "+cleanLine(reason)
	}
}

// fill reads the table's columns out of the device's own configuration
// text ('display set').
func (r *collectRow) fill(raw string) {
	r.Hostname = devText(r.id.Hostname)
	r.Model = devText(r.id.Model)
	r.Release = devText(r.id.Release)
	if r.Release == "" {
		r.Release = devconf.JunosRelease(raw)
	}
	tac, rad := map[string]bool{}, map[string]bool{}
	lo0 := map[string]bool{}
	for _, l := range strings.Split(raw, "\n") {
		w := strings.Fields(strings.TrimSpace(l))
		if len(w) < 3 || w[0] != "set" {
			continue
		}
		switch {
		case w[1] == "system" && w[2] == "authentication-order":
			for _, a := range w[3:] {
				if a = devText(a); a != "" && !slices.Contains(r.AuthOrder, a) {
					r.AuthOrder = append(r.AuthOrder, a)
				}
			}
		case w[1] == "system" && w[2] == "tacplus-server" && len(w) > 3:
			tac[w[3]] = true
		case w[1] == "system" && w[2] == "radius-server" && len(w) > 3:
			rad[w[3]] = true
		case w[1] == "system" && len(w) > 4 && w[2] == "login" && w[3] == "class" && w[4] == policy.EngineerClass:
			r.ENClass = true
		case w[1] == "system" && len(w) > 4 && w[2] == "services" && w[3] == "netconf" && w[4] == "ssh":
			r.Netconf = true
		case w[1] == "interfaces" && len(w) > 3 && w[2] == "lo0":
			if i := slices.Index(w, "filter"); i > 0 && i+2 < len(w) && (w[i+1] == "input" || w[i+1] == "input-list") {
				for _, n := range w[i+2:] {
					if n = devText(strings.Trim(n, `"[]`)); n != "" {
						lo0[n] = true
					}
				}
			}
		}
	}
	r.Tacplus, r.Radius = len(tac), len(rad)
	for n := range lo0 {
		r.Lo0Filter = append(r.Lo0Filter, n)
	}
	slices.Sort(r.Lo0Filter)
}

// maxDevText bounds device-reported text in a table cell.
const maxDevText = 64

// devText is text a device reported, made safe for a terminal, a table and a
// log: control characters shown as '?', one line, at most maxDevText
// characters.
func devText(s string) string {
	s = strings.Join(strings.Fields(cleanLine(s)), " ")
	if r := []rune(s); len(r) > maxDevText {
		s = string(r[:maxDevText]) + "..."
	}
	return s
}

// names decides what each collected device would be registered as: the
// name it reports, when that is a name the registry accepts and no earlier
// row of this run takes; else none, and the row says why.
func (c *collect) names() {
	_, res, err := c.inv.deviceLoad()
	if err != nil {
		return
	}
	taken := map[string]bool{}
	for _, r := range c.rows {
		if r.Result != collectOK {
			continue
		}
		name := strings.ToLower(r.id.Hostname) // a new name is lower case
		var why string
		switch {
		case name == "":
			why = "it reports no host name"
		case devreg.ValidateName(name) != nil:
			why = "the name it reports is not one the registry accepts"
		case taken[strings.ToLower(name)]:
			why = "another address of this run reports the same name"
		default:
			if err := res.CheckName(name, devssh.VendorJuniper, false, ""); err != nil {
				why = strings.Join(msgs(err), " ")
			}
		}
		if why != "" {
			r.Note = "no name to register it as (" + devText(why) + "): tacctl device add <name> " + r.Address + " --vendor juniper"
			continue
		}
		taken[strings.ToLower(name)] = true
		r.Name = name
	}
}

// addLine is the 'device add' the row would run.
func (r *collectRow) addLine() string {
	name := r.Name
	if name == "" {
		name = "<name>"
	}
	s := "tacctl device add " + name + " " + r.Address + " --vendor juniper"
	if r.Legacy {
		s += " --legacy-ssh"
	}
	return s
}

// print is the one table, then each device's 'device add' line.
func (c *collect) print() {
	inv := c.inv
	inv.echo("")
	t := ui.NewTable("Collected from "+fmt.Sprint(len(c.rows))+" address(es)", ui.Left("ADDRESS"), ui.Left("HOSTNAME"), ui.Left("MODEL"),
		ui.Left("RELEASE"), ui.Left("AUTH-ORDER"), ui.Left("SERVERS"), ui.Left("EN-CLASS"), ui.Left("NETCONF"), ui.Left("LO0-FILTER"),
		ui.Left("LEGACY"), ui.Left("RESULT"))
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "-"
	}
	for _, r := range c.rows {
		if r.Result != collectOK {
			t.Add(r.Address, "-", "-", "-", "-", "-", "-", "-", "-", yes(r.Legacy), r.Result)
			continue
		}
		t.Add(r.Address, dash(r.Hostname), dash(r.Model), dash(r.Release), dash(strings.Join(r.AuthOrder, ",")), r.serversText(),
			yes(r.ENClass), yes(r.Netconf), dash(strings.Join(r.Lo0Filter, ",")), yes(r.Legacy), r.Result)
	}
	inv.write(t.String())
	inv.echo("")
	for _, r := range c.rows {
		if r.Result != collectOK {
			inv.echo("  " + r.Address + ": " + r.Reason)
			if r.Banner != "" {
				inv.echo("    ssh banner: " + r.Banner)
			}
		}
	}
	for _, r := range c.rows {
		switch {
		case r.Result != collectOK:
		case r.Note != "":
			inv.echo("  " + r.Address + ": " + r.Note)
		default:
			inv.echo("  " + r.addLine())
		}
	}
	inv.echo("")
}

// serversText is the SERVERS cell: the TACACS+ and RADIUS servers the
// device is configured with.
func (r *collectRow) serversText() string {
	var parts []string
	if r.Tacplus > 0 {
		parts = append(parts, fmt.Sprintf("tacplus:%d", r.Tacplus))
	}
	if r.Radius > 0 {
		parts = append(parts, fmt.Sprintf("radius:%d", r.Radius))
	}
	return dash(strings.Join(parts, ","))
}

// registerAll is --register: one question, then 'device add' of each
// collected device through the registry's own registration code, every key
// shown pinned (the login itself was made against exactly those keys), and
// the read kept as the device's first pull record.
func (c *collect) registerAll(ctx context.Context) int {
	inv := c.inv
	var todo []*collectRow
	for _, r := range c.rows {
		if r.Result == collectOK && r.Name != "" {
			todo = append(todo, r)
		}
	}
	if len(todo) == 0 {
		inv.echo("  Nothing to register.")
		return batch.ExitOK
	}
	names := make([]string, len(todo))
	for i, r := range todo {
		names[i] = r.Name + " (" + r.Address + ")"
	}
	q := fmt.Sprintf("Register %d device(s), pinning the host keys shown: %s? [y/N] ", len(todo), strings.Join(names, ", "))
	if !c.yes && !c.pr.Confirm(q) {
		inv.app.Out.Info("Not registered.")
		return batch.ExitOK
	}
	code := batch.ExitOK
	for _, r := range todo {
		if ctx.Err() != nil {
			return batch.ExitInterrupted
		}
		args := []string{r.Name, r.Address, "--vendor", devssh.VendorJuniper, "--no-lookup"}
		if r.Legacy {
			args = append(args, "--legacy-ssh")
		}
		if err := inv.deviceAddWith(args, r.keys); err != nil {
			var ee *ExitError
			if !errors.As(err, &ee) || ee.Err != nil {
				inv.app.Out.ErrorE(strings.Join(msgs(err), " "))
			}
			r.Note = "not registered"
			code = batch.ExitFailed
			continue
		}
		r.Registered = true
		if err := c.keepRecord(r); err != nil {
			inv.app.Out.Warn(r.Name + ": the first record was not kept: " + err.Error() + " (tacctl device config pull " + r.Name + " reads it)")
			continue
		}
		inv.echo("  " + r.Name + ": the read is kept as its first pull record; tacctl device sync " + r.Name + " fills its empty fields from it.")
	}
	return code
}

// keepRecord keeps the read as the registered device's pull record, as the
// pull makes it (login=local:<account> for a local login).
func (c *collect) keepRecord(r *collectRow) error {
	inv := c.inv
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, ok := res.Lookup(r.Name, devreg.ScopeFilter{})
	if !ok || !e.Configured {
		return errors.New("no scope's prefixes cover " + r.Address)
	}
	render := inv.newManagedRender(managedOptions{}, inv.callerScopes().restricted)
	render.prepare([]devreg.Entry{e})
	expected, err := render.Expected(e)
	if err != nil {
		return err
	}
	ext, err := devconf.ExtractWith(e.Vendor, r.raw, devconf.Options{Expected: expected})
	if err != nil {
		return err
	}
	results, err := devconf.CompareAll(expected, ext)
	if err != nil {
		return err
	}
	facts := devconf.Facts{Release: r.id.Release, Model: r.id.Model}
	if facts.Release == "" {
		facts.Release = devconf.JunosRelease(r.raw)
	}
	login := ""
	if c.local != nil {
		login = localLoginText(c.local.account)
	}
	pr := &pullRun{inv: inv, user: c.user, store: inv.configStore()}
	o := &pullOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Transport: transportSSH, Netconf: netconfNotProbed,
		Facts: devconf.CleanFacts(facts), Login: login}
	// no plain view was read (nothing else is typed on an address nobody
	// registered): the plan says the groups' inheritance was not checked
	// until a pull reads it
	return pr.recordSuccess(o, e, ext, results, nil)
}

// audit is the run's audit lines (D141): the user, the address, the login
// and the result; never a password and never a device's text.
func (c *collect) audit() {
	inv := c.inv
	for _, r := range c.rows {
		res := r.Result
		extra := ""
		switch {
		case res == "":
			res = "refused"
		case r.Registered:
			res, extra = "registered", " device="+r.Name
		}
		inv.app.Audit().Raw("auth.info", fmt.Sprintf("device collect user=%s addr=%s login=%s result=%s%s",
			c.user, r.Address, c.loginWord(), res, extra))
	}
	if len(c.rows) == 0 {
		inv.app.Audit().Raw("auth.info", fmt.Sprintf("device collect user=%s addr=- login=%s result=refused", c.user, c.loginWord()))
	}
}

// collectJSON is one address in --json.
type collectJSON struct {
	Address        string   `json:"address"`
	Result         string   `json:"result"`
	Reason         string   `json:"reason,omitempty"`
	Banner         string   `json:"banner,omitempty"`
	Hostname       string   `json:"hostname,omitempty"`
	Model          string   `json:"model,omitempty"`
	Release        string   `json:"release,omitempty"`
	AuthOrder      []string `json:"authentication_order,omitempty"`
	TacplusServers int      `json:"tacplus_servers"`
	RadiusServers  int      `json:"radius_servers"`
	ENClass        bool     `json:"en_class"`
	Netconf        bool     `json:"netconf"`
	Lo0Filter      []string `json:"lo0_filter,omitempty"`
	Legacy         bool     `json:"legacy"`
	HostKeys       []string `json:"host_keys,omitempty"`
	Name           string   `json:"name,omitempty"`
	Registered     bool     `json:"registered"`
	Add            string   `json:"add,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// printJSON prints the object of the run at the end.
func (c *collect) printJSON(code int) {
	out := struct {
		Login   string        `json:"login"`
		Devices []collectJSON `json:"devices"`
		Exit    int           `json:"exit"`
	}{Login: c.loginWord(), Devices: []collectJSON{}, Exit: code}
	for _, r := range c.rows {
		j := collectJSON{Address: r.Address, Result: r.Result, Reason: r.Reason, Banner: r.Banner, Hostname: r.Hostname, Model: r.Model,
			Release: r.Release, AuthOrder: r.AuthOrder, TacplusServers: r.Tacplus, RadiusServers: r.Radius, ENClass: r.ENClass,
			Netconf: r.Netconf, Lo0Filter: r.Lo0Filter, Legacy: r.Legacy, Name: r.Name, Registered: r.Registered, Note: r.Note}
		if j.Result == "" {
			j.Result = "refused"
		}
		for _, k := range r.keys {
			j.HostKeys = append(j.HostKeys, k.Fingerprint())
		}
		if r.Result == collectOK && r.Note == "" {
			j.Add = r.addLine()
		}
		out.Devices = append(out.Devices, j)
	}
	b, _ := json.Marshal(out)
	c.inv.write(string(b) + "\n")
}

// the one-shot callbacks of the run
type collectOnce struct {
	acceptOnce, rejectOnce sync.Once
	own                    devssh.PasswordSource
}
