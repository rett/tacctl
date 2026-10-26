package cli

// 'device enroll <address>... | --discovered' (docs/plans/0.2.17-plan.md
// D261-D264, D269, D272; enroll-workflow.md): the chain a person used to
// remember, run per address and attended. Stage 1, one address at a time in
// the order given: the refusals that need no question, the host-key scan, the
// one key shown and accepted by typing the device's name (D262), the vendor
// and name read by SNMP with a question for what cannot be read (D263), the
// registration question, and the registration at once through 'device add'
// (one snapshot for the run). Stage 2: one password, the pull of every device
// registered with a vendor tacctl reads, then the device's own configured
// name taken over in the registry (no question, nothing written to the
// device). Stage 3: the plan. Stage 4, Junos only: the offer of the apply
// review, device by device (D265). A device registered stays registered
// whatever happens later; the summary names each one's next step. No
// credential is kept, nothing is scheduled, and no device is written to but
// by the apply review.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// enrollUse is the usage line of the verb.
const enrollUse = "Usage: tacctl device enroll <address>... | --discovered [--host-key SHA256:<fp>] [--vendor cisco|juniper|wti|other] [--name <name>] [--legacy-ssh] [--json]"

// The results of one address (the RESULT column, the JSON's result and the
// audit line's result=).
const (
	enrollRefused    = "refused"
	enrollSkipped    = "skipped"
	enrollFailed     = "failed"
	enrollNotTried   = "not-tried"
	enrollRegistered = "registered"
	enrollOther      = "registered-other"
	enrollPullFailed = "pull-failed"
	enrollPlanned    = "planned"
	enrollApplied    = "applied"
	enrollDeclined   = "declined"
)

// Where a vendor came from (the JSON's vendor_source, the line's source=).
const (
	sourceSNMP  = "snmp"
	sourceGiven = "given"
	sourceAsked = "asked"
)

// enrollRow is one address of the run.
type enrollRow struct {
	Address string
	// Name is the registered name (after a rename, the new one); nameSource
	// is where the name registered came from: snmp, typed or given.
	Name, nameSource string
	Vendor           string
	VendorSource     string
	// Key is the acceptance's answer: accepted, skipped, refused or flag (""
	// before it was asked).
	Key        string
	key        devreg.HostKey
	offered    []devreg.HostKey
	legacy     bool
	Registered bool
	// RenamedFrom is the name typed or given before the device's own replaced
	// it; RenameKept why the device's own name was not taken.
	RenamedFrom, RenameKept string
	// keptLine is the 'device rename' line to run by hand.
	keptLine string
	Pull     string
	Plan     string
	Result   string
	Reason   string
	// next is the command line that takes the device on from where it stopped.
	next string
	// read is the SNMP read of the device's name and vendor.
	read chan enrollRead
}

// enrollRead is what SNMP said of an address: its sysName (lower-cased, ""
// for none, with why) and the vendor read.
type enrollRead struct {
	name, noName string
	vend         vendorRead
}

// enroll is one run.
type enroll struct {
	inv  *invocation
	user string
	pr   *ui.Prompter

	addrs                   []string
	discovered, asJSON      bool
	hostKey, vendor, name   string
	legacySSH, tty          bool
	rows                    []*enrollRow
	interrupted             bool
	snapshotTaken, released bool
	// ended: the input ended at a key's question; the rest is not tried.
	ended   bool
	release func()
	// pass is the run's one password, asked at the pull and lent to the
	// apply review.
	pass *runPassword
	// apply says what became of the offer: not-offered, declined or run.
	apply string
	// out is the standard output the run started with (with --json the
	// progress goes to standard error, the objects here).
	out io.Writer
}

// deviceEnroll is 'device enroll'.
func (inv *invocation) deviceEnroll(args []string) error {
	p, err := Parse(deviceSpecs["enroll"], args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.argErr(msg, enrollUse)
	}
	if err := inv.deviceVerbAllowed("device", "enroll", tier.Engineer); err != nil {
		return err
	}
	user, err := inv.configLogin("device enroll")
	if err != nil {
		return err
	}
	pr := inv.app.Prompter()
	e := &enroll{inv: inv, user: user, pr: pr, tty: pr.Interactive(), discovered: p.Has("--discovered"), asJSON: p.Has("--json"),
		hostKey: p.Value("--host-key"), vendor: strings.ToLower(p.Value("--vendor")), name: p.Value("--name"),
		legacySSH: p.Has("--legacy-ssh"), apply: "not-offered"}
	if err := e.args(p); err != nil {
		return err
	}
	defer e.done()
	saved := inv.app.Out.Stdout
	e.out = saved
	code, err := e.run()
	inv.app.Out.Stdout = saved
	if err != nil {
		// a run that stopped on an error still says what each address is
		// left as, the registered ones with their next step
		code = exitStatus(err)
		for _, r := range e.rows {
			if r.Result == "" {
				r.Result, r.Reason = enrollNotTried, "the run stopped on an error"
				r.next = "tacctl device enroll " + r.Address
			}
		}
	}
	e.audit()
	e.summary(code)
	if e.asJSON {
		e.printJSON(code)
	}
	switch {
	case err != nil:
		return err
	case code != 0:
		return exit(code)
	}
	return nil
}

// args checks what needs no device and no registry (exit 2).
func (e *enroll) args(p Parsed) error {
	inv := e.inv
	seen := map[string]bool{}
	for _, a := range p.Args {
		addr, err := devreg.NormalizeAddress(a)
		if err != nil || strings.Contains(a, "/") {
			msg := "Invalid address '" + a + "': one IPv4 or IPv6 address per device."
			if err != nil {
				msg = strings.Join(msgs(err), " ")
			}
			return inv.argErr(msg, enrollUse)
		}
		if !seen[addr] {
			seen[addr] = true
			e.addrs = append(e.addrs, addr)
		}
	}
	one := !e.discovered && len(e.addrs) == 1
	switch {
	case e.discovered && len(e.addrs) > 0:
		return inv.argErr("Name the addresses, or give --discovered, not both.", enrollUse)
	case !e.discovered && len(e.addrs) == 0:
		return inv.argErr("Name the addresses to enroll, or give --discovered (the addresses 'tacctl device discover' lists).", enrollUse)
	}
	for _, f := range []string{"--host-key", "--vendor", "--name"} {
		if p.Has(f) && !one {
			return inv.argErr(f+" answers for ONE device: give one address (a list is answered at the terminal, device by device).", enrollUse)
		}
	}
	switch {
	case p.Has("--host-key") && !devreg.ValidFingerprint(e.hostKey):
		return inv.argErr("Invalid --host-key '"+e.hostKey+"': expected SHA256:<fingerprint> as ssh prints it.", enrollUse)
	case p.Has("--vendor") && !slices.Contains(append(sortedVendors(), devreg.VendorOther), e.vendor):
		return inv.argErr("--vendor takes cisco, juniper, wti or other: '"+p.Value("--vendor")+"'", enrollUse)
	case p.Has("--name"):
		if err := devreg.ValidateName(e.name); err != nil {
			return inv.argErr(append(msgs(err), enrollUse)...)
		}
		if err := names.RequireLower(e.name); err != nil {
			return inv.argErr(append(msgs(err), enrollUse)...)
		}
	}
	if !e.tty && e.hostKey == "" {
		return inv.argErr("No terminal to answer the host-key question on: the key of an address nobody registered is accepted by a person, "+
			"device by device, by typing its name. Give --host-key SHA256:<fp> with one address (the fingerprint read on the device's console). Nothing was changed.", enrollUse)
	}
	return nil
}

// done drops what the run still holds: the snapshot hold and the password.
func (e *enroll) done() {
	e.releaseHold()
	if e.pass != nil {
		e.pass.password = ""
		if d, ok := e.pass.src.(interface{ Done() }); ok {
			d.Done()
		}
	}
}

// releaseHold ends the run's one snapshot (later writes take their own).
func (e *enroll) releaseHold() {
	if e.release != nil && !e.released {
		e.released = true
		e.release()
	}
}

// say is a line of the run's progress: on standard error with --json.
func (e *enroll) say(s string) {
	if e.asJSON {
		e.inv.stderrLine(s)
		return
	}
	e.inv.echo(s)
}

// run is the four stages; the code is the exit status.
func (e *enroll) run() (int, error) {
	inv := e.inv
	if e.asJSON {
		// the questions and the progress go to standard error; the pull's,
		// the plan's and the run's objects to standard output
		saved := inv.app.Out.Stdout
		inv.app.Out.Stdout = inv.app.Out.Stderr
		defer func() { inv.app.Out.Stdout = saved }()
	}
	if err := e.admissible(); err != nil {
		return 0, err
	}
	if len(e.rows) == 0 {
		inv.app.Out.Info("No unregistered address has authenticated: nothing to enroll. 'tacctl device discover' reads the logs for them.")
		return batch.ExitOK, nil
	}
	// 1. identity and registration, one address at a time
	for _, r := range e.rows {
		if r.Result != "" {
			continue
		}
		if e.interrupted || inv.ctx.Err() != nil {
			e.interrupted = true
			r.Result, r.Reason = enrollNotTried, "interrupted"
			continue
		}
		if e.ended {
			r.Result, r.Reason = enrollNotTried, "the input ended at an earlier question"
			r.next = "tacctl device enroll " + r.Address
			continue
		}
		if err := e.identity(r); err != nil {
			return 0, err
		}
	}
	// the vendors read, for the vendor-differs notice (the reads of the
	// addresses whose keys were read have been awaited)
	reads := map[string]vendorRead{}
	for _, r := range e.rows {
		if r.read != nil && len(r.offered) > 0 {
			reads[r.Address] = r.awaitRead().vend
		}
	}
	inv.keepDetections(reads)
	if e.interrupted {
		e.releaseHold()
		return batch.ExitInterrupted, nil
	}
	// 2. the pull, and the name the device is configured with
	if e.asJSON {
		inv.app.Out.Stdout = e.out
	}
	pulled, interrupted, err := e.pull()
	if err != nil {
		return 0, err
	}
	e.releaseHold()
	if interrupted {
		return batch.ExitInterrupted, nil
	}
	// 3. the plan
	planned := e.plan(pulled)
	// 4. the offer, Junos only
	if code := e.offer(planned); code == batch.ExitInterrupted {
		return code, nil
	}
	return e.code(), nil
}

// code is the exit status of the rows: 0 when every address went as far as
// its vendor allows, 1 when one was refused, skipped or failed.
func (e *enroll) code() int {
	for _, r := range e.rows {
		switch r.Result {
		case enrollPlanned, enrollApplied, enrollOther:
		default:
			return batch.ExitFailed
		}
	}
	return batch.ExitOK
}

// admissible makes the rows: the addresses named, or with --discovered those
// 'device discover' lists. What is refused before any question is a row of
// its own, and the run goes on: an address registered already, an address no
// scope answers, a scope the caller is not a member of, a break-glass hold.
func (e *enroll) admissible() error {
	inv := e.inv
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if e.discovered {
		for _, u := range res.Unregistered(false) {
			// the addresses of other scopes are not an engineer's to enroll
			if info, covered := m.LookupAddr(u.Address); covered && inv.scopeAddrProblem(info.Scope) != "" {
				continue
			}
			e.addrs = append(e.addrs, u.Address)
		}
	}
	for _, addr := range e.addrs {
		r := &enrollRow{Address: addr, Pull: "not-tried", Plan: "not-tried"}
		e.rows = append(e.rows, r)
		// a registered device of another scope is not found (and then refused
		// as an address that is not the engineer's)
		if ent, ok := res.Lookup(addr, inv.deviceFilter()); ok && ent.Address == addr {
			r.Result = enrollRefused
			if ent.Source == devreg.SourceHost {
				r.Reason = "registered already as '" + ent.Name + "' (an enrolled Linux host)"
				continue
			}
			r.Reason = "registered already as '" + ent.Name + "'"
			r.next = "tacctl device config pull " + ent.Name
			continue
		}
		info, covered := m.LookupAddr(addr)
		if !covered {
			r.Result, r.Reason = enrollRefused, "no scope's prefixes cover it"
			r.next = "tacctl scope prefixes <scope> add <cidr>"
			continue
		}
		if msg := inv.scopeAddrProblem(info.Scope); msg != "" {
			r.Result, r.Reason = enrollRefused, msg
			continue
		}
		if msg := loginProblem(m, e.user, info.Scope); msg != "" {
			r.Result, r.Reason = enrollRefused, strings.TrimSuffix(msg, ".")
			continue
		}
		if h, held := inv.holdAt(addr); held {
			r.Result, r.Reason = enrollRefused, holdRefusal(h.Device)
			continue
		}
	}
	return nil
}

// startRead starts the SNMP read of an address's name and vendor, beside its
// host-key scan; the answer is awaited at the question.
func (e *enroll) startRead(r *enrollRow) {
	inv := e.inv
	r.read = make(chan enrollRead, 1)
	go func() {
		var rd enrollRead
		sys, problem, err := inv.sysName(r.Address)
		switch {
		case problem != "":
			rd.noName, rd.vend = problem, vendorRead{problem: problem}
			r.read <- rd
			return
		case err != nil && !errors.Is(err, errEmptySysName):
			why := "no SNMP answer"
			if w := snmpReason(err); w != "" {
				why += " (" + w + ")"
			}
			rd.noName, rd.vend = why, vendorRead{err: err}
			r.read <- rd
			return
		case err != nil:
			rd.noName = "its sysName is empty"
		default:
			rd.name = sys
		}
		rd.vend = inv.readVendor(r.Address)
		r.read <- rd
	}()
}

// awaitRead is the SNMP read of r, once it has come.
func (r *enrollRow) awaitRead() enrollRead {
	rd := <-r.read
	r.read <- rd
	return rd
}

// checkName is the name rules of a name a device is about to be registered
// under (newNameRules: enroll has no --allow-generic).
func (e *enroll) checkName(vendor string) func(string) error { return e.inv.newNameRules(vendor) }

// newNameRules is the name rules of a name a device is about to be registered
// under by a person's answer (enroll, onboard): valid, lower case, not taken
// by a device or an enrolled host, not generic. Its error names the rule,
// never the name, which may be what a person typed.
func (inv *invocation) newNameRules(vendor string) func(string) error {
	return func(n string) error {
		if devreg.ValidateName(n) != nil {
			return errors.New("the name is not a valid device name (letters, digits, '.', '_' and '-')")
		}
		if names.RequireLower(n) != nil {
			return errors.New("the name has upper case: names are lower case")
		}
		_, res, err := inv.deviceLoad()
		if err != nil {
			return err
		}
		if _, taken := res.NameTaken(n); taken {
			return errors.New("the name is already registered (a device or an enrolled host)")
		}
		if res.CheckName(n, vendor, false, "") != nil {
			return errors.New("the name is a generic name (a factory or image default)")
		}
		return nil
	}
}

// scan reads the address's host keys: ssh-keyscan, then for a device that
// gives none the legacy algorithms (as 'device collect' does); --legacy-ssh
// scans with them at once.
func (e *enroll) scan(r *enrollRow) bool {
	inv := e.inv
	r.legacy = e.legacySSH
	keys, err := inv.scanDevice(r.Address, devssh.DefaultPort, r.legacy)
	if !r.legacy && errors.Is(err, devreg.ErrNoAnswer) && inv.ctx.Err() == nil {
		if k2, err2 := inv.scanDevice(r.Address, devssh.DefaultPort, true); err2 == nil && len(k2) > 0 {
			keys, err, r.legacy = k2, nil, true
		}
	}
	switch {
	case inv.ctx.Err() != nil:
		e.interrupted = true
		r.Result, r.Reason = enrollNotTried, "interrupted"
	case errors.Is(err, devreg.ErrNoAnswer):
		r.Result, r.Reason = enrollRefused, "no ssh host key could be read (ssh-keyscan): not reachable on port 22"
	case err != nil:
		r.Result, r.Reason = enrollRefused, cleanLine(strings.Join(msgs(err), " "))
	case len(keys) == 0:
		r.Result, r.Reason = enrollRefused, "no ssh host key could be read"
	default:
		r.offered = keys
		return true
	}
	return false
}

// identity is stage 1 for one address: the scan, the key, the vendor and the
// name, the registration question and the registration.
func (e *enroll) identity(r *enrollRow) error {
	inv := e.inv
	e.say("")
	e.startRead(r)
	if !e.scan(r) {
		return nil
	}
	rd := r.awaitRead()
	// the name the device gives itself, when the registry would take it
	snmpName := ""
	if rd.name != "" {
		n := strings.ToLower(rd.name)
		vendorGuess := orWord(e.vendor, rd.vend.vendor)
		if err := e.checkName(vendorGuess)(n); err != nil {
			e.say("  " + r.Address + " calls itself '" + devText(rd.name) + "' (SNMP sysName), which is not taken as its name: " +
				devText(strings.Join(msgs(err), " ")))
		} else {
			snmpName = n
		}
	}
	// the vendor: --vendor, else the one the device names
	vendor, vsource := "", ""
	switch {
	case e.vendor != "":
		vendor, vsource = e.vendor, sourceGiven
		if rd.vend.vendor != "" && rd.vend.vendor != e.vendor {
			e.say("  " + rd.vend.says() + "; --vendor " + e.vendor + " is taken.")
		}
	case rd.vend.vendor != "":
		vendor, vsource = rd.vend.vendor, sourceSNMP
	}
	name, nsource := snmpName, "snmp"
	if e.name != "" {
		name, nsource = e.name, "given"
	}
	// Without a terminal what a person would answer must have been given.
	if !e.tty {
		switch {
		case vendor == "":
			r.Result, r.Reason = enrollSkipped, "the vendor could not be read"
			r.next = "tacctl device add " + orWord(name, "<name>") + " " + r.Address + " --vendor <vendor>"
			return nil
		case name == "":
			r.Result, r.Reason = enrollSkipped, "no name to register it as (the device gives none by SNMP)"
			r.next = "tacctl device enroll " + r.Address + " --host-key " + e.hostKey + " --name <name>"
			return nil
		}
	}
	// the key: --host-key names it, else the person accepts the one shown
	if e.hostKey != "" {
		k, ok := devreg.MatchFingerprint(r.offered, e.hostKey)
		if !ok {
			r.Key, r.Result, r.Reason = string(keyRefused), enrollRefused, "no host key it offers matches --host-key "+e.hostKey
			e.say("  " + r.Address + " offers:")
			inv.echoKeys("    ", r.offered)
			e.say("  Check the fingerprint on the device console: " + devreg.VerifyHint(orWord(vendor, devreg.VendorOther)) + ".")
			inv.hostKeyLine("device enroll", e.user, r.Address, name, devreg.HostKey{}, keyRefused, "flag")
			return nil
		}
		e.say("  " + r.Address + ": " + e.hostKey + " matches --host-key.")
		if name == "" {
			// a terminal (without one, name is given): asked for, with the
			// rules, before the acceptance's line, so that the line names it
			n, ok := e.askName(r, vendor)
			if !ok {
				if r.Result != enrollNotTried {
					inv.hostKeyLine("device enroll", e.user, r.Address, "-", k, hostKeyAnswer(r.Result), "flag")
				}
				return nil
			}
			name, nsource = n, "typed"
		}
		if !e.keyLogged(r, name, k, keyAccepted, "flag") {
			return nil
		}
		r.key, r.Key = k, "flag"
	} else {
		ans := inv.acceptHostKey(r.Address, devssh.DefaultPort, vendor, name, r.offered, e.checkName(orWord(vendor, devreg.VendorOther)))
		switch ans.answer {
		case keyInterrupted:
			e.interrupted = true
			r.Result, r.Reason = enrollNotTried, "interrupted"
			return nil
		case keyAccepted:
			if !e.keyLogged(r, ans.name, ans.key, keyAccepted, "confirmed") {
				return nil
			}
			r.key, r.Key = ans.key, string(keyAccepted)
			if name == "" {
				name, nsource = ans.name, "typed"
			}
		default:
			device := "-"
			if ans.answer == keyRefused {
				device = name
			}
			inv.hostKeyLine("device enroll", e.user, r.Address, device, ans.key, ans.answer, "confirmed")
			r.Key = string(ans.answer)
			r.Result, r.Reason = string(ans.answer), ans.reason
			r.next = "tacctl device enroll " + r.Address
			// the end of input ends the run: no address after it is scanned
			// or asked
			e.ended = ans.eof
			return nil
		}
	}
	r.Name, r.nameSource = name, nsource
	// the vendor a person gives when the device names none
	if vendor == "" {
		v, ok := e.askVendor(r)
		if !ok {
			return nil
		}
		vendor, vsource = v, sourceAsked
	}
	r.Vendor, r.VendorSource = vendor, vsource
	// one registration question per device, at a terminal
	if e.tty {
		why := map[string]string{sourceSNMP: "the device says so", sourceGiven: "--vendor", sourceAsked: "as answered"}[vsource]
		got, ok, interrupted := inv.askLine("  Register " + r.Address + " as '" + name + "' (" + vendor + ", " + why + ")? [y/N] ")
		switch {
		case interrupted:
			e.interrupted = true
			r.Result, r.Reason = enrollNotTried, "interrupted"
			return nil
		case !ok || (strings.ToLower(got) != "y" && strings.ToLower(got) != "yes"):
			r.Result, r.Reason = enrollSkipped, "not registered (the registration question was not answered yes)"
			r.next = "tacctl device enroll " + r.Address
			return nil
		}
	}
	return e.register(r)
}

// keyLogged writes the acceptance's line before anything uses the key; under
// audit.strict a line that was not written refuses the device: nothing is
// pinned or registered.
func (e *enroll) keyLogged(r *enrollRow, device string, k devreg.HostKey, answer hostKeyAnswer, source string) bool {
	why := e.inv.hostKeyLine("device enroll", e.user, r.Address, device, k, answer, source)
	if why != "" && e.inv.auditStrict() {
		r.Key, r.Result = string(keyRefused), enrollRefused
		r.Reason = "the acceptance's audit line was not written (logger: " + why + ") and audit.strict is set; nothing was pinned"
		return false
	}
	return true
}

// askName asks the name of a device whose key --host-key named and that gives
// no name of its own: checked by the rules, with no second try.
func (e *enroll) askName(r *enrollRow, vendor string) (string, bool) {
	got, ok, interrupted := e.inv.askLine("  The name to register " + r.Address + " as (Enter skips the device): ")
	switch {
	case interrupted:
		e.interrupted = true
		r.Result, r.Reason = enrollNotTried, "interrupted"
		return "", false
	case !ok || got == "":
		r.Result, r.Reason = enrollSkipped, "no name was given"
		r.next = "tacctl device enroll " + r.Address
		return "", false
	}
	if err := e.checkName(orWord(vendor, devreg.VendorOther))(got); err != nil {
		r.Result, r.Reason = enrollRefused, strings.Join(msgs(err), " ")
		r.next = "tacctl device enroll " + r.Address
		return "", false
	}
	return got, true
}

// askVendor asks the vendor of a device that names none tacctl reads: once,
// at the terminal; Enter skips the device. Without a terminal the device is
// skipped with the 'device add' line.
func (e *enroll) askVendor(r *enrollRow) (string, bool) {
	addLine := "tacctl device add " + r.Name + " " + r.Address + " --vendor <vendor>"
	if !e.tty {
		r.Result, r.Reason, r.next = enrollSkipped, "the vendor could not be read", addLine
		return "", false
	}
	got, ok, interrupted := e.inv.askLine("  Vendor of " + r.Address + " (cisco, juniper, wti or other; Enter skips the device): ")
	got = strings.ToLower(got)
	switch {
	case interrupted:
		e.interrupted = true
		r.Result, r.Reason = enrollNotTried, "interrupted"
		return "", false
	case !ok || got == "":
		r.Result, r.Reason, r.next = enrollSkipped, "the vendor could not be read", addLine
		return "", false
	case !slices.Contains(append(sortedVendors(), devreg.VendorOther), got):
		r.Result, r.Reason, r.next = enrollRefused, "the answer is not a vendor: cisco, juniper, wti or other", addLine
		return "", false
	}
	return got, true
}

// register registers the device at once through 'device add', with the one
// key accepted pinned and the others shown as offered and not pinned. The
// first registration of the run takes the run's one snapshot and holds the
// snapshotter, so later writes of the run take none.
func (e *enroll) register(r *enrollRow) error {
	inv := e.inv
	if !e.snapshotTaken {
		e.snapshotTaken = true
		snaps := inv.app.Snapshots()
		saved := snaps.Out
		if e.asJSON {
			// its line is progress: standard error, as the rest
			snaps.Out = ui.Output{Stdout: inv.app.Out.Stderr, Stderr: inv.app.Out.Stderr}
		}
		_, err := inv.snapshotFirstID()
		snaps.Out = saved
		if err != nil {
			return err
		}
		e.release = inv.app.Snapshots().Hold()
	}
	args := []string{r.Name, r.Address, "--vendor", r.Vendor, "--no-lookup", "--host-key", r.key.Fingerprint()}
	if r.legacy {
		args = append(args, "--legacy-ssh")
	}
	inv.keyAccepted = r.Key == string(keyAccepted)
	err := inv.deviceAddWith(args, r.offered)
	inv.keyAccepted = false
	if err != nil {
		var ee *ExitError
		why := "the registry refused it (above)"
		if !errors.As(err, &ee) || ee.Err != nil {
			why = strings.Join(msgs(err), " ")
		}
		r.Result, r.Reason = enrollFailed, "not registered: "+why
		r.next = "tacctl device enroll " + r.Address
		return nil
	}
	r.Registered = true
	if r.Vendor == devreg.VendorOther {
		r.Result, r.Pull, r.Plan = enrollOther, "not-read", "not-read"
		r.next = "tacctl device vendor " + r.Name + " <vendor> (or --from-device), then: tacctl device config pull " + r.Name
		return nil
	}
	r.Result = enrollRegistered
	r.next = "tacctl device config pull " + r.Name
	return nil
}

// pull is stage 2: one password, the pull of every device registered with a
// vendor tacctl reads, then the name step. It returns the entries pulled
// (under the names they have now).
func (e *enroll) pull() ([]devreg.Entry, bool, error) {
	inv := e.inv
	var todo []*enrollRow
	for _, r := range e.rows {
		if r.Result == enrollRegistered {
			todo = append(todo, r)
		}
	}
	if len(todo) == 0 {
		return nil, false, nil
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return nil, false, err
	}
	var entries []devreg.Entry
	var rows []*enrollRow
	for _, r := range todo {
		ent, ok := res.Lookup(r.Name, devreg.ScopeFilter{})
		if !ok || !ent.Configured {
			r.Result, r.Reason = enrollPullFailed, "no scope's prefixes cover it now"
			continue
		}
		entries = append(entries, ent)
		rows = append(rows, r)
	}
	if len(entries) == 0 {
		return nil, false, nil
	}
	// the password, once, after every question and before the first login
	src := inv.hooks.newDevicePasswords(inv)
	pw, err := src.Password(inv.ctx, e.user)
	if err != nil {
		if d, ok := src.(interface{ Done() }); ok {
			d.Done()
		}
		for _, r := range rows {
			r.Result, r.Pull, r.Reason = enrollPullFailed, "not-tried", "no password: "+err.Error()
		}
		return nil, inv.ctx.Err() != nil, nil
	}
	e.pass = &runPassword{src: src, password: string(pw)}
	askpass.Zero(pw)
	render := inv.newManagedRender(managedOptions{}, true)
	render.prepare(entries)
	st := inv.deviceConfigSettings()
	pa := pullArgs{transport: st.transport, timeout: st.timeout, json: e.asJSON}
	view := inv.newPullView(entries, e.asJSON, e.user, false)
	sum, outs, err := inv.runPull(pullBatch{entries: entries, render: render, args: pa, user: e.user, view: view, pass: e.pass})
	if err != nil {
		return nil, false, err
	}
	inv.hooks.pullDone()
	if !e.asJSON {
		inv.echo("")
		inv.echo("  pull: " + sum.Line())
	}
	var pulled []devreg.Entry
	for i, r := range rows {
		res := sum.Entries[i].Result
		if res.Status == batch.StatusOK {
			r.Pull = "ok"
			pulled = append(pulled, entries[i])
			continue
		}
		r.Pull, r.Result = "failed", enrollPullFailed
		switch {
		case res.Status == batch.StatusNotStarted || res.Status == batch.StatusSkipped:
			r.Pull, r.Reason = "not-tried", "the pull did not start: "+res.Text()
		case outs[i] != nil && outs[i].Reason != "":
			r.Reason = "the pull failed: " + outs[i].Reason
		default:
			r.Reason = "the pull failed: " + res.Text()
		}
		r.next = "tacctl device config pull " + r.Name
	}
	if sum.Interrupted || inv.ctx.Err() != nil {
		for _, r := range rows {
			if r.Pull == "ok" {
				r.Result, r.next = enrollRegistered, "tacctl device config plan "+r.Name
			}
		}
		return nil, true, nil
	}
	saved := inv.app.Out.Stdout
	if e.asJSON {
		inv.app.Out.Stdout = inv.app.Out.Stderr
	}
	for i, ent := range pulled {
		for _, r := range rows {
			if r.Name == ent.Name {
				pulled[i] = e.takeName(r, ent)
			}
		}
	}
	inv.app.Out.Stdout = saved
	return pulled, false, nil
}

// deviceOwnName is the name a device is configured with, as its last good pull
// read it: Junos 'system host-name', IOS 'hostname', a WTI unit's Site ID
// when it is not generic; the first label, lower-cased; "" for none.
func deviceOwnName(rec *devconf.Record, vendor string, extra []string) string {
	n := rec.Hostname
	if vendor == "wti" {
		n = ""
		if rec.Unit != nil && !devreg.IsGeneric(rec.Unit.SiteID, extra) {
			n = rec.Unit.SiteID
		}
	}
	n, _, _ = strings.Cut(strings.TrimSpace(n), ".")
	return strings.ToLower(n)
}

// heldNow reports whether a break-glass hold stands on the device now, from
// tacctl.yaml as it is on disk (a hold placed since the run began included).
func heldNow(inv *invocation, name, addr string) bool {
	for _, h := range conf.Load(inv.app.Paths.Overrides, backend.Default().IDs()).Holds() {
		if strings.EqualFold(h.Device, name) && sameAddress(h.Address, addr) {
			return true
		}
	}
	return false
}

// renameKept is the row's words for a name the device is configured with that
// was not taken over: the name as a device reported it, made safe for a
// terminal and a log, and the 'device rename' line to run by hand, only when
// the name is one the registry accepts ("" otherwise: no line could run).
func renameKept(own, why, line string) (kept, hint string) {
	kept = "the device is configured as '" + devText(own) + "', and " + devText(why)
	if devreg.ValidateName(own) == nil {
		hint = line
	}
	return kept, hint
}

// takeName is the name step (D263): a device registered under a name typed
// or given (never one read by SNMP, which is the device's own already) whose
// configuration names it otherwise is renamed to that name in the registry,
// with no question and nothing written to the device; a name that is taken,
// is not a valid name, is generic, or a device that is held keeps the name
// registered, with the reason and the 'device rename' line. It returns the
// entry under the name it has now.
func (e *enroll) takeName(r *enrollRow, ent devreg.Entry) devreg.Entry {
	inv := e.inv
	if r.nameSource == "snmp" {
		return ent
	}
	recs, err := inv.configStore().Load()
	if err != nil {
		return ent
	}
	rec, ok := recs.Of(ent.Name)
	if !ok {
		return ent
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return ent
	}
	own := deviceOwnName(rec, ent.Vendor, f.GenericNames)
	if own == "" || own == ent.Name {
		return ent
	}
	line := "tacctl device rename " + ent.Name + " " + own
	why := ""
	switch taken, isTaken := res.NameTaken(own); {
	case devreg.ValidateName(own) != nil:
		why = "it is not a valid device name"
	case isTaken && taken.Source == devreg.SourceHost:
		why = "an enrolled host has that name"
	case isTaken:
		why = "the device '" + taken.Name + "' has that name"
	case res.CheckName(own, ent.Vendor, false, "") != nil:
		why, line = "it is a generic name", line+" --allow-generic"
	case heldNow(inv, ent.Name, ent.Address):
		why = "break-glass is held on " + ent.Name
	}
	if why == "" {
		if err := inv.renameDevice(ent.Name, own, ent.Address, false, kvp("reason", "device-name")); err != nil {
			why = "the registry refused the rename"
			var ee *ExitError
			if !errors.As(err, &ee) || ee.Err != nil {
				why = strings.Join(msgs(err), " ")
			}
		}
	}
	if why != "" {
		r.RenameKept, r.keptLine = renameKept(own, why, line)
		hint := ""
		if r.keptLine != "" {
			hint = " (" + r.keptLine + ")"
		}
		e.say("  " + ent.Name + ": kept; " + r.RenameKept + hint)
		return ent
	}
	e.say("  renamed " + ent.Name + " -> " + own + " (the device's configured name; nothing was written to the device)")
	r.RenamedFrom, r.Name = ent.Name, own
	_, res, err = inv.deviceLoad()
	if err == nil {
		if n, ok := res.Lookup(own, devreg.ScopeFilter{}); ok {
			return n
		}
	}
	ent.Name = own
	return ent
}

// plan is stage 3: the plan of every device pulled, printed as 'device config
// plan <names>' prints it. It returns the Junos devices whose plan has a
// change.
func (e *enroll) plan(pulled []devreg.Entry) []devreg.Entry {
	inv := e.inv
	if len(pulled) == 0 {
		return nil
	}
	render := inv.newManagedRender(managedOptions{}, true)
	render.prepare(pulled)
	chosen := &chosenDevices{entries: pulled, render: render}
	if !e.asJSON {
		inv.echo("")
	}
	// as 'device config plan --no-secrets': each secret a marked line, so
	// the run prints none; 'device config plan <name>' prints the region to
	// paste, and the apply review renders its own
	results, _, err := inv.planEntries(chosen, planOptions{asJSON: e.asJSON, noSecrets: true}, e.user, nil, "Usage: tacctl device config "+deviceConfigUse("plan"))
	if !e.asJSON && len(results) > 0 {
		inv.echo("")
		inv.echo("  The plan above leaves each secret as a marked line; to paste it: tacctl device config plan <name>.")
	}
	byName := map[string]planDevice{}
	for _, p := range results {
		byName[strings.ToLower(p.e.Name)] = p
	}
	var junos []devreg.Entry
	for _, ent := range pulled {
		r := e.rowOf(ent.Name)
		if r == nil {
			continue
		}
		p, ok := byName[strings.ToLower(ent.Name)]
		switch {
		case err != nil || !ok:
			r.Plan, r.Result, r.Reason = "cannot", enrollFailed, "the plan could not be made"
			r.next = "tacctl device config plan " + r.Name
		case !p.planned():
			r.Plan, r.Result, r.Reason = "cannot", enrollFailed, "the plan could not be made: "+cleanLine(p.cannot)
			r.next = "tacctl device config plan " + r.Name
		case p.status.State == plan.StatusNeedsChange:
			r.Plan, r.Result, r.next = "differs", enrollPlanned, ""
			if ent.Vendor == devssh.VendorJuniper {
				junos = append(junos, ent)
				r.next = "tacctl device config apply " + r.Name
			}
		default:
			// planned, and nothing for the review: say why none is offered
			r.Plan, r.Result, r.next = "ok", enrollPlanned, ""
			r.Reason = "nothing to apply: the plan has no change"
			if ent.Vendor != devssh.VendorJuniper {
				r.Reason = "nothing to paste: the plan has no change"
			}
		}
	}
	return junos
}

// rowOf is the row of the device registered as name.
func (e *enroll) rowOf(name string) *enrollRow {
	for _, r := range e.rows {
		if r.Registered && strings.EqualFold(r.Name, name) {
			return r
		}
	}
	return nil
}

// offer is stage 4: the Junos devices whose plan has a change are named and
// one question offers the apply review, which then asks each device's name
// (D265). With --json, or without a terminal, the chain ends at the plan.
func (e *enroll) offer(junos []devreg.Entry) int {
	inv := e.inv
	if len(junos) == 0 {
		return 0
	}
	names := make([]string, len(junos))
	for i, ent := range junos {
		names[i] = ent.Name
	}
	list := strings.Join(names, ",")
	switch {
	case e.asJSON:
		inv.stderrLine("The apply review is not offered with --json; run: tacctl device config apply " + list)
		return 0
	case !e.tty:
		inv.stderrLine("The apply review needs a terminal; run: tacctl device config apply " + list)
		return 0
	}
	inv.echo("")
	got, ok, interrupted := inv.askLine("Run the apply review for " + strings.Join(names, ", ") +
		" now (the plan is checked on each device, then each is confirmed on its own)? [y/N] ")
	switch {
	case interrupted:
		e.interrupted = true
		return batch.ExitInterrupted
	case !ok || (strings.ToLower(got) != "y" && strings.ToLower(got) != "yes"):
		e.apply = "declined"
		return 0
	}
	e.apply = "run"
	return e.applyReview(junos, list)
}

// applyReview runs 'device config apply' over the Junos devices with the
// run's one password: Phase A, the per-device review, Phase B.
func (e *enroll) applyReview(junos []devreg.Entry, list string) int {
	inv := e.inv
	usage := "Usage: tacctl device config " + deviceConfigUse("apply")
	p, err := Parse(deviceConfigSpecs["apply"], []string{list})
	if err != nil {
		return batch.ExitFailed
	}
	aa, err := inv.applyArgsOf(p)
	if err != nil {
		return batch.ExitFailed
	}
	render := inv.newManagedRender(aa.pull.render, true)
	render.prepare(junos)
	chosen := &chosenDevices{entries: junos, render: render}
	ctl := inv.newApplyCtl(e.user, aa, chosen, e.pass.src, usage)
	defer close(ctl.run.holdDone)
	ctl.run.password = e.pass.password
	err = ctl.run2(junos)
	ctl.run.password = ""
	for _, o := range ctl.rows {
		r := e.rowOf(o.Name)
		if r == nil {
			continue
		}
		switch w := o.word(); {
		case w == "applied" || w == "applied-by-other":
			r.Result, r.next = enrollApplied, ""
		case w == "no-change":
			r.Result, r.next = enrollPlanned, ""
		case w == "skipped" && (o.Skipped == notApprovedWrong || o.Skipped == notApprovedEOF):
			r.Result, r.Reason = enrollDeclined, o.Skipped
		case w == "skipped":
			r.Reason = o.Skipped
		default:
			r.Result, r.Reason = enrollFailed, "the apply: "+w+": "+cleanLine(o.reason())
		}
	}
	if exitStatus(err) == batch.ExitInterrupted {
		e.interrupted = true
		return batch.ExitInterrupted
	}
	return 0
}

// keyWord is the KEY cell.
func (r *enrollRow) keyWord() string { return dash(r.Key) }

// summary is the table and, under it, the next step of every device that did
// not reach the end of its chain (standard error with --json).
func (e *enroll) summary(code int) {
	inv := e.inv
	out := inv.app.Out.Stdout
	if e.asJSON {
		out = inv.app.Out.Stderr
	}
	pf := func(s string) { _, _ = fmt.Fprintln(out, s) }
	pf("")
	t := ui.NewTable(fmt.Sprintf("Enrolled %d address(es)", len(e.rows)), ui.Left("ADDRESS"), ui.Left("NAME"), ui.Left("VENDOR"),
		ui.Left("KEY"), ui.Left("PULL"), ui.Left("PLAN"), ui.Left("RESULT"))
	for _, r := range e.rows {
		pull, pl := r.Pull, r.Plan
		if r.Result == enrollOther {
			pull, pl = "-", "-"
		}
		t.Add(r.Address, dash(r.Name), dash(r.Vendor), r.keyWord(), pull, pl, r.Result)
	}
	_, _ = fmt.Fprint(out, t.String())
	pf("")
	for _, r := range e.rows {
		var parts []string
		if r.RenamedFrom != "" {
			parts = append(parts, "renamed "+r.RenamedFrom+" -> "+r.Name+" (the device's configured name)")
		}
		if r.RenameKept != "" {
			kept := "kept " + r.Name + ": " + r.RenameKept
			if r.keptLine != "" {
				kept += " (" + r.keptLine + ")"
			}
			parts = append(parts, kept)
		}
		if r.Reason != "" {
			parts = append(parts, r.Result+": "+r.Reason)
		}
		if r.Result == enrollOther {
			parts = append(parts, "registered as other: set the vendor with tacctl device vendor "+r.Name+" <vendor> (or --from-device), then pull")
		} else if r.next != "" {
			parts = append(parts, "next: "+r.next)
		}
		for _, p := range parts {
			pf("  " + r.Address + ": " + p)
		}
	}
	switch {
	case code == batch.ExitInterrupted:
		pf("  Interrupted: the devices registered stay registered; each row says what it still needs.")
	case e.apply == "declined":
		pf("  The apply review was not run; each device it was offered for: tacctl device config apply <name>.")
	}
	pf("")
}

// audit is one line per address (D269): the person, the address, the name,
// the vendor and where it came from, the result. Never a password, a key
// value or a device's text.
func (e *enroll) audit() {
	for _, r := range e.rows {
		e.inv.app.Audit().Line(audit.Info, "device enroll", kvp("user", e.user), kvp("addr", r.Address), kvp("device", orWord(r.Name, "-")),
			kvp("vendor", orWord(r.Vendor, "-")), kvp("source", orWord(r.VendorSource, "-")), kvp("result", r.Result))
	}
}

// enrollJSON is one address in --json (D272).
type enrollJSON struct {
	Address      string       `json:"address"`
	Name         string       `json:"name,omitempty"`
	Vendor       string       `json:"vendor,omitempty"`
	VendorSource string       `json:"vendor_source,omitempty"`
	HostKey      *enrollKeyJS `json:"host_key,omitempty"`
	Key          string       `json:"key"`
	Registered   bool         `json:"registered"`
	RenamedFrom  string       `json:"renamed_from,omitempty"`
	RenameKept   string       `json:"rename_kept,omitempty"`
	Pull         string       `json:"pull"`
	Plan         string       `json:"plan"`
	Result       string       `json:"result"`
	Reason       string       `json:"reason,omitempty"`
	Next         string       `json:"next,omitempty"`
}

// enrollKeyJS is the key accepted: its algorithm and fingerprint.
type enrollKeyJS struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// printJSON prints the object of the run, after the pull's and the plan's.
func (e *enroll) printJSON(code int) {
	out := struct {
		Login   string       `json:"login"`
		Devices []enrollJSON `json:"devices"`
		Apply   string       `json:"apply"`
		Exit    int          `json:"exit"`
	}{Login: "own", Devices: []enrollJSON{}, Apply: e.apply, Exit: code}
	for _, r := range e.rows {
		j := enrollJSON{Address: r.Address, Name: r.Name, Vendor: r.Vendor, VendorSource: r.VendorSource, Key: orWord(r.Key, "not-tried"),
			Registered: r.Registered, RenamedFrom: r.RenamedFrom, RenameKept: r.RenameKept, Pull: r.Pull, Plan: r.Plan,
			Result: r.Result, Reason: r.Reason, Next: r.next}
		if r.key.Type != "" {
			j.HostKey = &enrollKeyJS{Type: r.key.Type, Fingerprint: r.key.Fingerprint()}
		}
		if r.Result == enrollOther {
			j.Next = ""
		}
		out.Devices = append(out.Devices, j)
	}
	b, _ := json.Marshal(out)
	_, _ = e.out.Write(append(b, '\n'))
}
