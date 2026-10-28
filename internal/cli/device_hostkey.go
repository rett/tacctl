package cli

// Host-key pinning on the command line (docs/plans/operator-console.md
// 3.7): 'device add' scans and pins (deviceAddKeys), 'device hostkey <name>
// show|accept|set' shows and re-pins, and 'host enroll'/'host sync' pin an
// enrolled host once (pinHostKeys, handed to the hosts package). Every pin
// is written through the registry's Mutate, which regenerates the
// known_hosts that 'tacctl ssh' checks against.

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/hosts"
)

// scanTarget is the address or host, port and legacy flag a scan of e
// uses: a device's registered address, an enrolled host's ssh target. ok
// is false for a host enrolled with --local.
func scanTarget(e devreg.Entry) (addr string, port int, legacy, ok bool) {
	if e.Source == devreg.SourceHost {
		h, p, ok := hosts.ScanTarget(e.Target, strconv.Itoa(e.SSHPort()))
		return h, p, false, ok
	}
	return e.Address, e.SSHPort(), e.LegacySSH, true
}

// realKeyFallback is the host-key scan of a legacy-ssh device that
// ssh-keyscan read nothing from (hooks.keyFallback replaces it in tests):
// tacctl's own ssh client, which negotiates the SHA-1 key exchange and CBC
// ciphers old IOS needs and stops at the host key, before any authentication
// (devssh.ScanHostKeys). It dials as the device sessions do, so the tests'
// dial override applies.
func realKeyFallback(inv *invocation) devreg.KeyFallback {
	dial := inv.deviceDialer()
	return func(ctx context.Context, address string, port int) ([]devreg.HostKey, error) {
		texts, err := devssh.ScanHostKeys(ctx, address, port, devssh.DefaultConnectTimeout, dial)
		if err != nil {
			return nil, err
		}
		return devreg.ParseHostKeys(texts), nil
	}
}

// scanDevice reads the host keys of a device or host at addr: ssh-keyscan,
// and for a legacy-ssh device the built-in client when that reads nothing.
func (inv *invocation) scanDevice(addr string, port int, legacy bool) ([]devreg.HostKey, error) {
	return devreg.ScanWith(inv.ctx, inv.app.Runner, addr, port, legacy, inv.hooks.scanFallback(inv))
}

// scanLearningLegacy is the scan of 'device enroll' and 'device collect', which
// find out whether a device needs legacy-ssh: ssh-keyscan alone (with its
// one-type retry, without the built-in client) first, so that a device only
// the built-in client reads is not mistaken for a modern one, then the legacy
// scan (the built-in client among it). legacy is whether the keys came from
// the legacy scan; a device neither reads is the first scan's error.
func (inv *invocation) scanLearningLegacy(addr string, port int) (keys []devreg.HostKey, legacy bool, err error) {
	keys, err = devreg.ScanWith(inv.ctx, inv.app.Runner, addr, port, false, nil)
	if errors.Is(err, devreg.ErrNoAnswer) && inv.ctx.Err() == nil {
		if k2, err2 := inv.scanDevice(addr, port, true); err2 == nil && len(k2) > 0 {
			return k2, true, nil
		}
	}
	return keys, false, err
}

// scanKeys reads the keys at addr; a device that does not answer is the
// refusal that names it, ending with what to do (orElse).
func (inv *invocation) scanKeys(addr string, port int, legacy bool, orElse ...string) ([]devreg.HostKey, error) {
	keys, err := inv.scanDevice(addr, port, legacy)
	if errors.Is(err, devreg.ErrNoAnswer) {
		tried := " (ssh-keyscan)"
		if legacy {
			tried = " (ssh-keyscan, and tacctl's own ssh client for legacy-ssh)"
		}
		return nil, inv.usageErr(append([]string{"No ssh host key could be read from " + addr + " port " + strconv.Itoa(port) +
			tried + "; nothing was changed."}, orElse...)...)
	}
	if err != nil && inv.ctx.Err() == nil {
		return nil, inv.usageErr(append(msgs(err), orElse...)...)
	}
	return keys, err
}

func msgs(err error) []string {
	var lines interface{ Lines() []string }
	if errors.As(err, &lines) {
		return lines.Lines()
	}
	return []string{err.Error()}
}

// echoKeys prints keys, one per line, indented.
func (inv *invocation) echoKeys(indent string, keys []devreg.HostKey) {
	for _, k := range keys {
		inv.echo(indent + k.Display())
	}
}

// --- device add --------------------------------------------------------------------

// deviceAddKeys scans the device add registers and picks the keys to pin:
// every key it offers, or with --host-key only the key of that
// fingerprint (the others were not verified). nil keys with a nil error is
// --no-host-key. trusted are keys the caller scanned already ('device
// enroll', 'collect', 'onboard', which pass the key accepted as --host-key):
// they stand for the scan.
func (inv *invocation) deviceAddKeys(d devreg.Device, p Parsed, retry string, trusted []devreg.HostKey) (pin, offered []devreg.HostKey, err error) {
	if p.Has("--no-host-key") {
		return nil, nil, nil
	}
	if trusted != nil {
		offered = trusted
	} else {
		offered, err = inv.scanKeys(d.Address, d.SSHPort(), d.LegacySSH,
			"Check the address and the port, or register it without a pinned key: "+retry)
		if err != nil {
			return nil, nil, err
		}
	}
	if !p.Has("--host-key") {
		return offered, offered, nil
	}
	fp := p.Value("--host-key")
	k, ok := devreg.MatchFingerprint(offered, fp)
	if !ok {
		lines := []string{"No host key " + d.Address + " offers matches " + fp + "; nothing was registered.", "It offers:"}
		for _, o := range offered {
			lines = append(lines, "  "+o.Display())
		}
		lines = append(lines, "Check the fingerprint on the device console: "+devreg.VerifyHint(d.Vendor)+".")
		return nil, nil, inv.usageErr(lines...)
	}
	return []devreg.HostKey{k}, offered, nil
}

// deviceAddReport prints what was pinned at registration.
func (inv *invocation) deviceAddReport(d devreg.Device, p Parsed, pin, offered []devreg.HostKey) {
	switch {
	case len(pin) == 0:
		return
	case p.Has("--host-key"):
		if inv.keyAccepted {
			inv.echo("  Host key pinned (the key you accepted):")
		} else {
			inv.echo("  Host key pinned (it matches --host-key):")
		}
		inv.echoKeys("    ", pin)
		if len(offered) > len(pin) {
			var rest []devreg.HostKey
			for _, k := range offered {
				if k != pin[0] {
					rest = append(rest, k)
				}
			}
			inv.echo("  Also offered, not pinned (unverified); after checking them: tacctl device hostkey " + d.Name + " accept")
			inv.echoKeys("    ", rest)
		}
	default:
		inv.echo("  Host keys pinned (" + strconv.Itoa(len(pin)) + "); compare with the device console before first use:")
		inv.echoKeys("    ", pin)
		inv.echo("  On the device: " + devreg.VerifyHint(d.Vendor) + ".")
		inv.echo("  If they differ, do not connect; verify and re-pin: tacctl device hostkey " + d.Name + " accept")
	}
}

// --- the acceptance of one device's key (0.2.17 D262) ------------------------------

// hostKeyAnswer is how a person answered the acceptance of a host key.
type hostKeyAnswer string

const (
	// keyAccepted: the device's name was typed back (or --host-key named the
	// key).
	keyAccepted hostKeyAnswer = "accepted"
	// keySkipped: Enter, or the end of input: the device is left alone.
	keySkipped hostKeyAnswer = "skipped"
	// keyRefused: an answer that is not the device's name, a name the rules
	// refuse, or a --host-key the device does not offer.
	keyRefused hostKeyAnswer = "refused"
	// keyInterrupted: a Ctrl-C came at the question; no line is written.
	keyInterrupted hostKeyAnswer = "interrupted"
)

// hostKeyResult is the answer of acceptHostKey: the key to pin, the name the
// answer carries (the one shown, or the one typed), the answer and, for a
// skip or a refusal, why in words.
type hostKeyResult struct {
	key    devreg.HostKey
	name   string
	answer hostKeyAnswer
	reason string
	// eof: the input ended at the question (a skip).
	eof bool
}

// pinnedKey is the one key of offered that a person compares and accepts:
// the first in devreg's type order (ssh-ed25519, the ECDSA curves, ssh-rsa),
// whatever order offered is in. ok is false when nothing is offered.
func pinnedKey(offered []devreg.HostKey) (devreg.HostKey, bool) {
	keys := devreg.SortKeys(offered)
	if len(keys) == 0 {
		return devreg.HostKey{}, false
	}
	return keys[0], true
}

// showHostKey prints the one key that will be pinned, the others offered,
// and how to see the key on the device's console: the vendor's command, or
// every vendor's when the vendor is not known yet. pinned: the device has
// pinned keys already and nothing new is pinned ('device onboard' of a device
// an earlier onboard registered): the key is the one to check.
func (inv *invocation) showHostKey(addr string, port int, vendor string, pin devreg.HostKey, offered []devreg.HostKey, pinned bool) {
	where := addr
	if port != 0 && port != devssh.DefaultPort {
		where += " port " + strconv.Itoa(port)
	}
	inv.echo("  " + where + " offers:")
	if pinned {
		inv.echo("    Key to check:  " + pin.Display())
	} else {
		inv.echo("    Will pin:  " + pin.Display())
	}
	var rest []devreg.HostKey
	for _, k := range devreg.SortKeys(offered) {
		if k != pin {
			rest = append(rest, k)
		}
	}
	switch {
	case len(rest) > 0 && pinned:
		inv.echo("    Also offered:")
		inv.echoKeys("      ", rest)
	case len(rest) > 0:
		inv.echo("    Also offered, not pinned (unverified):")
		inv.echoKeys("      ", rest)
	}
	if vendor != "" && vendor != devreg.VendorOther {
		inv.echo("    On the device: " + devreg.VerifyHint(vendor) + ".")
		return
	}
	inv.echo("    On the device:")
	for _, v := range sortedVendors() {
		inv.echo("      " + devreg.VerifyHint(v) + ".")
	}
}

// acceptHostKey shows the one key of a device that would be pinned (the first
// of offered in type order) and asks the one question that accepts it: the
// person compares the key with the device's console and types the device's
// name back. When name is known (the device's own, read by SNMP), that name
// accepts the key; when it is not, the name typed is the name the device is
// registered as, checked by check. Enter (or the end of input) skips the
// device; any other answer refuses it, with no second try. Nothing is ever
// typed or pasted from a fingerprint, and there is no answer for several
// devices. It writes no line: the caller writes hostKeyLine for every
// answer but an interrupted one.
func (inv *invocation) acceptHostKey(addr string, port int, vendor, name string, offered []devreg.HostKey, check func(string) error) hostKeyResult {
	return inv.askHostKey(keyQuestion{addr: addr, port: port, vendor: vendor, name: name, offered: offered, check: check,
		then: "register it", skip: "skip the device"})
}

// keyQuestion is one acceptance's question (0.2.17 D262, D270): the device,
// the keys it offers, the answer that accepts the key (name, or with none
// the name check accepts), and the question's words: what accepting leads to
// (then; thenNew when the name typed is a new one: enroll says nothing more,
// the name registers it), what Enter does (skip), and, when the answer is
// the device's address rather than a name ('device collect' of a device
// that gives no name), byAddress; pinned when the device has pinned keys
// already and nothing new is pinned (showHostKey).
type keyQuestion struct {
	addr      string
	port      int
	vendor    string
	name      string
	offered   []devreg.HostKey
	check     func(string) error
	then      string
	thenNew   string
	skip      string
	byAddress bool
	pinned    bool
}

// askHostKey is acceptHostKey with the question's words of the verb that asks
// it: 'device enroll', 'device collect' and 'device onboard' ask the same
// question, accepted by the same answer.
func (inv *invocation) askHostKey(kq keyQuestion) hostKeyResult {
	addr, name := kq.addr, kq.name
	pin, ok := pinnedKey(kq.offered)
	if !ok {
		return hostKeyResult{answer: keyRefused, reason: "no ssh host key could be read"}
	}
	inv.showHostKey(addr, kq.port, kq.vendor, pin, kq.offered, kq.pinned)
	what, wrong := "the device name ("+name+")", "the answer typed is not the device's name"
	if kq.byAddress {
		what, wrong = "the address ("+name+")", "the answer typed is not the device's address"
	}
	q := "  Compare the key with the console of " + addr + ". Type " + what + " to accept it and " + kq.then + ", or press Enter to " + kq.skip + ": "
	if name == "" {
		q = "  Compare the key with the console of " + addr + ". Type the name to register it as to accept it" + kq.thenNew + ", or press Enter to " + kq.skip + ": "
	}
	check := kq.check
	got, ok, interrupted := inv.askLine(q)
	r := hostKeyResult{key: pin}
	switch {
	case interrupted:
		r.answer = keyInterrupted
	case !ok:
		r.answer, r.reason, r.eof = keySkipped, "not accepted (no answer: the input ended)", true
	case got == "":
		r.answer, r.reason = keySkipped, "not accepted"
	case name != "" && got != name:
		r.answer, r.reason = keyRefused, wrong
	case name != "":
		r.answer, r.name = keyAccepted, name
	default:
		// check's text names the rule, never what was typed
		if err := check(got); err != nil {
			r.answer, r.reason = keyRefused, strings.Join(msgs(err), " ")
			break
		}
		r.answer, r.name = keyAccepted, got
	}
	return r
}

// hostKeyLine is the audit line of one answer to a host-key acceptance (0.2.17
// D262), at auth.notice, written before anything uses the key: the person,
// the address, the device's name ('-' before one is known), the algorithm and
// the fingerprint (public values), the answer and where it came from
// (confirmed: typed at the terminal; flag: --host-key). verb is the command's
// words. It returns why the line was not written ("" when it was).
func (inv *invocation) hostKeyLine(verb, user, addr, device string, key devreg.HostKey, answer hostKeyAnswer, source string) string {
	alg, fp := "-", "-"
	if key.Type != "" {
		alg, fp = key.Type, key.Fingerprint()
	}
	return inv.app.Audit().Line(audit.Notice, verb+" hostkey", kvp("user", user), kvp("addr", addr), kvp("device", orWord(device, "-")),
		kvp("alg", alg), kvp("fp", fp), kvp("result", string(answer)), kvp("source", source))
}

// --- device hostkey -----------------------------------------------------------------

func (inv *invocation) deviceHostkey(args []string) error {
	p, err := inv.deviceParse("hostkey", args)
	if err != nil {
		return err
	}
	action := "show"
	if len(p.Args) > 1 {
		action = p.Args[1]
	}
	usage := "Usage: tacctl device hostkey <name> [show|accept [-y]|set SHA256:<fingerprint>]"
	switch {
	case action == "set" && len(p.Args) != 3:
		return inv.usageErr("'set' needs the fingerprint to pin: SHA256:<fingerprint> as ssh prints it.", usage)
	case action != "set" && len(p.Args) > 2:
		return inv.usageErr("Unknown argument: '"+p.Args[2]+"'", usage)
	case action != "show" && action != "accept" && action != "set":
		return inv.usageErr("Unknown action: '"+action+"'", usage)
	case action == "set" && !devreg.ValidFingerprint(p.Args[2]):
		return inv.usageErr("Invalid fingerprint '" + p.Args[2] + "': expected SHA256:<fingerprint> as ssh prints it.")
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, p.Args[0])
	if err != nil {
		return err
	}
	// A host's pins are the superuser's: 'host sync' pins and checks them,
	// so an engineer, who deploys no host, is told it is not found.
	if e.Source == devreg.SourceHost && inv.callerScopes().restricted {
		return inv.deniedUsage(reasonSuperuser, "Device '"+p.Args[0]+"' not found. List them with: tacctl device list")
	}
	pinned := devreg.ParseHostKeys(e.HostKeys)
	if action == "show" {
		inv.echo("")
		if len(pinned) == 0 {
			inv.echo("  No host key is pinned for '" + e.Name + "'.")
			inv.echo("  Pin what it offers after checking on its console: tacctl device hostkey " + e.Name + " accept")
		} else {
			inv.echo("  Host keys pinned for '" + e.Name + "':")
			for _, k := range pinned {
				inv.echo("    " + k.Display())
				inv.echo("             " + k.String())
			}
		}
		inv.echo("  On the device: " + devreg.VerifyHint(e.Vendor) + ".")
		inv.echo("")
		return nil
	}
	addr, port, legacy, ok := scanTarget(e)
	if !ok {
		return inv.usageErr("'" + e.Name + "' is this server (enrolled with --local); there is no ssh host key to pin.")
	}
	offered, err := inv.scanKeys(addr, port, legacy, "Check that it is up and that ssh listens on port "+strconv.Itoa(port)+".")
	if err != nil {
		return err
	}
	a := inv.app
	want := offered
	if action == "set" {
		k, ok := devreg.MatchFingerprint(offered, p.Args[2])
		if !ok {
			lines := []string{"No host key '" + e.Name + "' (" + addr + ") offers matches " + p.Args[2] + "; the pin was not changed.", "It offers:"}
			for _, o := range offered {
				lines = append(lines, "  "+o.Display())
			}
			return inv.usageErr(lines...)
		}
		want = []devreg.HostKey{k}
	}
	if devreg.KeysEqual(e.HostKeys, want) {
		a.Out.Info("The keys pinned for '" + e.Name + "' are already these; nothing was changed.")
		inv.echoKeys("    ", want)
		return nil
	}
	inv.echo("")
	if len(pinned) > 0 {
		inv.echo("  Pinned now:")
		inv.echoKeys("    ", pinned)
	} else {
		inv.echo("  Pinned now: none")
	}
	inv.echo("  To pin (offered by " + addr + " port " + strconv.Itoa(port) + "):")
	inv.echoKeys("    ", want)
	inv.echo("  On the device: " + devreg.VerifyHint(e.Vendor) + ".")
	inv.echo("")
	if action == "accept" && !p.Has("-y") &&
		!a.Prompter().ConfirmPrefix("  Pin these keys? Only if they match the device console. [y/N]: ") {
		a.Out.Info("Aborted; the pin was not changed.")
		return nil
	}
	name, src := e.Name, e.Source
	hostkeyBase := "device hostkey " + action + " name=" + name + " keys=" + strconv.Itoa(len(want)) + " by=" + inv.sudoUser()
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		if src == devreg.SourceHost {
			f.SetHostKeys(name, devreg.KeyStrings(want))
			return nil
		}
		d := f.Find(name)
		if d == nil {
			return inv.usageErr("Device '" + name + "' not found.")
		}
		d.HostKeys = devreg.KeyStrings(want)
		return nil
	}); err != nil {
		inv.verbResult(audit.Info, hostkeyBase, failReason(err, "store"))
		return err
	}
	inv.verbResult(audit.Info, hostkeyBase, "")
	a.Out.Info("Pinned " + strconv.Itoa(len(want)) + " host key(s) for '" + name + "'.")
	return nil
}

// --- enrolled hosts -----------------------------------------------------------------

// pinHostKeys is the hosts.KeyPinner of 'host enroll' and 'host sync'.
// session is the host's own public keys, read over the enrolment's
// authenticated ssh connection (the administrator's ssh, which checked the
// host against their known_hosts). A host with nothing pinned gets only the
// keys that read and an ssh-keyscan of the target agree on: a key type the
// two give different keys for refuses the pin (both sets are printed and
// logged), a type only one of them has is reported and not pinned. A
// pinned host is only checked against the session's keys (a changed key or
// a new key type is reported, the pin stays). Every problem is a warning;
// the enrolment or sync itself has succeeded. A first pin only adds to the
// registry, so it takes no snapshot (a 'host sync --all' would take one per
// host).
func (inv *invocation) pinHostKeys(ctx context.Context, name, host string, port int, session []byte, sessionErr error) {
	a := inv.app
	fix := "Check on the host (" + devreg.VerifyHint(devreg.VendorLinux) + "), then: tacctl device hostkey " + name + " accept"
	var own []devreg.HostKey
	if sessionErr == nil {
		own = devreg.ParsePubKeys(session)
	}
	if len(own) == 0 {
		why := "no key in /etc/ssh/ssh_host_*_key.pub"
		if sessionErr != nil {
			why, _, _ = strings.Cut(sessionErr.Error(), "\n")
		}
		a.Out.WarnE(name + ": the host's ssh keys could not be read over the enrolment session (" + why + "); none pinned or checked.")
		a.Out.WarnE("  " + fix)
		return
	}
	f, err := devreg.Load(a.Paths.DevicesFile)
	if err != nil {
		a.Out.WarnE(name + ": host keys not pinned: " + strings.Join(msgs(err), " "))
		return
	}
	pinned := f.HostKeysOf(name)
	if len(pinned) > 0 {
		c := devreg.Compare(pinned, own)
		switch devreg.HostPinAction(pinned, own) {
		case devreg.PinChanged:
			a.Out.WarnE(name + ": the ssh host key differs from the one pinned; the pin was not changed.")
			a.Out.WarnE("  Pinned: " + devreg.Displays(devreg.ParseHostKeys(pinned)))
			a.Out.WarnE("  On the host: " + devreg.Displays(own))
			a.Out.WarnE("  " + fix)
		case devreg.PinAdded:
			a.Out.InfoE(name + ": has host key types that are not pinned (" + devreg.Displays(c.Added) +
				"); after checking them on the host: tacctl device hostkey " + name + " accept")
		}
		return
	}
	scan, err := devreg.Scan(ctx, a.Runner, host, port, false)
	if errors.Is(err, devreg.ErrNoAnswer) {
		a.Out.WarnE(name + ": no ssh host key could be read from " + host + " port " + strconv.Itoa(port) +
			" (ssh-keyscan) to check the session's against; none pinned.")
		a.Out.WarnE("  " + fix)
		return
	}
	if err != nil {
		if ctx.Err() == nil {
			a.Out.WarnE(name + ": host keys not pinned: " + strings.Join(msgs(err), " "))
		}
		return
	}
	c := devreg.CrossCheckKeys(own, scan)
	if c.Conflict {
		a.Audit().Raw("auth.warning", "host hostkey-mismatch name="+name+" host="+host+" port="+strconv.Itoa(port)+" by="+inv.sudoUser())
		a.Out.WarnE(name + ": the keys the host holds and the keys offered at " + host + " port " + strconv.Itoa(port) +
			" differ; nothing was pinned.")
		a.Out.WarnE("  Read over the enrolment session: " + devreg.Displays(own))
		a.Out.WarnE("  Offered to ssh-keyscan:          " + devreg.Displays(scan))
		a.Out.WarnE("  Something may stand between this server and the host. " + fix +
			" (or: tacctl device hostkey " + name + " set SHA256:<fingerprint>)")
		return
	}
	if len(c.OnlySession) > 0 {
		a.Out.InfoE(name + ": not offered to ssh-keyscan, not pinned: " + devreg.Displays(c.OnlySession))
	}
	if len(c.OnlyScan) > 0 {
		a.Out.InfoE(name + ": offered but not among the host's key files, not pinned: " + devreg.Displays(c.OnlyScan))
	}
	if len(c.Agreed) == 0 {
		a.Out.WarnE(name + ": the session and ssh-keyscan agree on no key; none pinned.")
		a.Out.WarnE("  " + fix)
		return
	}
	_, err = devreg.Mutate(a.Paths.DevicesFile, a.Paths.KnownHosts, nil, func(f *devreg.File) error {
		if len(f.HostKeysOf(name)) == 0 {
			f.SetHostKeys(name, devreg.KeyStrings(c.Agreed))
		}
		return nil
	})
	if err != nil {
		a.Out.WarnE(name + ": host keys not pinned: " + strings.Join(msgs(err), " "))
		return
	}
	a.Out.InfoE(name + ": pinned " + strconv.Itoa(len(c.Agreed)) + " ssh host key(s) for 'tacctl ssh': " + devreg.Displays(c.Agreed))
}

// forgetHostKeys drops what the registry holds of an unenrolled host: its
// pinned keys and its address (no snapshot: they mean nothing without the
// host).
func (inv *invocation) forgetHostKeys(name string) {
	a := inv.app
	f, err := devreg.Load(a.Paths.DevicesFile)
	if err != nil || f.Host(name) == nil {
		return
	}
	if _, err := devreg.Mutate(a.Paths.DevicesFile, a.Paths.KnownHosts, nil, func(f *devreg.File) error {
		f.ForgetHost(name)
		return nil
	}); err != nil {
		a.Out.WarnE(name + ": its pinned host keys and address could not be removed: " + strings.Join(msgs(err), " "))
	}
}
