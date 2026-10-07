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

	"github.com/rett/tacctl/internal/devreg"
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

// scanKeys reads the keys at addr; a device that does not answer is the
// refusal that names it, ending with what to do (orElse).
func (inv *invocation) scanKeys(addr string, port int, legacy bool, orElse ...string) ([]devreg.HostKey, error) {
	keys, err := devreg.Scan(inv.ctx, inv.app.Runner, addr, port, legacy)
	if errors.Is(err, devreg.ErrNoAnswer) {
		return nil, inv.usageErr(append([]string{"No ssh host key could be read from " + addr + " port " + strconv.Itoa(port) +
			" (ssh-keyscan); nothing was changed."}, orElse...)...)
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
// --no-host-key.
func (inv *invocation) deviceAddKeys(d devreg.Device, p Parsed, retry string) (pin, offered []devreg.HostKey, err error) {
	if p.Has("--no-host-key") {
		return nil, nil, nil
	}
	offered, err = inv.scanKeys(d.Address, d.SSHPort(), d.LegacySSH,
		"Check the address and the port, or register it without a pinned key: "+retry)
	if err != nil {
		return nil, nil, err
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
		inv.echo("  Host key pinned (it matches --host-key):")
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
		return err
	}
	a.Logger(inv.ctx, "auth.info", "device hostkey "+action+" name="+name+" keys="+strconv.Itoa(len(want))+" by="+inv.sudoUser())
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
		a.Logger(ctx, "auth.warning", "host hostkey-mismatch name="+name+" host="+host+" port="+strconv.Itoa(port))
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
