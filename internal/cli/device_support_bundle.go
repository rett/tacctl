package cli

// 'device support-bundle <name> [--vendor cisco|juniper|wti] [--login
// <local-user>] [--out <dir>]': what a developer needs of a device to make
// tacctl read it right, collected in one attended login and made safe to
// share. A fixed list of read-only commands per vendor (Junos and IOS: the
// version, the hardware or inventory, the stack, the login's permissions or
// privilege, the commit history; a WTI unit: the screens its reader walks,
// without the user directory), the SNMP system group, none of the
// configuration. The text is scrubbed before it is written (internal/scrub):
// names, users, classes, addresses, serial numbers, locations, contacts and
// time zones become the standard example values (docs/development), secrets
// are removed, and what was replaced is kept apart in a private file beside
// the directory, never in it.
//
// The login is the one of 'device config pull': the caller's own TACACS+
// account with the password asked on the terminal, or with --login (Junos)
// the one-shot password of a local account. Nothing is kept.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/scrub"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// supportBundleUse is the usage line of the verb.
const supportBundleUse = "Usage: tacctl device support-bundle <name> [--vendor cisco|juniper|wti] [--login <local-user>] [--out <dir>]"

// bundleCommandTimeout is how long one command may take.
const bundleCommandTimeout = 30 * time.Second

// bundleCmd is one command of a vendor's list and the name its file gets.
type bundleCmd struct{ name, cmd string }

// bundleCommands are the read-only commands collected, per vendor. None of
// them prints the configuration.
var bundleCommands = map[string][]bundleCmd{
	devssh.VendorJuniper: {
		{"version", "show version | no-more"},
		{"version-all-members", "show version invoke-on all-routing-engines | no-more"},
		{"chassis-hardware", "show chassis hardware | no-more"},
		{"virtual-chassis", "show virtual-chassis | no-more"},
		{"chassis-cluster", "show chassis cluster status | no-more"},
		{"routing-engine", "show chassis routing-engine | no-more"},
		{"uptime", "show system uptime | no-more"},
		{"cli-authorization", "show cli authorization | no-more"},
		{"commit-history", "show system commit | no-more"},
		{"compare-rollback-0", "show configuration | compare rollback 0 | no-more"},
	},
	"cisco": {
		{"version", "show version"},
		{"inventory", "show inventory"},
		{"switch", "show switch"},
		{"module", "show module"},
		{"clock", "show clock"},
		{"privilege", "show privilege"},
		{"identity-lines", "show running-config | include ^(hostname|ip domain|clock timezone|snmp-server location|snmp-server contact)"},
	},
}

// bundleVendors are the vendors a bundle is made for.
var bundleVendors = []string{"cisco", devssh.VendorJuniper, "wti"}

// bundleFile is one file of a bundle, before and after scrubbing.
type bundleFile struct {
	name, text string
}

// deviceSupportBundle is 'device support-bundle'.
func (inv *invocation) deviceSupportBundle(args []string) error {
	p, err := Parse(deviceSpecs["support-bundle"], args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.argErr(msg, supportBundleUse)
	}
	if err := inv.deviceVerbAllowed("device", "support-bundle", tier.Engineer); err != nil {
		return err
	}
	vendorFlag := strings.ToLower(p.Value("--vendor"))
	if p.Has("--vendor") && !contains(bundleVendors, vendorFlag) {
		return inv.argErr("--vendor takes cisco, juniper or wti: '"+p.Value("--vendor")+"'", supportBundleUse)
	}
	var local *localLogin
	if p.Has("--login") {
		acct, err := inv.localAccountOf(p.Value("--login"), supportBundleUse)
		if err != nil {
			return err
		}
		if err := inv.localLoginGate(p, "support-bundle"); err != nil {
			return err
		}
		local = &localLogin{account: acct}
	}
	user, err := inv.configLogin("device support-bundle")
	if err != nil {
		return err
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, p.Args[0])
	if err != nil {
		return err
	}
	vendor := vendorFlag
	if vendor == "" {
		vendor = e.Vendor
	}
	switch {
	case e.Source == devreg.SourceHost:
		return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; a bundle is made of a network device.")
	case !contains(bundleVendors, vendor):
		return inv.usageErr("Device '"+e.Name+"' has vendor '"+e.Vendor+"', which has no command list.",
			"Name the vendor for this run: tacctl device support-bundle "+e.Name+" --vendor cisco|juniper|wti")
	case !e.Configured:
		return inv.usageErr("Device '"+e.Name+"' ("+dashAddrText(e.Address)+") is in no scope: no scope's prefixes cover its address.",
			"Add them with: tacctl scope prefixes <scope> add <cidr>")
	case local != nil && vendor != devssh.VendorJuniper:
		return inv.usageErr("--login is for Junos devices: '" + e.Name + "' is read as " + vendor + ". Nothing was sent.")
	case local != nil && len(e.HostKeys) == 0:
		return inv.usageErr("'"+e.Name+"' has no pinned host key, and a local password goes only to a device whose key was verified. Nothing was sent.",
			"Pin it after comparing it with the device console: tacctl device hostkey "+e.Name+" accept")
	}
	if local == nil {
		if m, merr := inv.model(); merr == nil {
			if msg := loginProblem(m, user, e.Scope); msg != "" {
				return inv.usageErr(msg + " (device " + e.Name + ")")
			}
		}
	}
	if _, held := inv.holdOf(e.Name, e.Address); held {
		return inv.usageErr(holdRefusal(e.Name))
	}
	dir, err := inv.bundleDir(p.Value("--out"))
	if err != nil {
		return err
	}

	account := user
	var pw devicePasswords
	var secret []byte
	if local != nil {
		account = local.account
		src := inv.hooks.newLocalPasswords(inv, local.account, e.Name+" ("+e.Address+")")
		defer src.Done()
		pw = src
	} else {
		pw = inv.hooks.newDevicePasswords(inv)
		if d, ok := pw.(interface{ Done() }); ok {
			defer d.Done()
		}
	}
	secret, err = pw.Password(inv.ctx, account)
	if err != nil {
		if errors.Is(err, ui.ErrInterrupted) {
			return err
		}
		return inv.usageErr("Cannot log in to " + e.Name + ": " + err.Error())
	}
	password := string(secret)
	askpass.Zero(secret)

	st := inv.deviceConfigSettings()
	ctx, cancel := context.WithTimeout(inv.ctx, 4*st.timeout)
	defer cancel()
	files, notes, err := inv.collectBundle(ctx, e, vendor, account, local, pw, password)
	password = ""
	if err != nil {
		return err
	}
	if sn := inv.bundleSNMP(e); sn != "" {
		files = append(files, bundleFile{"snmp-system-group", sn})
	}
	names, err := inv.writeBundle(dir, e, vendor, user, account, files, notes)
	if err != nil {
		return err
	}
	inv.app.Audit().Raw("auth.info", fmt.Sprintf("device support-bundle user=%s device=%s vendor=%s login=%s files=%d result=ok",
		user, e.Name, vendor, loginKind(local), names))
	return nil
}

func loginKind(l *localLogin) string {
	if l != nil {
		return devconf.LocalLoginPrefix + l.account
	}
	return "own"
}

// bundleDir is the directory the bundle is written to: --out, else a new one
// in the current directory named by the time, made absolute. Nothing may be at
// that path or at its private map's (<dir>.map): the bundle is written as the
// caller and never replaces anything.
func (inv *invocation) bundleDir(out string) (string, error) {
	if out == "" {
		out = "support-bundle-" + inv.app.Knobs.Now().UTC().Format("20060102-150405")
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", inv.usageErr("Cannot resolve '" + out + "': " + err.Error())
	}
	if abs == "/" {
		return "", inv.usageErr("--out names a directory to create, not '/'.")
	}
	for _, p := range []string{abs, abs + ".map"} {
		if _, err := os.Lstat(p); err == nil {
			return "", inv.usageErr("'" + p + "' exists: name a directory (--out) that does not exist yet, whose '.map' file does not exist either.")
		}
	}
	return abs, nil
}

// collectBundle logs in and runs the vendor's commands. A command that fails
// is recorded in its file and the next one runs; a session that is closed or
// timed out ends the list, the commands left being noted.
func (inv *invocation) collectBundle(ctx context.Context, e devreg.Entry, vendor, account string, local *localLogin, pw devicePasswords, password string) ([]bundleFile, []string, error) {
	src := func() (string, error) { return password, nil }
	if local != nil {
		src = local.sendOnce()
	}
	client, err := devssh.Dial(ctx, inv.deviceTarget(e, account, src))
	if err != nil {
		result, reason, hint := resultOf(ctx, e.Name, err)
		if errors.Is(err, devssh.ErrAuth) {
			pw.Rejected()
		}
		inv.app.Audit().Raw("auth.warning", "device support-bundle user="+inv.sudoUser()+" device="+e.Name+" result="+result)
		msg := "Cannot read " + e.Name + ": " + reason + "."
		if hint != "" {
			msg += " Run: " + hint
		}
		return nil, nil, inv.usageErr(msg)
	}
	defer func() { _ = client.Close() }()
	pw.Accepted()

	if vendor == "wti" {
		f, err := inv.collectWTI(ctx, client)
		return f, nil, err
	}
	var opts []devssh.CLIOption
	if local != nil {
		opts = local.cliOptions()
	}
	s, err := client.CLI(vendor, opts...)
	if err != nil {
		return nil, nil, inv.usageErr("Cannot open the command line of " + e.Name + ": " + shortReason(err))
	}
	defer func() { _ = s.Close() }()
	var files []bundleFile
	var notes []string
	for i, c := range bundleCommands[vendor] {
		cctx, cancel := context.WithTimeout(ctx, bundleCommandTimeout)
		out, err := s.Run(cctx, c.cmd)
		cancel()
		body := "# " + c.cmd + "\n" + out
		if err != nil {
			body += "\n# error: " + shortReason(err) + "\n"
			notes = append(notes, c.cmd+": "+shortReason(err))
		}
		files = append(files, bundleFile{fmt.Sprintf("%02d-%s", i+1, c.name), body})
		if err != nil && (ctx.Err() != nil || errors.Is(err, devssh.ErrClosed) || errors.Is(err, context.DeadlineExceeded)) {
			for _, rest := range bundleCommands[vendor][i+1:] {
				notes = append(notes, rest.cmd+": not run")
			}
			break
		}
	}
	return files, notes, nil
}

// collectWTI reads the unit's screens as the pull's reader walks them, with
// no user directory.
func (inv *invocation) collectWTI(ctx context.Context, c *devssh.Client) ([]bundleFile, error) {
	term, err := c.Terminal(ctx)
	if err != nil {
		return nil, inv.usageErr("Cannot open the unit's text interface: " + shortReason(err))
	}
	raw, _, err := devconf.ReadWTI(ctx, clientTerm{term, c}, devconf.WTIReadOptions{})
	if err != nil {
		return nil, inv.usageErr("Cannot read the unit's screens: " + shortReason(err))
	}
	return []bundleFile{{"01-wti-screens", "# the screens of the pull's read, without the user directory\n" + raw}}, nil
}

// bundleSNMP is the SNMP system group as text ("" when it cannot be read).
func (inv *invocation) bundleSNMP(e devreg.Entry) string {
	g, _ := inv.snmpGetterForAddr(e.Address)
	if g == nil {
		return ""
	}
	var b strings.Builder
	if id, err := g.SysIdentity(inv.ctx, e.Address); err == nil {
		fmt.Fprintf(&b, "sysObjectID.0: %s\nsysDescr.0: %s\n", id.ObjectID, strings.ReplaceAll(id.Descr, "\n", " | "))
	}
	if n, err := g.SysName(inv.ctx, e.Address); err == nil {
		fmt.Fprintf(&b, "sysName.0: %s\n", strings.TrimSpace(n))
	}
	if l, err := g.SysLocation(inv.ctx, e.Address); err == nil {
		fmt.Fprintf(&b, "sysLocation.0: %s\n", strings.TrimSpace(l))
	}
	return b.String()
}

// writeBundle scrubs the files and writes them with the README into dir and
// the map beside it. It returns the number of files. A text that still holds
// a real value after scrubbing refuses the bundle: nothing is written.
func (inv *invocation) writeBundle(dir string, e devreg.Entry, vendor, user, account string, files []bundleFile, notes []string) (int, error) {
	sc := scrub.New()
	sc.Learn(scrub.Addr4, e.Address)
	sc.Learn(scrub.Host, e.Name)
	if e.Hostname != "" {
		sc.Learn(scrub.Host, e.Hostname)
	}
	sc.Learn(scrub.User, user)
	sc.Learn(scrub.User, account)
	texts := make([]string, len(files))
	for i, f := range files {
		texts[i] = f.text
	}
	if sn := findFile(files, "snmp-system-group"); sn >= 0 {
		for _, l := range strings.Split(files[sn].text, "\n") {
			if v, ok := strings.CutPrefix(l, "sysName.0: "); ok {
				sc.Learn(scrub.Host, v)
			}
		}
	}
	clean := sc.ApplyAll(texts)
	for i, t := range clean {
		if leaks := sc.Leaks(t); len(leaks) > 0 {
			return 0, inv.usageErr(fmt.Sprintf("The scrubbed text of %s still holds %d value(s) it learned to replace; nothing was written.", files[i].name, len(leaks)))
		}
	}
	readme := fmt.Sprintf("tacctl support bundle\n\nCollected with tacctl %s on %s by an attended login.\nVendor: %s\n\n"+
		"Every name, user, class, address, serial number, location, contact and time zone in these files is an example value, and secrets are removed.\n"+
		"Read the files before you share them.\n\nCommands run (read only; the configuration itself is not collected):\n",
		inv.build.Version, inv.app.Knobs.Now().UTC().Format("2006-01-02 15:04 UTC"), vendor)
	if vendor == "wti" {
		readme += "  the screens of the unit's pull (without the user directory)\n"
	}
	for _, c := range bundleCommands[vendor] {
		readme += "  " + c.cmd + "\n"
	}
	readme += "  the SNMP system group, when SNMP is set up\n"
	if len(notes) > 0 {
		readme += "\nNot answered:\n"
		for _, n := range notes {
			readme += "  " + sc.Apply(n) + "\n"
		}
	}
	mapPath := dir + ".map"
	var mb strings.Builder
	mb.WriteString("# What was replaced in " + filepath.Base(dir) + ": kind, real value, example. PRIVATE: keep this file out of the bundle and out of every repository.\n")
	for _, pr := range sc.Pairs() {
		mb.WriteString(string(pr.Kind) + "\t" + pr.Real + "\t" + pr.Example + "\n")
	}
	// Everything is created as the caller (what a lower tier names is never
	// written with root's rights), new files only, a symbolic link never
	// followed; a failure takes back what was made.
	var made []string
	err := inv.asCaller(func() error {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
		made = append(made, dir)
		create := func(path, text string, mode os.FileMode) error {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
			if err != nil {
				return err
			}
			made = append(made, path)
			_, err = f.WriteString(text)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			return err
		}
		if err := create(filepath.Join(dir, "README.txt"), readme, 0o644); err != nil {
			return err
		}
		for i, f := range files {
			if err := create(filepath.Join(dir, f.name+".txt"), clean[i], 0o644); err != nil {
				return err
			}
		}
		return create(mapPath, mb.String(), 0o600)
	})
	if err != nil {
		_ = inv.asCaller(func() error {
			for i := len(made) - 1; i >= 0; i-- {
				_ = os.Remove(made[i])
			}
			return nil
		})
		return 0, inv.usageErr("Cannot write the bundle: " + err.Error() + ". Nothing was kept.")
	}
	inv.echo(fmt.Sprintf("Wrote %d files to %s (names, users, addresses, serial numbers and time zones are examples; secrets are removed).", len(files)+1, dir))
	inv.echo("Read them before you share them. What was replaced is in " + mapPath + " (private: it holds the real values).")
	return len(files) + 1, nil
}

func findFile(files []bundleFile, name string) int {
	for i, f := range files {
		if f.name == name {
			return i
		}
	}
	return -1
}
