package cli

// 'tacctl ssh <name>' (docs/plans/operator-console.md 5, and the plan of
// record's finding 1.3 a): a session to a registered device or an enrolled
// host, as the user who asked for it. The registry is root's, so the front
// door re-execs under sudo as for every root command; the root side
// resolves the name, admits only an active tacctl user whose scopes hold
// the entry's (every tier, superusers included), logs the session, and runs
// ssh as SUDO_USER with the terminal, logging in as SUDO_USER by password
// (no agent, no key, no other login), returning ssh's exit status. The
// shell and the console run the same line ('sudo -n tacctl ssh <name>'), so
// there is one path to audit. 'device ssh' is the same command.

import (
	"errors"
	"io"
	"os"
	"slices"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerFamily(sshCmd)
	registerSpecFunc("ssh", func(path []string) (Spec, bool) { return sshSpec, len(path) == 1 })
}

// sshSpec is the arguments of 'tacctl ssh' before '--' (what follows it is
// handed to ssh as it is).
var sshSpec = Spec{MaxArgs: 1, Args: []string{KindDevices}, Flags: []Flag{
	{Names: []string{"-p"}, Value: true},
}}

const (
	sshUse   = "ssh <name|address> [-p <port>] [-- <ssh args>]"
	sshShort = "Session to a registered device or enrolled host, as you (never root)"
)

func sshCmd(inv *invocation) *cobra.Command {
	return withRun(verb(sshUse, sshShort), inv.native(withPreflight, inv.ssh))
}

// sshUsage is the usage of 'tacctl ssh'.
func sshUsage() string {
	return "\n" + ui.Bold + "SSH to a Device" + ui.NC + `

Usage: tacctl ` + sshUse + `

Opens an ssh session to a registered device or an enrolled Linux host, named
by its name or its registered address ('tacctl device list'). ssh runs as you,
never as root, and logs in as you: your username, your tacctl password (public
keys and the agent are not used). The device's vendor profile applies
(legacy-ssh: the old IOS algorithms), and a device with pinned host keys is
held to them: a key that changed is refused, with the fingerprints to compare
and the command that re-pins it.

  -p <port>        Connect to <port> (default: the device's port, else 22)
  -- <ssh args>    Pass the rest to ssh for this session (a remote command)

Only active tacctl users reach a device, and only one in a scope of their own,
whatever their tier; a device no scope covers is reached by no one. Every
session is logged to syslog (auth.info).

Examples:
  tacctl ssh core-sw1
  tacctl ssh 10.99.0.1 -p 2222
  tacctl ssh core-sw1 -- show version

`
}

// sshTerminal reports whether stdin is a terminal; the Go tests replace it.
var sshTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// sshPlan is what 'tacctl ssh' resolved: the entry, where ssh connects
// and as whom, and the ssh command.
type sshPlan struct {
	entry  devreg.Entry
	target string
	port   int
	cmd    hosts.SSH
	args   []string
}

// ssh is 'tacctl ssh' and 'device ssh'.
func (inv *invocation) ssh(args []string) error {
	a := inv.app
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		inv.write(sshUsage())
		return nil
	}
	var extra []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, extra = args[:i], args[i+1:]
	}
	usage := "Usage: tacctl " + sshUse
	p, err := Parse(sshSpec, args)
	if err != nil {
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			return inv.usageErr("Unknown option: '"+uf.Flag+"' (pass ssh's own options after --)", usage)
		}
		return inv.usageErr(err.Error(), usage)
	}
	if len(p.Args) == 0 {
		return inv.usageErr("Name the device or host to connect to.", usage)
	}
	if p.Has("-p") {
		if _, err := devreg.ValidatePort(p.Value("-p")); err != nil {
			return err
		}
	}
	caller := a.Env.Get("SUDO_USER")
	if caller == "" || caller == "root" {
		return inv.usageErr("tacctl ssh runs ssh as the user who invoked it; run it from your own account, not as root")
	}
	if err := inv.verifySudoUser("tacctl ssh"); err != nil {
		return err
	}
	if !sshTerminal(a.Stdin) {
		return inv.usageErr("a terminal is required: tacctl ssh opens an interactive session")
	}
	plan, err := inv.sshResolve(p, caller, extra)
	if err != nil {
		return err
	}
	e := plan.entry
	addr := e.Address
	if addr == "" {
		addr = plan.target
	}
	a.Logger(inv.ctx, "auth.info", "ssh user="+caller+" device="+e.Name+" addr="+addr)
	code, _, startErr := hosts.Attached(inv.ctx, a.Runner, plan.cmd.Cmd(plan.args...), a.Stdin, a.Out)
	if startErr != nil {
		a.Out.Error("ssh could not be run (" + startErr.Error() + "); it comes with the openssh-client package.")
		if code == 0 {
			code = 127
		}
		return exit(code)
	}
	if code == 255 && devreg.Pinned(e) {
		inv.sshKeyMismatch(plan, caller)
	}
	if code != 0 {
		return exit(code)
	}
	return nil
}

// sshResolve finds the entry (by name or registered address, devices and
// hosts alike), admits the caller (sshAdmit), and builds the ssh command:
// the profile, the pinning options of a pinned entry (whose known_hosts is
// brought up to date first), then -p, '-l <caller>', the target and the
// extra arguments (after the target: ssh takes them as the remote command).
func (inv *invocation) sshResolve(p Parsed, caller string, extra []string) (sshPlan, error) {
	a := inv.app
	key := p.Args[0]
	_, res, err := inv.deviceLoad()
	if err != nil {
		return sshPlan{}, err
	}
	e, ok := res.Lookup(key, devreg.ScopeFilter{})
	if !ok {
		if _, aerr := devreg.NormalizeAddress(key); aerr == nil {
			return sshPlan{}, inv.usageErr("'" + key + "' is not a registered device; register it: tacctl device add <name> " + key)
		}
		return sshPlan{}, inv.usageErr("Device '"+key+"' not found. List them with: tacctl device list",
			"tacctl ssh reaches registered devices and enrolled hosts only; register one with: tacctl device add <name> <address>")
	}
	if err := inv.sshAdmit(caller, e); err != nil {
		return sshPlan{}, err
	}
	target, ok := devreg.SSHTarget(e)
	if !ok {
		return sshPlan{}, inv.usageErr("'" + e.Name + "' is this server (enrolled with --local); there is no ssh session to open.")
	}
	plan := sshPlan{entry: e, target: target, port: e.SSHPort()}
	port := ""
	if e.Port != 0 {
		port = strconv.Itoa(e.Port)
	}
	if p.Has("-p") {
		port = p.Value("-p")
		plan.port, _ = strconv.Atoi(port)
	}
	if devreg.Pinned(e) {
		if err := devreg.SyncKnownHosts(a.Paths.DevicesFile, a.Paths.KnownHosts); err != nil {
			return sshPlan{}, err
		}
	} else {
		inv.sshUnpinnedNotice(res, e)
	}
	// No agent socket and no identity (an enrolled host's is the
	// provisioning account's): the session is the caller's, by password.
	plan.cmd = hosts.SSH{
		AsUser:  caller,
		Options: devreg.OptionArgs(devreg.SSHOptions(e, a.Paths.KnownHosts)),
		Port:    port,
	}
	plan.args = append(append(plan.args, "-l", caller, target), extra...)
	return plan, nil
}

// sshAdmit is who may open a session: an active tacctl user (in the store,
// not disabled, with a password) whose scopes hold the entry's, at every
// tier, superusers included; the device then checks the same password
// against this server. An entry no scope covers is refused to everyone. A
// refusal is logged ('ssh DENY user= device= scope= reason=').
func (inv *invocation) sshAdmit(caller string, e devreg.Entry) error {
	a := inv.app
	deny := func(reason, msg string) error {
		a.Logger(inv.ctx, "auth.warning", "ssh DENY user="+caller+" device="+e.Name+" scope="+dash(e.Scope)+" reason="+reason)
		return inv.usageErr(msg)
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	u := m.User(caller)
	switch {
	case u == nil:
		return deny("not-a-tacctl-user", "'"+caller+"' is not a tacctl user; tacctl ssh logs you in with your tacctl account, so only tacctl users may use it.")
	case u.IsDisabled():
		return deny("disabled", "tacctl user '"+caller+"' is disabled; tacctl ssh is for active tacctl users.")
	case e.Scope == "" || !e.Configured:
		return deny("unconfigured", "'"+e.Name+"' is in no configured scope, so no one may open a session to it.")
	case !slices.Contains(u.Scopes, e.Scope):
		return deny("scope", "'"+caller+"' has no access to scope '"+e.Scope+"' (device "+e.Name+")")
	}
	return nil
}

// sshUnpinnedNotice warns, on stderr, that nothing pinned stands between
// the user and an impostor: ssh then asks with the user's own known_hosts.
// A device whose hostkey-unpinned notice was acknowledged is not warned
// about again.
func (inv *invocation) sshUnpinnedNotice(res *devreg.Resolver, e devreg.Entry) {
	warn := ui.Output{Stdout: inv.app.Out.Stderr, Stderr: inv.app.Out.Stderr}
	if e.Source == devreg.SourceHost {
		warn.Warn("hostkey-unpinned: no host key is pinned for '" + e.Name + "'; ssh checks it against your own known_hosts. " +
			"Pin it after checking on the host (" + devreg.VerifyHint(devreg.VendorLinux) + "): 'tacctl device hostkey " + e.Name + " accept'")
		return
	}
	for _, n := range devreg.Open(res.NoticesFor(e)) {
		if n.Kind == devreg.NoticeHostKeyUnpinned {
			warn.Warn(n.Kind + ": " + n.Text)
		}
	}
}

// sshKeyMismatch explains an ssh that ended with 255 on a pinned entry when
// the reason is the host key: the keys are read again (as root, as 'device
// add' reads them) and, when the pinned key is not among them, the pinned
// and offered fingerprints are printed with the vendor's command to check
// them and the commands that re-pin. Any other failure (no route, refused,
// a wrong password) is left to ssh's own message.
func (inv *invocation) sshKeyMismatch(plan sshPlan, caller string) {
	a, e := inv.app, plan.entry
	addr, port, legacy, ok := scanTarget(e)
	if !ok {
		return
	}
	if plan.port != 0 {
		port = plan.port
	}
	offered, err := devreg.Scan(inv.ctx, a.Runner, addr, port, legacy)
	if err != nil {
		return
	}
	if !devreg.Compare(e.HostKeys, offered).Changed {
		return
	}
	a.Logger(inv.ctx, "auth.warning", "ssh hostkey-mismatch user="+caller+" device="+e.Name+" addr="+addr)
	a.Out.ErrorE("The ssh host key of '" + e.Name + "' (" + addr + " port " + strconv.Itoa(port) +
		") is not the one pinned for it; ssh refused the connection.")
	inv.stderrLine("  Pinned:  " + devreg.Displays(devreg.ParseHostKeys(e.HostKeys)))
	inv.stderrLine("  Offered: " + devreg.Displays(offered))
	inv.stderrLine("  Compare on the device console: " + devreg.VerifyHint(e.Vendor) + ".")
	inv.stderrLine("  If the change is expected (a replaced or reset unit), re-pin it after verifying (administrators):")
	inv.stderrLine("    tacctl device hostkey " + e.Name + " accept")
	inv.stderrLine("    tacctl device hostkey " + e.Name + " set SHA256:<fingerprint>")
}
