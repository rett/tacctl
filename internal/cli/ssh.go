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
//
// From a console session (TACCTL_CONSOLE set: the console puts it on every
// line) ssh reads no configuration file and can open nothing but the
// session: '-F /dev/null', no local command, no control master, no
// forwardings, no agent, no escape character unless console.yaml's
// ssh_escape, the target after '--' (so no word after it is an option), and
// an entry with no pinned host key is refused.
//
// When the session's password cache holds the caller's password (D70,
// password_cache.go) and the entry's host key is pinned, ssh gets the cached
// password from the user's own shell without a prompt: SSH_ASKPASS names this
// binary (askpass_cmd.go), SSH_ASKPASS_REQUIRE=force, and ssh asks once
// (NumberOfPasswordPrompts=1), reads no configuration file and checks the
// pinned host key strictly, so a redirected or substituted hop is never
// handed the password. In that case ssh is started as the user directly
// (uid, gid and groups set in the child; no sudo, whose log lines would
// carry the variable), with TACCTL_ASKPASS, a token made for this line, in
// its environment and nowhere else. The cache forgets the password when ssh
// ends with status 255 (a refusal cannot be told from other failures of the
// connection).

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
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
	{Names: []string{"-X"}}, {Names: []string{"-Y"}}, {Names: []string{"-g"}},
	{Names: []string{"-L"}, Value: true, Repeat: true},
	{Names: []string{"-R"}, Value: true, Repeat: true},
	{Names: []string{"-D"}, Value: true, Repeat: true},
}}

// reForwardSpec is the shape of an -L, -R or -D argument: addresses, ports,
// host names and socket paths, nothing ssh would read as an option.
var reForwardSpec = regexp.MustCompile(`^[A-Za-z0-9.:/\[\]_*-]+$`)

const (
	sshUse   = "ssh <name|address> [-p <port>] [-X|-Y] [-g] [-L|-R|-D <spec>]... [-- <ssh args>]"
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
  -X, -Y           Forward X11 (untrusted, trusted) to this server's display
  -L <spec>        Forward a local port, as ssh -L (repeatable)
  -R <spec>        Forward a remote port, as ssh -R (repeatable)
  -D <spec>        Open a SOCKS proxy, as ssh -D (repeatable)
  -g               Let -L and -D ports listen on every address, as ssh -g
  -- <ssh args>    Pass the rest to ssh for this session (a remote command)

Only active tacctl users reach a device, and only one in a scope of their own,
whatever their tier; a device no scope covers is reached by no one. Every
session is logged to syslog (auth.info). In the login console, forwarding
(-X, -Y, -L, -R, -D) is for the tiers of 'tacctl console forwarding tiers'
(default: superuser); -X uses the display of an 'ssh -X' login to this server.
There, -L and -D ports listen on loopback only, unless 'tacctl console
forwarding gateway-ports' is enabled (then -g and a bind address such as
0.0.0.0:8443:localhost:443 open them to the network).

Examples:
  tacctl ssh core-sw1
  tacctl ssh 10.99.0.1 -p 2222
  tacctl ssh core-sw1 -- show version
  tacctl ssh core-sw1 -L 8443:localhost:443

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
	// The password cache's variable is read once and taken out of the
	// environment before anything else runs.
	cacheClient := inv.takeAskpass()
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
	if inv.sshConsole() && len(extra) > 0 && strings.HasPrefix(extra[0], "-") {
		return inv.usageErr("In the tacctl console the words after -- are the remote command; ssh's own options are not available.")
	}
	fwd, kinds, err := inv.sshForwarding(p, caller)
	if err != nil {
		return err
	}
	plan, err := inv.sshResolve(p, caller, extra, fwd)
	if err != nil {
		return err
	}
	e := plan.entry
	addr := e.Address
	if addr == "" {
		addr = plan.target
	}
	forward := ""
	if len(kinds) > 0 {
		forward = " forward=" + strings.Join(kinds, ",")
	}
	// A cached password is used only for a pinned entry (the host key is
	// then checked strictly against the pin) and when ssh's own options
	// are not user words (an option after the target would be ssh's).
	cached := false
	optionAfterTarget := len(extra) > 0 && strings.HasPrefix(extra[0], "-")
	if cacheClient != nil && devreg.Pinned(e) && !optionAfterTarget {
		if have, err := cacheClient.Have(inv.ctx); err == nil && have {
			cached = true
		}
	}
	cmd := plan.cmd.Cmd(plan.args...)
	cacheNote := ""
	if cached {
		// Started as the user directly, not through sudo, so that the
		// token is never a sudo variable or argument. An account that
		// cannot be looked up locally (a directory service the static
		// binary does not read) keeps the old path and the prompt.
		if c, ok := inv.sshCachedCommand(plan, caller, cacheClient); ok {
			cmd, cacheNote = c, " password=cached"
		} else {
			cached = false
		}
	}
	a.Logger(inv.ctx, "auth.info", "ssh user="+caller+" device="+e.Name+" addr="+addr+forward+cacheNote+inv.sshConsoleField())
	start := a.Knobs.Now()
	code, _, startErr := hosts.Attached(inv.ctx, a.Runner, cmd, a.Stdin, a.Out)
	if cached && code == 255 {
		// ssh gave up: the password may be what the device refused.
		// (not the invocation's context: a hangup still forgets)
		_ = cacheClient.Forget(context.WithoutCancel(inv.ctx))
	}
	if startErr != nil && code == 0 {
		code = 127
	}
	a.Logger(inv.ctx, "auth.info", "ssh end user="+caller+" device="+e.Name+" status="+strconv.Itoa(code)+
		" duration="+console.Seconds(a.Knobs.Now().Sub(start))+inv.sshConsoleField())
	if startErr != nil {
		a.Out.Error("ssh could not be run (" + startErr.Error() + "); it comes with the openssh-client package.")
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
func (inv *invocation) sshResolve(p Parsed, caller string, extra, fwd []string) (sshPlan, error) {
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
	inConsole := inv.sshConsole()
	if inConsole && !devreg.Pinned(e) {
		a.Logger(inv.ctx, "auth.warning", "ssh DENY user="+caller+" device="+e.Name+" scope="+dash(e.Scope)+" reason=unpinned"+inv.sshConsoleField())
		return sshPlan{}, inv.usageErr("'" + e.Name + "' has no pinned host key, so the console does not connect to it; an administrator pins it: tacctl device hostkey " + e.Name + " accept")
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
	opts := devreg.OptionArgs(devreg.SSHOptions(e, a.Paths.KnownHosts))
	plan.args = append(append(plan.args, fwd...), "-l", caller)
	if inConsole {
		opts = append(sshConsoleOptions(inv.sshEscape(), len(fwd) > 0), opts...)
		plan.args = append(plan.args, "--")
	}
	plan.cmd = hosts.SSH{AsUser: caller, Options: opts, Port: port}
	if slices.Contains(fwd, "-X") || slices.Contains(fwd, "-Y") {
		plan.cmd.Env = []string{"DISPLAY=" + a.Env.Get("DISPLAY")}
	}
	plan.args = append(append(plan.args, target), extra...)
	return plan, nil
}

// sshCachedOptions are the options ssh gets besides the plan's when it
// asks the password cache: one password prompt (a refused password is not
// offered again), and the same closed set a console session has when the
// plan does not have it already (no configuration file: no SendEnv,
// ProxyJump, ProxyCommand or Match exec of the user's, no local command, no
// control master, no agent). The pinned host key's strict checking is the
// entry's own (devreg.PinOptions), which the cache is used with only.
func sshCachedOptions(console bool) []string {
	o := []string{"-o", "NumberOfPasswordPrompts=1"}
	if console {
		return o // sshConsoleOptions has the rest
	}
	return append([]string{"-F", "/dev/null", "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ForwardAgent=no"}, o...)
}

// sshAccount is what the cached path needs of the caller's account to start
// ssh as them without sudo.
type sshAccount struct {
	UID, GID uint32
	Groups   []uint32
	Home     string
}

// sshAccountOf looks the caller up in the local account database, with the
// supplementary groups (tests replace it).
var sshAccountOf = func(name string) (sshAccount, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return sshAccount{}, err
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return sshAccount{}, errors.New("the account's ids are not numbers")
	}
	acct := sshAccount{UID: uint32(uid), GID: uint32(gid), Home: u.HomeDir}
	gids, err := u.GroupIds()
	if err != nil {
		return sshAccount{}, err
	}
	for _, g := range gids {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return sshAccount{}, errors.New("a group id is not a number")
		}
		acct.Groups = append(acct.Groups, uint32(n))
	}
	return acct, nil
}

// sshUserEnvKeep are the variables of the invoking process's environment
// that ssh run as the user keeps, which is what 'sudo -u <user> -H' kept
// (its env_keep and env_check defaults that matter to ssh): the terminal
// and locale, and the X11 display. HOME, USER, LOGNAME and PATH are set from
// the account, SUDO_* and the rest are not passed.
var sshUserEnvKeep = []string{"TERM", "COLORTERM", "LANG", "LANGUAGE", "TZ", "DISPLAY", "XAUTHORITY"}

// sshUserEnviron is the explicit environment of the ssh a user's own account
// runs: the account's HOME, USER, LOGNAME, PATH, the variables of
// sshUserEnvKeep and LC_* the process has, then extra (later entries win).
func sshUserEnviron(environ []string, acct sshAccount, name string, extra []string) []string {
	path := "/usr/local/bin:/usr/bin:/bin"
	vals := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := vals[k]; !ok {
			order = append(order, k)
		}
		vals[k] = v
	}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case !ok:
		case k == "PATH" && v != "":
			path = v
		case slices.Contains(sshUserEnvKeep, k), strings.HasPrefix(k, "LC_"):
			set(k, v)
		}
	}
	set("HOME", acct.Home)
	set("USER", name)
	set("LOGNAME", name)
	set("PATH", path)
	for _, kv := range extra {
		if k, v, ok := strings.Cut(kv, "="); ok {
			set(k, v)
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+vals[k])
	}
	return out
}

// sshCachedCommand is the ssh command of a plan whose password comes from
// the cache: the plan's options with those of sshCachedOptions first (ssh
// keeps the first value of an option), started as the caller (their uid, gid
// and supplementary groups, set in the child before exec) with an explicit
// environment: SSH_ASKPASS naming this binary, the line's TACCTL_ASKPASS,
// and what sshUserEnviron gives. There is no sudo in this path, so the token
// is never an argument or a 'sudo' variable and reaches no log; it is in the
// environment of ssh and of the helper ssh starts, once. ok is false when the
// caller's account cannot be looked up here.
func (inv *invocation) sshCachedCommand(plan sshPlan, caller string, c *askpass.Client) (execx.Cmd, bool) {
	a := inv.app
	acct, err := sshAccountOf(caller)
	if err != nil || acct.Home == "" {
		return execx.Cmd{}, false
	}
	// The account looked up here must be the one sudo ran this for: the
	// socket was checked to be SUDO_UID's, and root is never the user.
	if acct.UID == 0 || c.ExpectUID <= 0 || acct.UID != uint32(c.ExpectUID) {
		return execx.Cmd{}, false
	}
	s := plan.cmd
	s.Options = append(sshCachedOptions(inv.sshConsole()), s.Options...)
	extra := append(slices.Clone(s.Env),
		"SSH_ASKPASS="+a.Exe, "SSH_ASKPASS_REQUIRE=force", askpass.HelperEnv+"=1", askpass.EnvVar+"="+c.Env())
	s.AsUser, s.AuthSock, s.Env = "", "", nil
	cmd := s.Cmd(plan.args...)
	cmd.Env = sshUserEnviron(a.Env.Environ(), acct, caller, extra)
	cmd.Credential = &syscall.Credential{Uid: acct.UID, Gid: acct.GID, Groups: acct.Groups}
	return cmd, true
}

// sshConsoleOptions are the options a console session's ssh starts with:
// no configuration file (no ~/.ssh/config, no /etc/ssh/ssh_config: no
// ProxyCommand, LocalCommand, Match exec or Include), no local command, no
// control master, no forwardings unless forwarding (the session's own
// -X/-Y/-L/-R/-D, which ClearAllForwardings would clear too; with -F
// /dev/null there are no others), no agent, and no escape character unless
// escape (console.yaml's ssh_escape: '~.' for a hung session, at the cost
// of '~C').
func sshConsoleOptions(escape, forwarding bool) []string {
	o := []string{"-F", "/dev/null", "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no"}
	if !forwarding {
		o = append(o, "-o", "ClearAllForwardings=yes")
	}
	o = append(o, "-o", "ForwardAgent=no")
	if !escape {
		o = append(o, "-o", "EscapeChar=none")
	}
	return o
}

// sshForwarding is the session's forwarding options as ssh takes them (-X,
// -Y, then each -L, -R and -D with its argument) and their kinds for the
// log (x11, local, remote, dynamic). Every argument must look like a
// forwarding spec. In a console session they are for the tiers of console
// forwarding tiers only; a refusal is logged ('ssh DENY ... reason=forward').
// There, -g and an -L or -D that listens on another address than loopback
// need console forwarding gateway-ports too ('reason=gateway'): ssh binds
// an explicit bind address (0.0.0.0, *, or an empty one) on this server
// even without -g. -X/-Y need an X11 display (an 'ssh -X' login to this
// server).
func (inv *invocation) sshForwarding(p Parsed, caller string) (args, kinds []string, err error) {
	for _, f := range []string{"-X", "-Y"} {
		if p.Has(f) {
			args = append(args, f)
			if !slices.Contains(kinds, "x11") {
				kinds = append(kinds, "x11")
			}
		}
	}
	for _, f := range []struct{ flag, kind string }{{"-L", "local"}, {"-R", "remote"}, {"-D", "dynamic"}} {
		for _, v := range p.Values(f.flag) {
			if !reForwardSpec.MatchString(v) || strings.HasPrefix(v, "-") {
				return nil, nil, inv.usageErr("'" + v + "' is not a forwarding spec for " + f.flag + " (as ssh takes it, e.g. 8443:localhost:443).")
			}
			args = append(args, f.flag, v)
			if !slices.Contains(kinds, f.kind) {
				kinds = append(kinds, f.kind)
			}
		}
	}
	if p.Has("-g") {
		if len(p.Values("-L")) == 0 && len(p.Values("-D")) == 0 {
			return nil, nil, inv.usageErr("-g only matters with -L or -D.")
		}
		args = append([]string{"-g"}, args...)
	}
	if len(args) == 0 {
		return nil, nil, nil
	}
	if slices.Contains(kinds, "x11") && !console.ValidDisplay(inv.app.Env.Get("DISPLAY")) {
		return nil, nil, inv.usageErr("-X needs an X11 display, and this session has none: log in to this server with 'ssh -X' (or -Y) first.")
	}
	if inv.sshConsole() {
		pol, perr := inv.consolePolicy()
		t := inv.tierGate().Caller(inv.ctx)
		if perr != nil || !pol.Forwarding(t) {
			inv.app.Logger(inv.ctx, "auth.warning", "ssh DENY user="+caller+" reason=forward tier="+string(t)+inv.sshConsoleField())
			return nil, nil, inv.usageErr("Forwarding (-X, -Y, -L, -R, -D) is not available to the " + string(t) + " tier in the console; an administrator allows it with: tacctl console forwarding tiers <tiers>")
		}
		if !pol.GatewayPorts() {
			var open []string
			if p.Has("-g") {
				open = append(open, "-g")
			}
			for _, f := range []string{"-L", "-D"} {
				for _, v := range p.Values(f) {
					if b, ok := forwardBind(f, v); ok && !loopbackBind(b) {
						open = append(open, f+" "+v)
					}
				}
			}
			if len(open) > 0 {
				inv.app.Logger(inv.ctx, "auth.warning", "ssh DENY user="+caller+" reason=gateway tier="+string(t)+inv.sshConsoleField())
				return nil, nil, inv.usageErr("In the console, forwarded ports listen on loopback only ("+strings.Join(open, ", ")+" would listen on other addresses of this server).",
					"An administrator allows it with: tacctl console forwarding gateway-ports enable")
			}
		}
	}
	return args, kinds, nil
}

// forwardBind is the bind address of an -L or -D spec as ssh reads it
// ([bind:]port:host:hostport, [bind:]port:/socket, /socket:..., or
// [bind:]port for -D), with ok false when it names none (ssh then listens
// on loopback) or listens on a local socket. A bracketed IPv6 address is
// one field.
func forwardBind(flag, spec string) (bind string, ok bool) {
	if strings.HasPrefix(spec, "/") {
		return "", false
	}
	var fields []string
	cur, depth := "", 0
	for _, r := range spec {
		switch {
		case r == '[':
			depth++
		case r == ']':
			depth--
		case r == ':' && depth == 0:
			fields = append(fields, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	fields = append(fields, cur)
	n := len(fields)
	switch {
	case flag == "-D" && n == 2:
	case flag == "-L" && n == 4:
	case flag == "-L" && n == 3 && strings.HasPrefix(fields[2], "/"):
	default:
		return "", false
	}
	return strings.Trim(fields[0], "[]"), true
}

// loopbackBind reports whether ssh binds bind on loopback only.
func loopbackBind(bind string) bool {
	if bind == "localhost" {
		return true
	}
	ip := net.ParseIP(bind)
	return ip != nil && ip.IsLoopback()
}

// sshConsole reports whether this 'tacctl ssh' comes from a console
// session (TACCTL_CONSOLE set, whatever its value).
func (inv *invocation) sshConsole() bool { return inv.app.Env.Get(console.EnvMarker) != "" }

// sshConsoleField is ' console=<session>' for the log lines of a console
// session's ssh, else "".
func (inv *invocation) sshConsoleField() string {
	if !inv.sshConsole() {
		return ""
	}
	return " console=" + console.MarkerValue(inv.app.Env.Get(console.EnvMarker))
}

// sshEscape is console.yaml's ssh_escape (false when it cannot be read).
func (inv *invocation) sshEscape() bool {
	f, err := console.Load(inv.app.Paths.ConsoleFile)
	return err == nil && f.SSHEscape
}

// sshAdmit is who may open a session: an active tacctl user (in the store,
// not disabled, with a password) whose scopes hold the entry's, at every
// tier, superusers included; the device then checks the same password
// against this server. An entry no scope covers is refused to everyone. A
// refusal is logged ('ssh DENY user= device= scope= reason=').
func (inv *invocation) sshAdmit(caller string, e devreg.Entry) error {
	a := inv.app
	deny := func(reason, msg string) error {
		a.Logger(inv.ctx, "auth.warning", "ssh DENY user="+caller+" device="+e.Name+" scope="+dash(e.Scope)+" reason="+reason+inv.sshConsoleField())
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
	offered, err := inv.scanDevice(addr, port, legacy)
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
