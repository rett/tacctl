package cli

// The 'host' family (lib/linux_hosts.sh cmd_host at 0.1.16), native since
// WP3.2: list, enroll, sync, unenroll and default-method. 'tacctl host'
// pushes the 'config linux' scripts to a host over ssh and runs them there,
// and keeps the registry of enrolled hosts (internal/hosts) so 'host sync'
// knows where to push account changes. ssh runs as the user who invoked
// sudo, so their keys and known_hosts are used (the re-exec carries
// SSH_AUTH_SOCK across sudo, reexec.go); the remote login must be root or
// able to sudo.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// hostFlags are the options of enroll and sync, for completion.
var (
	flagAllowUIDMismatch = Flag{Names: []string{"--allow-uid-mismatch"}}
	flagRemoveHome       = Flag{Names: []string{"--remove-home"}}
)

// hostSpecs are the arguments of each verb, for completion (args.go). Host
// names complete from the registry (KindHosts).
var hostSpecs = map[string]Spec{
	"list": {},
	"show": {MinArgs: 1, MaxArgs: 1, Args: []string{KindHosts}, Flags: []Flag{
		{Names: []string{"--all"}}, flagJSON, {Names: []string{"--check"}}}},
	"enroll": {MaxArgs: 1, Args: []string{""}, Flags: []Flag{
		{Names: []string{"--local"}},
		{Names: []string{"--scope"}, Value: true, Kind: KindScopes},
		{Names: []string{"--server"}, Value: true},
		{Names: []string{"--name"}, Value: true},
		{Names: []string{"--port"}, Value: true},
		{Names: []string{"--identity"}, Value: true, Kind: KindFile},
		{Names: []string{"--method"}, Value: true, Kind: methodWords},
		{Names: []string{"--build-on-host"}},
		{Names: []string{"--yes"}},
		{Names: []string{"--staging"}},
		flagAllowUIDMismatch, flagRemoveHome}},
	"sync": {MaxArgs: 1, Args: []string{KindHosts}, Flags: []Flag{{Names: []string{"--all"}}, flagAllowUIDMismatch, flagRemoveHome}},
	"move": {MaxArgs: 2, Args: []string{KindHosts, KindScopes}, Flags: []Flag{{Names: []string{"--all"}, Alone: true},
		{Names: []string{"--yes"}}, flagAllowUIDMismatch, flagRemoveHome}},
	"unenroll": {MinArgs: 1, MaxArgs: 1, Args: []string{KindHosts}, Flags: []Flag{{Names: []string{"--force"}}}},
	"target": {MinArgs: 1, MaxArgs: 2, Args: []string{KindHosts, ""}, Flags: []Flag{
		{Names: []string{"--port"}, Value: true},
		{Names: []string{"--identity"}, Value: true, Kind: KindFile},
		{Names: []string{"--no-identity"}}}},
	"default-method": {MaxArgs: 1, Args: []string{methodWords}},
}

// hostVerbs are the verbs ({Use, Short}), in usage order.
var hostVerbs = [][2]string{
	{"list", "Show enrolled hosts"},
	{"show <name> [--all] [--json] [--check]", "One enrolled host in full; --check compares it with what tacctl would make it"},
	{"enroll <[user@]host> | --local [options]", "Install TACACS+ or RADIUS login on a host over SSH and register it"},
	{"sync <name> | --all [options]", "Push account adds, deletions and tier changes"},
	{"move <name> [<scope>] | --all [options]", "Move an enrolled host to another scope (default: the scope answering its address)"},
	{"target <name> [<[user@]host>] [options]", "Show or change how tacctl reaches an enrolled host over ssh"},
	{"unenroll <name> [--force]", "Remove the login method from the host (accounts and homes are kept)"},
	{"default-method [tacplus|radius]", "Show or set the method for hosts enrolled without --method"},
}

func hostCmd(inv *invocation) *cobra.Command {
	c := verb("host <subcommand>", "Linux hosts: enroll, sync, unenroll TACACS+ or RADIUS login over SSH")
	c.RunE = inv.native(withPreflight, inv.host)
	for _, v := range hostVerbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.host(append([]string{word}, args...))
		})))
	}
	return c
}

// hostUsage is cmd_host_usage.
func hostUsage() string { return Usage("host", nil) }

// host is cmd_host: no sub-command is the usage (exit 0); an unknown one
// (help and -h included) is an error, then the usage (exit 1).
func (inv *invocation) host(args []string) error {
	if err := inv.verifySudoUser("tacctl host"); err != nil {
		return err
	}
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	switch sub := arg(args, 0); sub {
	case "list":
		return inv.hostList()
	case "show":
		return inv.hostShow(rest)
	case "enroll":
		return inv.hostEnroll(rest)
	case "move":
		return inv.hostMove(rest)
	case "sync":
		return inv.hostSync(rest)
	case "target":
		return inv.hostTarget(rest)
	case "unenroll":
		return inv.hostUnenroll(rest)
	case "default-method":
		return inv.hostDefaultMethod(rest)
	case "":
		inv.write(hostUsage())
		return nil
	default:
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(hostUsage())
		return exit(1)
	}
}

// registry is the host registry as it is now.
func (inv *invocation) registry() (*hosts.Registry, error) {
	return hosts.LoadRegistry(inv.app.Paths.LinuxHosts)
}

// --- list ------------------------------------------------------------------------

// hostList is cmd_host_list.
func (inv *invocation) hostList() error {
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	inv.echo("")
	if reg.Empty() {
		inv.echoE(ui.Bold + "Enrolled Linux hosts" + ui.NC)
		inv.echo(ui.Rule("Enrolled Linux hosts"))
		inv.echo("  None. Enroll one with: tacctl host enroll <[user@]host>")
		inv.echo("")
		return nil
	}
	t := ui.NewTable("Enrolled Linux hosts", ui.Left("NAME"), ui.Left("TARGET"), ui.Left("SCOPE"), ui.Left("SERVER"), ui.Left("METHOD"), ui.Left("USERS"))
	for _, e := range reg.Entries() {
		target := e.Target
		if e.Port != "" {
			target += ":" + e.Port
		}
		users := 0
		if m, err := inv.model(); err == nil {
			users = hosts.UserCount(m.LinuxUsers(e.Scope))
		}
		t.Add(e.Name, target, e.Scope, e.Server, reg.Method(e.Name), strconv.Itoa(users))
	}
	inv.write(t.String())
	inv.echo("")
	for _, e := range reg.Entries() {
		if msg := inv.hostScopeDrift(e, inv.hostAddress(e)); msg != "" {
			inv.app.Out.WarnE(msg)
		}
	}
	return nil
}

// --- enroll ----------------------------------------------------------------------

var (
	reTarget     = regexp.MustCompile(`^([a-z_][a-z0-9_-]*@)?[A-Za-z0-9][A-Za-z0-9.:-]*$`)
	reBareIPv4   = regexp.MustCompile(`^[0-9.]+$`)
	reHostName   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,25}$`)
	reHostLetter = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
	rePort       = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// cutField is "cut -d'|' -f<n>" of one line: the whole line when it has
// no '|', "" when it has fewer fields.
func cutField(line string, n int) string {
	f := strings.Split(line, "|")
	if len(f) == 1 {
		return line
	}
	if n-1 < len(f) {
		return f[n-1]
	}
	return ""
}

// shortHostname is 'hostname -s'.
func shortHostname() string {
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(h, ".")
	return h
}

// reportOnly prints what an error carries that has not been printed, as
// the command's end would, and goes on ('... || warn ...').
func (inv *invocation) reportOnly(err error) { _ = exitCode(err, inv.app.Out) }

// hostEnroll is cmd_host_enroll.
func (inv *invocation) hostEnroll(args []string) error {
	a := inv.app
	var target, scope, server, name, port, identity, method string
	isLocal, buildOnHost, removeHome, yes, staging := false, false, false, false, false
	var scriptArgs []string
	for i := 0; i < len(args); {
		w := args[i]
		switch w {
		case "--local":
			isLocal = true
			i++
		case "--build-on-host":
			buildOnHost = true
			i++
		case "--allow-uid-mismatch":
			scriptArgs = append(scriptArgs, w)
			i++
		case "--remove-home":
			removeHome = true
			i++
		case "--yes":
			yes = true
			i++
		case "--staging":
			staging = true
			i++
		case "--scope", "--server", "--name", "--port", "--identity":
			if i+1 >= len(args) {
				// 0.1.16 spins forever here ('shift 2 || true' cannot shift).
				return exit(1)
			}
			*map[string]*string{"--scope": &scope, "--server": &server, "--name": &name, "--port": &port, "--identity": &identity}[w] = args[i+1]
			i += 2
		case "--method":
			if arg(args, i+1) == "" {
				return inv.usageErr("--method needs a method: " + hosts.MethodList())
			}
			method = args[i+1]
			i += 2
		default:
			if strings.HasPrefix(w, "-") {
				a.Out.ErrorE("Unknown option: '" + w + "'")
				inv.write(hostUsage())
				return exit(1)
			}
			if target != "" {
				return inv.usageErr("Only one host per enroll.")
			}
			target = w
			i++
		}
	}

	reg, err := inv.registry()
	if err != nil {
		return err
	}
	var hostPart, hostIP string
	if isLocal {
		if target != "" {
			return inv.usageErr("--local takes no host argument.")
		}
		target, hostIP = hosts.Local, "127.0.0.1"
		if name == "" {
			name = shortHostname()
		}
		if server == "" {
			server = "127.0.0.1"
		}
	} else {
		if !reTarget.MatchString(target) {
			return inv.usageErr("Usage: tacctl host enroll <[user@]host> | --local  [options]")
		}
		hostPart = target
		if _, after, ok := strings.Cut(target, "@"); ok {
			hostPart = after
		}
		if login, explicit, isUser, err := inv.provisioningLogin(target); err != nil {
			return err
		} else if isUser {
			msg := "The provisioning account '" + login + "' (the ssh login for " + target + ") is a tacctl user."
			if !explicit {
				msg = "The provisioning account defaults to your username '" + login + "', which is a tacctl user."
			}
			return inv.usageErr(msg,
				"Enrolment logs in with a local account on the host that does not authenticate through tacctl (root or a dedicated",
				"administration account, kept working when this server is unreachable): tacctl host enroll <account>@"+hostPart)
		}
		res, err := a.Runner.Run(inv.ctx, execx.Cmd{Name: "getent", Args: []string{"ahostsv4", hostPart}, Stderr: io.Discard})
		if res.Code != 0 || err != nil {
			return inv.usageErr("Cannot resolve '" + hostPart + "'")
		}
		if lines := strings.SplitN(string(res.Stdout), "\n", 2); len(lines) > 0 {
			if f := strings.Fields(lines[0]); len(f) > 0 {
				hostIP = f[0]
			}
		}
		if hostIP == "" {
			return inv.usageErr("Could not resolve '" + hostPart + "' to an IPv4 address.")
		}
		if name == "" {
			// A bare IP has no hostname to borrow: 10.1.2.3 -> h10-1-2-3.
			if reBareIPv4.MatchString(hostPart) {
				name = "h" + strings.ReplaceAll(hostPart, ".", "-")
			} else {
				name, _, _ = strings.Cut(hostPart, ".")
			}
		}
		// Re-enrolling a registered host keeps the server address it has.
		if server == "" && reHostLetter.MatchString(name) {
			if e, ok := reg.Find(name); ok {
				server = cutField(e.Line, 5)
			}
		}
		if server == "" {
			res, err := a.Runner.Run(inv.ctx, execx.Cmd{Name: "ip", Args: []string{"-4", "route", "get", hostIP}, Stderr: io.Discard})
			if res.Code != 0 || err != nil {
				return inv.usageErr("Could not determine this server's address for " + hostPart + " (ip route failed); pass --server <address>")
			}
			if addrs := srcAddresses(string(res.Stdout)); len(addrs) > 0 {
				server = addrs[0]
			}
			if server == "" {
				return inv.usageErr("Could not work out which address " + hostPart + " should use for this server. Pass --server.")
			}
		}
	}
	if !reHostName.MatchString(name) {
		return inv.usageErr("Invalid host name '" + name + "'. Pass --name <letters, digits, _ or -, starting with a letter, max 26>.")
	}
	_, enrolled := reg.Find(name)
	if err := inv.hostNameCheck(name, enrolled); err != nil {
		return err
	}
	if port != "" && !rePort.MatchString(port) {
		return inv.usageErr("Invalid --port '" + port + "'.")
	}
	// One machine, one registration: a new name for a machine already
	// enrolled under another one would hold a second scope's secret and
	// users on it, and each sync would undo the other's.
	if other := inv.hostDuplicate(reg, name, target, hostIP, port); other != nil {
		how := other.Target
		if other.Target == hosts.Local {
			how = "--local"
		}
		again := "tacctl host enroll " + target + " --name " + other.Name
		if isLocal {
			again = "tacctl host enroll --local --name " + other.Name
		}
		return inv.usageErr("'"+name+"' is the enrolled host '"+other.Name+"' (enrolled as "+how+"): both reach "+hostIP+". Nothing was changed.",
			"Re-enroll it under its registered name: "+again,
			"or change how tacctl reaches it: tacctl host target "+other.Name+" "+target)
	}
	if identity != "" {
		if st, err := os.Stat(identity); err != nil || !st.Mode().IsRegular() {
			return inv.usageErr("Identity file '" + identity + "' not found.")
		}
	}

	// The scope: the one named with --scope; else the one a registered host
	// has (re-enrolling never moves a host to another scope); else the scope
	// that answers the host's address, which its logins reach the server
	// from. A host no scope covers is not enrolled: nothing would answer its
	// logins, and a scope made for it here would take the address from any
	// broader prefix, and with it that scope's users from the host.
	// A method named on the command line is checked first: its problem is
	// the operator's own, whatever the scope.
	if method != "" {
		if err := inv.linuxMethodRequire(method); err != nil {
			return err
		}
	}
	scopeGiven := scope != ""
	if staging && (!scopeGiven || isLocal) {
		return inv.usageErr("--staging provisions a host off-site for the scope it will be installed in: tacctl host enroll <[user@]host> --scope <scope> --staging")
	}
	if !scopeGiven {
		if e, ok := reg.Find(name); ok && e.Scope != "" {
			exists, err := inv.scopeExists(e.Scope)
			if err != nil {
				return err
			}
			if exists {
				scope = e.Scope
				a.Out.InfoE(name + " is registered in scope '" + scope + "' and stays in it (another one: --scope <name>).")
			}
		}
	}
	if scope == "" {
		m, err := inv.model()
		if err != nil {
			return err
		}
		info, found := m.LookupAddr(hostIP)
		if !found {
			return inv.hostNoScope(name, target, hostPart, hostIP)
		}
		scope = info.Scope
		a.Out.InfoE(hostScopeOrigin(name, target, hostPart, hostIP) + " is answered by scope '" + scope + "' (prefix " + info.Prefix + "); enrolling " + name + " there (another one: --scope <name>).")
	}
	if err := inv.hostEnrollAllowed(reg, name, scope, isLocal); err != nil {
		return err
	}

	// The method: the one asked for; else the one a registered host has (so
	// re-enrolling never switches a host by accident); else what the host's
	// scope says: its auth-method, else the one protocol its protocols
	// filter names; else the default. Re-enrolling with the other method is
	// how a host switches.
	prevMethod := reg.Method(name)
	var scopeMethod, scopeWhy string
	if exists, err := inv.scopeExists(scope); err == nil && exists {
		scopeMethod, scopeWhy = inv.linuxScopeMethod(scope)
	}
	switch {
	case method == "" && prevMethod != "":
		method = prevMethod
		if scopeMethod != "" && scopeMethod != method {
			a.Out.InfoE(name + " is registered with method " + method + " and keeps it; " + scopeWhy + ". To switch the host: --method " + scopeMethod)
		}
	case method == "" && scopeMethod != "":
		method = scopeMethod
		a.Out.InfoE("Method " + method + ": " + scopeWhy + ".")
	}
	if method == "" {
		method = inv.linuxDefaultMethod()
	}
	if err := inv.linuxMethodRequire(method); err != nil {
		return err
	}
	be, _ := hosts.MethodBackend(method)
	he := inv.hostsEnv()
	he.ReadKeys = true // pin from the enrolment session (pinHostKeys)
	if method == hosts.Tacplus && !isRegularFile(he.Paths.Tarball()) {
		return inv.usageErr("pam_tacplus tarball not found. Run 'tacctl config linux build' first.")
	}

	// The scope must serve the method's protocol. The host's own scope
	// (linux-<name>, which earlier releases made for it and no other host
	// uses), when found here rather than named with --scope and limited to
	// the other protocol, is opened to both for the switch and narrowed to
	// the new one once the host has switched. Any other scope is never
	// changed here.
	both := strings.Join(scopeProtocols, ",")
	openScope := false
	if !scopeGiven && scope == "linux-"+name && !reg.OtherHostsUse(scope, name) {
		protocols, err := inv.linuxScopeProtocols(scope)
		if err != nil {
			return err
		}
		openScope = protocols != "" && !strings.Contains(","+protocols+",", ","+be+",")
	}
	if !openScope {
		if err := inv.scopeRequire(scope); err != nil {
			return err
		} else if ok, err := inv.linuxScopeServes(scope, method); err != nil {
			return err
		} else if !ok {
			if !scopeGiven && scope == "linux-"+name && reg.OtherHostsUse(scope, name) {
				a.Out.ErrorE("Other enrolled hosts use scope '" + scope + "', so it is not changed here.")
			}
			return exit(1)
		}
	}
	// The scope must be the one that answers the host's requests (with
	// --staging it will: its bench address is added to it below).
	if !staging && !inv.hostScopeCovers(name, target, hostIP, scope, true) {
		return exit(1)
	}
	// Moving a registered host to another scope gives it that scope's
	// secret and users: the accounts of the users it loses are deleted
	// there, so that is confirmed first.
	if e, ok := reg.Find(name); ok && e.Scope != "" && e.Scope != scope {
		if err := inv.confirmScopeMove(name, e.Scope, scope, yes); err != nil {
			return err
		}
	}
	// The UID file numbered for the range, and a host that can hold the
	// range, before anything changes here or there.
	if err := inv.renumberUIDs(true); err != nil {
		return err
	}
	if err := he.CheckIDMap(inv.ctx, name, target, port, identity); err != nil {
		if errors.Is(err, hosts.ErrFailed) {
			a.Out.ErrorE("Enrollment of " + name + " refused; nothing was changed.")
		}
		return inv.hostsDone(err)
	}

	// Off-site: the bench address answered by the scope's own secret and
	// users until the host is seen in the scope's prefixes.
	if staging {
		if err := inv.stagingAdd(scope, hostIP, "host", name); err != nil {
			return err
		}
	}
	narrowScope := false
	if openScope {
		protocols, err := inv.linuxScopeProtocols(scope)
		if err != nil {
			return err
		}
		a.Out.InfoE("Scope '" + scope + "' was limited to " + protocols + "; opening it to " + be + " for this host.")
		if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "protocols="+both) }); err != nil {
			// 'store_apply ... || return 1'.
			inv.reportOnly(err)
			return exit(1)
		}
		narrowScope = true
	}

	// tacplus only: build the module here for the host's OS release when we
	// can, so the host needs no compiler. Anything short of that falls back
	// to compiling on the host from the embedded source. A radius host
	// installs its distribution's package.
	prebuilt := ""
	switch {
	case method == hosts.Radius:
		if buildOnHost {
			a.Out.Warn("--build-on-host does not apply to method radius: the host installs pam_radius_auth from its package repositories.")
		}
	case buildOnHost:
		a.Out.Info("pam_tacplus will be compiled on the host (--build-on-host).")
	default:
		image, arch, ok := he.Platform(inv.ctx, target, port, identity)
		if inv.ctx.Err() != nil {
			return ui.ErrInterrupted
		}
		if !ok {
			break
		}
		here := hosts.Machine()
		switch {
		case image == "":
			a.Out.Info("No container image is known for this host's OS; pam_tacplus will be compiled on the host.")
		case arch != here:
			a.Out.InfoE("The host is " + arch + " and this server is " + here + "; pam_tacplus will be compiled on the host.")
		default:
			dir, err := he.Prebuilt(inv.ctx, image)
			switch {
			case err == nil:
				prebuilt = dir
			case errors.Is(err, hosts.ErrFailed):
				a.Out.Warn("pam_tacplus will be compiled on the host instead.")
			default:
				return err
			}
		}
	}

	script, err := hosts.TempFile()
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(script) }()
	req, err := inv.scriptRequest(scope, server, method, script)
	if err != nil {
		return err
	}
	req.Temp, req.Prebuilt = true, prebuilt
	if err := inv.homesToDelete(he, &req, name, target, port, identity, removeHome); err != nil {
		return err
	}
	consoleCheck := false
	if target == hosts.Local {
		if consoleCheck, err = inv.consoleForLocal(&req); err != nil {
			return err
		}
	}
	res, err := he.WriteScript(req)
	if err != nil {
		return inv.hostsDone(err)
	}
	how := ""
	if method != hosts.Tacplus {
		how = ", method " + method
	}
	if prevMethod != "" && prevMethod != method {
		a.Out.InfoE("Switching " + name + " from " + prevMethod + " to " + method + ".")
	}
	a.Out.InfoE("Enrolling " + name + " (" + target + ") in scope '" + scope + "', server " + server + how + "...")
	code, err := he.RunScript(inv.ctx, target, port, identity, script, scriptArgs)
	if err != nil {
		return err
	}
	if code != 0 {
		if prevMethod != "" {
			inv.recordRun(name, "enroll", "the client script failed on the host (exit status "+strconv.Itoa(code)+")", he)
			a.Out.ErrorE("Enrollment of " + name + " failed; its registration (method " + prevMethod + ") was left as it was.")
			if narrowScope {
				a.Out.WarnE("Scope '" + scope + "' is still open to " + strings.Join(scopeProtocols, ", ") + "; see 'tacctl scope protocols " + scope + "'.")
			}
		} else {
			a.Out.ErrorE("Enrollment of " + name + " failed; the host was not registered.")
		}
		return exit(1)
	}
	if err := reg.Remember(hosts.Entry{Name: name, Target: target, Port: port, Scope: scope, Server: server, Identity: identity, Method: method}); err != nil {
		return err
	}
	if narrowScope {
		// Not when the scope's auth-method is the other protocol: narrowing
		// would leave that setting pointing at a backend that ignores the scope.
		if auth := inv.scopeAuthMethod(scope); auth != "" && auth != be {
			a.Out.WarnE("Scope '" + scope + "' has auth-method " + auth + ", so it stays open to " + strings.Join(scopeProtocols, ", ") + " instead of being limited to " + be + ".")
			a.Out.WarnE("To limit it: tacctl scope auth-method " + scope + " " + be + "   then   tacctl scope protocols " + scope + " set " + be)
		} else if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "protocols="+be) }); err != nil {
			inv.reportOnly(err)
			a.Out.WarnE("Could not limit scope '" + scope + "' to " + be + "; see 'tacctl scope protocols " + scope + "'.")
		}
	}
	a.Logger(inv.ctx, "auth.info", "host enroll name="+name+" target="+target+" scope="+scope+" method="+method+" by="+inv.sudoUser())
	if he.Summary != nil {
		a.Out.InfoE("Host '" + name + "' enrolled (" + he.Summary.Counts() + ").")
	} else {
		a.Out.InfoE("Host '" + name + "' enrolled.")
	}
	he.PinKeys(inv.ctx, hosts.Entry{Name: name, Target: target, Port: port})
	inv.hostFacts(he, name, target, hostIP)
	inv.recordRun(name, "enroll", "", he)
	if consoleCheck {
		inv.consoleAfterLocal()
	}
	if res.Users == "" {
		inv.echo("")
		inv.echo("  No users are in scope '" + scope + "' yet. To give someone a login on this host:")
		inv.echo("    tacctl user scope <username> add " + scope)
		inv.echo("    tacctl host sync " + name)
		inv.echo("")
	}
	return nil
}

// hostScopeCovers checks that scope answers the requests of a host whose
// requests come from addr (127.0.0.1 for this server itself, which talks
// to its own daemons over loopback). For this server the address is
// certain, so another scope (or none) answering it is refused, printed:
// every login would be refused. For another host it is the address its name
// resolves to, which NAT may change, so it is a warning. ok is false only
// for the refusal; an address that cannot be read is not checked.
// unchanged says whether nothing has been changed yet (the refusal says
// so).
// hostDuplicate is the registered host, other than name, that addr (on
// port) already reaches: its recorded address, the address its target
// resolves to, or, for this server's own registration (--local), any of
// this machine's addresses. nil when there is none.
func (inv *invocation) hostDuplicate(reg *hosts.Registry, name, target, addr, port string) *hosts.Entry {
	if addr == "" {
		return nil
	}
	local := target == hosts.Local || isLocalAddress(addr)
	for _, e := range reg.Entries() {
		if e.Name == name {
			continue
		}
		if e.Target == hosts.Local {
			if local {
				e := e
				return &e
			}
			continue
		}
		if target == hosts.Local || e.Port != port {
			continue
		}
		if inv.hostAddress(e) == addr {
			e := e
			return &e
		}
		if host, _, ok := hosts.ScanTarget(e.Target, e.Port); ok && inv.resolveV4(host) == addr {
			e := e
			return &e
		}
	}
	return nil
}

// isLocalAddress is an address of this machine (loopback included).
func isLocalAddress(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// hostScopeOrigin names the address a host's logins come from: the one
// its name resolves to, or 127.0.0.1 for this server's own.
func hostScopeOrigin(name, target, hostPart, addr string) string {
	if target == hosts.Local {
		return addr + " (where this server's own logins come from)"
	}
	if hostPart == addr {
		return addr + " (" + name + ")"
	}
	return addr + " (" + hostPart + ")"
}

// hostNoScope refuses a host whose address no scope covers: every login of
// it would be refused. Nothing has changed yet.
func (inv *invocation) hostNoScope(name, target, hostPart, addr string) error {
	a := inv.app
	a.Out.ErrorE("No scope covers " + hostScopeOrigin(name, target, hostPart, addr) + ", so the server would refuse every login of '" + name + "'. Nothing was changed.")
	a.Out.ErrorE("Add the address to the scope the host belongs in:   tacctl scope prefixes <scope> add " + addr + "/32")
	a.Out.ErrorE("or give it a scope of its own (its own secret):    tacctl scope add linux-" + name + " --prefixes " + addr + "/32 --secret generate")
	again := "tacctl host enroll " + target
	if target == hosts.Local {
		again = "tacctl host enroll --local"
	}
	a.Out.ErrorE("then enroll it again:   " + again + " [--scope <scope>]")
	return exit(1)
}

func (inv *invocation) hostScopeCovers(name, target, addr, scope string, unchanged bool) bool {
	if addr == "" {
		return true
	}
	m, err := inv.model()
	if err != nil {
		return true
	}
	info, found := m.LookupAddr(addr)
	if found && info.Scope == scope {
		return true
	}
	a := inv.app
	answered := "no scope covers it"
	if found {
		answered = "scope '" + info.Scope + "' answers it (prefix " + info.Prefix + ")"
	}
	fix := "Add it to the scope: tacctl scope prefixes " + scope + " add " + addr + "/32"
	if target == hosts.Local {
		a.Out.ErrorE("Scope '" + scope + "' does not cover " + addr + ", the address this server's own logins reach TACACS+ and RADIUS from (" + answered + "), so every login of '" + name + "' would be refused.")
		a.Out.ErrorE(fix)
		if unchanged {
			a.Out.ErrorE("Nothing was changed.")
		} else {
			a.Out.ErrorE("Enrollment of " + name + " stopped; scope '" + scope + "' is kept, nothing ran on the host.")
		}
		return false
	}
	a.Out.WarnE("Scope '" + scope + "' does not cover " + addr + ", the address '" + name + "' resolves to (" + answered + "). If its requests come from that address, its logins are refused.")
	if found {
		fix += "   (or enroll it in that scope: --scope " + info.Scope + ")"
	}
	a.Out.WarnE(fix)
	return true
}

// hostAddress is the address a registered host's logins come from, as
// recorded at its last enroll or sync (127.0.0.1 for this server); else the
// address its target resolves to; "" when neither is known.
func (inv *invocation) hostAddress(e hosts.Entry) string {
	if e.Target == hosts.Local {
		return "127.0.0.1"
	}
	if f, err := devreg.Load(inv.app.Paths.DevicesFile); err == nil {
		if addr := f.HostAddressOf(e.Name); addr != "" {
			return addr
		}
	}
	if host, _, ok := hosts.ScanTarget(e.Target, e.Port); ok {
		return inv.resolveV4(host)
	}
	return ""
}

// hostScopeDrift is what is wrong with where a registered host's logins
// are answered: "" when its scope answers addr (or addr is unknown). The
// host is never moved here: a move changes its secret and deletes the
// accounts of the users it loses, so it is left to an enroll that names
// the scope.
func (inv *invocation) hostScopeDrift(e hosts.Entry, addr string) string {
	if addr == "" {
		return ""
	}
	m, err := inv.model()
	if err != nil {
		return ""
	}
	info, found := m.LookupAddr(addr)
	if !m.Exists("scopes", e.Scope) {
		msg := e.Name + ": registered in scope '" + e.Scope + "', which no longer exists"
		if found {
			return msg + "; " + addr + " is answered by scope '" + info.Scope + "' (prefix " + info.Prefix + "). To move it there: tacctl host move " + e.Name
		}
		return msg + ", and no scope covers " + addr + ". Add the address to a scope, then: tacctl host move " + e.Name + " <scope>"
	}
	switch {
	case found && info.Scope == e.Scope:
		return ""
	case !found:
		return e.Name + ": registered in scope '" + e.Scope + "', but no scope covers " + addr + ", so its logins are refused. Add it: tacctl scope prefixes " + e.Scope + " add " + addr + "/32"
	}
	return e.Name + ": registered in scope '" + e.Scope + "', but " + addr + " is answered by scope '" + info.Scope + "' (prefix " + info.Prefix +
		"): its logins are checked against that scope's users and secret, so they are refused. To move it: tacctl host move " + e.Name +
		"   (or answer it from its own scope again: tacctl scope prefixes " + e.Scope + " add " + addr + "/32)"
}

// hostDriftReport warns about every enrolled host another scope answers
// (after a prefix change), and names the move for them all.
func (inv *invocation) hostDriftReport() {
	reg, err := inv.registry()
	if err != nil {
		return
	}
	n := 0
	for _, e := range reg.Entries() {
		if msg := inv.hostScopeDrift(e, inv.hostAddress(e)); msg != "" {
			inv.app.Out.WarnE(msg)
			n++
		}
	}
	if n > 1 {
		inv.app.Out.WarnE("To move them all: tacctl host move --all")
	}
}

// hostMove is 'host move <name> [<scope>] | --all': an enroll of the
// registered host (its target, port, identity, server and method) into
// scope, by default the scope that answers its address. The enroll says
// what the move does to its accounts and asks before deleting any
// (--yes). --all moves every host whose address another scope answers.
func (inv *invocation) hostMove(args []string) error {
	a := inv.app
	var name, scope string
	all := false
	var pass []string
	for _, w := range args {
		switch {
		case w == "--all":
			all = true
		case w == "--yes" || w == "--remove-home" || w == "--allow-uid-mismatch":
			pass = append(pass, w)
		case strings.HasPrefix(w, "-"):
			return inv.usageErr("Unknown option: '"+w+"'", "Usage: tacctl host move <name> [<scope>] | --all  [--yes] [--remove-home] [--allow-uid-mismatch]")
		case name == "":
			name = w
		case scope == "":
			scope = w
		default:
			return inv.usageErr("Usage: tacctl host move <name> [<scope>] | --all  [--yes] [--remove-home] [--allow-uid-mismatch]")
		}
	}
	if all == (name != "") {
		return inv.usageErr("Usage: tacctl host move <name> [<scope>] | --all  [--yes] [--remove-home] [--allow-uid-mismatch]")
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	f := inv.callerScopes()
	if all {
		failed, moved := 0, 0
		for _, e := range reg.Entries() {
			if !f.allows(e.Scope) || inv.hostScopeDrift(e, inv.hostAddress(e)) == "" {
				continue
			}
			if err := inv.hostMoveOne(reg, e, "", pass); err != nil {
				if !isExit(err) {
					return err
				}
				failed++
				continue
			}
			moved++
		}
		if moved+failed == 0 {
			a.Out.InfoE("Every enrolled host is answered by its scope; nothing to move.")
			return nil
		}
		if failed > 0 {
			a.Out.ErrorE(fmt.Sprintf("%d host(s) moved, %d not.", moved, failed))
			return exit(1)
		}
		return nil
	}
	e, ok := reg.Find(name)
	if !ok || !f.allows(e.Scope) {
		return inv.usageErr("No enrolled host named '" + name + "'. See 'tacctl host list'.")
	}
	return inv.hostMoveOne(reg, e, scope, pass)
}

// hostEnrollAllowed is nil when the caller may enroll the host name in
// scope: always, but for an engineer (a caller the scope filter
// restricts, D18), who enrolls and moves hosts of their own scopes only,
// into their own scopes, and never this server itself (--local: its
// accounts and PAM are the administrators'; its sync is open to them).
func (inv *invocation) hostEnrollAllowed(reg *hosts.Registry, name, scope string, local bool) error {
	f := inv.callerScopes()
	if !f.restricted {
		return nil
	}
	if local {
		return inv.usageErr("Enrolling this server (--local) is not the engineer tier's; its sync is: tacctl host sync <name of this server>")
	}
	if e, ok := reg.Find(name); ok && e.Scope != "" && !f.allows(e.Scope) {
		return inv.usageErr("'" + name + "' is enrolled in scope '" + e.Scope + "', which is not one of yours. Nothing was changed.")
	}
	return inv.ownScope(f, scope)
}

// isExit is an error that only carries an exit status (its message, if
// any, already printed).
func isExit(err error) bool {
	var x *ExitError
	return errors.As(err, &x)
}

// hostMoveOne moves one registered host (see hostMove).
func (inv *invocation) hostMoveOne(reg *hosts.Registry, e hosts.Entry, scope string, pass []string) error {
	a := inv.app
	if scope == "" {
		addr := inv.hostAddress(e)
		m, err := inv.model()
		if err != nil {
			return err
		}
		info, found := m.LookupAddr(addr)
		if addr == "" {
			return inv.usageErr(e.Name + ": its address is not known; name the scope: tacctl host move " + e.Name + " <scope>")
		}
		if !found {
			return inv.usageErr(e.Name + ": no scope covers " + addr + "; add it to one, or name the scope: tacctl host move " + e.Name + " <scope>")
		}
		scope = info.Scope
	} else if exists, err := inv.scopeExists(scope); err != nil {
		return err
	} else if !exists {
		return inv.usageErr("Scope '" + scope + "' does not exist.")
	}
	if scope == e.Scope {
		a.Out.InfoE(e.Name + " is already in scope '" + scope + "'.")
		return nil
	}
	args := []string{e.Target}
	if e.Target == hosts.Local {
		args = []string{"--local"}
	}
	args = append(args, "--name", e.Name, "--scope", scope, "--server", e.Server, "--method", reg.Method(e.Name))
	if e.Port != "" {
		args = append(args, "--port", e.Port)
	}
	if e.Identity != "" {
		args = append(args, "--identity", e.Identity)
	}
	return inv.hostEnroll(append(args, pass...))
}

// confirmScopeMove says what moving a registered host from one scope to
// another does to its accounts and, when it deletes any, asks (a terminal)
// or wants --yes. Nothing has changed yet.
func (inv *invocation) confirmScopeMove(name, from, to string, yes bool) error {
	a := inv.app
	m, err := inv.model()
	if err != nil {
		return err
	}
	members := func(scope string) map[string]bool {
		set := map[string]bool{}
		for _, r := range m.LinuxUsers(scope) {
			n, _, _ := strings.Cut(r, "|")
			set[n] = true
		}
		for _, n := range m.LinuxInactive(scope) {
			set[n] = true
		}
		return set
	}
	before, after := members(from), members(to)
	var lose []string
	for n := range before {
		if !after[n] {
			lose = append(lose, n)
		}
	}
	sort.Strings(lose)
	a.Out.InfoE("Moving " + name + " from scope '" + from + "' to scope '" + to + "': it gets that scope's secret and users.")
	if len(lose) == 0 {
		return nil
	}
	a.Out.WarnE("These users of '" + from + "' are not users of '" + to + "'; their accounts on " + name + " are deleted: " + strings.Join(lose, ", "))
	if yes {
		return nil
	}
	if p := a.Prompter(); p.Interactive() {
		if p.Confirm("Move " + name + " to '" + to + "' and delete those accounts? [y/N] ") {
			return nil
		}
		a.Out.InfoE("Nothing was changed.")
		return exit(1)
	}
	return inv.usageErr("Moving " + name + " to scope '" + to + "' deletes accounts; nothing was changed. Confirm with --yes.")
}

// localScopeWarning is the sync's word on this server's own scope: when
// it no longer covers 127.0.0.1 (a prefix removed, another scope shadowing
// it), the accounts are synced but nobody can log in.
func (inv *invocation) localScopeWarning(e hosts.Entry) {
	if msg := inv.localScopeDrift(e); msg != "" {
		inv.app.Out.WarnE(msg)
	}
}

// localScopeDrift is the warning about this server's own registration e
// when its scope does not answer 127.0.0.1 ("" when it does).
func (inv *invocation) localScopeDrift(e hosts.Entry) string {
	m, err := inv.model()
	if err != nil {
		return ""
	}
	if info, found := m.LookupAddr("127.0.0.1"); !found || info.Scope != e.Scope {
		return e.Name + ": scope '" + e.Scope + "' does not cover 127.0.0.1, where this server's own logins come from, so they are refused. Add it: tacctl scope prefixes " + e.Scope + " add 127.0.0.1/32"
	}
	return ""
}

// isRegularFile is '[[ -f <path> ]]'.
func isRegularFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// --- sync --------------------------------------------------------------------------

// hostSync is cmd_host_sync.
func (inv *invocation) hostSync(args []string) error {
	a := inv.app
	which, removeHome := "", false
	scriptArgs := []string{"--accounts-only"}
	for i := 0; i < len(args); {
		switch w := args[i]; {
		case w == "--allow-uid-mismatch":
			scriptArgs = append(scriptArgs, w)
			i++
		case w == "--remove-home":
			removeHome = true
			i++
		case w == "--all":
			which = "--all"
			i++
		case strings.HasPrefix(w, "-"):
			return inv.usageErr("Unknown option: '" + w + "'")
		default:
			which = w
			i++
		}
	}
	if which == "" {
		return inv.usageErr("Usage: tacctl host sync <name> | --all  [--allow-uid-mismatch] [--remove-home]")
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	var names []string
	f := inv.callerScopes()
	if which == "--all" {
		if reg.Exists() {
			// An engineer syncs the hosts of their own scopes.
			for _, n := range reg.Names() {
				if e, _ := reg.Find(n); f.allows(e.Scope) {
					names = append(names, n)
				}
			}
		}
		if len(names) == 0 {
			a.Out.Info("No hosts enrolled.")
			return nil
		}
	} else {
		if e, ok := reg.Find(which); !ok || e.Line == "" || !f.allows(e.Scope) {
			return inv.usageErr("No enrolled host named '" + which + "'. See 'tacctl host list'.")
		}
		names = []string{which}
	}

	if err := inv.renumberUIDs(true); err != nil {
		return err
	}
	he := inv.hostsEnv()
	he.ReadKeys = true
	failed := false
	for _, name := range names {
		e, _ := reg.Find(name)
		method := reg.Method(name)
		exists, err := inv.scopeExists(e.Scope)
		if err != nil {
			return err
		}
		if !exists {
			a.Out.ErrorE(name + ": scope '" + e.Scope + "' no longer exists; skipped.")
			inv.recordRun(name, "sync", "its scope '"+e.Scope+"' no longer exists", nil)
			failed = true
			continue
		}
		if e.Target != hosts.Local {
			if login, _, isUser, err := inv.provisioningLogin(e.Target); err != nil {
				return err
			} else if isUser {
				a.Out.Warn(name + ": the provisioning account '" + login + "' is a tacctl user; re-enrol with a local account that does not authenticate through tacctl: tacctl host enroll <account>@<host> --name " + name)
			}
		}
		ok, err := inv.syncOne(he, e, method, scriptArgs, removeHome)
		if err != nil {
			return err
		}
		if !ok {
			a.Out.ErrorE(name + ": sync failed (see the host's output above; nothing was changed there if it reported a conflict).")
			failed = true
		}
	}
	if failed {
		return exit(1)
	}
	return nil
}

// provisioningLogin is the account 'host' logs in to target with: the
// target's user, else the invoking user (ssh's default; root without
// sudo). isUser reports whether it is a tacctl user: provisioning must use a
// local account that does not authenticate through tacctl ('host enroll'
// refuses one, 'host sync' warns). 'tacctl ssh' never uses it.
func (inv *invocation) provisioningLogin(target string) (login string, explicit, isUser bool, err error) {
	if u, _, ok := strings.Cut(target, "@"); ok {
		login, explicit = u, true
	} else {
		login = inv.sudoUser()
	}
	m, err := inv.model()
	if err != nil {
		return login, explicit, false, err
	}
	return login, explicit, m.User(login) != nil, nil
}

// syncOne pushes an accounts-only script to one host and runs it; ok is
// false when the script could not be written or failed there. The run is
// recorded for 'host show', failed or not.
func (inv *invocation) syncOne(he *hosts.Env, e hosts.Entry, method string, scriptArgs []string, removeHome bool) (bool, error) {
	ok, reason, ran, err := inv.syncRun(he, e, method, scriptArgs, removeHome)
	switch {
	case errors.Is(err, ui.ErrInterrupted):
		reason = "interrupted"
	case err != nil:
		reason = strings.Join(msgs(err), " ")
	}
	var run *hosts.Env
	if ran {
		run = he
	}
	inv.recordRun(e.Name, "sync", reason, run)
	return ok, err
}

// syncRun is syncOne's run: reason says why it failed, ran whether the
// client script ran on the host.
func (inv *invocation) syncRun(he *hosts.Env, e hosts.Entry, method string, scriptArgs []string, removeHome bool) (ok bool, reason string, ran bool, err error) {
	// A host that cannot hold the range gets no account changes.
	if err := he.CheckIDMap(inv.ctx, e.Name, e.Target, e.Port, e.Identity); errors.Is(err, hosts.ErrFailed) {
		return false, "the host cannot hold the UID range " + he.UIDRange().String(), false, nil
	} else if err != nil {
		return false, "", false, err
	}
	script, err := hosts.TempFile()
	if err != nil {
		return false, "", false, err
	}
	defer func() { _ = os.Remove(script) }()
	req, err := inv.scriptRequest(e.Scope, e.Server, method, script)
	if err != nil {
		return false, "", false, err
	}
	req.Temp, req.AccountsOnly = true, true
	if err := inv.homesToDelete(he, &req, e.Name, e.Target, e.Port, e.Identity, removeHome); err != nil {
		return false, "", false, err
	}
	consoleCheck := false
	if e.Target == hosts.Local {
		inv.localScopeWarning(e)
		if consoleCheck, err = inv.consoleForLocal(&req); err != nil {
			return false, "", false, err
		}
	}
	res, err := he.WriteScript(req)
	if errors.Is(err, hosts.ErrFailed) {
		return false, "the client script could not be written", false, nil
	}
	if err != nil {
		return false, "", false, err
	}
	code, err := he.RunScript(inv.ctx, e.Target, e.Port, e.Identity, script, scriptArgs)
	if err != nil {
		return false, "", true, err
	}
	if code != 0 {
		return false, "the client script failed on the host (exit status " + strconv.Itoa(code) + ")", true, nil
	}
	counts := hosts.UsersText(hosts.CountLines(res.Users))
	if he.Summary != nil {
		counts = he.Summary.Counts()
	}
	inv.app.Out.InfoE(e.Name + ": synced (" + counts + ").")
	he.PinKeys(inv.ctx, e)
	resolved := "127.0.0.1"
	if host, _, ok := hosts.ScanTarget(e.Target, e.Port); ok {
		resolved = inv.resolveV4(host)
	}
	inv.hostFacts(he, e.Name, e.Target, resolved)
	if e.Target != hosts.Local {
		addr := inv.hostAddress(e)
		if addr == "" {
			addr = resolved
		}
		if msg := inv.hostScopeDrift(e, addr); msg != "" {
			inv.app.Out.WarnE(msg)
		}
	}
	if consoleCheck {
		inv.consoleAfterLocal()
	}
	return true, "", true, nil
}

// homesToDelete fills in which removed users' home directories the script
// deletes: every one with --remove-home; else the ones the operator answers
// yes for on the terminal (stdin), one question per removed user of the
// host; with no terminal none (the script keeps them and says so).
func (inv *invocation) homesToDelete(he *hosts.Env, req *hosts.ScriptRequest, name, target, port, identity string, removeHome bool) error {
	if removeHome {
		req.RemoveAllHomes = true
		return nil
	}
	var ask func(string) string
	if p := inv.app.Prompter(); p.Interactive() {
		ask = p.Ask
	}
	current := map[string]bool{}
	for _, r := range req.Rows {
		n, _, _ := strings.Cut(r, "|")
		current[n] = true
	}
	for _, n := range req.Inactive {
		current[n] = true
	}
	homes, err := he.HomesToDelete(inv.ctx, name, target, port, identity, current, ask)
	req.RemoveHomes = homes
	return err
}

// --- unenroll ------------------------------------------------------------------------

// hostUnenroll is cmd_host_unenroll.
func (inv *invocation) hostUnenroll(args []string) error {
	a := inv.app
	name, force := "", false
	for _, w := range args {
		switch {
		case w == "--force":
			force = true
		case strings.HasPrefix(w, "-"):
			return inv.usageErr("Unknown option: '" + w + "'")
		default:
			name = w
		}
	}
	if name == "" {
		return inv.usageErr("Usage: tacctl host unenroll <name> [--force]")
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	e, ok := reg.Find(name)
	if !ok || e.Line == "" {
		return inv.usageErr("No enrolled host named '" + name + "'. See 'tacctl host list'.")
	}
	label := hosts.MethodLabel(reg.Method(name))
	a.Out.InfoE("Removing " + label + " authentication from " + name + " (" + e.Target + ")...")

	script, err := hosts.TempFile()
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(script) }()
	if err := hosts.WriteRemoveScriptTo(script); err != nil {
		return err
	}
	code, err := inv.hostsEnv().RunScript(inv.ctx, e.Target, e.Port, e.Identity, script, nil)
	if err != nil {
		return err
	}
	if code != 0 {
		if !force {
			return inv.usageErr("Removal on " + name + " failed; it is still registered. Fix the cause, or pass --force to forget the host anyway.")
		}
		a.Out.WarnE("Removal on " + name + " failed; forgetting the host anyway (--force).")
	}
	if err := reg.Forget(name); err != nil {
		return err
	}
	inv.forgetHostKeys(name)
	if err := inv.hostRecords().Forget(name); err != nil {
		a.Out.WarnE(name + ": its record (" + inv.app.Paths.HostRecords + "/" + name + ".json) could not be removed: " + strings.Join(msgs(err), " "))
	}
	if e.Target == hosts.Local {
		// The remove script gave tacctl's accounts /bin/bash back; the
		// console's pieces go now (refused, and said, while an account
		// still has the console).
		_ = inv.consoleDeprovision()
	}
	a.Logger(inv.ctx, "auth.info", "host unenroll name="+name+" target="+e.Target+" by="+inv.sudoUser())
	a.Out.InfoE("Host '" + name + "' unenrolled. Local accounts and home directories were left in place.")
	if !reg.ScopeInUse(e.Scope) {
		inv.echo("")
		inv.echo("  No enrolled host uses scope '" + e.Scope + "' any more. To stop its secret being accepted:")
		inv.echo("    tacctl scope remove " + e.Scope)
		inv.echo("")
	}
	return nil
}

// --- default-method ------------------------------------------------------------------

// hostDefaultMethod is cmd_host_default_method: show or set the method
// 'host enroll' and 'config linux script' use when --method is not given
// (host.default_method in tacctl.yaml). A registered host keeps its own
// method when re-enrolled.
func (inv *invocation) hostDefaultMethod(args []string) error {
	a := inv.app
	method := arg(args, 0)
	if method == "" {
		inv.echo("")
		inv.echo("  Default method for new hosts: " + inv.linuxDefaultMethod())
		inv.echo("")
		inv.echo("  Usage: tacctl host default-method <" + strings.Join(hosts.Methods, "|") + ">")
		inv.echo("")
		return nil
	}
	id, ok := hosts.MethodBackend(method)
	if !ok {
		return inv.usageErr("Unknown method '" + method + "'. Methods: " + hosts.MethodList())
	}
	if err := a.Conf().Set("host.default_method", method); err != nil {
		return err
	}
	a.Out.InfoE("New hosts are enrolled with method '" + method + "' unless --method says otherwise.")
	ids, err := a.Backends().Enabled()
	if err != nil {
		return nil
	}
	if !contains(ids, id) {
		a.Out.Warn("The " + hosts.MethodLabel(method) + " backend is not enabled yet: tacctl backend enable " + id)
	}
	return nil
}
