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
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

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
	"enroll": {MaxArgs: 1, Args: []string{""}, Flags: []Flag{
		{Names: []string{"--local"}},
		{Names: []string{"--scope"}, Value: true, Kind: KindScopes},
		{Names: []string{"--server"}, Value: true},
		{Names: []string{"--name"}, Value: true},
		{Names: []string{"--port"}, Value: true},
		{Names: []string{"--identity"}, Value: true, Kind: KindFile},
		{Names: []string{"--method"}, Value: true, Kind: methodWords},
		{Names: []string{"--build-on-host"}},
		flagAllowUIDMismatch, flagRemoveHome}},
	"sync":     {MaxArgs: 1, Args: []string{KindHosts}, Flags: []Flag{{Names: []string{"--all"}}, flagAllowUIDMismatch, flagRemoveHome}},
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
	{"enroll <[user@]host> | --local [options]", "Install TACACS+ or RADIUS login on a host over SSH and register it"},
	{"sync <name> | --all [options]", "Push account adds, deletions and tier changes"},
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
	case "enroll":
		return inv.hostEnroll(rest)
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
	isLocal, buildOnHost, removeHome := false, false, false
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
	if identity != "" {
		if st, err := os.Stat(identity); err != nil || !st.Mode().IsRegular() {
			return inv.usageErr("Identity file '" + identity + "' not found.")
		}
	}

	// The method: the one asked for; else the one a registered host has (so
	// re-enrolling never switches a host by accident); else what the scope
	// the host will use says (the one named with --scope, or an existing
	// linux-<name>; a scope created below says nothing): its auth-method,
	// else the one protocol its protocols filter names; else the default.
	// Re-enrolling with the other method is how a host switches.
	prevMethod := reg.Method(name)
	var scopeMethod, scopeWhy string
	lookAt := scope
	if lookAt == "" {
		lookAt = "linux-" + name
	}
	if exists, err := inv.scopeExists(lookAt); err == nil && exists {
		scopeMethod, scopeWhy = inv.linuxScopeMethod(lookAt)
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

	// Each host gets its own scope (its address as a /32, its own secret)
	// unless told to share one, so a secret read off one host is useless
	// from any other. A scope created here serves the method's protocol
	// only. One found from an earlier enroll of this host with the other
	// method is opened to both for the switch and narrowed to the new one
	// once the host has switched; a scope other hosts use, or one named with
	// --scope, is never changed here.
	if scope != "" {
		if err := inv.scopeRequire(scope); err != nil {
			return err
		} else if ok, err := inv.linuxScopeServes(scope, method); err != nil {
			return err
		} else if !ok {
			return exit(1)
		}
		// The scope must be the one that answers the host's requests.
		if !inv.hostScopeCovers(name, target, hostIP, scope, true) {
			return exit(1)
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

	both := strings.Join(scopeProtocols, ",")
	narrowScope := false
	scopeGiven := scope != ""
	if scope == "" {
		scope = "linux-" + name
		exists, err := inv.scopeExists(scope)
		if err != nil {
			return err
		}
		if exists {
			a.Out.InfoE("Using existing scope '" + scope + "'.")
			protocols, err := inv.linuxScopeProtocols(scope)
			if err != nil {
				return err
			}
			if protocols != "" && !strings.Contains(","+protocols+",", ","+be+",") {
				if reg.OtherHostsUse(scope, name) {
					if _, err := inv.linuxScopeServes(scope, method); err != nil {
						return err
					}
					return inv.usageErr("Other enrolled hosts use scope '" + scope + "', so it is not changed here.")
				}
				a.Out.InfoE("Scope '" + scope + "' was limited to " + protocols + "; opening it to " + be + " for this host.")
				if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "protocols="+both) }); err != nil {
					// 'store_apply ... || return 1'.
					inv.reportOnly(err)
					return exit(1)
				}
				narrowScope = true
			}
		} else {
			a.Out.InfoE("Creating scope '" + scope + "' for " + hostIP + "/32...")
			if err := inv.discardStdout(func() error {
				return inv.scopeAdd([]string{scope, "--prefixes", hostIP + "/32", "--secret", "generate", "--protocols", be})
			}); err != nil {
				return err
			}
		}
	}

	// linux-<name> holds the host's /32, but an earlier prefix of another
	// scope can still answer it.
	if !scopeGiven && !inv.hostScopeCovers(name, target, hostIP, scope, false) {
		return exit(1)
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
		a.Out.ErrorE(fix + "   (or enroll without --scope: scope linux-" + name + ")")
		if unchanged {
			a.Out.ErrorE("Nothing was changed.")
		} else {
			a.Out.ErrorE("Enrollment of " + name + " stopped; scope '" + scope + "' is kept, nothing ran on the host.")
		}
		return false
	}
	a.Out.WarnE("Scope '" + scope + "' does not cover " + addr + ", the address '" + name + "' resolves to (" + answered + "). If its requests come from that address, its logins are refused.")
	a.Out.WarnE(fix)
	return true
}

// localScopeWarning is the sync's word on this server's own scope: when
// it no longer covers 127.0.0.1 (a prefix removed, another scope shadowing
// it), the accounts are synced but nobody can log in.
func (inv *invocation) localScopeWarning(e hosts.Entry) {
	m, err := inv.model()
	if err != nil {
		return
	}
	if info, found := m.LookupAddr("127.0.0.1"); !found || info.Scope != e.Scope {
		inv.app.Out.WarnE(e.Name + ": scope '" + e.Scope + "' does not cover 127.0.0.1, where this server's own logins come from, so they are refused. Add it: tacctl scope prefixes " + e.Scope + " add 127.0.0.1/32")
	}
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
	if which == "--all" {
		if reg.Exists() {
			names = reg.Names()
		}
		if len(names) == 0 {
			a.Out.Info("No hosts enrolled.")
			return nil
		}
	} else {
		if e, ok := reg.Find(which); !ok || e.Line == "" {
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
// false when the script could not be written or failed there.
func (inv *invocation) syncOne(he *hosts.Env, e hosts.Entry, method string, scriptArgs []string, removeHome bool) (bool, error) {
	// A host that cannot hold the range gets no account changes.
	if err := he.CheckIDMap(inv.ctx, e.Name, e.Target, e.Port, e.Identity); errors.Is(err, hosts.ErrFailed) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	script, err := hosts.TempFile()
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(script) }()
	req, err := inv.scriptRequest(e.Scope, e.Server, method, script)
	if err != nil {
		return false, err
	}
	req.Temp, req.AccountsOnly = true, true
	if err := inv.homesToDelete(he, &req, e.Name, e.Target, e.Port, e.Identity, removeHome); err != nil {
		return false, err
	}
	consoleCheck := false
	if e.Target == hosts.Local {
		inv.localScopeWarning(e)
		if consoleCheck, err = inv.consoleForLocal(&req); err != nil {
			return false, err
		}
	}
	res, err := he.WriteScript(req)
	if errors.Is(err, hosts.ErrFailed) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	code, err := he.RunScript(inv.ctx, e.Target, e.Port, e.Identity, script, scriptArgs)
	if err != nil {
		return false, err
	}
	if code != 0 {
		return false, nil
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
	if consoleCheck {
		inv.consoleAfterLocal()
	}
	return true, nil
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
