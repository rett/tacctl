package cli

// 'config linux' (lib/linux_hosts.sh cmd_config_linux at 0.1.16), native
// since WP3.2: build, script, remove-script, uid and builds. The family is
// handed to config.go's tree with registerConfigVerb, so its preflight rule
// (bin/tacctl.sh runs preflight before every 'config' verb but render) and
// its place in the config usage stay config.go's. The helpers shared with
// 'host' (method, scope and listener reads, the hosts.Env of the
// invocation) are here too.

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerConfigVerb("linux", configLinuxFamilySpec, configLinuxCmd)
}

// configLinuxFamilySpec is the spec of 'config linux' as config.go's
// registerConfigVerb takes it.
var configLinuxFamilySpec = Spec{MaxArgs: -1, Args: []string{"build|script|remove-script|uid|uid-range|builds", ""}}

// methodWords are the methods as a completion word list.
const methodWords = "tacplus|radius"

// configLinuxSpecs are the arguments of each verb, for completion (args.go).
var configLinuxSpecs = map[string]Spec{
	"build": {MaxArgs: -1},
	"script": {Flags: []Flag{
		{Names: []string{"--scope"}, Value: true, Kind: KindScopes},
		{Names: []string{"--server"}, Value: true},
		{Names: []string{"--method"}, Value: true, Kind: methodWords},
		{Names: []string{"--output", "-o"}, Value: true, Kind: KindFile}}},
	"remove-script": {Flags: []Flag{{Names: []string{"--output", "-o"}, Value: true, Kind: KindFile}}},
	"uid":           {MaxArgs: 2, Args: []string{KindUsers, ""}},
	"uid-range":     {MaxArgs: 1},
	"builds":        {MaxArgs: 1, Args: []string{"list|clear"}},
}

// configLinuxVerbs are the verbs ({Use, Short}), in usage order.
var configLinuxVerbs = [][2]string{
	{"build", "Fetch and prepare the pinned pam_tacplus source (once, and after upgrades)"},
	{"script [--scope <name>] [--server <address>] [--method tacplus|radius] [--output <file>]",
		"Write the install script for hosts in a scope (contains the secret)"},
	{"remove-script [--output <file>]", "Write the removal script (no secrets; accounts are left in place)"},
	{"uid [<username> [<uid>]]", "Show or change the UID/GID a user gets on every host"},
	{"uid-range [<min>-<max>]", "Show or change the UID range of all hosts (default 80000-89999)"},
	{"builds [list|clear]", "Show or drop the modules 'host enroll' built in containers"},
}

// configLinuxCmd builds 'config linux': the family word runs the
// dispatcher with its arguments, each verb runs it with the verb put back
// in front.
func configLinuxCmd(inv *invocation) *cobra.Command {
	c := verb("linux <subcommand>", "TACACS+ or RADIUS login for Linux hosts (install/removal scripts)")
	c.RunE = inv.native(withPreflight, inv.configLinux)
	for _, v := range configLinuxVerbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.configLinux(append([]string{word}, args...))
		})))
	}
	return c
}

// configLinuxUsage is cmd_config_linux's usage block.
func configLinuxUsage() string { return Usage("config-linux", nil) }

// configLinux is cmd_config_linux: no sub-command is the usage (exit 0),
// an unknown one the usage too (exit 1, no error line).
func (inv *invocation) configLinux(args []string) error {
	rest := []string{}
	if len(args) > 1 {
		rest = args[1:]
	}
	switch arg(args, 0) {
	case "build":
		return inv.hostsDone(inv.hostsEnv().BuildTarball(inv.ctx))
	case "script":
		return inv.configLinuxScript(rest)
	case "remove-script":
		return inv.configLinuxRemoveScript(rest)
	case "uid":
		return inv.configLinuxUID(rest)
	case "uid-range":
		return inv.configLinuxUIDRange(rest)
	case "builds":
		return inv.configLinuxBuilds(rest)
	case "":
		inv.write(configLinuxUsage())
		return nil
	}
	inv.write(configLinuxUsage())
	return exit(1)
}

// --- shared with 'host' -------------------------------------------------------

// hostsEnv is the hosts.Env of this invocation. ssh and podman run as the
// user who invoked sudo (SUDO_USER, when tacctl runs as root for someone
// other than root), with their agent socket. The tier gate before every
// command has refused a SUDO_USER that is not SUDO_UID's account.
func (inv *invocation) hostsEnv() *hosts.Env {
	a := inv.app
	rng, _ := inv.configuredUIDRange()
	asUser := ""
	if u := a.Env.Get("SUDO_USER"); a.EUID == 0 && u != "" && u != "root" {
		asUser = u
	}
	return &hosts.Env{
		Paths:    hosts.Paths{Dir: a.Paths.LinuxDir, VarLib: a.Paths.VarLib, UIDs: a.Paths.LinuxUIDs, Hosts: a.Paths.LinuxHosts, LoginDefs: a.Paths.LoginDefs, ProcSelf: a.Knobs.ProcSelf()},
		Range:    rng,
		Runner:   a.Runner,
		Out:      a.Out,
		Stdin:    a.Stdin,
		AsUser:   asUser,
		AuthSock: a.Env.Get("SSH_AUTH_SOCK"),
		Now:      a.Knobs.Now,
		// host enroll and host sync pin the host's ssh keys in the registry.
		PinHostKeys: inv.pinHostKeys,
	}
}

// configuredUIDRange is the UID range of tacctl.yaml (linux.uid_min,
// linux.uid_max; hosts.DefaultRange's numbers when unset) and why it cannot
// be used ("" when it can).
func (inv *invocation) configuredUIDRange() (hosts.Range, string) {
	lo := inv.confGet("linux.uid_min", strconv.Itoa(hosts.DefaultRange.Min))
	hi := inv.confGet("linux.uid_max", strconv.Itoa(hosts.DefaultRange.Max))
	r, ok := hosts.ParseRange(lo + "-" + hi)
	if !ok {
		return hosts.DefaultRange, "linux.uid_min and linux.uid_max must be whole numbers (they are '" + lo + "' and '" + hi + "')"
	}
	return r, hosts.RangeProblem(r)
}

// uidRange is configuredUIDRange for a command that uses it: a range that
// cannot be used stops the command (exit 1).
func (inv *invocation) uidRange() (hosts.Range, error) {
	r, problem := inv.configuredUIDRange()
	if problem != "" {
		inv.app.Out.ErrorE("The Linux UID range in tacctl.yaml (" + r.String() + ") cannot be used: " + problem + ".")
		inv.app.Out.ErrorE("Set one that can: tacctl config linux uid-range <min>-<max>")
		return r, exit(1)
	}
	return r, nil
}

// renumberUIDs numbers the UID file for the configured range
// (hosts.UIDs.RenumberTo), run by every command that reads or writes the
// file: 'config linux uid', 'config linux script', 'host enroll' and
// 'host sync'. A script must never carry a number of another range (its
// body renumbers the host's accounts to the server's numbers, which
// therefore must be renumbered first), and a listing must show the numbers
// hosts get; so it happens at the first of them, not at one chosen verb:
// after an upgrade from a release that gave out UIDs from 20000 up, and
// after the range is changed by hand in tacctl.yaml ('config linux
// uid-range' renumbers at once). Once the file is numbered for the range
// it changes nothing. With entries moved, the old file is kept next to it
// (<file>.pre-renumber-<UTC time>) and the change is logged ('uid-map
// renumbered <n> entries'). A renumbering that cannot be done (a number
// that is another name's, a range too small, one that overlaps a range the
// file was numbered for) changes nothing: printed as errors and exit 1
// when refuse is set, as warnings (and the command goes on) when not, so
// 'config linux uid' can still give a name another number.
func (inv *invocation) renumberUIDs(refuse bool) error {
	a := inv.app
	r, err := inv.uidRange()
	if err != nil {
		return err
	}
	uids := hosts.UIDs{Path: a.Paths.LinuxUIDs, Range: r}
	backup := uids.Path + ".pre-renumber-" + a.Knobs.Now().UTC().Format("20060102-150405")
	res, err := uids.RenumberTo(backup, false)
	if msgs := inv.renumberProblem(uids.Path, res.From, r, err); msgs != nil {
		say := a.Out.WarnE
		if refuse {
			say = a.Out.ErrorE
		}
		for _, m := range msgs {
			say(m)
		}
		if refuse {
			return exit(1)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if res.N > 0 {
		inv.renumbered(uids.Path, res, r, backup)
	}
	return nil
}

// renumbered says and logs that n entries moved.
func (inv *invocation) renumbered(path string, res hosts.Renumbering, to hosts.Range, backup string) {
	entries := strconv.Itoa(res.N) + " entries"
	if res.N == 1 {
		entries = "1 entry"
	}
	inv.app.Out.InfoE("Renumbered " + entries + " of " + path + " from " + res.From.String() + " to " + to.String() + " (the same offset; the old file is kept as " + backup + "). Hosts renumber the accounts tacctl created at their next enroll or sync.")
	inv.app.Logger(inv.ctx, "auth.info", "uid-map renumbered "+strconv.Itoa(res.N)+" entries from="+res.From.String()+" to="+to.String()+" backup="+backup)
}

// renumberProblem is what to print for a renumbering hosts.UIDs.RenumberTo
// refused (nil for any other error).
func (inv *invocation) renumberProblem(path string, from, to hosts.Range, err error) []string {
	head := "Cannot renumber " + path + " from " + from.String() + " to " + to.String() + ": "
	var c *hosts.UIDCollision
	var small *hosts.RangeTooSmall
	var over *hosts.RangeOverlap
	switch {
	case errors.As(err, &c):
		return []string{head + "'" + c.Name + "' (" + c.Old + ") would become " + c.New + ", which is already assigned to '" + c.Holder + "'. Nothing was changed.",
			"Give '" + c.Holder + "' another number first: tacctl config linux uid " + c.Holder + " <uid>"}
	case errors.As(err, &small):
		return []string{head + "'" + small.Name + "' (" + small.UID + ") would become " + strconv.Itoa(small.New) + ", past its end. Nothing was changed.",
			"Choose a range that holds every number given out: tacctl config linux uid-range <min>-<max>"}
	case errors.As(err, &over):
		return []string{head + "it overlaps " + over.With.String() + ", a range the file was numbered for (hosts may still have accounts there). Nothing was changed.",
			"Choose a range clear of it, or one that starts at " + strconv.Itoa(from.Min) + ": tacctl config linux uid-range <min>-<max>"}
	}
	return nil
}

// configLinuxUIDRange is 'config linux uid-range [<min>-<max>]': show the
// range, or change it. A change is checked first (hosts.RangeProblem, and
// whether the UID file can be renumbered for it), then written to
// tacctl.yaml, then the file is renumbered; nothing changes when a check
// fails. Hosts renumber their accounts at their next enroll or sync.
func (inv *invocation) configLinuxUIDRange(args []string) error {
	a := inv.app
	cur, problem := inv.configuredUIDRange()
	uids := hosts.UIDs{Path: a.Paths.LinuxUIDs, Range: cur}
	v := arg(args, 0)
	if v == "" {
		src := "default"
		if a.Conf().HasOverride("linux.uid_min") || a.Conf().HasOverride("linux.uid_max") {
			src = "tacctl.yaml"
		}
		inv.echo("")
		inv.echo("  Linux UID range: " + cur.String() + " (" + src + "; one range for all hosts)")
		if problem != "" {
			inv.echo("  Cannot be used: " + problem + ".")
		}
		if rec, prev, err := uids.Recorded(); err == nil && !rec.IsZero() {
			line := "  " + uids.Path + " is numbered for " + rec.String()
			if len(prev) > 0 {
				words := make([]string, len(prev))
				for i, p := range prev {
					words[i] = p.String()
				}
				line += " (before: " + strings.Join(words, ", ") + ")"
			}
			inv.echo(line)
		}
		inv.echo("")
		inv.echo("  Usage: tacctl config linux uid-range <min>-<max>")
		inv.echo("")
		return nil
	}
	r, ok := hosts.ParseRange(v)
	if !ok || len(args) > 1 {
		return inv.usageErr("Usage: tacctl config linux uid-range <min>-<max>   (for example 80000-89999)")
	}
	if p := hosts.RangeProblem(r); p != "" {
		return inv.usageErr("Cannot use UID range " + r.String() + ": " + p + ".")
	}
	if w := hosts.RangeWarning(r); w != "" {
		a.Out.WarnE(w)
	}
	uids.Range = r
	backup := uids.Path + ".pre-renumber-" + a.Knobs.Now().UTC().Format("20060102-150405")
	res, err := uids.RenumberTo(backup, true)
	if msgs := inv.renumberProblem(uids.Path, res.From, r, err); msgs != nil {
		for _, m := range msgs {
			a.Out.ErrorE(m)
		}
		return exit(1)
	}
	if err != nil {
		return err
	}
	if err := a.Conf().Set("linux.uid_min", strconv.Itoa(r.Min)); err != nil {
		return err
	}
	if err := a.Conf().Set("linux.uid_max", strconv.Itoa(r.Max)); err != nil {
		return err
	}
	if res, err = uids.RenumberTo(backup, false); err != nil {
		return err
	}
	if res.N > 0 {
		inv.renumbered(uids.Path, res, r, backup)
	}
	a.Out.InfoE("Linux UID range set to " + r.String() + " (was " + cur.String() + "). Hosts renumber the accounts tacctl created at their next enroll or sync.")
	a.Logger(inv.ctx, "auth.info", "uid-range set from="+cur.String()+" to="+r.String())
	return nil
}

// hostsDone maps a hosts error: ErrFailed (printed) is exit 1.
func (inv *invocation) hostsDone(err error) error {
	if errors.Is(err, hosts.ErrFailed) {
		return exit(1)
	}
	return err
}

// verifySudoUser refuses a SUDO_USER that is not the account of SUDO_UID
// (tier.VerifyCaller), for the commands that run programs as SUDO_USER
// ('host', 'tacctl ssh'). The tier gate has refused one already; this is
// the same check where the name is acted on.
func (inv *invocation) verifySudoUser(what string) error {
	a := inv.app
	u, uid := a.Env.Get("SUDO_USER"), a.Env.Get("SUDO_UID")
	if tier.VerifyCaller(inv.ctx, a.Runner, u, uid) != nil {
		return inv.usageErr("SUDO_USER '" + u + "' is not the account of SUDO_UID " + uid + "; " + what + " will not run ssh as it")
	}
	return nil
}

// sudoUser is ${SUDO_USER:-root}, for the audit lines.
func (inv *invocation) sudoUser() string {
	if u := inv.app.Env.Get("SUDO_USER"); u != "" {
		return u
	}
	return "root"
}

// linuxDefaultMethod is linux_default_method: host.default_method when it
// names a method, else tacplus.
func (inv *invocation) linuxDefaultMethod() string {
	m := inv.confGet("host.default_method", hosts.Tacplus)
	if _, ok := hosts.MethodBackend(m); !ok {
		return hosts.Tacplus
	}
	return m
}

// linuxMethodRequire is linux_method_require: the method is known and its
// backend enabled, else the reason is printed (exit 1).
func (inv *invocation) linuxMethodRequire(method string) error {
	id, ok := hosts.MethodBackend(method)
	if !ok {
		return inv.usageErr("Unknown method '" + method + "'. Methods: " + hosts.MethodList())
	}
	ids, err := inv.app.Backends().Enabled()
	if err != nil {
		return inv.usageErr(err.Error())
	}
	if !contains(ids, id) {
		return inv.usageErr("Method '"+method+"' needs the "+hosts.MethodLabel(method)+" backend, which is not enabled on this server.",
			"Enable it first: tacctl backend enable "+id)
	}
	return nil
}

// linuxScopeMethod is linux_scope_method: the method the scope stands for
// (its auth-method, else the one protocol its filter names) and the reason
// in words; "" when the scope decides nothing.
func (inv *invocation) linuxScopeMethod(scope string) (method, why string) {
	choice, source := inv.scopeProtocolChoice(scope)
	switch choice {
	case "tacacs":
		method = hosts.Tacplus
	case "radius":
		method = hosts.Radius
	default:
		return "", ""
	}
	if source == "protocols" {
		return method, "scope '" + scope + "' is served over " + choice + " only (tacctl scope protocols)"
	}
	return method, "scope '" + scope + "' has auth-method " + choice + " (tacctl scope auth-method)"
}

// linuxScopeProtocols is linux_scope_protocols: the scope's protocols
// filter as a csv ("" when it has none).
func (inv *invocation) linuxScopeProtocols(scope string) (string, error) {
	s, err := inv.scopeOf(scope)
	if err != nil || s == nil {
		return "", err
	}
	return joinNonEmpty(s.Protocols, ","), nil
}

// linuxScopeServes is linux_scope_serves: false, with the way to change
// it printed, when the scope's protocols filter leaves the method's
// protocol out.
func (inv *invocation) linuxScopeServes(scope, method string) (bool, error) {
	id, _ := hosts.MethodBackend(method)
	protocols, err := inv.linuxScopeProtocols(scope)
	if err != nil {
		return false, err
	}
	if protocols != "" && !strings.Contains(","+protocols+",", ","+id+",") {
		inv.app.Out.ErrorE("Scope '" + scope + "' is not served over " + hosts.MethodLabel(method) + " (its protocols: " + protocols + ").")
		inv.app.Out.ErrorE("Allow it: tacctl scope protocols " + scope + " set " + protocols + "," + id)
		return false, nil
	}
	return true, nil
}

// scriptRequest is a hosts.ScriptRequest with the model and listener reads
// of linux_write_install_script done: the scope's secret, its linux-users
// rows, the method's backend's listeners.
func (inv *invocation) scriptRequest(scope, server, method, output string) (hosts.ScriptRequest, error) {
	req := hosts.ScriptRequest{Scope: scope, Server: server, Method: method, Output: output}
	m, err := inv.model()
	if err != nil {
		return req, err
	}
	if m.Exists("scopes", scope) {
		req.Secret = m.Scope(scope).Secret
	}
	req.Rows = m.LinuxUsers(scope)
	req.Inactive = m.LinuxInactive(scope)
	id := backend.TACACS
	if method == hosts.Radius {
		id = "radius"
	}
	if b, err := inv.app.Backends().Get(id); err == nil {
		req.Listeners, _ = b.Listeners().List()
	}
	return req, nil
}

// srcAddresses is "awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'"
// over 'ip route get' output: every word after a "src".
func srcAddresses(out string) []string {
	var addrs []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		for i, w := range f {
			if w == "src" {
				next := ""
				if i+1 < len(f) {
					next = f[i+1]
				}
				addrs = append(addrs, next)
			}
		}
	}
	return addrs
}

// chownToCaller hands a file written under sudo to the caller
// ('chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" <f> 2>/dev/null || true').
func (inv *invocation) chownToCaller(path string) {
	uidText := inv.app.Env.Get("SUDO_UID")
	if uidText == "" {
		return
	}
	gidText := inv.app.Env.Get("SUDO_GID")
	if gidText == "" {
		gidText = uidText
	}
	uid, err1 := strconv.Atoi(uidText)
	gid, err2 := strconv.Atoi(gidText)
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}

// baseName is ${path##*/}.
func baseName(path string) string { return path[strings.LastIndexByte(path, '/')+1:] }

// --- script --------------------------------------------------------------------

// configLinuxScript is cmd_config_linux_script.
func (inv *invocation) configLinuxScript(args []string) error {
	a := inv.app
	var scope, server, output, method string
	for i := 0; i < len(args); i += 2 {
		var dst *string
		switch args[i] {
		case "--scope":
			dst = &scope
		case "--server":
			dst = &server
		case "--method":
			dst = &method
		case "--output", "-o":
			dst = &output
		default:
			return inv.usageErr("Unknown argument: '"+args[i]+"'",
				"Usage: tacctl config linux script [--scope <name>] [--server <address>] [--method tacplus|radius] [--output <file>]")
		}
		if i+1 >= len(args) {
			// 0.1.16 spins forever here ('shift 2 || true' cannot shift).
			return exit(1)
		}
		*dst = args[i+1]
	}
	// The method: the one asked for; else what the scope says (its
	// auth-method, else its only protocol); else the default. One that was
	// asked for is checked before the scope is.
	if method != "" {
		if err := inv.linuxMethodRequire(method); err != nil {
			return err
		}
	}
	if scope == "" {
		def, err := inv.defaultScope()
		if err != nil {
			return err
		}
		if def == "" {
			return inv.usageErr("No default scope set and no --scope provided.")
		}
		scope = def
	} else if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	if method == "" {
		m, why := inv.linuxScopeMethod(scope)
		if m != "" {
			a.Out.InfoE("Method " + m + ": " + why + ".")
			method = m
		} else {
			method = inv.linuxDefaultMethod()
		}
		if err := inv.linuxMethodRequire(method); err != nil {
			return err
		}
	}
	label := hosts.MethodLabel(method)
	if ok, err := inv.linuxScopeServes(scope, method); err != nil {
		return err
	} else if !ok {
		return exit(1)
	}
	if server == "" {
		res, err := a.Runner.Run(inv.ctx, execx.Cmd{Name: "ip", Args: []string{"-4", "route", "get", "1.0.0.0"}, Stderr: io.Discard})
		if res.Code != 0 || err != nil {
			return inv.usageErr("Could not determine this server's address (ip route failed); pass --server <address>")
		}
		server = strings.TrimRight(strings.Join(srcAddresses(string(res.Stdout)), "\n"), "\n")
		if server == "" {
			return inv.usageErr("Could not detect this server's address. Pass --server <address>.")
		}
	}

	if output == "" {
		output = "tacctl-linux-" + scope + ".sh"
	}
	req, err := inv.scriptRequest(scope, server, method, output)
	if err != nil {
		return err
	}
	if err := inv.renumberUIDs(true); err != nil {
		return err
	}
	res, err := inv.hostsEnv().WriteScript(req)
	if err != nil {
		return inv.hostsDone(err)
	}
	if res.Users == "" {
		a.Out.WarnE("No users in scope '" + scope + "' can become Linux accounts; the script installs " + label + " with no users.")
	}
	// Under sudo the file would otherwise be root's; hand it to the caller.
	inv.chownToCaller(output)

	a.Out.InfoE("Wrote " + output + " (mode 0600; contains the shared secret for scope '" + scope + "').")
	inv.echo("")
	inv.echo("  Server:  " + server + " port " + res.Port)
	if method == hosts.Radius {
		inv.echo("  Method:  radius (the host installs pam_radius_auth from its distribution's packages; EPEL on the RHEL family)")
	}
	var users strings.Builder
	for _, l := range strings.Split(res.Users, "\n") {
		if l == "" {
			continue
		}
		f := strings.Split(l, ":")
		second := ""
		if len(f) > 1 {
			second = f[1]
		}
		users.WriteString(f[0] + "(" + second + ") ")
	}
	inv.echo("  Users:   " + users.String())
	inv.echo("")
	inv.echo("  The target host's address must be inside scope '" + scope + "':")
	inv.echo("    tacctl scope lookup <host-ip>")
	inv.echo("  On the target host, as root, from a session you keep open:")
	inv.echo("    bash " + baseName(output) + "                   # install")
	inv.echo("    bash " + baseName(output) + " --accounts-only   # later: sync users only")
	inv.echo("  Then delete the script. 'tacctl host enroll' does all of this over SSH.")
	inv.echo("")
	return nil
}

// --- remove-script -------------------------------------------------------------

// configLinuxRemoveScript is cmd_config_linux_remove_script.
func (inv *invocation) configLinuxRemoveScript(args []string) error {
	a := inv.app
	output := ""
	switch arg(args, 0) {
	case "--output", "-o":
		output = arg(args, 1)
	case "":
	default:
		return inv.usageErr("Usage: tacctl config linux remove-script [--output <file>]")
	}
	if output == "" {
		output = "tacctl-linux-remove.sh"
	}
	if err := hosts.WriteRemoveScript(output); err != nil {
		var ie *hosts.InstallError
		if errors.As(err, &ie) {
			// 'install' failing under errexit: its complaint, exit 1.
			inv.stderrLine(ie.Msg)
			return exit(1)
		}
		return err
	}
	inv.chownToCaller(output)
	a.Out.InfoE("Wrote " + output + " (no secrets). Run it as root on the host to remove TACACS+ or RADIUS authentication.")
	a.Out.Info("Local accounts and home directories are left in place.")
	return nil
}

// --- uid -----------------------------------------------------------------------

// configLinuxUID is cmd_config_linux_uid: list, show or change the number
// a user gets as UID and primary GID on every host, one of the configured
// range. Only a change (and the renumbering for a new range, renumberUIDs)
// writes the UID file; a listing or a lookup leaves it as it is (absent
// stays absent). Changing it
// does not renumber accounts that already exist on enrolled hosts; the next
// sync reports them.
func (inv *invocation) configLinuxUID(args []string) error {
	a := inv.app
	username, uid := arg(args, 0), arg(args, 1)
	if err := inv.renumberUIDs(false); err != nil {
		return err
	}
	rng, _ := inv.configuredUIDRange()
	uids := hosts.UIDs{Path: a.Paths.LinuxUIDs, Range: rng}
	if username == "" {
		inv.echo("")
		const title, hint = "Assigned Linux UIDs", "(same number is the primary GID)"
		listing, err := uids.Listing()
		if err != nil {
			return err
		}
		if strings.TrimSpace(listing) != "" {
			t := ui.NewTable(title, ui.Left("USERNAME"), ui.Left("UID"), ui.Left("NOTE"))
			t.Hint = hint
			for _, l := range strings.Split(strings.TrimSpace(listing), "\n") {
				if f := strings.Fields(l); len(f) >= 2 {
					t.Add(f[0], f[1], strings.Join(f[2:], " "))
				}
			}
			inv.write(t.String())
		} else {
			inv.echoE(ui.Bold + title + ui.NC + " " + hint)
			inv.echo(ui.Rule(title + " " + hint))
			inv.echo("  None yet. A UID is assigned the first time a user is sent to a host.")
		}
		inv.echo("")
		inv.echo("  Change one: tacctl config linux uid <username> <uid>")
		inv.echo("")
		return nil
	}
	if err := names.ValidateUsername(username); err != nil {
		return inv.validated(err)
	}
	if uid == "" {
		got, err := uids.Lookup(username)
		if err != nil {
			return err
		}
		if got == "" {
			return inv.usageErr("No UID assigned to '" + username + "' yet.")
		}
		inv.echo(got)
		return nil
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("users", username) {
		return inv.usageErr("User '" + username + "' does not exist.")
	}
	if !rng.Contains(uid) {
		return inv.usageErr("UID must be a number from " + strconv.Itoa(rng.Min) + " to " + strconv.Itoa(rng.Max) + ": tacctl gives out UIDs (and the matching GIDs) in that range only.")
	}
	holder, err := uids.Holder(uid)
	if err != nil {
		return err
	}
	if holder != "" && holder != username {
		return inv.usageErr("UID " + uid + " is already assigned to '" + holder + "'.")
	}
	if err := uids.Touch(); err != nil {
		inv.stderrLine("touch: cannot touch '" + uids.Path + "': " + errnoText(err))
		return exit(1)
	}
	if err := uids.Assign(username, uid); err != nil {
		return err
	}
	a.Out.InfoE("'" + username + "' is now assigned UID/GID " + uid + ".")
	a.Out.Warn("Hosts that already have the account keep its old number until it is renumbered there:")
	inv.echo("    usermod -u " + uid + " " + username + " && groupmod -g " + uid + " " + username)
	inv.echo("    find / -xdev \\( -uid <old> -o -gid <old> \\) -exec chown -h " + username + ":" + username + " {} +")
	inv.echo("  'tacctl host sync' lists the hosts where the number still differs.")
	return nil
}

// errnoText is the C library's text of err's errno ("No such file or
// directory"), or err's own text.
func errnoText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	s := err.Error()
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// --- builds --------------------------------------------------------------------

// configLinuxBuilds is cmd_config_linux_builds.
func (inv *invocation) configLinuxBuilds(args []string) error {
	he := inv.hostsEnv()
	sub := arg(args, 0)
	if sub == "" {
		sub = "list"
	}
	switch sub {
	case "list":
		inv.echo("")
		builds := he.Builds()
		if len(builds) == 0 {
			title := "Prebuilt pam_tacplus modules (" + he.Paths.Builds() + ")"
			inv.echoE(ui.Bold + "Prebuilt pam_tacplus modules" + ui.NC + " (" + he.Paths.Builds() + ")")
			inv.echo(ui.Rule(title))
			inv.echo("  None yet. 'tacctl host enroll' builds one the first time it meets an OS release.")
		} else {
			t := ui.NewTable("Prebuilt pam_tacplus modules", ui.Left("IMAGE"), ui.Left("ARCH"), ui.Left("BUILT"), ui.Left("BASE IMAGE"))
			t.Hint = "(" + he.Paths.Builds() + ")"
			for _, b := range builds {
				t.Add(b.Image, b.Arch, b.Built, b.Digest)
			}
			inv.write(t.String())
		}
		inv.echo("")
		return nil
	case "clear":
		if err := he.ClearBuilds(); err != nil {
			return err
		}
		inv.app.Out.Info("Prebuilt modules removed; the next enroll of each OS release rebuilds.")
		return nil
	}
	return inv.usageErr("Usage: tacctl config linux builds [list|clear]")
}

// padTo is printf's %-<n>s.
func padTo(s string, n int) string {
	if l := len([]rune(s)); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

// discardStdout runs fn with everything it writes to stdout dropped ('>
// /dev/null'): the command's own lines, the pre-change snapshot's and the
// backend modules' (a render and restart inside a store change).
func (inv *invocation) discardStdout(fn func() error) error {
	a := inv.app
	env, snaps := a.BackendEnv(), a.Snapshots()
	saved, savedEnv, savedSnaps := a.Out, env.Out, snaps.Out
	a.Out.Stdout, env.Out.Stdout, snaps.Out.Stdout = io.Discard, io.Discard, io.Discard
	defer func() { a.Out, env.Out, snaps.Out = saved, savedEnv, savedSnaps }()
	return fn()
}
