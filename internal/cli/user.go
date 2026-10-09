package cli

// The 'user' family (lib/users.sh cmd_user at 0.1.16), native since WP2.4a.
// Every message, prompt, exit status and the order of the checks are the
// bash's: a check that comes before another in cmd_<verb> comes before it
// here, so the same wrong command line gets the same first complaint.

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// userSpecs are the arguments of each verb, for completion (args.go).
var userSpecs = map[string]Spec{
	"list": {},
	"show": {MinArgs: 1, MaxArgs: 1, Args: []string{KindUsers}},
	"add": {MinArgs: 2, MaxArgs: 2, Args: []string{"", KindGroups}, Flags: []Flag{
		{Names: []string{"--hash"}, Value: true}, {Names: []string{"--scopes"}, Value: true, Kind: KindScopes + KindList}}},
	"remove":  {MinArgs: 1, MaxArgs: 1, Args: []string{KindUsers}},
	"passwd":  {MinArgs: 1, MaxArgs: 1, Args: []string{KindUsers}, Flags: []Flag{{Names: []string{"--hash"}, Value: true}}},
	"disable": {MinArgs: 1, MaxArgs: 1, Args: []string{KindUsers}},
	"enable":  {MinArgs: 1, MaxArgs: 1, Args: []string{KindUsers}},
	"rename":  {MinArgs: 2, MaxArgs: 2, Args: []string{KindUsers, ""}},
	"move":    {MinArgs: 2, MaxArgs: 2, Args: []string{KindUsers, KindGroups}},
	"verify":  {MinArgs: 1, MaxArgs: 1, Args: []string{KindUsers}},
	"scope": {MinArgs: 1, MaxArgs: 3, Args: []string{KindUsers, "list|add|remove|replace", KindScopes + KindList},
		Flags: []Flag{{Names: []string{"--all"}, Only: "remove", Alone: true}}},
}

func userCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(withPreflight, run)
	}
	c := verb("user <subcommand>", "User management (list, add, remove, passwd, scope, ...)",
		withRun(verb("list", "List all users (name, group, status, pw age, scopes)"), n(inv.userList)),
		withRun(verb("show <username>", "Show user details incl. scope membership"), n(inv.userShow)),
		withRun(verb("add <username> <group> [--hash <hash>] [--scopes <s>[,s...]]", "Add a new user; lands in default scope"), n(inv.userAdd)),
		withRun(verb("remove <username>", "Remove a user"), n(inv.userRemove)),
		withRun(verb("passwd <username> [--hash <hash>]", "Change a user's password"), n(inv.userPasswd)),
		withRun(verb("disable <username>", "Disable a user (preserves hash)"), n(inv.userDisable)),
		withRun(verb("enable <username>", "Re-enable a disabled user"), n(inv.userEnable)),
		withRun(verb("rename <old> <new>", "Rename a user"), n(inv.userRename)),
		withRun(verb("move <user> <group>", "Move user to a different group"), n(inv.userMove)),
		withRun(verb("verify <username>", "Verify password and show user details"), n(inv.userVerify)),
		withRun(verb("scope <user> {list|add|remove|replace} [<scope>[,<scope>...]] | remove --all",
			"Manage which scopes the user can auth from"), n(inv.userScope)),
	)
	// No sub-command, 'help' or an unknown word: the usage, exit 1.
	c.RunE = n(func([]string) error {
		inv.write(userUsage())
		return exit(1)
	})
	return c
}

// withRun gives c its RunE.
func withRun(c *cobra.Command, run func(*cobra.Command, []string) error) *cobra.Command {
	c.RunE = run
	return c
}

// write prints s on stdout as it is.
func (inv *invocation) write(s string) { _, _ = inv.app.Out.Stdout.Write([]byte(s)) }

// userUsage is cmd_user's usage block.
func userUsage() string { return Usage("user", nil) }

// arg is "${n:-}" of args (0-based).
func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// usageErr prints one [ERROR] line per message (error "...") and exits 1.
func (inv *invocation) usageErr(msgs ...string) error {
	for _, m := range msgs {
		inv.app.Out.ErrorE(m)
	}
	return exit(1)
}

// requireStore is 'store_require || exit 1'.
func (inv *invocation) requireStore() error { return inv.app.Backends().Require() }

// userInfo is _user_info: model_user_info plus the user's scopes and the
// ones among them that do not exist. ok is false for an unknown user; err
// is a model that could not be read.
type userInfo struct {
	group, status, passwordChanged, privLvl, juniperClass, hashType string
	hasHash                                                         bool
	scopes, orphans                                                 []string
}

func (inv *invocation) userInfo(name string) (ui userInfo, ok bool, err error) {
	m, err := inv.model()
	if err != nil {
		return ui, false, err
	}
	lines, ok := m.UserInfo(name)
	if !ok {
		return ui, false, nil
	}
	for _, l := range lines {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "group":
			ui.group = v
		case "status":
			ui.status = v
		case "password_changed":
			ui.passwordChanged = v
		case "priv_lvl":
			ui.privLvl = v
		case "juniper_class":
			ui.juniperClass = v
		case "hash_type":
			ui.hashType = v
		case "has_hash":
			ui.hasHash = v == "1"
		case "scope":
			s, exists := v, "1"
			if i := strings.LastIndexByte(v, '|'); i >= 0 {
				s, exists = v[:i], v[i+1:]
			}
			ui.scopes = append(ui.scopes, s)
			if exists != "1" {
				ui.orphans = append(ui.orphans, s)
			}
		}
	}
	return ui, true, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// userExists is model_user_exists, a model read error returned.
func (inv *invocation) userExists(name string) (bool, error) {
	m, err := inv.model()
	if err != nil {
		return false, err
	}
	return m.Exists("users", name), nil
}

// groupCheck is the 'Group does not exist. Available: a|b|c' refusal of
// add and move (model_group_exists, model_group_info's names joined by
// '|'); extra are more error lines after it.
func (inv *invocation) groupCheck(group string, extra ...string) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	if m.Exists("groups", group) {
		return nil
	}
	var avail []string
	for _, l := range m.GroupInfo() {
		n, _, _ := strings.Cut(l, "|")
		avail = append(avail, n)
	}
	return inv.usageErr(append([]string{"Group '" + group + "' does not exist. Available: " + strings.Join(avail, "|")}, extra...)...)
}

// hashArg is _user_hash_arg: the --hash value as canonical hex, or the
// four error lines and exit 1.
func (inv *invocation) hashArg(v string) (string, error) {
	h, ok := hash.Normalize(v)
	if !ok {
		return "", inv.usageErr("Invalid bcrypt hash.", "Accepted forms:",
			"  - hex-encoded (from 'tacctl hash'): 24326224313224...",
			"  - raw (from bcrypt libs):           $2b$12$...")
	}
	return h, nil
}

// promptHash is 'password=$(prompt_password <user>); hash=$(generate_hash
// "$password")': the password asked (or generated) and hashed at the
// configured cost, the salt from the knobs' random source.
func (inv *invocation) promptHash(username string) (string, error) {
	a := inv.app
	t := a.Tunables()
	pw, err := a.Prompter().PromptPassword(username, t.PasswordMinLength, a.Knobs.Rand())
	if err != nil {
		return "", err
	}
	return hash.GenerateWith(pw, t.BcryptCost, a.Knobs.Rand())
}

// scopeList is the --scopes / 'user scope' parsing: split on commas (the
// first line only, 'read -ra'), each entry through 'echo | xargs', every
// name must be a scope, repeats dropped. It returns the names, or the
// error (printed) of the first that does not exist.
func (inv *invocation) scopeList(csv string) ([]string, error) {
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	all := m.ScopesByRouting()
	if i := strings.IndexByte(csv, '\n'); i >= 0 {
		csv = csv[:i]
	}
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		s, err := shellquote.XargsEcho(raw)
		if err != nil {
			// 's=$(echo "$s" | xargs)' fails under 'set -eo pipefail':
			// xargs's complaint, then exit 1.
			inv.stderrLine("xargs: " + err.Error())
			return nil, exit(1)
		}
		if s == "" {
			continue
		}
		if !contains(all, s) {
			return nil, inv.usageErr("Scope '" + s + "' does not exist. Available: " + strings.Join(all, " "))
		}
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// --- list -------------------------------------------------------------------

// userUID is the user's Linux UID from the server's map, "-" when it has
// none (or the map cannot be read). A read never assigns one.
func (inv *invocation) userUID(name string) string {
	uid, err := (hosts.UIDs{Path: inv.app.Paths.LinuxUIDs}).Lookup(name)
	if err != nil || uid == "" {
		return "-"
	}
	return uid
}

func (inv *invocation) userList([]string) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	t := ui.NewTable("Users", ui.Left("USERNAME"), ui.Left("UID"), ui.Left("GROUP"), ui.Left("STATUS"), ui.Left("PW CHANGED"), ui.Left("SCOPES"))
	for _, row := range m.UserRows() {
		f := strings.SplitN(row, "|", 5)
		for len(f) < 5 {
			f = append(f, "")
		}
		if f[0] == "" {
			continue
		}
		color := ui.Green
		if f[2] == "disabled" {
			color = ui.Red
		}
		display := "(none)"
		if f[4] != "" {
			sc := strings.Split(f[4], ",")
			if len(sc) > 3 {
				display = fmt.Sprintf("%s,%s,%s (…+%d)", sc[0], sc[1], sc[2], len(sc)-3)
			} else {
				display = f[4]
			}
		}
		t.Add(f[0], inv.userUID(f[0]), f[1], ui.Styled(color, f[2]), f[3], display)
	}
	inv.echo("")
	inv.write(t.String())
	inv.echo("")
	return nil
}

// --- show -------------------------------------------------------------------

func (inv *invocation) userShow(args []string) error {
	username := arg(args, 0)
	if username == "" {
		return inv.usageErr("Usage: tacctl user show <username>")
	}
	if err := names.ValidateUsername(username); err != nil {
		return err
	}
	u, ok, err := inv.userInfo(username)
	if err != nil {
		return err
	}
	if !ok {
		return inv.usageErr("User '" + username + "' does not exist.")
	}
	age := ""
	if u.passwordChanged != "unknown" {
		if d, err := time.ParseInLocation("2006-01-02", u.passwordChanged, time.Local); err == nil {
			age = fmt.Sprint((inv.app.Knobs.Now().Unix() - d.Unix()) / 86400)
		}
	}
	last := inv.app.Backends().LastLogin(inv.ctx, username)

	b, nc := ui.Bold, ui.NC
	inv.echo("")
	inv.echoE("  " + b + "User:" + nc + "             " + username)
	inv.echoE("  " + b + "Group:" + nc + "            " + u.group)
	inv.echoE("  " + b + "UID:" + nc + "              " + inv.userUID(username))
	if u.status == "disabled" {
		inv.echoE("  " + b + "Status:" + nc + "           " + ui.Red + "disabled" + nc)
	} else {
		inv.echoE("  " + b + "Status:" + nc + "           " + ui.Green + "active" + nc)
	}
	if age != "" {
		inv.echoE("  " + b + "Password changed:" + nc + " " + u.passwordChanged + " (" + age + " days ago)")
	} else {
		inv.echoE("  " + b + "Password changed:" + nc + " " + u.passwordChanged)
	}
	inv.echoE("  " + b + "Last login:" + nc + "       " + last)
	if u.privLvl != "" {
		inv.echoE("  " + b + "Cisco priv-lvl:" + nc + "   " + u.privLvl)
	}
	if u.juniperClass != "" {
		inv.echoE("  " + b + "Juniper class:" + nc + "    " + u.juniperClass)
	}
	inv.echoE("  " + b + "Hash type:" + nc + "        " + u.hashType)
	if len(u.scopes) == 0 {
		inv.echoE("  " + b + "Scopes:" + nc + "           " + ui.Red + "(none — cannot authenticate on any device)" + nc)
	} else {
		first := true
		for _, s := range u.scopes {
			if s == "" {
				continue
			}
			label := s
			if contains(u.orphans, s) {
				label = ui.Red + s + " (ORPHAN)" + nc
			}
			if first {
				inv.echoE("  " + b + "Scopes:" + nc + "           " + label)
				first = false
			} else {
				inv.echoE("                    " + label)
			}
		}
	}
	inv.echo("")
	return nil
}

// --- add --------------------------------------------------------------------

const userAddUsage = "Usage: tacctl user add <username> <group> [--hash <bcrypt-hash>] [--scopes <name>[,<name>...]]"

func (inv *invocation) userAdd(args []string) error {
	a := inv.app
	username, group := arg(args, 0), arg(args, 1)
	if username == "" {
		return inv.usageErr(userAddUsage)
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateUsername(username); err != nil {
		return err
	}
	if err := names.RejectReservedUsername(username); err != nil {
		return err
	}
	if err := inv.groupCheck(group, "Usage: tacctl user add <username> <group>"); err != nil {
		return err
	}
	if exists, err := inv.userExists(username); err != nil {
		return err
	} else if exists {
		return inv.usageErr("User '" + username + "' already exists.")
	}

	var hexHash, scopesCSV string
	rest := args[min(2, len(args)):]
	for len(rest) > 0 {
		switch rest[0] {
		case "--hash":
			v := arg(rest, 1)
			if v == "" {
				return inv.usageErr("Usage: tacctl user add <username> <group> --hash <bcrypt-hash>")
			}
			h, err := inv.hashArg(v)
			if err != nil {
				return err
			}
			hexHash = h
			rest = rest[2:]
		case "--scopes":
			scopesCSV = arg(rest, 1)
			if scopesCSV == "" {
				return inv.usageErr("Usage: tacctl user add <username> <group> --scopes <name>[,<name>...]")
			}
			rest = rest[2:]
		default:
			return inv.usageErr("Unknown argument: '"+rest[0]+"'", userAddUsage)
		}
	}

	var scopes []string
	if scopesCSV != "" {
		var err error
		if scopes, err = inv.scopeList(scopesCSV); err != nil {
			return err
		}
		if len(scopes) == 0 {
			return inv.usageErr("No valid scope names provided.")
		}
	} else {
		def, err := inv.defaultScope()
		if err != nil {
			return err
		}
		if def == "" {
			return inv.usageErr("No scopes exist and no default scope is set.",
				"Create one first: tacctl scope add <name> --prefixes <cidrs>")
		}
		scopes = []string{def}
	}
	display := strings.Join(scopes, ",")
	if why := breakGlassClash(a.Conf(), username, scopes); why != "" {
		return inv.usageErr(why)
	}

	inv.echo("")
	inv.echoE("  Adding user: " + ui.Bold + username + ui.NC + " (" + group + ")")
	if hexHash == "" {
		h, err := inv.promptHash(username)
		if err != nil {
			return err
		}
		hexHash = h
	} else {
		a.Out.Info("Using pre-generated bcrypt hash.")
	}
	if err := inv.storeApply(func(s *store.Store) error {
		return s.UserSet(username, "group="+group, "scopes="+display, "hash="+hexHash, "disabled=false", "password_changed=today")
	}); err != nil {
		return err
	}
	a.Out.InfoE("User '" + username + "' added (" + group + ") with scopes: " + display)
	inv.echo("")
	return nil
}

// defaultScope is read_default_scope: scope.default when it names a scope,
// else the only scope when there is exactly one, else "".
func (inv *invocation) defaultScope() (string, error) {
	v, _ := inv.app.Conf().Get("scope.default", "")
	m, err := inv.model()
	if err != nil {
		return "", err
	}
	all := m.ScopeNames()
	if v != "" && contains(all, v) {
		return v, nil
	}
	if len(all) == 1 {
		return all[0], nil
	}
	return "", nil
}

// --- remove -----------------------------------------------------------------

func (inv *invocation) userRemove(args []string) error {
	username := arg(args, 0)
	if username == "" {
		return inv.usageErr("Usage: tacctl user remove <username>")
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateUsername(username); err != nil {
		return err
	}
	if exists, err := inv.userExists(username); err != nil {
		return err
	} else if !exists {
		return inv.usageErr("User '" + username + "' does not exist.")
	}
	inv.echo("")
	if !inv.app.Prompter().Confirm("  Remove user '" + username + "'? This cannot be undone. [y/N]: ") {
		inv.app.Out.Info("Cancelled.")
		return nil
	}
	watch := inv.watchServerTiers()
	if err := inv.storeApply(func(s *store.Store) error { return s.UserDel(username) }); err != nil {
		return err
	}
	inv.app.Out.Info("User '" + username + "' removed.")
	inv.echo("")
	return watch.lowered("'"+username+"'", "'"+username+"' keeps the groups of the old tier")
}

// --- passwd -----------------------------------------------------------------

func (inv *invocation) userPasswd(args []string) error {
	username := arg(args, 0)
	if username == "" {
		return inv.usageErr("Usage: tacctl user passwd <username> [--hash <bcrypt-hash>]")
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateUsername(username); err != nil {
		return err
	}
	if err := names.RejectReservedUsername(username); err != nil {
		return err
	}
	if exists, err := inv.userExists(username); err != nil {
		return err
	} else if !exists {
		return inv.usageErr("User '" + username + "' does not exist.")
	}
	// Only '--hash <h>' right after the name counts; anything else is
	// ignored, as in bash.
	hexHash := ""
	if arg(args, 1) == "--hash" {
		v := arg(args, 2)
		if v == "" {
			return inv.usageErr("Usage: tacctl user passwd <username> --hash <bcrypt-hash>")
		}
		h, err := inv.hashArg(v)
		if err != nil {
			return err
		}
		hexHash = h
	}
	inv.echo("")
	inv.echoE("  Changing password for: " + ui.Bold + username + ui.NC)
	if hexHash == "" {
		h, err := inv.promptHash(username)
		if err != nil {
			return err
		}
		hexHash = h
	} else {
		inv.app.Out.Info("Using pre-generated bcrypt hash.")
	}
	// Setting a password also enables the account (how the seeded
	// placeholder users are activated).
	if err := inv.storeApply(func(s *store.Store) error {
		return s.UserSet(username, "hash="+hexHash, "disabled=false", "password_changed=today")
	}); err != nil {
		return err
	}
	inv.app.Out.Info("Password changed for '" + username + "'.")
	inv.echo("")
	return nil
}

// --- disable / enable -------------------------------------------------------

// userLookup is the common head of disable, enable and verify: the usage
// line when no name is given, store_require when needStore, the name check
// and _user_info.
func (inv *invocation) userLookup(args []string, verb string, needStore bool) (string, userInfo, error) {
	username := arg(args, 0)
	if username == "" {
		return "", userInfo{}, inv.usageErr("Usage: tacctl user " + verb + " <username>")
	}
	if needStore {
		if err := inv.requireStore(); err != nil {
			return "", userInfo{}, err
		}
	}
	if err := names.ValidateUsername(username); err != nil {
		return "", userInfo{}, err
	}
	u, ok, err := inv.userInfo(username)
	if err != nil {
		return "", userInfo{}, err
	}
	if !ok {
		return "", userInfo{}, inv.usageErr("User '" + username + "' does not exist.")
	}
	return username, u, nil
}

func (inv *invocation) userDisable(args []string) error {
	username, u, err := inv.userLookup(args, "disable", true)
	if err != nil {
		return err
	}
	if u.status == "disabled" {
		inv.app.Out.Warn("User '" + username + "' is already disabled.")
		return nil
	}
	watch := inv.watchServerTiers()
	if err := inv.storeApply(func(s *store.Store) error { return s.UserSet(username, "disabled=true") }); err != nil {
		return err
	}
	inv.app.Out.Info("User '" + username + "' disabled. Use 'enable' to restore access.")
	inv.echo("")
	return watch.lowered("'"+username+"'", "'"+username+"' keeps the groups of the old tier")
}

func (inv *invocation) userEnable(args []string) error {
	username, u, err := inv.userLookup(args, "enable", true)
	if err != nil {
		return err
	}
	if u.status != "disabled" {
		inv.app.Out.Warn("User '" + username + "' is not disabled.")
		return nil
	}
	// Nothing to restore: a seeded placeholder, the accounting sink, or a
	// user whose saved hash did not survive the import.
	if !u.hasHash {
		return inv.usageErr("No saved hash found for '"+username+"'. Set a new password instead:",
			"  tacctl user passwd "+username)
	}
	if err := inv.storeApply(func(s *store.Store) error { return s.UserSet(username, "disabled=false") }); err != nil {
		return err
	}
	inv.app.Out.Info("User '" + username + "' re-enabled with previous password.")
	inv.echo("")
	return nil
}

// --- verify -----------------------------------------------------------------

// failDelay is the pause after a wrong password ('sleep 0.5'): the CLI is
// no fast local bcrypt oracle.
const failDelay = 500 * time.Millisecond

// pause waits d, or until the command is cancelled.
func (inv *invocation) pause(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-inv.ctx.Done():
	}
}

func (inv *invocation) userVerify(args []string) error {
	a := inv.app
	username, u, err := inv.userLookup(args, "verify", false)
	if err != nil {
		return err
	}
	b, nc := ui.Bold, ui.NC
	inv.echo("")
	inv.echoE("  " + b + "User:" + nc + "           " + username)
	inv.echoE("  " + b + "Group:" + nc + "          " + u.group)
	if u.status == "disabled" {
		inv.echoE("  " + b + "Status:" + nc + "         " + ui.Red + "disabled" + nc)
		inv.echoE("  " + b + "PW changed:" + nc + "     " + u.passwordChanged)
		inv.echo("")
		return inv.usageErr("User is disabled — cannot verify password.")
	}
	inv.echoE("  " + b + "Status:" + nc + "         " + ui.Green + "active" + nc)
	inv.echoE("  " + b + "PW changed:" + nc + "     " + u.passwordChanged)
	inv.echo("")

	m, _ := inv.model()
	stored := m.User(username).Hash
	if err := hash.VerifyCostError(stored); err != nil {
		a.Out.Error(err.Error())
		return exit(1)
	}
	pw, err := a.Prompter().Password("  Enter password to verify: ")
	if err != nil {
		return err
	}
	result := hash.Verify(pw, stored)

	callerUID := a.Env.Get("SUDO_UID")
	if callerUID == "" {
		callerUID = fmt.Sprint(a.EUID)
	}
	caller := a.Env.Get("SUDO_USER")
	if caller == "" {
		caller = "root"
	}
	by := " by=" + caller + "(uid=" + callerUID + ")"
	if result == hash.Match {
		a.Logger(inv.ctx, "auth.info", "verify OK user="+username+by)
		a.Out.Info("Password is correct.")
	} else {
		inv.pause(failDelay)
		a.Logger(inv.ctx, "auth.warning", "verify FAIL user="+username+" result="+string(result)+by)
		a.Out.Error("Password does not match.")
	}
	inv.echo("")
	return nil
}

// --- rename / move ----------------------------------------------------------

func (inv *invocation) userRename(args []string) error {
	oldname, newname := arg(args, 0), arg(args, 1)
	if oldname == "" || newname == "" {
		return inv.usageErr("Usage: tacctl user rename <old-username> <new-username>")
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	for _, check := range []func() error{
		func() error { return names.ValidateUsername(oldname) },
		func() error { return names.ValidateUsername(newname) },
		func() error { return names.RejectReservedUsername(newname) },
	} {
		if err := check(); err != nil {
			return err
		}
	}
	if exists, err := inv.userExists(oldname); err != nil {
		return err
	} else if !exists {
		return inv.usageErr("User '" + oldname + "' does not exist.")
	}
	if exists, err := inv.userExists(newname); err != nil {
		return err
	} else if exists {
		return inv.usageErr("User '" + newname + "' already exists.")
	}
	if u, ok, err := inv.userInfo(oldname); err != nil {
		return err
	} else if ok {
		if why := breakGlassClash(inv.app.Conf(), newname, u.scopes); why != "" {
			return inv.usageErr(why)
		}
	}
	// The old name is gone from the model afterwards, so its account on this
	// server (and its tac-superuser) goes at the sync that follows; the new
	// name gets its account there.
	watch := inv.watchServerTiers()
	if err := inv.storeApply(func(s *store.Store) error { return s.UserRename(oldname, newname) }); err != nil {
		return err
	}
	inv.app.Out.Info("User renamed: " + oldname + " -> " + newname)
	inv.echo("")
	return watch.lowered("'"+oldname+"'", "'"+oldname+"' keeps the groups of the old tier")
}

func (inv *invocation) userMove(args []string) error {
	username, newgroup := arg(args, 0), arg(args, 1)
	if username == "" || newgroup == "" {
		// 0.1.16 printed 'tacctl move'; the word 'user' is added in 0.2.0
		// (docs/plans/go-rewrite.md 3.9 item 5).
		return inv.usageErr("Usage: tacctl user move <username> <new-group>")
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateUsername(username); err != nil {
		return err
	}
	if err := names.ValidateClassName(newgroup); err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	usr := m.User(username)
	if usr == nil {
		return inv.usageErr("User '" + username + "' does not exist.")
	}
	oldgroup := usr.Group
	if err := inv.groupCheck(newgroup); err != nil {
		return err
	}
	if oldgroup == newgroup {
		inv.app.Out.Info("User '" + username + "' is already in group '" + newgroup + "'.")
		return nil
	}
	watch := inv.watchServerTiers()
	if err := inv.storeApply(func(s *store.Store) error { return s.UserSet(username, "group="+newgroup) }); err != nil {
		return err
	}
	inv.app.Out.Info("User '" + username + "' moved: " + oldgroup + " -> " + newgroup)
	inv.echo("")
	return watch.lowered("'"+username+"'", "'"+username+"' keeps the groups of the old tier")
}

// --- scope ------------------------------------------------------------------

// userScopeHelp is the usage cmd_user_scope prints after the list for
// help, -h and --help.
func userScopeHelp(username string) string {
	u := username
	return "Usage:\n" +
		"  tacctl user scope " + u + " list                          Show current (default)\n" +
		"  tacctl user scope " + u + " add     <scope>[,<scope>...]  Grant scope access\n" +
		"  tacctl user scope " + u + " remove  <scope>[,<scope>...]  Revoke scope access\n" +
		"  tacctl user scope " + u + " replace <scope>[,<scope>...]  Replace full list\n" +
		"  tacctl user scope " + u + " remove  --all                 Revoke every scope (confirms)\n" +
		"\n"
}

func (inv *invocation) userScope(args []string) error {
	a := inv.app
	username, sub, csv := arg(args, 0), arg(args, 1), arg(args, 2)
	if username == "" {
		return inv.usageErr("Usage: tacctl user scope <user> {list|add|remove|replace} [<scope>[,<scope>...]]",
			"       tacctl user scope <user> remove --all")
	}
	switch sub {
	case "set":
		return inv.usageErr("'set' was renamed: use 'tacctl user scope " + username + " replace <scope>[,<scope>...]'")
	case "clear":
		return inv.usageErr("'clear' was renamed: use 'tacctl user scope " + username + " remove --all'")
	}
	// 'remove --all' empties the list; it takes no scope names.
	removeAll := false
	if sub == "remove" {
		removeAll = contains(args[2:], "--all")
		if removeAll && len(args) != 3 {
			return inv.usageErr("Usage: tacctl user scope " + username + " remove --all   ('--all' takes no scope names)")
		}
	}
	mutating := sub == "add" || sub == "remove" || sub == "replace"
	if mutating {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	if err := names.ValidateUsername(username); err != nil {
		return err
	}
	u, ok, err := inv.userInfo(username)
	if err != nil {
		return err
	}
	if !ok {
		return inv.usageErr("User '" + username + "' does not exist.")
	}

	switch {
	case sub == "" || sub == "list" || sub == "-h" || sub == "--help" || sub == "help":
		inv.echo("")
		inv.echoE(ui.Bold + "Scopes for user '" + username + "'" + ui.NC)
		inv.echo(ui.Rule("Scopes for user '" + username + "'"))
		if len(u.scopes) == 0 {
			inv.echoE("  " + ui.Red + "(none — user cannot authenticate on any device)" + ui.NC)
		} else {
			for _, s := range u.scopes {
				if s == "" {
					continue
				}
				if contains(u.orphans, s) {
					inv.echoE("  " + ui.Red + "- " + s + "  (ORPHAN: scope does not exist)" + ui.NC)
				} else {
					inv.echo("  - " + s)
				}
			}
		}
		inv.echo("")
		if sub == "" || sub == "list" {
			return nil
		}
		inv.write(userScopeHelp(username))
		return nil
	case removeAll:
		return inv.userScopeRemoveAll(username, u.scopes)
	case mutating:
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", "Run 'tacctl user scope "+username+"' for usage.")
	}

	if csv == "" {
		msgs := []string{"Usage: tacctl user scope " + username + " " + sub + " <scope>[,<scope>...]"}
		if sub == "remove" {
			msgs = append(msgs, "       tacctl user scope "+username+" remove --all")
		}
		return inv.usageErr(msgs...)
	}
	requested, err := inv.scopeList(csv)
	if err != nil {
		return err
	}
	if len(requested) == 0 {
		return inv.usageErr("No valid scope names provided.")
	}

	current := u.scopes
	var newList, changed, noop []string
	switch sub {
	case "replace":
		newList, changed = requested, requested
	case "add":
		newList = append([]string(nil), current...)
		for _, s := range requested {
			if contains(current, s) {
				noop = append(noop, s)
			} else {
				changed = append(changed, s)
				newList = append(newList, s)
			}
		}
		if len(changed) == 0 {
			a.Out.InfoE("No new scopes (already present: " + strings.Join(noop, " ") + ").")
			inv.echo("")
			return nil
		}
	case "remove":
		for _, s := range requested {
			if contains(current, s) {
				changed = append(changed, s)
			} else {
				noop = append(noop, s)
			}
		}
		if len(changed) == 0 {
			a.Out.WarnE("Nothing to remove (not present: " + strings.Join(noop, " ") + ").")
			return nil
		}
		for _, s := range current {
			if !contains(changed, s) {
				newList = append(newList, s)
			}
		}
	}
	if sub == "add" || sub == "replace" {
		if why := breakGlassClash(a.Conf(), username, changed); why != "" {
			return inv.usageErr(why)
		}
	}
	var kept []string
	for _, s := range newList {
		if strings.TrimSpace(s) != "" {
			kept = append(kept, s)
		}
	}
	list := strings.Join(kept, ",")
	// Taking this server's scope away (remove, replace) drops the account's
	// groups at the next sync like a lower tier does.
	watch := inv.watchServerTiers()
	if err := inv.storeApply(func(s *store.Store) error { return s.UserSet(username, "scopes="+list) }); err != nil {
		return err
	}
	var v string
	switch sub {
	case "add":
		v = fmt.Sprintf("Granted %d scope(s) to", len(changed))
	case "remove":
		v = fmt.Sprintf("Revoked %d scope(s) from", len(changed))
	default:
		v = "Replaced scopes on"
	}
	a.Out.InfoE(v + " user '" + username + "': " + strings.Join(changed, " "))
	if len(noop) > 0 {
		a.Out.InfoE("(Skipped: " + strings.Join(noop, " ") + ")")
	}
	if list == "" {
		a.Out.Warn("User '" + username + "' now has NO scopes — they cannot auth on any device")
		a.Out.Warn("until you run: tacctl user scope " + username + " add <scope>")
	}
	inv.echo("")
	return watch.lowered("'"+username+"'", "'"+username+"' keeps the groups of the old tier")
}

// userScopeRemoveAll is _user_scope_remove_all: empty the user's scope
// list after a [y/N] confirmation (any answer starting with y or Y).
func (inv *invocation) userScopeRemoveAll(username string, current []string) error {
	a := inv.app
	if len(current) == 0 {
		a.Out.Info("User '" + username + "' already has no scopes.")
		return nil
	}
	a.Out.Warn("WARNING: " + username + " will be unable to authenticate on any device")
	a.Out.Warn("until you grant at least one scope with 'tacctl user scope " + username + " add <name>'")
	a.Out.Warn("(Distinct from 'tacctl user disable' — the password hash is preserved.)")
	if !a.Prompter().ConfirmPrefix("  Remove all scopes from '" + username + "'? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	watch := inv.watchServerTiers()
	if err := inv.storeApply(func(s *store.Store) error { return s.UserSet(username, "scopes=") }); err != nil {
		return err
	}
	a.Out.Info("Removed all scopes from user '" + username + "'.")
	inv.echo("")
	return watch.lowered("'"+username+"'", "'"+username+"' keeps the groups of the old tier")
}
