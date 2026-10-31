package cli

// The SNMPv3 user pool (D303 to D306 of docs/plans/0.2.23-plan.md): the verbs
// 'v3-user add|remove|default|list' of 'config snmp', 'scope snmp <scope>'
// and 'device snmp <device>', one implementation for the three levels. A
// level holds a pool of users (a name and the two passphrases each) and a
// default user or none (internal/snmpcred); the version, the port, the
// timeout and the protocols stay one setting per level. Adding a user changes
// nothing but the pool; a device uses its own default, else its scope's,
// else the config's, and may be told to use a user of any of the three pools
// (names are unique across them, so none shadows another).

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/snmpcred"
	"github.com/rett/tacctl/internal/ui"
)

// snmpV3UserActions are the words after 'v3-user'.
const snmpV3UserActions = "add|remove|default|list"

// snmpV3UserSpec is the arguments of 'v3-user' at a level; the protocols are
// the config's and the scope's (a device reads with its scope's or the
// config's).
func snmpV3UserSpec(protocols bool) Spec {
	flags := []Flag{{Names: []string{"--default"}, Only: "add", Desc: "Make the user the default"}}
	if protocols {
		flags = append(flags,
			Flag{Names: []string{"--auth"}, Value: true, Only: "add", Kind: strings.Join(snmp.AuthProtocols, "|")},
			Flag{Names: []string{"--priv"}, Value: true, Only: "add", Kind: strings.Join(snmp.PrivProtocols, "|")})
	}
	flags = append(flags,
		Flag{Names: []string{"--stdin"}, Only: "add"},
		Flag{Names: []string{"--none"}, Only: "default", Desc: "Choose no default user"})
	return Spec{MinArgs: 1, MaxArgs: 2, Args: []string{snmpV3UserActions, ""}, Flags: flags}
}

// snmpV3UserUsage are the usage lines of 'v3-user' under the verb family
// setter.
func snmpV3UserUsage(setter string, protocols bool) []string {
	add := "Usage: " + setter + " v3-user add <user> "
	if protocols {
		add += "[--auth sha|sha256] [--priv aes128] "
	}
	pad := strings.Repeat(" ", len("Usage: "))
	return []string{
		add + "[--default] [--stdin]",
		pad + setter + " v3-user remove <user>",
		pad + setter + " v3-user default [<user>|--none]",
		pad + setter + " v3-user list",
	}
}

// snmpStore is the credential files, with the registry's word on which
// devices have an snmp: entry (snmpcred.Store.Mapped): a device's file is
// written in the format that entry allows.
func (inv *invocation) snmpStore() snmpcred.Store {
	return snmpcred.Store{File: inv.app.Paths.SNMPFile, Dir: inv.app.Paths.SNMPDir, Mapped: func(name string) bool {
		d := inv.deviceNamed(name)
		return d != nil && !d.SNMP.Empty()
	}}
}

// snmpPool is where the verbs work: the config, a scope or a device.
type snmpPool struct {
	inv    *invocation
	level  snmpcred.Level
	setter string
	// scope is the scope the level is (a scope) or is in (a device); empty
	// for the config and for a device in no scope.
	scope string
	dev   *devreg.Entry
	// protocols: --auth and --priv are accepted (the config and a scope).
	protocols bool
}

func (inv *invocation) configPool() snmpPool {
	return snmpPool{inv: inv, level: snmpcred.Level{Kind: snmpcred.LevelDefault}, setter: snmpSetter(""), protocols: true}
}

func (inv *invocation) scopePool(scope string) snmpPool {
	return snmpPool{inv: inv, level: snmpcred.Level{Kind: snmpcred.LevelScope, Name: scope}, setter: snmpSetter(scope), scope: scope, protocols: true}
}

func (inv *invocation) devicePool(e devreg.Entry) snmpPool {
	return snmpPool{inv: inv, level: snmpcred.Level{Kind: snmpcred.LevelDevice, Name: e.Name}, setter: deviceSNMPSetter(e.Name), scope: e.Scope, dev: &e}
}

func (pl snmpPool) store() snmpcred.Store {
	return pl.inv.snmpStore()
}

// label is how the level is named in the messages.
func (pl snmpPool) label() string {
	switch pl.level.Kind {
	case snmpcred.LevelScope:
		return "scope '" + pl.level.Name + "'"
	case snmpcred.LevelDevice:
		return "device '" + pl.level.Name + "'"
	}
	return "the config"
}

// levelLabel is the label of another level.
func levelLabel(l snmpcred.Level) string {
	switch l.Kind {
	case snmpcred.LevelScope:
		return "scope '" + l.Name + "'"
	case snmpcred.LevelDevice:
		return "device '" + l.Name + "'"
	}
	return "the config"
}

// setterOfLevel is the verb family of a level.
func setterOfLevel(l snmpcred.Level) string {
	switch l.Kind {
	case snmpcred.LevelScope:
		return snmpSetter(l.Name)
	case snmpcred.LevelDevice:
		return deviceSNMPSetter(l.Name)
	}
	return snmpSetter("")
}

// read is the credentials the level has: for a device the file that is in
// force (deviceSNMPOwnOf).
func (pl snmpPool) read() (snmpcred.Creds, error) {
	if pl.dev != nil {
		own, err := pl.inv.deviceSNMPOwnOf(pl.dev.Device)
		if err != nil {
			return snmpcred.Creds{}, pl.inv.unreadableOwn(pl.dev.Name, err)
		}
		return own.Creds, nil
	}
	return pl.store().Load(pl.level)
}

// forWrite is the credentials a verb that changes the level starts from. A
// device's file that was ignored or cannot be read starts empty, and the verb
// says so (credsToReplace).
func (pl snmpPool) forWrite() (snmpcred.Creds, error) {
	if pl.dev != nil {
		return pl.inv.credsToReplace(pl.dev.Name), nil
	}
	return pl.store().Load(pl.level)
}

// write saves the level's credentials; nothing at all removes the file. A
// device's state is snapshotted first: the snapshot holds the old file.
func (pl snmpPool) write(c snmpcred.Creds) error {
	if pl.dev != nil {
		if err := pl.inv.snapshotFirst(); err != nil {
			return err
		}
	}
	pl.inv.app.Audit().Touch()
	return pl.store().Save(pl.level, c)
}

// devicesOfScope are the registered devices the scope answers, by name.
func (pl snmpPool) devicesOfScope() ([]string, error) {
	if pl.level.Kind != snmpcred.LevelScope {
		return nil, nil
	}
	_, res, err := pl.inv.deviceLoad()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range res.All() {
		if e.Source == devreg.SourceDevice && e.Scope == pl.level.Name {
			out = append(out, e.Name)
		}
	}
	return out, nil
}

// reachable are the pools a user can be looked up in from this level, the
// level's own first: a device's own, its scope's and the config's; a scope's
// and the config's, their own alone when own is set (the pools a default may
// name).
func (pl snmpPool) reachable(own bool) ([]snmpcred.Pool, error) {
	cur, err := pl.read()
	if err != nil {
		return nil, err
	}
	out := []snmpcred.Pool{{Level: pl.level, Creds: cur}}
	if pl.level.Kind != snmpcred.LevelDevice && own {
		return out, nil
	}
	st := pl.store()
	if pl.scope != "" && pl.level.Kind == snmpcred.LevelDevice {
		c, err := st.Load(snmpcred.Level{Kind: snmpcred.LevelScope, Name: pl.scope})
		if err != nil {
			return nil, err
		}
		out = append(out, snmpcred.Pool{Level: snmpcred.Level{Kind: snmpcred.LevelScope, Name: pl.scope}, Creds: c})
	}
	if pl.level.Kind != snmpcred.LevelDefault {
		c, err := st.Load(snmpcred.Level{Kind: snmpcred.LevelDefault})
		if err != nil {
			return nil, err
		}
		out = append(out, snmpcred.Pool{Level: snmpcred.Level{Kind: snmpcred.LevelDefault}, Creds: c})
	}
	return out, nil
}

// checkUserName is nil when name is an SNMPv3 user name.
func (inv *invocation) checkUserName(user string) error {
	if !reSNMPUser.MatchString(user) || names.SNMPTokenProblem(user, names.SNMPUserMax) != "" {
		return inv.usageErr("Invalid SNMPv3 user '" + user + "': 1-32 printable characters, no blanks, no '?' or '\"'.")
	}
	return nil
}

// run is 'v3-user <action> ...' of the level; args are the words after
// 'v3-user', already parsed by snmpV3UserSpec into p.
func (pl snmpPool) run(p Parsed) error {
	inv := pl.inv
	action := p.Args[0]
	usage := snmpV3UserUsage(pl.setter, pl.protocols)
	if !slices.Contains(strings.Split(snmpV3UserActions, "|"), action) {
		return inv.usageErr(append([]string{"Unknown action '" + action + "': add, remove, default or list."}, usage...)...)
	}
	// A flag of another action is refused (Only is for completion).
	for _, f := range []string{"--default", "--auth", "--priv", "--stdin"} {
		if p.Has(f) && action != "add" {
			return inv.usageErr(append([]string{f + " is for 'v3-user add'."}, usage...)...)
		}
	}
	if p.Has("--none") && action != "default" {
		return inv.usageErr(append([]string{"--none is for 'v3-user default'."}, usage...)...)
	}
	arg1 := ""
	if len(p.Args) > 1 {
		arg1 = p.Args[1]
	}
	switch action {
	case "add":
		if arg1 == "" {
			return inv.usageErr(usage...)
		}
		return pl.add(arg1, p)
	case "remove":
		if arg1 == "" {
			return inv.usageErr(usage...)
		}
		return pl.remove(arg1)
	case "default":
		if arg1 != "" && p.Has("--none") {
			return inv.usageErr(append([]string{"Give a user or --none, not both."}, usage...)...)
		}
		return pl.setDefault(arg1, p.Has("--none"))
	default:
		if arg1 != "" {
			return inv.usageErr(usage...)
		}
		return pl.list()
	}
}

// add puts a user in the pool, or replaces its passphrases when the level
// has it already (the way to change them).
func (pl snmpPool) add(user string, p Parsed) error {
	inv := pl.inv
	if err := inv.checkUserName(user); err != nil {
		return err
	}
	auth, priv := p.Value("--auth"), p.Value("--priv")
	if p.Has("--auth") && auth != snmp.AuthSHA && auth != snmp.AuthSHA256 {
		return inv.usageErr("Unknown --auth '" + auth + "': sha or sha256.")
	}
	if p.Has("--priv") && priv != snmp.PrivAES128 {
		return inv.usageErr("Unknown --priv '" + priv + "': aes128.")
	}
	if err := pl.checkUnique(user); err != nil {
		return err
	}
	stdin := p.Has("--stdin")
	ap, err := inv.readSecret(stdin, "authentication passphrase")
	if err != nil {
		return err
	}
	if msg := secretProblem(ap, "the authentication passphrase", 8, names.SNMPPassphraseMax); msg != "" {
		return inv.usageErr(msg)
	}
	pp, err := inv.readSecret(stdin, "privacy passphrase")
	if err != nil {
		return err
	}
	if msg := secretProblem(pp, "the privacy passphrase", 8, names.SNMPPassphraseMax); msg != "" {
		return inv.usageErr(msg)
	}
	c, err := pl.forWrite()
	if err != nil {
		return err
	}
	_, had := c.Find(user)
	c.Put(snmpcred.User{Name: user, AuthPass: ap, PrivPass: pp})
	if p.Has("--default") {
		c.Default = user
	}
	if err := pl.write(c); err != nil {
		return err
	}
	conf := inv.app.Conf()
	if auth != "" {
		if err := conf.Set(pl.protocolPath("auth"), auth); err != nil {
			return err
		}
	}
	if priv != "" {
		if err := conf.Set(pl.protocolPath("priv"), priv); err != nil {
			return err
		}
	}
	verb := "added to"
	if had {
		verb = "passphrases replaced in"
	}
	inv.app.Out.InfoE("SNMPv3 user '" + user + "' " + verb + " the pool of " + pl.label() + " (" + pl.file() + ")" +
		map[bool]string{true: "; it is the default", false: ""}[c.Default == user] + ".")
	pl.next(c)
	return nil
}

// protocolPath is the tacctl.yaml key of the level's auth or priv protocol.
func (pl snmpPool) protocolPath(which string) string {
	key := conf.SNMPKeyAuth
	if which == "priv" {
		key = conf.SNMPKeyPriv
	}
	if pl.level.Kind == snmpcred.LevelScope {
		return conf.SNMPPath(pl.level.Name, key)
	}
	return "snmp.v3." + which
}

// file is the credentials file of the level.
func (pl snmpPool) file() string {
	p, _ := pl.store().Path(pl.level)
	return p
}

// checkUnique refuses a user name another level that can see it holds.
func (pl snmpPool) checkUnique(user string) error {
	devs, err := pl.devicesOfScope()
	if err != nil {
		return err
	}
	peers, err := pl.store().Peers(pl.level, pl.scope, devs)
	if err != nil {
		return err
	}
	if l, ok := snmpcred.Holder(user, peers); ok {
		return pl.inv.usageErr("The SNMPv3 user '"+user+"' is in the pool of "+levelLabel(l)+" already: a name stands for one user wherever a device can see it.",
			"Remove it there first ("+setterOfLevel(l)+" v3-user remove "+user+") or choose another name. Nothing was changed.")
	}
	return nil
}

// remove takes a user out of the pool. A default that names it is cleared;
// a device that chose it (from another level's pool) is a refusal.
func (pl snmpPool) remove(user string) error {
	inv := pl.inv
	c, err := pl.forWrite()
	if err != nil {
		return err
	}
	if _, ok := c.Find(user); !ok {
		list := "it has none"
		if len(c.Users) > 0 {
			list = "it has: " + strings.Join(c.Names(), ", ")
		}
		return inv.usageErr("The pool of " + pl.label() + " has no user '" + user + "' (" + list + "). Nothing was changed.")
	}
	devs, err := pl.devicesOfScope()
	if err != nil {
		return err
	}
	refs, err := pl.store().Referrers(user, pl.level, devs)
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		var who []string
		for _, r := range refs {
			who = append(who, levelLabel(r))
		}
		return inv.usageErr("The SNMPv3 user '"+user+"' is the default of "+strings.Join(who, ", ")+": removing it would leave "+plural(len(refs), "it", "them")+" without a usable user.",
			"Choose another first ("+setterOfLevel(refs[0])+" v3-user default <user> or --none), then remove it. Nothing was changed.")
	}
	wasDefault := c.Default == user
	c.Drop(user)
	if err := pl.write(c); err != nil {
		return err
	}
	inv.app.Out.InfoE("SNMPv3 user '" + user + "' removed from the pool of " + pl.label() + ".")
	if wasDefault {
		inv.app.Out.Info(pl.label() + " has no default user now: " + pl.inheritWord() + ".")
	}
	pl.next(c)
	return nil
}

// inheritWord says what applies when the level has no default.
func (pl snmpPool) inheritWord() string {
	switch pl.level.Kind {
	case snmpcred.LevelDevice:
		return "its scope's default applies, else the config's"
	case snmpcred.LevelScope:
		return "the config's default applies"
	}
	return "no SNMPv3 lookup can be made until one is chosen (" + pl.setter + " v3-user default <user>)"
}

// setDefault shows, sets or clears the level's default user.
func (pl snmpPool) setDefault(user string, clear bool) error {
	inv := pl.inv
	if user == "" && !clear {
		c, err := pl.read()
		if err != nil {
			return err
		}
		if c.Default == "" {
			inv.echo("not set")
			return nil
		}
		inv.echo(c.Default)
		return nil
	}
	c, err := pl.forWrite()
	if err != nil {
		return err
	}
	if clear {
		if c.Default == "" {
			inv.app.Out.Info(pl.label() + " has no default user; nothing was changed.")
			return nil
		}
		c.Default = ""
		if err := pl.write(c); err != nil {
			return err
		}
		inv.app.Out.InfoE("The default SNMPv3 user of " + pl.label() + " is cleared: " + pl.inheritWord() + ".")
		pl.next(c)
		return nil
	}
	pools, err := pl.reachable(true)
	if err != nil {
		return err
	}
	if _, ok := snmpcred.Holder(user, pools); !ok {
		return inv.usageErr(pl.noSuchUser(user, pools)...)
	}
	if c.Default == user {
		inv.app.Out.Info("'" + user + "' is the default SNMPv3 user of " + pl.label() + " already; nothing was changed.")
		return nil
	}
	c.Default = user
	if err := pl.write(c); err != nil {
		return err
	}
	holder, _ := snmpcred.Holder(user, pools)
	from := ""
	if holder != pl.level {
		from = " (a user of " + levelLabel(holder) + ")"
	}
	inv.app.Out.InfoE("SNMPv3 user '" + user + "'" + from + " is the default of " + pl.label() + ".")
	pl.next(c)
	return nil
}

// noSuchUser is the refusal of a default that names nobody the level can
// use, with the users it can.
func (pl snmpPool) noSuchUser(user string, pools []snmpcred.Pool) []string {
	var have []string
	for _, p := range pools {
		for _, u := range p.Creds.Users {
			have = append(have, u.Name+" ("+levelLabel(p.Level)+")")
		}
	}
	msg := "No SNMPv3 user '" + user + "' to choose for " + pl.label() + ": "
	if len(have) == 0 {
		msg += "its pool is empty"
	} else {
		msg += "it can use " + strings.Join(have, ", ")
	}
	return []string{msg + ".", "Add it first: " + pl.setter + " v3-user add " + user + ". Nothing was changed."}
}

// next says what is still missing for the level's lookups after a change
// (c is the level's credentials as written).
func (pl snmpPool) next(c snmpcred.Creds) {
	inv := pl.inv
	var e snmpcred.Effective
	var err error
	switch pl.level.Kind {
	case snmpcred.LevelDevice:
		var own deviceSNMPOwn
		if own, err = inv.deviceSNMPOwnOf(pl.dev.Device); err == nil {
			e, err = inv.snmpEffectiveOwn(pl.scope, own)
		}
	default:
		e, err = inv.snmpEffective(pl.scope)
	}
	if err != nil {
		return
	}
	switch {
	case e.V3Problem != "":
		inv.app.Out.Warn("Not usable: " + e.V3Problem + ".")
	case e.Version != snmp.V3:
		cur := "not set"
		if e.Version != "" {
			cur = e.Version
		}
		inv.app.Out.Info("The SNMP version of " + pl.label() + " is " + cur + ": " + pl.setter + " version v3 reads with SNMPv3.")
	case e.User == "":
		inv.app.Out.Info("No user is the default of " + pl.label() + ": " + pl.setter + " v3-user default <user> chooses one.")
	}
}

// list prints the pool: names and whether the passphrases are set, never a
// passphrase. A caller below the engineer tier is told how many only.
func (pl snmpPool) list() error {
	inv := pl.inv
	c, err := pl.read()
	if err != nil {
		return err
	}
	title := "SNMPv3 users of " + pl.label()
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	if !inv.snmpUserVisible() {
		inv.echo("  " + strconv.Itoa(len(c.Users)) + " " + plural(len(c.Users), "user", "users") + " (the names are for the engineer tier and above)")
		inv.echo("")
		return nil
	}
	if len(c.Users) == 0 {
		inv.echo("  none (" + pl.setter + " v3-user add <user>)")
	}
	for _, u := range c.Users {
		mark := ""
		if u.Name == c.Default {
			mark = "  default"
		}
		state := "passphrases set"
		switch {
		case u.AuthPass == "" && u.PrivPass == "":
			state = "no passphrases"
		case u.AuthPass == "":
			state = "no authentication passphrase"
		case u.PrivPass == "":
			state = "no privacy passphrase"
		}
		inv.echo("  " + u.Name + mark + "  (" + state + ")")
	}
	if c.Default != "" {
		if _, own := c.Find(c.Default); !own {
			inv.echo("  default: " + c.Default + " (a user of another level's pool)")
		}
	}
	if pl.level.Kind == snmpcred.LevelDevice {
		if pools, err := pl.reachable(false); err == nil {
			for _, p := range pools[1:] {
				if len(p.Creds.Users) > 0 {
					inv.echo("  may also use: " + strings.Join(p.Creds.Names(), ", ") + " (" + levelLabel(p.Level) + ")")
				}
			}
		}
	}
	inv.echo("")
	return nil
}

// warnReferrers warns, before a verb that takes a whole pool away (clear, a
// scope's removal), about the devices whose default names a user of it: they
// cannot be read with SNMPv3 until they choose another. Nothing is refused:
// the pool goes either way.
func (pl snmpPool) warnReferrers() {
	c, err := pl.read()
	if err != nil || len(c.Users) == 0 {
		return
	}
	devs, err := pl.devicesOfScope()
	if err != nil {
		return
	}
	var who []string
	for _, u := range c.Users {
		refs, err := pl.store().Referrers(u.Name, pl.level, devs)
		if err != nil {
			return
		}
		for _, r := range refs {
			who = append(who, r.Name+" ("+u.Name+")")
		}
	}
	if len(who) > 0 {
		pl.inv.app.Out.Warn("These devices choose a user of " + pl.label() + "'s pool, which goes: " + strings.Join(who, ", ") +
			". Their SNMPv3 lookups fail until each is given another ('tacctl device snmp <device> v3-user default <user>').")
	}
}

// revealable is the user that 'show --reveal <user>' may print for the level,
// and the level whose pool holds it. The caller of a restricted tier (an
// engineer) may reveal a user of the level's own pool and the user in force
// (inForce), never another user of the config's pool or the scope's: that
// pool belongs to every scope, and a restricted caller reads their own
// scopes' settings only. Whoever may not is told what a missing user is told.
func (pl snmpPool) revealable(user, inForce string) (snmpcred.User, snmpcred.Level, bool, error) {
	pools, err := pl.reachable(false)
	if err != nil {
		return snmpcred.User{}, snmpcred.Level{}, false, err
	}
	l, ok := snmpcred.Holder(user, pools)
	if !ok {
		return snmpcred.User{}, snmpcred.Level{}, false, nil
	}
	if pl.inv.callerScopes().restricted && l != pl.level && user != inForce {
		return snmpcred.User{}, snmpcred.Level{}, false, nil
	}
	for _, p := range pools {
		if p.Level == l {
			u, _ := p.Creds.Find(user)
			return u, l, true, nil
		}
	}
	return snmpcred.User{}, snmpcred.Level{}, false, nil
}

// snmpNameFindings are the warnings of 'config validate' for an SNMPv3 user
// name that two pools a device can see hold, under the membership of the
// scopes now (a device's scope is the one its address falls in): each scope's
// pool against the config's, each device's own pool against its scope's and
// the config's. The lookup takes the device's own pool, then its scope's, then
// the config's, so the nearer pool wins; the finding names the levels and
// never a user. A restricted caller is told nothing: the pools are not theirs.
func (inv *invocation) snmpNameFindings() []validateFinding {
	if inv.callerScopes().restricted {
		return nil
	}
	st := inv.snmpStore()
	cfg, err := st.Load(snmpcred.Level{Kind: snmpcred.LevelDefault})
	if err != nil {
		return nil
	}
	shared := func(a, b snmpcred.Creds) bool {
		for _, u := range a.Users {
			if _, ok := b.Find(u.Name); ok {
				return true
			}
		}
		return false
	}
	var out []validateFinding
	add := func(text, fix string) {
		out = append(out, validateFinding{Section: "snmp_users", Level: levelWarning, Text: text, Fix: fix})
	}
	scopes := map[string]snmpcred.Creds{}
	names, _ := snmpcred.ScopeNames(st.Dir)
	for _, n := range names {
		c, err := st.Load(snmpcred.Level{Kind: snmpcred.LevelScope, Name: n})
		if err != nil {
			continue
		}
		scopes[n] = c
		if shared(c, cfg) {
			add("scope '"+n+"' and the config hold an SNMPv3 user of the same name; the scope's pool is searched first", "tacctl scope snmp "+n+" v3-user list")
		}
	}
	// The report has its own word on the registry; the note deviceLoad prints
	// once is not part of it.
	inv.registryNoted = true
	_, res, err := inv.deviceLoad()
	if err != nil {
		return out
	}
	for _, e := range res.All() {
		if e.Source != devreg.SourceDevice {
			continue
		}
		own, err := inv.deviceSNMPOwnOf(e.Device)
		if err != nil || len(own.Creds.Users) == 0 {
			continue
		}
		fix := "tacctl device snmp " + shellquote.Q(e.Name) + " v3-user list"
		if shared(own.Creds, cfg) {
			add("device '"+e.Name+"' and the config hold an SNMPv3 user of the same name; the device's pool is searched first", fix)
		}
		if sc, ok := scopes[e.Scope]; ok && e.Scope != "" && shared(own.Creds, sc) {
			add("device '"+e.Name+"' and its scope '"+e.Scope+"' hold an SNMPv3 user of the same name; the device's pool is searched first", fix)
		}
	}
	return out
}
