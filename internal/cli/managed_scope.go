package cli

// The scope of this server's own logins (0.2.21, pwchange.ManagedScope):
// tacctl manages it, every user is a member of it for the server's login
// only, and no listing shows it. This file is the command side: whether the
// server is registered in it (managedScope), the model the server's own
// accounts are made from (serverModel), the model the listings show
// (shownModel), the refusal of the verbs that name it (reservedScope), and
// the cleanup of a stored copy in a user's own scopes (managedCleanup).

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// managedScope is pwchange.ManagedScope when this server is registered in it
// (the registry's local entry names it) and the scope of that name is the
// managed one (pwchange.Server.ManagedIn: it answers the server's login
// addresses only), "" otherwise or when the registry or the store cannot be
// read. An operator's scope of that name is none of tacctl's: it is listed and
// edited like any other.
func (inv *invocation) managedScope() string {
	if e, ok, err := inv.localHost(); err == nil && ok && e.Scope == pwchange.ManagedScope {
		if m, err := inv.model(); err == nil && pwchange.ServerOf(e).ManagedIn(m) {
			return e.Scope
		}
	}
	return ""
}

// serverModel is the model the accounts of a host are made from: on this
// server in the managed scope (srv, the server's registration) every user is
// in it (pwchange.WithServerScope), registered yet or about to be.
func (inv *invocation) serverModel(m *model.Model, srv pwchange.Server) *model.Model {
	return pwchange.WithServerScope(inv.app.Conf(), m, srv)
}

// serverOfEntry is the server of a registry entry for serverModel: this
// server's registration, the zero Server for any other host.
func serverOfEntry(e hosts.Entry) pwchange.Server {
	if e.Target != hosts.Local {
		return pwchange.Server{}
	}
	return pwchange.ServerOf(e)
}

// shownModel is the model the listings show: without the managed scope while
// the server is registered in it.
func (inv *invocation) shownModel() (*model.Model, error) {
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	return m.WithoutScope(inv.managedScope()), nil
}

// reservedText is the refusal of a verb that names the managed scope.
const reservedText = "Scope '" + pwchange.ManagedScope + "' is reserved."

// reservedScope refuses a verb that works on the scope name while the server
// is registered in the managed scope.
func (inv *invocation) reservedScope(name string) error {
	if name == pwchange.ManagedScope && inv.managedScope() != "" {
		return inv.usageErr(reservedText + " Nothing was changed.")
	}
	return nil
}

// reservedNewScope refuses a verb that would make the name a scope of the
// operator's (scope add, scope rename to it), whether or not the server is
// registered in it yet.
func (inv *invocation) reservedNewScope(name string) error {
	if name == pwchange.ManagedScope {
		return inv.usageErr(reservedText + " Pick another name. Nothing was changed.")
	}
	return nil
}

// reservedScopeArg is run with the refusal of reservedScope for its first
// argument: the verbs 'scope <verb> <scope> ...'.
func (inv *invocation) reservedScopeArg(run func([]string) error) func([]string) error {
	return func(args []string) error {
		if err := inv.reservedScope(arg(args, 0)); err != nil {
			return err
		}
		return run(args)
	}
}

// managedCleanup wraps a store change: a user whose record the change writes
// (a new name included) loses the managed scope from its stored scopes, in
// the same mutation, while the server is registered in it. The user is a
// member of it without it, so the stored copy is clutter; nothing else is
// rewritten. Users the change does not write are left as they are.
func (inv *invocation) managedCleanup(fn func(*store.Store) error) func(*store.Store) error {
	if inv.managedScope() == "" {
		return fn
	}
	return func(s *store.Store) error {
		before := model.FromStore(s)
		if err := fn(s); err != nil {
			return err
		}
		after := model.FromStore(s)
		for _, u := range after.Users {
			if !slices.Contains(u.Scopes, pwchange.ManagedScope) {
				continue
			}
			if was := before.User(u.Name); was != nil && sameUser(was, u) {
				continue
			}
			kept := slices.DeleteFunc(slices.Clone(u.Scopes), func(s string) bool { return s == pwchange.ManagedScope })
			if err := s.UserSet(u.Name, "scopes="+joinComma(kept)); err != nil {
				return err
			}
		}
		return nil
	}
}

// sameUser reports whether a store change left the user's record as it was.
func sameUser(a, b *model.User) bool {
	return a.Group == b.Group && slices.Equal(a.Scopes, b.Scopes) && a.Hash == b.Hash && a.Disabled == b.Disabled &&
		a.PasswordChanged == b.PasswordChanged && a.AccountingSink == b.AccountingSink && a.PasswordChangeRequired == b.PasswordChangeRequired
}

func joinComma(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// noScopesText is the word of a listing for a user with no scope of its own:
// red, unless the server is registered in the managed scope, where the user
// still logs in to the server (the listings do not say how).
func (inv *invocation) noScopesText(text string) string {
	if inv.managedScope() != "" {
		return text
	}
	return ui.Red + text + ui.NC
}

// errManagedNeedsEnroll says that this server's own login cannot be taken
// over without a new client setup (the scope it is registered in serves
// others too): only 'host enroll --local' does that.
var errManagedNeedsEnroll = errors.New("this server's own login needs 'tacctl host enroll --local'")

// errManagedClash says that a scope of the operator's has the reserved name,
// so this server's own login cannot be set up or repaired. The caller says
// it with managedClashText.
var errManagedClash = errors.New("a scope of the operator's has the reserved name")

// managedClashText is the one line of the refusal: the clash and the fix.
const managedClashText = reservedText + " Rename the scope of that name first: tacctl scope rename " + pwchange.ManagedScope + " <new-name>. Nothing was changed."

// managedSetupErr is the refusal managedSetup's error says: the clash (one
// line, the fix named); anything else as it is.
func (inv *invocation) managedSetupErr(err error) error {
	if errors.Is(err, errManagedClash) {
		return inv.usageErr(managedClashText)
	}
	return err
}

// entryManaged reports whether e, the registration of this server, is in the
// managed scope as tacctl manages it (pwchange.Server.ManagedIn).
func (inv *invocation) entryManaged(e hosts.Entry) bool {
	if e.Target != hosts.Local || e.Scope != pwchange.ManagedScope {
		return false
	}
	m, err := inv.model()
	return err == nil && pwchange.ServerOf(e).ManagedIn(m)
}

// managedClashFinding is the finding of an enrolled server whose own login
// cannot be managed because a scope of the operator's has the reserved name:
// the scope answers an address other than the server's login addresses. Only
// an enrolled server has one: before the enrolment 'host enroll --local'
// refuses with the same words.
func (inv *invocation) managedClashFinding(entries []hosts.Entry) (hostFinding, bool) {
	var e hosts.Entry
	found := false
	for _, x := range entries {
		if x.Target == hosts.Local {
			e, found = x, true
		}
	}
	if !found {
		return hostFinding{}, false
	}
	m, err := inv.model()
	if err != nil {
		return hostFinding{}, false
	}
	servers := []pwchange.Server{pwchange.ServerOf(e)}
	if addr := inv.app.Conf().ServerAddress(); addr != "" {
		servers = append(servers, pwchange.Server{Scope: pwchange.ManagedScope, Address: addr})
	}
	if !pwchange.Clash(m, servers...) {
		return hostFinding{}, false
	}
	return hostFinding{
		Text:  "a scope of the operator's has the name '" + pwchange.ManagedScope + "', which this server's own login needs, so a sync or an enrolment of '" + e.Name + "' is refused",
		Fix:   "tacctl scope rename " + pwchange.ManagedScope + " <new-name>",
		Hosts: []string{e.Name},
	}, true
}

// sharedWith are the others a scope of this server's serves, by name: the
// other enrolled hosts registered in it, its staging addresses, the devices
// and enrolled hosts whose address falls in its prefixes, and any prefix
// that answers more than the server (pwchange.Server.SharedPrefixes). None:
// the scope is the server's alone and can be taken over as it is.
func (inv *invocation) sharedWith(m *model.Model, reg *hosts.Registry, scope string, srv pwchange.Server) ([]string, error) {
	sc := m.Scope(scope)
	if sc == nil {
		return nil, nil
	}
	var out []string
	for _, p := range srv.SharedPrefixes(sc) {
		out = append(out, "prefix "+p)
	}
	for _, e := range reg.Entries() {
		if e.Target != hosts.Local && e.Scope == scope {
			out = append(out, "host "+e.Name)
		}
	}
	for _, s := range inv.stagingLoad() {
		if s.Scope == scope {
			out = append(out, "staging "+s.CIDR)
		}
	}
	devs, err := inv.hostDevices()
	if err != nil {
		return nil, err
	}
	in := func(addr string) bool {
		for _, p := range sc.Prefixes {
			if addr != "" && cidr.ContainsAddr(p, addr) {
				return true
			}
		}
		return false
	}
	for _, d := range devs.Devices {
		if in(d.Address) {
			out = append(out, "device "+d.Name)
		}
	}
	for _, e := range reg.Entries() {
		if e.Target != hosts.Local && e.Scope != scope && in(devs.HostAddressOf(e.Name)) {
			out = append(out, "host "+e.Name)
		}
	}
	return out, nil
}

// secretUsable reports whether a scope secret can be written to the PAM
// configuration of this server and is no placeholder.
func (inv *invocation) secretUsable(secret string) bool {
	return secret != "" && !strings.HasPrefix(secret, "REPLACE") && reSecretSafe.MatchString(secret) && runes(secret) >= inv.app.Tunables().SecretMinLength
}

var reSecretSafe = regexp.MustCompile(`^[A-Za-z0-9_.+/=-]+$`)

// managedPrefixesWrite sets the managed scope's prefixes to the server's
// login addresses (prefixes), taking each of them out of any other scope
// that has it exactly (one prefix, one scope).
func managedPrefixesWrite(s *store.Store, prefixes []string) error {
	m := model.FromStore(s)
	for _, sc := range m.Scopes {
		if sc.Name == pwchange.ManagedScope {
			continue
		}
		kept := slices.DeleteFunc(slices.Clone(sc.Prefixes), func(p string) bool { return slices.Contains(prefixes, canonCIDR(p)) })
		if len(kept) != len(sc.Prefixes) {
			if err := s.ScopeSet(sc.Name, "prefixes="+strings.Join(kept, ",")); err != nil {
				return err
			}
		}
	}
	return s.ScopeSet(pwchange.ManagedScope, "prefixes="+strings.Join(prefixes, ","))
}

func canonCIDR(p string) string {
	if n, ok := store.ParseNet(p); ok {
		return n.String()
	}
	return p
}

// managedSetup makes the managed scope ready for this server's own login at
// the server address server, before the client script runs (the enrolment,
// fresh is true) or the sync of the server (fresh is false):
//
//   - registered in it: the prefixes are the login addresses and the secret
//     is usable; anything else is repaired (the secret only by an enrolment,
//     whose script writes it), with one line;
//   - registered in another scope that serves only the server: that scope is
//     renamed to the managed one in one apply, its secret kept (the server's
//     PAM configuration stays valid), its prefixes made the login addresses;
//   - registered in a scope that serves others too, or not registered: a new
//     managed scope with a secret of its own (an enrolment only; the sync
//     says what to run), the old scope left for the others.
//
// An operator's own scope of the reserved name, one that answers an address
// other than the server's login addresses, is never taken over, repaired or
// given members: managedSetup refuses with errManagedClash, whichever scope the
// server is registered in. A scope of that name that answers the login
// addresses only, has no member and is shared with no one is what an
// enrolment that did not finish left, when the server is registered in no
// other scope: the enrolment adopts it. undo, when not nil, takes a new scope
// out again when the client script fails.
func (inv *invocation) managedSetup(reg *hosts.Registry, server string, fresh bool) (undo func(), err error) {
	a := inv.app
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	srv := pwchange.Server{Scope: pwchange.ManagedScope, Address: server}
	prefixes := srv.Prefixes()
	cur, registered := inv.localEntryOf(reg)
	servers := []pwchange.Server{srv}
	if registered {
		servers = append(servers, pwchange.ServerOf(cur))
	}
	exists := m.Scope(pwchange.ManagedScope) != nil
	ours := registered && cur.Scope == pwchange.ManagedScope
	if exists {
		sc := m.Scope(pwchange.ManagedScope)
		if !pwchange.OnlyLoginAddresses(sc, servers...) {
			return nil, errManagedClash
		}
		if !ours {
			// an enrolment that did not finish may have made it
			others, err := inv.sharedWith(m, reg, pwchange.ManagedScope, srv)
			if err != nil {
				return nil, err
			}
			if len(others) > 0 || len(m.Members(pwchange.ManagedScope)) > 0 || (registered && cur.Scope != pwchange.ManagedScope) {
				return nil, errManagedClash
			}
			ours = true
		}
	}
	if ours && exists {
		sc := m.Scope(pwchange.ManagedScope)
		var fields []string
		if !slices.Equal(canonList(sc.Prefixes), prefixes) {
			fields = append(fields, "prefixes")
		}
		if !inv.secretUsable(sc.Secret) {
			if !fresh {
				a.Out.WarnE("This server's own login needs a new secret: tacctl host enroll --local")
			} else {
				fields = append(fields, "secret")
			}
		}
		if len(fields) == 0 {
			return nil, nil
		}
		secret, err := ui.RandomBase64(a.Knobs.Rand(), 24)
		if err != nil {
			return nil, err
		}
		if err := inv.applyStore(func(s *store.Store) error {
			if slices.Contains(fields, "secret") {
				if err := s.ScopeSet(pwchange.ManagedScope, "secret="+secret); err != nil {
					return err
				}
			}
			return managedPrefixesWrite(s, prefixes)
		}); err != nil {
			return nil, err
		}
		a.Out.InfoE("Repaired the managed server login.")
		return nil, nil
	}
	if registered && cur.Scope != "" && m.Scope(cur.Scope) != nil {
		old := cur.Scope
		others, err := inv.sharedWith(m, reg, old, srv)
		if err != nil {
			return nil, err
		}
		if len(others) == 0 {
			if err := inv.scopeRenameCheck(old, pwchange.ManagedScope); err != nil {
				return nil, inv.scopeRefused(err)
			}
			if err := inv.scopeRenameWith(old, pwchange.ManagedScope, func(s *store.Store) error { return managedPrefixesWrite(s, prefixes) }); err != nil {
				return nil, err
			}
			a.Out.InfoE("Scope '" + old + "' served this server's own login only: tacctl manages it from now on, with its secret kept.")
			return nil, nil
		}
		if !fresh {
			return nil, errManagedNeedsEnroll
		}
		a.Out.InfoE("Scope '" + old + "' also serves " + strings.Join(others, ", ") + " and stays for them; this server's own login gets its own, set up by this enrolment.")
	}
	if !fresh {
		return nil, errManagedNeedsEnroll
	}
	secret, err := ui.RandomBase64(a.Knobs.Rand(), 24)
	if err != nil {
		return nil, err
	}
	before := map[string][]string{}
	for _, sc := range m.Scopes {
		before[sc.Name] = sc.Prefixes
	}
	if err := inv.applyStore(func(s *store.Store) error {
		if err := s.ScopeSet(pwchange.ManagedScope, "prefixes="+strings.Join(prefixes, ","), "secret="+secret); err != nil {
			return err
		}
		return managedPrefixesWrite(s, prefixes)
	}); err != nil {
		return nil, err
	}
	return func() {
		// the client script failed: the scopes are put back as they were
		_ = inv.applyStore(func(s *store.Store) error {
			if err := s.ScopeDel(pwchange.ManagedScope, true); err != nil {
				return err
			}
			for name, p := range before {
				if err := s.ScopeSet(name, "prefixes="+strings.Join(p, ",")); err != nil {
					return err
				}
			}
			return nil
		})
	}, nil
}

func canonList(list []string) []string {
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, canonCIDR(p))
	}
	return out
}

// localEntryOf is the registry's entry of this server.
func (inv *invocation) localEntryOf(reg *hosts.Registry) (hosts.Entry, bool) {
	for _, e := range reg.Entries() {
		if e.Target == hosts.Local {
			return e, true
		}
	}
	return hosts.Entry{}, false
}

// localServerAddress is the server address of 'host enroll --local': the one
// given (checked: an IP address devices and hosts can reach, which need not
// be on this machine), else the one recorded for this server, else the
// address of the interface with the default route, said in one line.
func (inv *invocation) localServerAddress(reg *hosts.Registry, given string) (string, error) {
	if given != "" {
		if err := hosts.CheckServerAddress(given); err != nil {
			return "", inv.usageErr(err.Error() + ". Nothing was changed.")
		}
		return canonAddr(given), nil
	}
	// the recorded address: the setting, else (an install from before
	// 0.2.21) the copy in this server's registry entry; never replaced by
	// what the detection finds
	if addr := inv.app.Conf().ServerAddress(); addr != "" {
		return addr, nil
	}
	if e, ok := inv.localEntryOf(reg); ok && hosts.CheckServerAddress(e.Server) == nil {
		return canonAddr(e.Server), nil
	}
	detect := inv.app.ServerAddress
	if detect == nil {
		detect = hosts.LocalServerAddress
	}
	addr, iface, err := detect()
	if err != nil {
		return "", inv.usageErr("No address of this machine can be the server address: give --server <address>. Nothing was changed.")
	}
	inv.app.Out.InfoE("Using " + addr + " as the server address (the address of " + iface + "); pass --server to use another.")
	return addr, nil
}

func canonAddr(s string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return a.String()
	}
	return s
}

// managedRemove takes the managed scope out with this server's registration
// e (host unenroll, host forget): nothing else can use it. A scope of the
// reserved name that is the operator's (not the managed one) is left alone.
func (inv *invocation) managedRemove(e hosts.Entry) {
	if !inv.entryManaged(e) {
		return
	}
	if err := inv.applyStore(func(s *store.Store) error { return s.ScopeDel(pwchange.ManagedScope, true) }); err != nil {
		inv.reportOnly(err)
	}
}

// recordServerAddress writes the server address to server.addresses when it
// differs: after the registry entry of this server holds the same address
// (host enroll --local), so the two never differ for long, and 0.2.20, which
// reads the entry, finds it after a rollback (which removes the key).
func (inv *invocation) recordServerAddress(addr string) error {
	c := inv.app.Conf()
	if c.ServerAddress() == addr {
		return nil
	}
	return c.SetList(conf.ServerAddressesKey, []string{addr})
}
