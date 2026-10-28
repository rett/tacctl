// Package pwchange decides who is held to a required password change
// (0.2.20, the store flag users.<name>.password_change_required).
//
// The flag is the administrator's request; whether it binds a user is
// decided here, at run time and everywhere the same way (the renderers, the
// login console, the command line, the verbs that list it): a superuser is
// never held to it, whatever the store says, and the user's tier is read
// from the group as it is now, so a user moved into a superuser group is
// exempt from then on and one moved out is held again. The tier is the one
// tier.ForGroup makes of the group's setting in tacctl.yaml and its priv-lvl;
// a member of a group that needs a tier setting and has lost it (priv-lvl 15
// or more, not the built-in superuser group) is held at the operator tier by
// the gate, and is held here too.
//
// The package is pure but for LocalServer, which reads the host registry for
// the one fact the carve needs (where this server is enrolled and by which
// method); the model and the tacctl.yaml view are arguments. It is imported by
// the renderers, so it must not import policy (which imports the RADIUS
// renderer).
package pwchange

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// superuserBand is the priv-lvl from which a group needs a tier setting
// (policy.SuperuserBand).
const superuserBand = 15

// Tier is the tier of the user's group as the flag sees it: the tier the
// gate gives the user, except that a group that lost its tier setting
// (ambiguous) is the operator tier, as the gate holds its members; the
// user's own state (disabled, the accounting sink) is not looked at. A user
// without a group, or a group without a priv-lvl, is tier.None.
func Tier(c *conf.Config, m *model.Model, u *model.User) tier.Tier {
	return GroupTier(c, m, u.Group)
}

// GroupTier is Tier for a group by name: what a user of the group is, for
// the verbs that decide before the user exists.
func GroupTier(c *conf.Config, m *model.Model, group string) tier.Tier {
	g := m.Group(group)
	if g == nil || g.PrivLvl == nil {
		return tier.None
	}
	setting := conf.GroupTierSetting(c, group)
	t := tier.ForGroup(setting, strconv.Itoa(*g.PrivLvl))
	// as policy.NeedsTier: the built-in superuser group is the superuser tier
	// by definition, any other group at priv-lvl 15 or more needs a setting
	if setting == "" && *g.PrivLvl >= superuserBand && group != "superuser" && tier.Rank(t) > tier.Rank(tier.Operator) {
		return tier.Operator
	}
	return t
}

// Superuser reports whether the user is a superuser by the tier of the
// group: the users the flag never binds.
func Superuser(c *conf.Config, m *model.Model, u *model.User) bool {
	return Tier(c, m, u) == tier.Superuser
}

// Subject reports whether the user is held to a password change now: the
// flag is set, the user is no accounting sink, and no superuser.
func Subject(c *conf.Config, m *model.Model, u *model.User) bool {
	return u != nil && u.PasswordChangeRequired && !u.AccountingSink && !Superuser(c, m, u)
}

// ServerAddress is the address this server's own logins (the console's
// pam_tacplus or pam_radius) come from by default: the one 'host enroll
// --local' needs a scope to cover.
const ServerAddress = "127.0.0.1"

// Server is how this server's own logins reach the backends, from the host
// registry's entry of the server (the one 'host enroll --local' writes): the
// scope it is enrolled in and the protocol of its method. Only that scope,
// for that protocol, is where a user who must change the password keeps a
// place; the zero Server (not enrolled, or the registry cannot be read) keeps
// none, so such a user is rendered nowhere.
type Server struct {
	// Scope is the scope the server is enrolled in.
	Scope string
	// Protocol is "tacacs" for the tacplus method, "radius" for radius: the
	// protocol of the server's own logins.
	Protocol string
	// Address is the registry's server field: where the server's PAM module
	// connects ("" for none, which is ServerAddress).
	Address string
}

// ServerOf is the Server of a registry entry of the local host.
func ServerOf(e hosts.Entry) Server {
	proto, _ := hosts.MethodBackend(e.EffectiveMethod())
	return Server{Scope: e.Scope, Protocol: proto, Address: e.Server}
}

// LocalServer reads the registry at path and returns the Server of its local
// entry; the zero Server when there is none or the file cannot be read.
func LocalServer(path string) Server {
	r, err := hosts.LoadRegistry(path)
	if err != nil {
		return Server{}
	}
	for _, e := range r.Entries() {
		if e.Target == hosts.Local {
			return ServerOf(e)
		}
	}
	return Server{}
}

// LoginAddresses are the addresses the server's own logins come from: the
// loopback address, and the address its PAM module is told to connect to when
// that is another address (host enroll --local --server <address>), because
// a connection to an address of the machine itself is sourced from that
// address. Whatever scope is meant to answer the server must answer all of
// them, and a prefix that holds one of them is the server's, not a device's.
func (s Server) LoginAddresses() []string {
	out := []string{ServerAddress}
	if a := strings.TrimSpace(s.Address); a != "" && a != ServerAddress {
		if _, ok := store.ParseNet(a); ok {
			out = append(out, a)
		}
	}
	return out
}

// Carve is the model a renderer of protocol ("tacacs" or "radius") writes: a
// user held to a password change keeps, of the scopes of theirs, only the
// scope this server is enrolled in, and only in the protocol of the server's
// own logins. A login from a device finds no scope the user is in and fails
// as for an unknown user, in either protocol; the login at tacctl, which comes
// from the server, still works and the password can be changed there. In the
// other protocol the user is rendered with no scope at all: a catch-all scope
// of that protocol that answers 127.0.0.1 too would otherwise keep every device
// of that protocol open to the old password. Every other user, a superuser and
// an unflagged one included, is the same user. The decision is made here and
// now from the group's tier, never from the store alone (Subject), so the same
// model renders the same bytes. The store is not changed.
func Carve(m *model.Model, view *yamlpy.Map, protocol string, server Server) *model.Model {
	c := conf.View(view)
	return m.WithUserScopes(func(u *model.User) ([]string, bool) {
		if !Subject(c, m, u) {
			return nil, false
		}
		keep := []string{}
		if server.Scope != "" && server.Protocol == protocol {
			for _, s := range u.Scopes {
				if s == server.Scope {
					keep = append(keep, s)
				}
			}
		}
		return keep, true
	})
}

// SharedPrefixes are the prefixes of the scope that answer more than this
// server: any that is not inside 127.0.0.0/8, is not ::1 and is not one of the
// server's other login addresses (Server.LoginAddresses) as a single-address
// prefix. A scope that has one is shared with devices, and the devices in it
// still authenticate a held user: the scope is all a renderer can cut by.
func (s Server) SharedPrefixes(sc *model.Scope) []string {
	var out []string
	for _, p := range sc.Prefixes {
		if cidr.ContainsNet("127.0.0.0/8", p) || cidr.ContainsAddr("::1/128", p) {
			continue
		}
		if n, ok := store.ParseNet(p); ok && n.IsHost() && s.holdsLoginAddress(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (s Server) holdsLoginAddress(prefix string) bool {
	for _, a := range s.LoginAddresses() {
		if cidr.ContainsAddr(prefix, a) {
			return true
		}
	}
	return false
}

// Pending are the users held to a password change now, by name.
func Pending(c *conf.Config, m *model.Model) []*model.User {
	var out []*model.User
	for _, n := range m.UserNames() {
		if u := m.User(n); Subject(c, m, u) {
			out = append(out, u)
		}
	}
	return out
}
