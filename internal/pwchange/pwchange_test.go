package pwchange

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

func testModel(t *testing.T) *model.Model {
	t.Helper()
	st := store.Empty()
	set := func(name string, f ...string) {
		t.Helper()
		if err := st.GroupSet(name, f...); err != nil {
			t.Fatal(err)
		}
	}
	set("netops", "priv_lvl=15", "juniper_class=NET-CLASS")
	set("helpdesk", "priv_lvl=7", "juniper_class=HD-CLASS")
	if err := st.ScopeSet("lab", "prefixes=192.0.2.0/24", "secret=example-secret-example-secret"); err != nil {
		t.Fatal(err)
	}
	if err := st.ScopeSet("srv", "prefixes=127.0.0.1/32", "secret=example-secret-example-secret"); err != nil {
		t.Fatal(err)
	}
	for _, u := range [][2]string{
		{"alice", "superuser"}, {"bob", "operator"}, {"carol", "readonly"}, {"dave", "netops"}, {"erin", "helpdesk"},
	} {
		if err := st.UserSet(u[0], "group="+u[1], "scopes=lab,srv", "disabled=false", "password_change_required=true"); err != nil {
			t.Fatal(err)
		}
	}
	// a user that is not flagged, and the accounting sink
	if err := st.UserSet("frank", "group=operator", "scopes=lab,srv"); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("root", "group=readonly", "password_change_required=true"); err != nil {
		t.Fatal(err)
	}
	return model.FromStore(st)
}

func view(tiers ...string) *conf.Config {
	t := yamlpy.NewMap()
	for i := 0; i+1 < len(tiers); i += 2 {
		t.Set(tiers[i], tiers[i+1])
	}
	return conf.View(yamlpy.NewMap("tier", t))
}

func names(us []*model.User) []string {
	var out []string
	for _, u := range us {
		out = append(out, u.Name)
	}
	return out
}

// A superuser is never held to the flag, and the tier is the group's now.
func TestSubjectFollowsTheTierOfTheGroup(t *testing.T) {
	m := testModel(t)
	for _, c := range []struct {
		name string
		cfg  *conf.Config
		want bool
	}{
		// the built-in superuser group is the superuser tier
		{"alice", view(), false},
		{"bob", view(), true},
		{"carol", view(), true},
		// a group at 15 with no setting lost its tier: held at the operator tier, so held
		{"dave", view(), true},
		// the setting makes it a superuser group, or an engineer's
		{"dave", view("netops", "superuser"), false},
		{"dave", view("netops", "engineer"), true},
		// a group at 7 set to superuser: exempt
		{"erin", view("helpdesk", "superuser"), false},
		{"erin", view(), true},
		// a setting that cannot be one is readonly, never a superuser
		{"dave", view("netops", "root"), true},
		// not flagged, and the accounting sink
		{"frank", view(), false},
		{"root", view(), false},
	} {
		if got := Subject(c.cfg, m, m.User(c.name)); got != c.want {
			t.Errorf("Subject(%s) = %v, want %v", c.name, got, c.want)
		}
	}
	if Subject(view(), m, nil) {
		t.Error("an unknown user is held")
	}
}

// A flagged superuser is exempt, not unflagged: moved out of the superuser
// group the flag binds again, with no write to the store.
func TestSuperuserIsExemptAtRunTimeNotUnflagged(t *testing.T) {
	m := testModel(t)
	if !m.User("alice").PasswordChangeRequired || Subject(view(), m, m.User("alice")) {
		t.Fatal("alice is flagged and a superuser")
	}
	if !Superuser(view(), m, m.User("alice")) || Superuser(view(), m, m.User("bob")) {
		t.Error("Superuser")
	}
	if got := names(Pending(view(), m)); !slices.Equal(got, []string{"bob", "carol", "dave", "erin"}) {
		t.Errorf("Pending: %v", got)
	}
	// a user with no group is none: held
	u := *m.User("bob")
	u.Group = "gone"
	if Superuser(view(), m, &u) {
		t.Error("a user of a missing group is a superuser")
	}
}

var (
	tacplusServer = Server{Scope: "srv", Protocol: "tacacs"}
	radiusServer  = Server{Scope: "srv", Protocol: "radius"}
)

// Carve leaves a held user in the scope this server is enrolled in and in no
// other, and every other user as they are.
func TestCarveKeepsTheServersScopeOnly(t *testing.T) {
	m := testModel(t)
	got := Carve(m, yamlpy.NewMap(), "tacacs", tacplusServer)
	for name, want := range map[string]string{"alice": "lab,srv", "bob": "srv", "carol": "srv", "dave": "srv", "erin": "srv", "frank": "lab,srv"} {
		if g := strings.Join(got.User(name).Scopes, ","); g != want {
			t.Errorf("%s: %q, want %q", name, g, want)
		}
	}
	if got.User("alice") != m.User("alice") || got.User("frank") != m.User("frank") {
		t.Error("a user the flag does not bind is copied")
	}
	if g := strings.Join(m.User("bob").Scopes, ","); g != "lab,srv" {
		t.Errorf("the receiver was changed: %q", g)
	}
}

// splitModel is bob (operator, flagged) in a catch-all scope 'all' and in 'srv',
// where srv serves srvProto and all serves allProto: all answers 127.0.0.1
// too, but is not the scope the server is enrolled in.
func splitModel(t *testing.T, srvProto, allProto string) *model.Model {
	t.Helper()
	st := store.Empty()
	if err := st.ScopeSet("srv", "prefixes=127.0.0.1/32", "secret=example-secret-example-secret", "protocols="+srvProto); err != nil {
		t.Fatal(err)
	}
	if err := st.ScopeSet("all", "prefixes=0.0.0.0/0", "secret=example-secret-example-secret", "protocols="+allProto); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("bob", "group=operator", "scopes=all,srv", "password_change_required=true"); err != nil {
		t.Fatal(err)
	}
	return model.FromStore(st)
}

// A scope that answers 127.0.0.1 for the other protocol is not the server's:
// the server's logins use one protocol, and a flagged user is not rendered for
// the other at all, so none of its devices accepts the old password.
func TestCarveDropsEveryScopeOfTheOtherProtocol(t *testing.T) {
	for _, c := range []struct {
		name               string
		srvProto, allProto string
		server             Server
		protocol           string
		want               string
	}{
		// the failing input: a RADIUS server, srv radius-only, all a TACACS+ catch-all
		{"radius server, tacacs file", "radius", "tacacs", radiusServer, "tacacs", ""},
		{"radius server, radius file", "radius", "tacacs", radiusServer, "radius", "srv"},
		// the mirror: a TACACS+ server, srv tacacs-only, all a RADIUS catch-all
		{"tacacs server, radius file", "tacacs", "radius", tacplusServer, "radius", ""},
		{"tacacs server, tacacs file", "tacacs", "radius", tacplusServer, "tacacs", "srv"},
		// both protocols serve both scopes: the method of the server decides
		{"radius server, tacacs file, both served", "tacacs,radius", "tacacs,radius", radiusServer, "tacacs", ""},
		{"tacacs server, radius file, both served", "tacacs,radius", "tacacs,radius", tacplusServer, "radius", ""},
		{"tacacs server, tacacs file, both served", "tacacs,radius", "tacacs,radius", tacplusServer, "tacacs", "srv"},
		// a server that is not enrolled keeps no scope
		{"not enrolled", "tacacs,radius", "tacacs,radius", Server{}, "tacacs", ""},
		// a registry scope that is not one of the user's
		{"another scope", "tacacs", "tacacs", Server{Scope: "other", Protocol: "tacacs"}, "tacacs", ""},
	} {
		m := splitModel(t, c.srvProto, c.allProto)
		got := Carve(m, yamlpy.NewMap(), c.protocol, c.server)
		if g := strings.Join(got.User("bob").Scopes, ","); g != c.want {
			t.Errorf("%s: bob is in %q, want %q", c.name, g, c.want)
		}
	}
}

func TestServerOfAndLoginAddresses(t *testing.T) {
	if s := ServerOf(hosts.Entry{Name: "tacacs", Target: hosts.Local, Scope: "srv", Server: "127.0.0.1"}); s != (Server{Scope: "srv", Protocol: "tacacs", Address: "127.0.0.1"}) {
		t.Errorf("tacplus: %+v", s)
	}
	if s := ServerOf(hosts.Entry{Scope: "srv", Method: "radius"}); s.Protocol != "radius" {
		t.Errorf("radius: %+v", s)
	}
	for _, c := range []struct {
		server string
		want   []string
	}{
		{"", []string{"127.0.0.1"}},
		{"127.0.0.1", []string{"127.0.0.1"}},
		{"192.0.2.10", []string{"127.0.0.1", "192.0.2.10"}},
		{"tacacs.example.net", []string{"127.0.0.1"}},
	} {
		if got := (Server{Address: c.server}).LoginAddresses(); !slices.Equal(got, c.want) {
			t.Errorf("LoginAddresses(%q) = %v, want %v", c.server, got, c.want)
		}
	}
}

func TestLocalServerReadsTheRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if got := LocalServer(path); got != (Server{}) {
		t.Errorf("no file: %+v", got)
	}
	reg := "web1|admin@web1.example.net|22|lab|192.0.2.10||\n" + "tacacs|local||srv|127.0.0.1||radius\n"
	if err := os.WriteFile(path, []byte(reg), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LocalServer(path); got != (Server{Scope: "srv", Protocol: "radius", Address: "127.0.0.1"}) {
		t.Errorf("local entry: %+v", got)
	}
	if err := os.WriteFile(path, []byte("web1|admin@web1.example.net|22|lab|192.0.2.10||\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LocalServer(path); got != (Server{}) {
		t.Errorf("no local entry: %+v", got)
	}
	// a path that is a directory cannot be read: no server
	if got := LocalServer(dir); got != (Server{}) {
		t.Errorf("unreadable: %+v", got)
	}
}

func TestSharedPrefixes(t *testing.T) {
	s := &model.Scope{Name: "srv", Prefixes: []string{"127.0.0.1/32", "127.0.0.0/8", "::1/128", "192.0.2.10/32", "192.0.2.0/24", "198.51.100.9/32", "2001:db8::/32"}}
	if got := (Server{Address: "192.0.2.10"}).SharedPrefixes(s); !slices.Equal(got, []string{"192.0.2.0/24", "198.51.100.9/32", "2001:db8::/32"}) {
		t.Errorf("with the server's address: %v", got)
	}
	if got := (Server{}).SharedPrefixes(s); !slices.Equal(got, []string{"192.0.2.10/32", "192.0.2.0/24", "198.51.100.9/32", "2001:db8::/32"}) {
		t.Errorf("without: %v", got)
	}
	if got := (Server{Address: "127.0.0.1"}).SharedPrefixes(&model.Scope{Prefixes: []string{"127.0.0.1/32"}}); len(got) != 0 {
		t.Errorf("a scope of the server alone: %v", got)
	}
}

// Pending are the users held now, by name.
func TestPendingIsOrderedByName(t *testing.T) {
	if got := names(Pending(view(), testModel(t))); !slices.Equal(got, []string{"bob", "carol", "dave", "erin"}) {
		t.Errorf("Pending: %v", got)
	}
}
