package pwchange

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

// managedModel has the managed scope, users in it and not, a user with a
// period, one whose group has no priv-lvl, a disabled one and the sink.
func managedModel(t *testing.T) *model.Model {
	t.Helper()
	st := store.Empty()
	if err := st.GroupSet("nolevel", "priv_lvl=1", "juniper_class=X-CLASS"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"lab", ManagedScope} {
		p := "192.0.2.0/24"
		if s == ManagedScope {
			p = "127.0.0.1/32,198.51.100.7/32"
		}
		if err := st.ScopeSet(s, "prefixes="+p, "secret=example-secret-example-secret"); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range [][3]string{
		{"alice", "superuser", "lab"}, {"bob", "operator", "lab," + ManagedScope}, {"carol", "readonly", ""},
		{"alice.smith", "operator", "lab"}, {"dave", "nolevel", "lab"},
	} {
		if err := st.UserSet(u[0], "group="+u[1], "scopes="+u[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UserSet("erin", "group=operator", "scopes=lab", "disabled=true"); err != nil {
		t.Fatal(err)
	}
	m := model.FromStore(st)
	// a group whose priv-lvl a hand edit lost: its members' tier is none
	m.Group("nolevel").PrivLvl = nil
	return m
}

// Every user but the sink, a name with a period and a tier of none is in the
// managed scope while the server is registered in it; the store's model and
// the device scopes are as they were.
func TestWithServerScope(t *testing.T) {
	m := managedModel(t)
	srv := Server{Scope: ManagedScope, Protocol: "tacacs", Address: "198.51.100.7"}
	got := WithServerScope(view(), m, srv)
	if want := []string{"alice", "bob", "carol", "erin"}; !slices.Equal(got.Members(ManagedScope), want) {
		t.Errorf("members %v, want %v", got.Members(ManagedScope), want)
	}
	if !slices.Equal(got.Members("lab"), m.Members("lab")) {
		t.Errorf("lab changed: %v", got.Members("lab"))
	}
	if !slices.Equal(m.Members(ManagedScope), []string{"bob"}) {
		t.Errorf("the receiver changed: %v", m.Members(ManagedScope))
	}
	// registered in another scope, or the scope is gone: nothing implicit
	for _, s := range []Server{{Scope: "lab", Protocol: "tacacs"}, {}} {
		if out := WithServerScope(view(), m, s); out != m {
			t.Errorf("%+v: the model changed", s)
		}
	}
	if out := WithServerScope(view(), m.WithoutScope(ManagedScope), srv); !slices.Equal(out.Members(ManagedScope), nil) {
		t.Errorf("no scope: %v", out.Members(ManagedScope))
	}
}

// The prefixes are the login addresses as host prefixes.
func TestManagedPrefixes(t *testing.T) {
	for addr, want := range map[string]string{"": "127.0.0.1/32", "127.0.0.1": "127.0.0.1/32", "198.51.100.7": "127.0.0.1/32,198.51.100.7/32",
		"2001:db8::7": "127.0.0.1/32,2001:db8::7/128"} {
		if got := strings.Join((Server{Scope: ManagedScope, Address: addr}).Prefixes(), ","); got != want {
			t.Errorf("%q: %s, want %s", addr, got, want)
		}
	}
	if (Server{Scope: "lab"}).Managed() || !(Server{Scope: ManagedScope}).Managed() {
		t.Error("Managed")
	}
}

// A user held to a password change keeps the managed scope only, so the
// server still answers them; a device does not.
func TestCarveKeepsTheManagedScope(t *testing.T) {
	st := store.Empty()
	for _, s := range []string{"lab", ManagedScope} {
		p := map[string]string{"lab": "192.0.2.0/24", ManagedScope: "127.0.0.1/32"}[s]
		if err := st.ScopeSet(s, "prefixes="+p, "secret=example-secret-example-secret"); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UserSet("bob", "group=operator", "scopes=lab", "password_change_required=true"); err != nil {
		t.Fatal(err)
	}
	srv := Server{Scope: ManagedScope, Protocol: "tacacs"}
	m := WithServerScope(view(), model.FromStore(st), srv)
	out := Carve(m, nil, "tacacs", srv)
	if got := out.User("bob").Scopes; !slices.Equal(got, []string{ManagedScope}) {
		t.Errorf("bob's scopes %v", got)
	}
}

// A scope called like the managed one that answers an address other than the
// server's login addresses is an operator's: no user is made a member of it,
// whichever scope the registry names, and ManagedIn and Clash tell the two
// apart by the prefixes alone.
func TestWithServerScopeNeverFillsAnOperatorsScope(t *testing.T) {
	m := managedModel(t)
	sc := m.Scope(ManagedScope)
	srv := Server{Scope: ManagedScope, Protocol: "tacacs", Address: "198.51.100.7"}
	if !srv.ManagedIn(m) || Clash(m, srv) || !OnlyLoginAddresses(sc, srv) {
		t.Fatal("the server's own scope is not recognised")
	}
	// the login addresses of the server before and after an address change
	other := Server{Scope: ManagedScope, Address: "192.0.2.10"}
	if srv.ManagedIn(model.FromStore(withPrefixes(t, "127.0.0.1/32,192.0.2.10/32"))) || !OnlyLoginAddresses(sc, other, srv) {
		t.Error("the login addresses of the other server count")
	}
	for _, prefixes := range []string{"127.0.0.1/32,198.51.100.0/24", "198.51.100.7/32,203.0.113.5/32", "10.0.0.0/8", "127.0.0.0/8"} {
		op := model.FromStore(withPrefixes(t, prefixes))
		if srv.ManagedIn(op) || !Clash(op, srv) {
			t.Errorf("%s: taken for the managed scope", prefixes)
		}
		if out := WithServerScope(view(), op, srv); out != op || len(out.Members(ManagedScope)) != 1 {
			t.Errorf("%s: users were added: %v", prefixes, out.Members(ManagedScope))
		}
	}
	// no such scope is no clash; a subset of the login addresses is the
	// managed scope (a repair gives it the rest)
	if Clash(m.WithoutScope(ManagedScope), srv) {
		t.Error("a clash without a scope")
	}
	if !srv.ManagedIn(model.FromStore(withPrefixes(t, "127.0.0.1/32"))) {
		t.Error("a subset of the login addresses is not the managed scope")
	}
}

// withPrefixes is a store whose scope called tacctl has prefixes, with bob
// in it.
func withPrefixes(t *testing.T, prefixes string) *store.Store {
	t.Helper()
	st := store.Empty()
	if err := st.ScopeSet(ManagedScope, "prefixes="+prefixes, "secret=example-secret-example-secret"); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("bob", "group=operator", "scopes="+ManagedScope); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("carol", "group=readonly", "scopes="); err != nil {
		t.Fatal(err)
	}
	return st
}

// A scope in a file from elsewhere is taken for the managed scope of some
// server by its shape: one or two single-address prefixes, 127.0.0.1 among
// them.
func TestLooksManaged(t *testing.T) {
	for prefixes, want := range map[string]bool{
		"127.0.0.1/32": true, "127.0.0.1/32,198.51.100.7/32": true, "198.51.100.7/32,127.0.0.1/32": true, "127.0.0.1/32,2001:db8::7/128": true,
		"198.51.100.7/32": false, "127.0.0.1/32,198.51.100.0/24": false, "127.0.0.0/8": false,
		"127.0.0.1/32,198.51.100.7/32,198.51.100.8/32": false,
	} {
		sc := model.FromStore(withPrefixes(t, prefixes)).Scope(ManagedScope)
		if got := LooksManaged(sc); got != want {
			t.Errorf("%s: %v, want %v", prefixes, got, want)
		}
	}
	if LooksManaged(nil) {
		t.Error("no scope")
	}
}
