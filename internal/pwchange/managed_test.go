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
