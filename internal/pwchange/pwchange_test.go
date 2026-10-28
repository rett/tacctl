package pwchange

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
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

// Carve leaves a held user in the scope that answers this server and in no
// other, and every other user as they are.
func TestCarveKeepsTheServersScopeOnly(t *testing.T) {
	m := testModel(t)
	got := Carve(m, yamlpy.NewMap(), "tacacs")
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
