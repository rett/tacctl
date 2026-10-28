package radius_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/store"
)

// pwModel is the multi-scope fixture with a scope of its own for this server
// (127.0.0.1) that bob, carol and alice are in, and the given users flagged
// for a password change.
func pwModel(t *testing.T, flagged ...string) *model.Model {
	t.Helper()
	st, err := store.Load(fixtures + "store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ScopeSet("srv", "prefixes=127.0.0.1/32", "secret=srv-secret-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct{ name, scopes string }{{"alice", "prod,lab,srv"}, {"bob", "lab,srv"}, {"carol", "lab,dmz,srv"}} {
		if err := st.UserSet(u.name, "scopes="+u.scopes); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range flagged {
		if err := st.UserSet(n, "password_change_required=true"); err != nil {
			t.Fatal(err)
		}
	}
	return model.FromStore(st)
}

var reUserEntry = regexp.MustCompile(`(?m)^(\S+)\tTmp-String-0 == "[0-9a-f]+/([^"]+)"`)

// entries is the (user, scope) entries of a users file, each user's scopes
// sorted and joined.
func entries(users string) map[string]string {
	by := map[string][]string{}
	for _, m := range reUserEntry.FindAllStringSubmatch(users, -1) {
		by[m[1]] = append(by[m[1]], m[2])
	}
	out := map[string]string{}
	for u, s := range by {
		sort.Strings(s)
		out[u] = strings.Join(s, ",")
	}
	return out
}

// A user who must change the password has an entry for this server's own
// scope only: a device's login finds no entry and is rejected, as for an
// unknown user. The others, a flagged superuser included, are as they were;
// the clients do not change, and the output is the same every time.
func TestRenderPasswordChangeKeepsTheUserInTheServersScopeOnly(t *testing.T) {
	render := func(m *model.Model) *radius.Output {
		out, err := radius.Render(m, cfg(t).Merged(), params("debian"))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	plain := render(pwModel(t))
	if e := entries(plain.Users); e["bob"] != "lab,srv" || e["carol"] != "dmz,lab,srv" || e["alice"] != "lab,prod,srv" {
		t.Fatalf("the entries without a flag: %v", e)
	}
	flagged := render(pwModel(t, "bob", "carol", "alice"))
	e := entries(flagged.Users)
	if e["bob"] != "srv" || e["carol"] != "srv" {
		t.Errorf("a flagged user has entries beyond the server's scope: %v", e)
	}
	if e["alice"] != "lab,prod,srv" {
		t.Errorf("a flagged superuser's entries changed: %v", e["alice"])
	}
	if only := entries(render(pwModel(t, "bob")).Users); only["carol"] != "dmz,lab,srv" || only["bob"] != "srv" {
		t.Errorf("flagging bob changed another user: %v", only)
	}
	if strings.ReplaceAll(flagged.Conf, flagged.RenderID, "") != strings.ReplaceAll(plain.Conf, plain.RenderID, "") {
		t.Error("the clients changed: a required change refuses logins, not the device")
	}
	if again := render(pwModel(t, "carol", "alice", "bob")); again.Users != flagged.Users || again.RenderID != flagged.RenderID {
		t.Error("the same flags render differently")
	}
	if plain.Users == flagged.Users {
		t.Error("the flags changed nothing")
	}
}

// A scope that RADIUS does not serve is no server scope for it: a flagged
// user has no entry at all.
func TestRenderPasswordChangeWithoutAServerScope(t *testing.T) {
	st, err := store.Load(fixtures + "store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ScopeSet("srv", "prefixes=127.0.0.1/32", "secret=srv-secret-0123456789abcdef", "protocols=tacacs"); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("bob", "scopes=lab,srv", "password_change_required=true"); err != nil {
		t.Fatal(err)
	}
	out, err := radius.Render(model.FromStore(st), cfg(t).Merged(), params("debian"))
	if err != nil {
		t.Fatal(err)
	}
	if e := entries(out.Users); e["bob"] != "" || e["carol"] == "" {
		t.Errorf("entries: %v", e)
	}
}
