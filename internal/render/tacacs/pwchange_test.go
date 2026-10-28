package tacacs

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

var updatePwchange = flag.Bool("update-pwchange", false, "rewrite testdata/pwchange.users.yaml")

// pwStore is the multi-scope fixture with a scope of its own for this server
// (127.0.0.1, where its own logins come from) that all three users are in,
// and bob, carol and alice flagged for a password change.
func pwStore(t *testing.T, flagged ...string) *store.Store {
	t.Helper()
	st := loadStore(t, "store.multiscope.yaml")
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
	return st
}

func scopesOf(t *testing.T, st *store.Store, view string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for n, s := range userScopes(t, render(t, st, viewOf(t, view).Merged())) {
		out[n] = strings.Join(s, ",")
	}
	return out
}

// A user who must change the password is rendered into this server's own
// scope only, so every device-sourced login finds no scope of theirs and
// fails as for an unknown user; the others, a flagged superuser included,
// are as without the flag (0.2.20).
func TestRenderPasswordChangeKeepsTheUserInTheServersScopeOnly(t *testing.T) {
	before := scopesOf(t, pwStore(t), "")
	if before["bob"] != "lab,srv" || before["carol"] != "lab,dmz,srv" || before["alice"] != "prod,lab,srv" {
		t.Fatalf("the scopes without a flag: %v", before)
	}
	got := scopesOf(t, pwStore(t, "bob", "carol", "alice"), "")
	if got["bob"] != "srv" || got["carol"] != "srv" {
		t.Errorf("a flagged user is not in the server's scope only: %v", got)
	}
	if got["alice"] != before["alice"] {
		t.Errorf("a flagged superuser's scopes changed: %v", got["alice"])
	}
	// an unflagged user is untouched, the file differs for the flagged only
	only := scopesOf(t, pwStore(t, "bob"), "")
	if only["bob"] != "srv" || only["carol"] != before["carol"] || only["alice"] != before["alice"] {
		t.Errorf("flagging bob changed another user: %v", only)
	}
	// the stored scopes are not touched: the store says what it said
	if st := pwStore(t, "bob"); strings.Join(modelScopes(t, st, "bob"), ",") != "lab,srv" {
		t.Error("the store's scopes changed")
	}
}

func modelScopes(t *testing.T, st *store.Store, user string) []string {
	t.Helper()
	v, _ := entry(st, "users", user).Get("scopes")
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

// The exemption is decided from the tier of the group as it is now: a user
// moved into a superuser group (or whose group's tier is set to superuser) is
// exempt and one moved out is held, with the flag as it was.
func TestRenderPasswordChangeFollowsTheTierOfTheGroup(t *testing.T) {
	st := pwStore(t, "bob", "alice")
	if err := st.UserSet("bob", "group=superuser"); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("alice", "group=operator"); err != nil {
		t.Fatal(err)
	}
	got := scopesOf(t, st, "")
	if got["bob"] != "lab,srv" || got["alice"] != "srv" {
		t.Errorf("after the moves: %v", got)
	}
	// a tier setting makes the group a superuser group
	got = scopesOf(t, pwStore(t, "bob", "carol"), "tier:\n  operator: superuser\n")
	if got["bob"] != "lab,srv" || got["carol"] != "srv" {
		t.Errorf("with operator at tier superuser: %v", got)
	}
}

// With no scope that answers the server (or none this backend serves) a
// held user has no scope at all: nothing authenticates them, and the file
// still reads back.
func TestRenderPasswordChangeWithoutAServerScope(t *testing.T) {
	st := pwStore(t, "bob")
	if err := st.ScopeSet("srv", "protocols=radius"); err != nil {
		t.Fatal(err)
	}
	got := scopesOf(t, st, "")
	if got["bob"] != "" {
		t.Errorf("bob is in %q though no tacacs scope answers 127.0.0.1", got["bob"])
	}
	if _, err := renderFile(t, st, defaultView(t)); err != nil {
		t.Fatalf("the read-back refused the render: %v", err)
	}
}

// A render with flags reads back through the importer (RenderToFile's check)
// and is the same bytes every time.
func TestRenderPasswordChangeIsDeterministicAndReadsBack(t *testing.T) {
	a := render(t, pwStore(t, "bob", "carol", "alice"), defaultView(t))
	b := render(t, pwStore(t, "carol", "alice", "bob"), defaultView(t))
	if string(a) != string(b) {
		t.Error("the order the flags were set in changes the bytes")
	}
	if _, err := renderFile(t, pwStore(t, "bob", "carol", "alice"), defaultView(t)); err != nil {
		t.Fatalf("the read-back refused the render: %v", err)
	}
	if string(a) == string(render(t, pwStore(t), defaultView(t))) {
		t.Error("the flags changed nothing")
	}
	// no flag, no difference to the render of before the feature: the same
	// bytes as when the store holds the key false
	st := pwStore(t)
	if err := st.UserSet("bob", "password_change_required=false"); err != nil {
		t.Fatal(err)
	}
	if string(render(t, st, defaultView(t))) != string(render(t, pwStore(t), defaultView(t))) {
		t.Error("an unflagged store renders differently")
	}
}

// The users section of the fixture rendered with all three flagged is a
// golden (the rest of the file holds the fixture's hashes and secrets, which
// no golden of this change carries; go test -run TestRenderPasswordChangeGolden
// -update-pwchange rewrites it).
func TestRenderPasswordChangeGolden(t *testing.T) {
	text := string(render(t, pwStore(t, "bob", "carol", "alice"), defaultView(t)))
	i, j := strings.Index(text, "# --- Users ---"), strings.Index(text, "# --- Secret Providers")
	if i < 0 || j < i {
		t.Fatal("the users section is not in the file")
	}
	got := []byte(text[i:j])
	path := filepath.Join("testdata", "pwchange.users.yaml")
	if *updatePwchange {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	diffText(t, got, readFile(t, path), "the users of the render with a required password change")
}
