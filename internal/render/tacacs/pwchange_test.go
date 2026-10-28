package tacacs

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/store"
)

// srvTacacs is this server enrolled in scope 'srv' with the tacplus method;
// srvRadius the same with the radius method.
var (
	srvTacacs = pwchange.Server{Scope: "srv", Protocol: "tacacs"}
	srvRadius = pwchange.Server{Scope: "srv", Protocol: "radius"}
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
	return scopesAs(t, st, view, srvTacacs)
}

// scopesAs is scopesOf for a server enrolled as server.
func scopesAs(t *testing.T, st *store.Store, view string, server pwchange.Server) map[string]string {
	t.Helper()
	out := map[string]string{}
	text, err := Render(st, viewOf(t, view).Merged(), nil, server)
	if err != nil {
		t.Fatal(err)
	}
	for n, s := range userScopes(t, text) {
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
	if _, err := renderFileAs(t, st, defaultView(t), srvTacacs); err != nil {
		t.Fatalf("the read-back refused the render: %v", err)
	}
}

// A render with flags reads back through the importer (RenderToFile's check)
// and is the same bytes every time.
func TestRenderPasswordChangeIsDeterministicAndReadsBack(t *testing.T) {
	a := renderAs(t, pwStore(t, "bob", "carol", "alice"), defaultView(t), srvTacacs)
	b := renderAs(t, pwStore(t, "carol", "alice", "bob"), defaultView(t), srvTacacs)
	if string(a) != string(b) {
		t.Error("the order the flags were set in changes the bytes")
	}
	if _, err := renderFileAs(t, pwStore(t, "bob", "carol", "alice"), defaultView(t), srvTacacs); err != nil {
		t.Fatalf("the read-back refused the render: %v", err)
	}
	if string(a) == string(renderAs(t, pwStore(t), defaultView(t), srvTacacs)) {
		t.Error("the flags changed nothing")
	}
	// no flag, no difference to the render of before the feature: the same
	// bytes as when the store holds the key false
	st := pwStore(t)
	if err := st.UserSet("bob", "password_change_required=false"); err != nil {
		t.Fatal(err)
	}
	if string(renderAs(t, st, defaultView(t), srvTacacs)) != string(renderAs(t, pwStore(t), defaultView(t), srvTacacs)) {
		t.Error("an unflagged store renders differently")
	}
}

// The users section of the fixture rendered with all three flagged is a
// golden (the rest of the file holds the fixture's hashes and secrets, which
// no golden of this change carries; go test -run TestRenderPasswordChangeGolden
// -update-pwchange rewrites it).
func TestRenderPasswordChangeGolden(t *testing.T) {
	text := string(renderAs(t, pwStore(t, "bob", "carol", "alice"), defaultView(t), srvTacacs))
	i, j := strings.Index(text, "# --- Users ---"), strings.Index(text, "# --- Secret Providers")
	if i < 0 || j < i {
		t.Fatal("the users section is not in the file")
	}
	got := []byte(strings.TrimRight(text[i:j], "\n") + "\n")
	path := filepath.Join("testdata", "pwchange.users.yaml")
	if *updatePwchange {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	diffText(t, got, readFile(t, path), "the users of the render with a required password change")
}

// splitStore is pwStore with this server's scope 'srv' served by one protocol
// and a catch-all scope 'all' served by the other, bob (flagged) in both: the
// catch-all answers 127.0.0.1 for its own protocol, but it is not the scope
// this server is enrolled in.
func splitStore(t *testing.T, srvProto, allProto string) *store.Store {
	t.Helper()
	st := pwStore(t, "bob")
	if err := st.ScopeSet("srv", "protocols="+srvProto); err != nil {
		t.Fatal(err)
	}
	if err := st.ScopeSet("all", "prefixes=0.0.0.0/0", "secret=all-secret-0123456789abcdef", "protocols="+allProto); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("bob", "scopes=all,srv"); err != nil {
		t.Fatal(err)
	}
	return st
}

// The server's logins use RADIUS and a catch-all scope serves TACACS+: the
// scope that answers 127.0.0.1 for TACACS+ is not this server's, so a flagged
// user is not rendered for TACACS+ at all and every TACACS+ device refuses
// them. The mirror (TACACS+ server, RADIUS catch-all) is the TACACS+ file
// keeping the server scope and nothing else.
func TestRenderPasswordChangeDropsTheOtherProtocolsScopes(t *testing.T) {
	// a RADIUS server: srv is radius-only, all is tacacs-only
	st := splitStore(t, "radius", "tacacs")
	if got := scopesAs(t, st, "", srvRadius)["bob"]; got != "" {
		t.Errorf("TACACS+ file, RADIUS server: bob is in %q, devices still accept him", got)
	}
	// the same file for a user who is not flagged still has his scopes
	if err := st.UserSet("bob", "password_change_required=false"); err != nil {
		t.Fatal(err)
	}
	if got := scopesAs(t, st, "", srvRadius)["bob"]; got != "all" {
		t.Errorf("unflagged: %q", got)
	}
	// a TACACS+ server: srv is tacacs-only, all is radius-only; the TACACS+
	// file keeps the server scope
	st = splitStore(t, "tacacs", "radius")
	if got := scopesAs(t, st, "", srvTacacs)["bob"]; got != "srv" {
		t.Errorf("TACACS+ file, TACACS+ server: bob is in %q", got)
	}
	// both protocols serve both scopes: the protocol of the server decides,
	// not the scope that happens to answer 127.0.0.1
	st = splitStore(t, "tacacs,radius", "tacacs,radius")
	if got := scopesAs(t, st, "", srvRadius)["bob"]; got != "" {
		t.Errorf("TACACS+ file, RADIUS server, scopes serve both: bob is in %q", got)
	}
	if got := scopesAs(t, st, "", srvTacacs)["bob"]; got != "srv" {
		t.Errorf("TACACS+ file, TACACS+ server, scopes serve both: bob is in %q", got)
	}
	// a server that is not enrolled (the zero Server) keeps nothing
	if got := scopesAs(t, st, "", pwchange.Server{})["bob"]; got != "" {
		t.Errorf("no server: bob is in %q", got)
	}
}

// The scope is the registry's, not the one that answers 127.0.0.1: another
// scope with the same address that sorts first is not the server's.
func TestRenderPasswordChangeKeepsTheEnrolledScope(t *testing.T) {
	st := pwStore(t, "bob")
	if err := st.ScopeSet("local", "prefixes=127.0.0.0/8", "secret=local-secret-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := st.UserSet("bob", "scopes=local,srv"); err != nil {
		t.Fatal(err)
	}
	if got := scopesAs(t, st, "", srvTacacs)["bob"]; got != "srv" {
		t.Errorf("bob is in %q", got)
	}
	if got := scopesAs(t, st, "", pwchange.Server{Scope: "local", Protocol: "tacacs"})["bob"]; got != "local" {
		t.Errorf("enrolled in local: bob is in %q", got)
	}
}
