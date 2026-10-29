package tacacs

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/store"
)

// srvManaged is this server registered in the scope tacctl manages for its own
// login (0.2.21), with the tacplus method.
var srvManaged = pwchange.Server{Scope: pwchange.ManagedScope, Protocol: "tacacs"}

// managedStore is the multi-scope fixture with the managed scope (127.0.0.1)
// that no user has in the store.
func managedStore(t *testing.T, prefixes string, flagged ...string) *store.Store {
	t.Helper()
	st := loadStore(t, "store.multiscope.yaml")
	if err := st.ScopeSet(pwchange.ManagedScope, "prefixes="+prefixes, "secret=tacctl-secret-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	for _, n := range flagged {
		if err := st.UserSet(n, "password_change_required=true"); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// Every user is in the managed scope for the server's own login, added to the
// scopes the store gives them; a lockdown on the scope takes the locked group
// out of it, and a user who must change the password keeps it alone, in the
// server's protocol (the Carved model the renderer writes and reads back).
func TestRenderManagedScopeIsEveryUsersAndCarved(t *testing.T) {
	got := scopesAs(t, managedStore(t, "127.0.0.1/32"), "", srvManaged)
	if got["alice"] != "prod,lab,tacctl" || got["bob"] != "lab,tacctl" || got["carol"] != "lab,dmz,tacctl" {
		t.Errorf("every user is in the managed scope, after the scopes of their own: %v", got)
	}
	// the server is registered in another scope: nothing is added
	if got := scopesAs(t, managedStore(t, "127.0.0.1/32"), "", pwchange.Server{Scope: "lab", Protocol: "tacacs"}); got["bob"] != "lab" {
		t.Errorf("registered elsewhere: %v", got)
	}
	// a lockdown of operator on the managed scope: bob loses the server login
	// only, whatever scopes he has
	locked := scopesAs(t, managedStore(t, "127.0.0.1/32"), "emergency:\n  lockdown:\n    tacctl:\n      groups: [operator]\n      since: '2026-10-25T12:00:00Z'\n      by: alice\n", srvManaged)
	if locked["bob"] != "lab" || locked["alice"] != "prod,lab,tacctl" || locked["carol"] != "lab,dmz,tacctl" {
		t.Errorf("a lockdown on the managed scope: %v", locked)
	}
	// who must change the password: the server's login alone, in the protocol
	// of the server's logins; none in the other
	held := scopesAs(t, managedStore(t, "127.0.0.1/32", "bob", "alice"), "", srvManaged)
	if held["bob"] != "tacctl" || held["alice"] != "prod,lab,tacctl" || held["carol"] != "lab,dmz,tacctl" {
		t.Errorf("a flagged user: %v", held)
	}
	other := scopesAs(t, managedStore(t, "127.0.0.1/32", "bob"), "", pwchange.Server{Scope: pwchange.ManagedScope, Protocol: "radius"})
	if other["bob"] != "" {
		t.Errorf("a flagged user in the protocol the server does not use: %q", other["bob"])
	}
	// the file the renderer writes survives its read-back
	if _, err := renderFile(t, managedStore(t, "127.0.0.1/32", "bob"), defaultView(t)); err != nil {
		t.Fatal(err)
	}
}

// A scope of that name that answers more than the server's login addresses is
// the operator's: no user is added to it, whatever the registry says.
func TestRenderAnOperatorsScopeCalledTacctlGetsNoMembers(t *testing.T) {
	got := scopesAs(t, managedStore(t, "127.0.0.1/32,198.51.100.0/24"), "", srvManaged)
	if got["bob"] != "lab" || got["carol"] != "lab,dmz" || strings.Contains(got["alice"], "tacctl") {
		t.Errorf("users were added to the operator's scope: %v", got)
	}
}
