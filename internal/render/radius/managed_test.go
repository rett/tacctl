package radius_test

import (
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/store"
)

// managedModel is the multi-scope fixture with the managed scope that no user
// has in the store.
func managedModel(t *testing.T, prefixes string, flagged ...string) *model.Model {
	t.Helper()
	st, err := store.Load(fixtures + "store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ScopeSet(pwchange.ManagedScope, "prefixes="+prefixes, "secret=tacctl-secret-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	for _, n := range flagged {
		if err := st.UserSet(n, "password_change_required=true"); err != nil {
			t.Fatal(err)
		}
	}
	return model.FromStore(st)
}

// Every user has an entry for the managed scope, as well as for the scopes the
// store gives them; a lockdown on it takes the locked group's entry out; a
// user who must change the password keeps the server's scope alone, in the
// protocol of the server's own logins, and has no entry when the server uses
// the other one; an operator's scope of that name gets none.
func TestRenderManagedScopeIsEveryUsersAndCarved(t *testing.T) {
	srv := pwchange.Server{Scope: pwchange.ManagedScope, Protocol: "radius"}
	got := entries(renderAs(t, managedModel(t, "127.0.0.1/32"), srv).Users)
	if got["alice"] != "lab,prod,tacctl" || got["bob"] != "lab,tacctl" || got["carol"] != "dmz,lab,tacctl" {
		t.Errorf("every user is in the managed scope: %v", got)
	}
	if got := entries(renderAs(t, managedModel(t, "127.0.0.1/32"), pwchange.Server{Scope: "lab", Protocol: "radius"}).Users); got["bob"] != "lab" {
		t.Errorf("registered elsewhere: %v", got)
	}
	held := entries(renderAs(t, managedModel(t, "127.0.0.1/32", "bob", "alice"), srv).Users)
	if held["bob"] != "tacctl" || held["alice"] != "lab,prod,tacctl" || held["carol"] != "dmz,lab,tacctl" {
		t.Errorf("a flagged user: %v", held)
	}
	if other := entries(renderAs(t, managedModel(t, "127.0.0.1/32", "bob"), pwchange.Server{Scope: pwchange.ManagedScope, Protocol: "tacacs"}).Users); other["bob"] != "" {
		t.Errorf("a flagged user in the protocol the server does not use: %q", other["bob"])
	}
	op := entries(renderAs(t, managedModel(t, "127.0.0.1/32,198.51.100.0/24"), srv).Users)
	if op["bob"] != "lab" || op["alice"] != "lab,prod" {
		t.Errorf("users were added to the operator's scope: %v", op)
	}
}

// A lockdown on the managed scope takes the locked group out of it, nothing
// else.
func TestRenderManagedScopeLockdown(t *testing.T) {
	srv := pwchange.Server{Scope: pwchange.ManagedScope, Protocol: "radius"}
	p := params("debian")
	p.Server = srv
	out, err := radius.Render(managedModel(t, "127.0.0.1/32"), holdConf(t, "emergency:\n  lockdown:\n    tacctl:\n      groups: [operator]\n      since: '2026-10-25T12:00:00Z'\n      by: alice\n").Merged(), p)
	if err != nil {
		t.Fatal(err)
	}
	got := entries(out.Users)
	if got["bob"] != "lab" || got["alice"] != "lab,prod,tacctl" || got["carol"] != "dmz,lab,tacctl" {
		t.Errorf("a lockdown on the managed scope: %v", got)
	}
}
