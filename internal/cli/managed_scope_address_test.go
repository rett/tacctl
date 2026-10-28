package cli

import (
	"strings"
	"testing"
)

// Moving the server address (host enroll --local --server another) renders
// the users' server login with the registration that holds the new address:
// the renders of the setup, which see the old registration, are not the last.
func TestManagedServerAddressChangeRendersTheLoginAgain(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs, "--server", "203.0.113.9")
	enrolLocal(t, hs, "--server", "198.51.100.20")
	if hs.registry() != "authsrv|local||tacctl|198.51.100.20|\n" {
		t.Fatalf("registry %q", hs.registry())
	}
	for _, u := range []string{"alice", "bob", "carol"} {
		if b := renderedBlock(t, hs, u); !strings.Contains(b, `"tacctl"`) {
			t.Errorf("%s has no server login after the move:\n%s", u, b)
		}
	}
}
