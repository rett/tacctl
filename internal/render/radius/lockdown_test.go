package radius_test

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/render/radius"
)

// An emergency lockdown takes the scope out of the users of the locked
// groups: a user left with no scope has no entry in the users file (0.2.19).
func TestRenderLockdownDropsTheLockedUsers(t *testing.T) {
	render := func(yaml string) *radius.Output {
		out, err := radius.Render(loadModel(t, fixtures+"store.multiscope.yaml"), holdConf(t, yaml).Merged(), params("debian"))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	plain := render("")
	for _, u := range []string{"alice", "bob", "carol"} {
		if !strings.Contains(plain.Users, u) {
			t.Fatalf("%s is not in the users file:\n%s", u, plain.Users)
		}
	}
	locked := render("emergency:\n  lockdown:\n    lab:\n      groups:\n        - operator\n        - readonly\n      since: '2026-10-25T12:00:00Z'\n      by: alice\n")
	if strings.Contains(locked.Users, "bob") {
		t.Errorf("bob (operator, lab only) is in the users file:\n%s", locked.Users)
	}
	if !strings.Contains(locked.Users, "alice") || !strings.Contains(locked.Users, "carol") {
		t.Errorf("a superuser or a user with another scope is gone:\n%s", locked.Users)
	}
	if strings.ReplaceAll(locked.Conf, locked.RenderID, "") != strings.ReplaceAll(plain.Conf, plain.RenderID, "") {
		t.Error("the clients changed: a lockdown refuses logins, not the device")
	}
}
