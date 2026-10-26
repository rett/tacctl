package tacacs

import (
	"strings"
	"testing"
)

const lockdownYAML = "emergency:\n  lockdown:\n    lab:\n      groups:\n        - operator\n        - readonly\n      since: '2026-10-25T12:00:00Z'\n      by: alice\n      reason: credential leak\n"

// userScopes is the scopes of each user of a rendered file.
func userScopes(t *testing.T, data []byte) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	users, _ := decoded(t, data)["users"].([]any)
	for _, u := range users {
		m := u.(map[string]any)
		var scopes []string
		for _, s := range m["scopes"].([]any) {
			scopes = append(scopes, s.(string))
		}
		out[m["name"].(string)] = scopes
	}
	return out
}

// An emergency lockdown takes the scope out of the users of the locked
// groups and changes nothing else (0.2.19).
func TestRenderLockdownTakesTheScopeOutOfTheLockedGroups(t *testing.T) {
	st := loadStore(t, "store.multiscope.yaml")
	plain := userScopes(t, render(t, st, defaultView(t)))
	if strings.Join(plain["bob"], ",") != "lab" || strings.Join(plain["carol"], ",") != "dmz,lab" && strings.Join(plain["carol"], ",") != "lab,dmz" {
		t.Fatalf("the scopes without a lockdown: %v", plain)
	}
	view := viewOf(t, lockdownYAML).Merged()
	got := render(t, loadStore(t, "store.multiscope.yaml"), view)
	locked := userScopes(t, got)
	if len(locked["bob"]) != 0 || strings.Join(locked["carol"], ",") != "dmz" {
		t.Errorf("the scopes of the locked groups: %v", locked)
	}
	if strings.Join(locked["alice"], ",") != strings.Join(plain["alice"], ",") {
		t.Errorf("a superuser's scopes changed: %v", locked["alice"])
	}
	if strings.Contains(string(got), "credential leak") {
		t.Error("the reason is in the rendered file")
	}
	// the read-back of the written file compares against the same model
	if _, err := renderFile(t, loadStore(t, "store.multiscope.yaml"), view); err != nil {
		t.Fatalf("the read-back refused a render with a lockdown: %v", err)
	}
	// lifted, the file is what it was
	if string(render(t, loadStore(t, "store.multiscope.yaml"), defaultView(t))) != string(render(t, st, defaultView(t))) {
		t.Error("a render without the lockdown differs from the first one")
	}
}
