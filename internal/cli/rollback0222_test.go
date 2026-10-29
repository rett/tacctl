package cli

import (
	"strings"
	"testing"
)

// server.name (0.2.22) is a key every older release refuses, so every
// target's plan removes it, and --apply does.
func TestRollbackEveryTargetRemovesTheServerName(t *testing.T) {
	for _, v := range []string{"0.2.20", "0.2.19", "0.2.18", "0.2.17", "0.2.16", "0.2.9", "0.2.3"} {
		hs := rollbackState(t)
		hs.step("", "server", "name", "core-1")
		hs.run(hs.runner(), "rollback", v)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if out := hs.all(); !strings.Contains(out, "remove server.name") {
			t.Errorf("%s dry run:\n%s", v, out)
		}
		hs.run(hs.runner(), "rollback", v, "--apply", "--yes")
		hs.expect(0, "Applying.", "")
		if strings.Contains(hs.overrides(), "name: core-1") {
			t.Errorf("%s: the key stayed:\n%s", v, hs.overrides())
		}
	}
}
