//go:build testknobs

package cli

import (
	"strings"
	"testing"
)

// A snapshot that cannot be taken is a refusal: nothing is changed.
func TestHostRenameThatCannotSnapshotChangesNothing(t *testing.T) {
	sb := renameLab(t)
	before := sb.renameState()
	sb.run("", []string{"host", "rename", "web1", "web7"}, "TACCTL_FAULT=snapshot")
	sb.expect(1, "", "Could not snapshot the current state. Nothing was changed.")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
}

// The scope step runs after the host is renamed and fails (the render of
// the scope rename): the host keeps the old scope and the retry is named.
func TestHostRenameScopeStepFaulted(t *testing.T) {
	sb := scopeRenameLab(t)
	sb.run("", []string{"host", "rename", "web1", "web9", "--yes"}, "TACCTL_FAULT=render-commit:tacacs")
	if sb.code != 1 {
		t.Fatalf("exit %d\n%s", sb.code, sb.printed())
	}
	for _, want := range []string{"Host renamed. Scope 'linux-web1' was NOT renamed: ", "; the host keeps it. Retry: tacctl scope rename linux-web1 linux-web9."} {
		if !strings.Contains(sb.stderr(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, sb.stderr())
		}
	}
	if !strings.Contains(sb.registryText(), "web9|root@198.51.100.10||linux-web1|") {
		t.Errorf("registry %q", sb.registryText())
	}
}
