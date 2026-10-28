package cli

import (
	"os"
	"strings"
	"testing"
)

// The rendered users section names the users it cut out of their scopes, and
// 'store import' of that file refuses to take it for a plain store: it names
// them and wants --force, the flag the command already has for what the
// store cannot represent. --check says so too.
func TestStoreImportRefusesAFileWithCarvedUsers(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	live := sb.renderedConfig()
	if !strings.Contains(live, "# --- Users ---\n# tacctl-carved reason=password-change protocol=tacacs users=bob\nusers:") {
		t.Fatalf("the users section does not name the carved user:\n%s", live)
	}
	before := sb.read("state/store.yaml")
	for _, args := range [][]string{{"store", "import", "--replace"}, {"store", "import", "--check"}} {
		sb.run("", args)
		out := plain(sb.out.String() + sb.err.String())
		if sb.code == 0 || !strings.Contains(out, "user 'bob': cut to this server's own scope in the file (tacacs) because it must change the password") ||
			!strings.Contains(out, "re-run with --force") {
			t.Errorf("%v: exit %d\n%s", args, sb.code, out)
		}
	}
	if sb.read("state/store.yaml") != before {
		t.Error("a refused import changed the store")
	}
	// forced, the user comes back as the file shows him: the server scope, no requirement
	sb.run("", []string{"store", "import", "--replace", "--force"})
	sb.expect(0, "Dropped (--force)", "")
	if out := plain(sb.out.String()); !strings.Contains(out, "user 'bob': cut to this server's own scope") {
		t.Errorf("--force does not list the user:\n%s", out)
	}
	if got := flaggedUsers(t, sb); got != "" {
		t.Errorf("flagged after the forced import: %q", got)
	}
	// a file without a carved user imports as before
	sb.asAlice("", "user", "require-password-change", "--all", "off")
	sb.run("", []string{"config", "render"})
	if strings.Contains(sb.renderedConfig(), "tacctl-carved") {
		t.Errorf("a marker though nobody is carved:\n%s", sb.renderedConfig())
	}
	sb.run("", []string{"store", "import", "--replace"})
	if strings.Contains(plain(sb.out.String()+sb.err.String()), "cut to this server") {
		t.Errorf("an import of a file with nobody carved:\n%s", sb.out.String()+sb.err.String())
	}
}

// A user the marker names who is not in the file's store is not a reason to
// refuse (a hand-edited file), and the lockdown's carve is named the same way.
func TestStoreImportNamesLockdownCarvedUsers(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	live := sb.renderedConfig()
	marked := strings.Replace(live, "# --- Users ---\n", "# --- Users ---\n# tacctl-carved reason=lockdown protocol=tacacs users=bob,nobody\n", 1)
	if marked == live {
		t.Fatal("no users section")
	}
	if err := os.WriteFile(sb.path("tmp", "marked.yaml"), []byte(marked), 0o600); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"store", "import", "--check", sb.path("tmp", "marked.yaml")})
	out := plain(sb.out.String() + sb.err.String())
	if sb.code == 0 || !strings.Contains(out, "user 'bob': cut out of the scope an emergency lockdown locks (tacacs)") || strings.Contains(out, "'nobody'") {
		t.Errorf("exit %d\n%s", sb.code, out)
	}
}
