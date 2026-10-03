package cli

// 'tacctl store rollback' end to end, in-process: the rollback half of
// tests/integration/upgrade_store_flip.bats. A flipped install is made the
// way an operator can make one: the live legacy tacquito.yaml imported
// (the import keeps the pre-store copy), then rendered. The bats file
// itself and the store corpus pin the bytes against 0.1.16.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func (sb *sandbox) preStore() []string {
	m, _ := filepath.Glob(sb.path("state", "backups", "legacy", "tacquito.yaml.pre-store.*"))
	var out []string
	for _, f := range m {
		if st, err := os.Lstat(f); err == nil && st.Mode().IsRegular() {
			out = append(out, f)
		}
	}
	return out
}

// flippedSandbox is flipped_install: it returns the sha256 of the
// pre-flip tacquito.yaml.
func flippedSandbox(t *testing.T) (*sandbox, string) {
	t.Helper()
	sb := newSandbox(t, false)
	sandboxRADIUS(sb)
	sb.write("etc/tacquito.yaml", fixture(t, "legacy.fresh-install.yaml"), 0o640)
	original := fileSHA(t, sb.path("etc", "tacquito.yaml"))
	sb.run("", []string{"store", "import"})
	sb.expect(0, "Pre-store "+sb.path("etc", "tacquito.yaml")+" kept as "+sb.path("state", "backups", "legacy", "tacquito.yaml.pre-store."), "")
	sb.run("", []string{"config", "render", "--force"})
	sb.expect(0, "", "")
	if len(sb.preStore()) != 1 {
		t.Fatal(sb.preStore())
	}
	return sb, original
}

func TestStoreRollbackRestoresThePreStoreFileAndRestarts(t *testing.T) {
	sb, original := flippedSandbox(t)
	out := plain(sb.run("y\n", []string{"store", "rollback"}))
	sb.expect(0, "Rolled back", "")
	cfg := sb.path("etc", "tacquito.yaml")
	for _, s := range []string{
		"\nRoll back to the pre-store configuration\n\n  This restores " + sb.preStore()[0] + "\n  as " + cfg +
			", removes " + sb.path("state", "store.yaml") + " and the render records,\n",
		"[INFO] Config snapshot saved to " + sb.path("state", "backups") + "/",
		"[INFO] Service restarted.\n",
		"[INFO] Rolled back: " + cfg + " is the pre-store file again and the store is gone (legacy read-only mode).\n" +
			"[INFO] To move to the store again: 'tacctl store import --check', then 'tacctl upgrade' (or 'tacctl store import' and 'tacctl config render --force').\n\n",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "no longer says") {
		t.Error("an unchanged store drew the warning")
	}
	if fileSHA(t, cfg) != original {
		t.Error("tacquito.yaml is not the pre-store file")
	}
	if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o640 {
		t.Error("mode")
	}
	for _, f := range []string{"store.yaml", "rendered.json"} {
		if _, err := os.Stat(sb.path("state", f)); !os.IsNotExist(err) {
			t.Error(f, "left")
		}
	}
	if !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Error(sb.runner.Argvs())
	}
	// The store went into a snapshot first; the pre-store file is still there.
	if m, _ := filepath.Glob(sb.path("state", "backups", "*", "store.yaml")); len(m) != 1 {
		t.Error(m)
	}
	if len(sb.preStore()) != 1 {
		t.Error("pre-store copy gone")
	}
	// Legacy read-only mode under the new code.
	sb.run("", []string{"user", "list"})
	sb.expect(0, "engineer", "")
	sb.run("", []string{"user", "add", "zed", "superuser", "--hash", testHash})
	sb.expect(1, "", "store not initialised")
}

func TestStoreRollbackAnythingButYChangesNothing(t *testing.T) {
	sb, _ := flippedSandbox(t)
	storeBefore, cfgBefore := fileSHA(t, sb.path("state", "store.yaml")), fileSHA(t, sb.path("etc", "tacquito.yaml"))
	for _, answer := range []string{"n\n", "yes\n", ""} {
		sb.run(answer, []string{"store", "rollback"})
		sb.expect(0, "[INFO] Cancelled.\n", "")
		if fileSHA(t, sb.path("state", "store.yaml")) != storeBefore || fileSHA(t, sb.path("etc", "tacquito.yaml")) != cfgBefore {
			t.Error("changed")
		}
		if _, err := os.Stat(sb.path("state", "rendered.json")); err != nil {
			t.Error("render records gone")
		}
		if sb.runner.Called("systemctl") {
			t.Error("systemctl")
		}
	}
}

func TestStoreRollbackWarnsWhenTheStoreChangedSinceTheImport(t *testing.T) {
	sb, original := flippedSandbox(t)
	sb.run("", []string{"user", "add", "alice", "superuser", "--hash", testHash})
	sb.expect(0, "", "")
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(0, "[WARN] The store no longer says what the pre-store file says: users, groups, scopes or filters changed since the import.\n"+
		"[WARN] Those changes stop being in effect. They stay in the snapshot, not in "+sb.path("etc", "tacquito.yaml")+".\n", "")
	if fileSHA(t, sb.path("etc", "tacquito.yaml")) != original {
		t.Error("not rolled back")
	}
	found := false
	m, _ := filepath.Glob(sb.path("state", "backups", "*", "store.yaml"))
	for _, f := range m {
		if data, _ := os.ReadFile(f); strings.Contains(string(data), "alice") {
			found = true
		}
	}
	if !found {
		t.Error("the change is not in a snapshot")
	}
}

func TestStoreRollbackKeepsAHandEditedRenderedConfigFirst(t *testing.T) {
	sb, original := flippedSandbox(t)
	f, _ := os.OpenFile(sb.path("etc", "tacquito.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("# hand edit\n")
	_ = f.Close()
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(0, "Rolled back", "[WARN] Previous "+sb.path("etc", "tacquito.yaml")+" saved to "+sb.path("state", "backups", "legacy", "tacquito.yaml.drift."))
	m, _ := filepath.Glob(sb.path("state", "backups", "legacy", "tacquito.yaml.drift.*"))
	if len(m) != 1 || !strings.Contains(sb.read(strings.TrimPrefix(m[0], sb.dir+"/")), "# hand edit") {
		t.Error(m)
	}
	if fileSHA(t, sb.path("etc", "tacquito.yaml")) != original {
		t.Error("not rolled back")
	}
}

func TestStoreRollbackRefusals(t *testing.T) {
	// No store: already in legacy mode.
	sb := newSandbox(t, false)
	sb.write("etc/tacquito.yaml", fixture(t, "legacy.fresh-install.yaml"), 0o640)
	before := fileSHA(t, sb.path("etc", "tacquito.yaml"))
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(1, "", "[ERROR] There is no store at "+sb.path("state", "store.yaml")+": this install is already in legacy read-only mode. Nothing to roll back.")
	if fileSHA(t, sb.path("etc", "tacquito.yaml")) != before || sb.runner.Called("systemctl") {
		t.Error("touched")
	}

	// A store that never had a legacy file: nothing to roll back to.
	sb = newSandbox(t, true)
	sb.run("", []string{"config", "render"})
	storeBefore := fileSHA(t, sb.path("state", "store.yaml"))
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(1, "", "[ERROR] No pre-store config (tacquito.yaml.pre-store.<timestamp>) under "+sb.path("state", "backups", "legacy")+
		"/: there is nothing to roll back to.\n[ERROR] A fresh install starts with its store and never had a legacy tacquito.yaml. The store was left untouched.\n")
	if fileSHA(t, sb.path("state", "store.yaml")) != storeBefore || sb.runner.Called("systemctl") {
		t.Error("touched")
	}

	// Another backend enabled: legacy mode serves TACACS+ only.
	sb, _ = flippedSandbox(t)
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\n", 0o640)
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(1, "", "[ERROR] Backend(s) radius are enabled, and legacy mode (what a rollback returns to) serves TACACS+ only.\n"+
		"[ERROR] Disable them first ('tacctl backend disable <id>'). Nothing was changed.\n")
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, ldap]\n", 0o640)
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(1, "", "[ERROR] tacctl.yaml: backends.enabled names 'ldap', and this tacctl has no such backend")

	// A pre-store file that cannot be read as a config.
	sb, _ = flippedSandbox(t)
	pre := sb.preStore()[0]
	if err := os.WriteFile(pre, []byte("users: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	storeBefore, cfgBefore := fileSHA(t, sb.path("state", "store.yaml")), fileSHA(t, sb.path("etc", "tacquito.yaml"))
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(1, "", "tacctl store: "+pre+": ")
	sb.expect(1, "", "[ERROR] "+pre+" cannot be read as a tacquito.yaml. Nothing was changed.\n")
	if fileSHA(t, sb.path("state", "store.yaml")) != storeBefore || fileSHA(t, sb.path("etc", "tacquito.yaml")) != cfgBefore {
		t.Error("touched")
	}

	// Arguments: usage, exit 2.
	for _, extra := range [][]string{{"--force"}, {""}, {"help"}} {
		sb.run("y\n", append([]string{"store", "rollback"}, extra...))
		sb.expect(2, "", "[ERROR] Usage: tacctl store rollback\n")
	}
	if _, err := os.Stat(sb.path("state", "store.yaml")); err != nil {
		t.Error("store gone")
	}
}

func TestStoreRollbackTakesTheNewestRegularPreStoreFile(t *testing.T) {
	sb, original := flippedSandbox(t)
	sb.write("state/backups/legacy/tacquito.yaml.pre-store.20200101_000000", "older\n", 0o600)
	if err := os.Symlink("/etc/passwd", sb.path("state", "backups", "legacy", "tacquito.yaml.pre-store.99990101_000000")); err != nil {
		t.Fatal(err)
	}
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(0, "Rolled back", "")
	if fileSHA(t, sb.path("etc", "tacquito.yaml")) != original {
		t.Error("the wrong file came back")
	}
}

func TestStoreRollbackThenImportAgainAndRollBackAgain(t *testing.T) {
	sb, original := flippedSandbox(t)
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(0, "Rolled back", "")
	// A second import reuses the pre-store copy (same bytes).
	sb.run("", []string{"store", "import"})
	sb.expect(0, "Store written to", "")
	if len(sb.preStore()) != 1 {
		t.Error(sb.preStore())
	}
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(0, "Rolled back", "")
	if fileSHA(t, sb.path("etc", "tacquito.yaml")) != original {
		t.Error("not the original")
	}
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(1, "", "already in legacy read-only mode")
	if left, _ := os.ReadDir(sb.path("tmp")); len(left) != 0 {
		t.Errorf("TMPDIR not empty: %v", left)
	}
}

func TestStoreRollbackIsSuperuserOnly(t *testing.T) {
	if !tier.Permits(tier.Superuser, "store", "rollback") || tier.Permits(tier.Operator, "store", "rollback") ||
		tier.Permits(tier.Readonly, "store", "rollback") {
		t.Error("tiers")
	}
}
