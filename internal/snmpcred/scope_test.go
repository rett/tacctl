package snmpcred

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeFileNeverLeavesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"", "../x", "a/b", "a.b", ".hidden", "-x", "x y", strings.Repeat("a", 33), "a\x00b"} {
		if p, err := ScopeFile(dir, bad); err == nil {
			t.Errorf("ScopeFile(%q) = %q", bad, p)
		}
		if _, err := LoadScope(dir, bad); err == nil {
			t.Errorf("LoadScope(%q) accepted", bad)
		}
		if err := SaveScope(dir, bad, Creds{Community: "x"}); err == nil {
			t.Errorf("SaveScope(%q) accepted", bad)
		}
	}
	p, err := ScopeFile(dir, "lab-1_x")
	if err != nil || p != filepath.Join(dir, "lab-1_x.yaml") {
		t.Errorf("good name: %q %v", p, err)
	}
}

// One file per scope: 0600 in a 0700 directory, the format of snmp.yaml,
// removed with the last credential, and the directory with the last file.
func TestScopeFilesModesAndRemoval(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snmp")
	if c, err := LoadScope(dir, "lab"); err != nil || !c.Empty() {
		t.Fatalf("missing: %+v %v", c, err)
	}
	// A directory made too open is closed on the first save.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lab := Creds{Community: "lab-community"}
	prod := Creds{User: "alice", AuthPass: "auth-pass-1", PrivPass: "priv-pass-2"}
	if err := SaveScope(dir, "lab", lab); err != nil {
		t.Fatal(err)
	}
	if err := SaveScope(dir, "prod", prod); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory: %v %v", fi, err)
	}
	for _, s := range []string{"lab", "prod"} {
		fi, err := os.Stat(filepath.Join(dir, s+".yaml"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", s, fi, err)
		}
	}
	if got, err := LoadScope(dir, "lab"); err != nil || got != lab {
		t.Errorf("lab: %+v %v", got, err)
	}
	if got, err := LoadScope(dir, "prod"); err != nil || got != prod {
		t.Errorf("prod: %+v %v", got, err)
	}
	// The scopes do not see each other.
	if got, _ := LoadScope(dir, "dmz"); !got.Empty() {
		t.Errorf("dmz: %+v", got)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if !strings.HasPrefix(string(data), Header) || !strings.Contains(string(data), "version: 1") {
		t.Errorf("text:\n%s", data)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Errorf("%d files", len(ents))
	}
	// Rename moves the file.
	if err := RenameScope(dir, "lab", "lab2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadScope(dir, "lab2"); got != lab {
		t.Errorf("renamed: %+v", got)
	}
	if got, _ := LoadScope(dir, "lab"); !got.Empty() {
		t.Errorf("old name: %+v", got)
	}
	if err := RenameScope(dir, "nosuch", "other"); err != nil {
		t.Errorf("renaming a scope without a file: %v", err)
	}
	// Saving nothing, and removing, delete the file; the last one the directory.
	if err := SaveScope(dir, "lab2", Creds{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lab2.yaml")); !os.IsNotExist(err) {
		t.Errorf("empty credentials left the file: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("directory gone with a file still in it: %v", err)
	}
	if err := RemoveScope(dir, "prod"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("empty directory kept: %v", err)
	}
	if err := RemoveScope(dir, "prod"); err != nil {
		t.Errorf("removing what is not there: %v", err)
	}
}

// A snmp.yaml written by 0.2.2 loads unchanged, and a scope's file is read
// by the same reader.
func TestOldDefaultFileLoadsUnchanged(t *testing.T) {
	dir := t.TempDir()
	old := "# tacctl SNMP credentials (the sysName name hint of 'tacctl device add'). Secret: 0600, never printed.\n" +
		"# Edit with 'tacctl config snmp community|v3-user|clear'.\nversion: 1\ncommunity: public-ish\nv3:\n  user: alice\n" +
		"  auth_passphrase: auth-pass-1\n  priv_passphrase: priv-pass-2\n"
	p := filepath.Join(dir, "snmp.yaml")
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	want := Creds{Community: "public-ish", User: "alice", AuthPass: "auth-pass-1", PrivPass: "priv-pass-2"}
	if err != nil || c != want {
		t.Fatalf("old file: %+v %v", c, err)
	}
	// Written back as 0.2.2 writes it (the code is unchanged), and read again.
	text, err := c.Text()
	if err != nil || !strings.HasPrefix(string(text), Header) {
		t.Fatalf("rewritten: %s %v", text, err)
	}
	if err := os.WriteFile(p, text, 0o600); err != nil {
		t.Fatal(err)
	}
	if again, err := Load(p); err != nil || again != want {
		t.Errorf("read back: %+v %v", again, err)
	}
	// The same bytes as a scope's file.
	if err := os.MkdirAll(filepath.Join(dir, "snmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snmp", "lab.yaml"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadScope(filepath.Join(dir, "snmp"), "lab"); err != nil || got != want {
		t.Errorf("scope file: %+v %v", got, err)
	}
	// A scope file that does not parse is an error that names the file.
	if err := os.WriteFile(filepath.Join(dir, "snmp", "bad.yaml"), []byte("version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadScope(filepath.Join(dir, "snmp"), "bad"); err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("bad scope file: %v", err)
	}
}

// The scope's own value, then the default's, then the built-in; and which.
func TestResolve(t *testing.T) {
	def := Layer{Version: "v2c", Port: 1161, Auth: "sha256", Creds: Creds{Community: "default-comm", User: "du", AuthPass: "da", PrivPass: "dp"}}
	scope := Layer{Version: "v3", Timeout: 5, Creds: Creds{User: "su", AuthPass: "sa", PrivPass: "sp"}}

	e := Resolve(scope, def)
	if e.Version != "v3" || e.VersionFrom != FromScope {
		t.Errorf("version: %q %s", e.Version, e.VersionFrom)
	}
	if e.Port != 1161 || e.PortFrom != FromDefault || e.Timeout != 5 || e.TimeoutFrom != FromScope {
		t.Errorf("port/timeout: %d %s %d %s", e.Port, e.PortFrom, e.Timeout, e.TimeoutFrom)
	}
	if e.Auth != "sha256" || e.AuthFrom != FromDefault || e.Priv != "aes128" || e.PrivFrom != FromBuiltIn {
		t.Errorf("auth/priv: %q %s %q %s", e.Auth, e.AuthFrom, e.Priv, e.PrivFrom)
	}
	// The community is the default's; the v3 unit is the scope's, as a whole.
	if e.Community != "default-comm" || e.CommunityFrom != FromDefault {
		t.Errorf("community: %q %s", e.Community, e.CommunityFrom)
	}
	if e.User != "su" || e.AuthPass != "sa" || e.PrivPass != "sp" || e.V3From != FromScope || e.CredFrom() != FromScope {
		t.Errorf("v3: %+v", e)
	}

	// A scope with nothing of its own inherits everything, and says so.
	e = Resolve(Layer{}, def)
	if e.Version != "v2c" || e.VersionFrom != FromDefault || e.CredFrom() != FromDefault || e.Community != "default-comm" {
		t.Errorf("inherited: %+v", e)
	}
	// A device in no scope is the default alone.
	if e2 := Resolve(Layer{}, def); e2 != e {
		t.Error("no scope differs from an empty scope")
	}

	// A scope that sets a v3 user but not the passphrases does not borrow the
	// default's passphrases: the unit is the scope's, and incomplete.
	partial := Resolve(Layer{Version: "v3", Creds: Creds{User: "su"}}, def)
	if partial.User != "su" || partial.AuthPass != "" || partial.HasV3() || partial.V3From != FromScope {
		t.Errorf("partial v3: %+v", partial)
	}

	// Nothing anywhere: the built-ins, and "not set".
	none := Resolve(Layer{}, Layer{})
	if none.Version != "" || none.VersionFrom != NotSet || none.Port != 161 || none.PortFrom != FromBuiltIn ||
		none.Timeout != 2 || none.Auth != "sha" || none.CredFrom() != NotSet || none.V3From != NotSet || none.CommunityFrom != NotSet {
		t.Errorf("empty: %+v", none)
	}
}

func TestEffectiveConfig(t *testing.T) {
	cfg, problem := Resolve(Layer{}, Layer{}).Config("tacctl config snmp")
	if problem != "SNMP is not configured ('tacctl config snmp')" || cfg.Port != 161 {
		t.Errorf("not configured: %q", problem)
	}
	_, problem = Resolve(Layer{Version: "v2c"}, Layer{}).Config("tacctl scope snmp lab")
	if problem != "no SNMP community is set ('tacctl scope snmp lab community')" {
		t.Errorf("no community: %q", problem)
	}
	_, problem = Resolve(Layer{Version: "v3"}, Layer{}).Config("tacctl scope snmp lab")
	if problem != "no SNMPv3 user is set ('tacctl scope snmp lab v3-user <user>')" {
		t.Errorf("no v3: %q", problem)
	}
	_, problem = Resolve(Layer{Version: "v1"}, Layer{}).Config("tacctl config snmp")
	if !strings.Contains(problem, "is not v2c or v3") {
		t.Errorf("bad version: %q", problem)
	}
	cfg, problem = Resolve(Layer{Version: "v2c", Port: 1161}, Layer{Creds: Creds{Community: "c"}, Timeout: 4}).Config("x")
	if problem != "" || cfg.Community != "c" || cfg.Port != 1161 || cfg.Timeout.Seconds() != 4 || cfg.Retries != 1 {
		t.Errorf("v2c: %+v %q", cfg, problem)
	}
	cfg, problem = Resolve(Layer{Version: "v3", Creds: Creds{User: "u", AuthPass: "a", PrivPass: "p"}}, Layer{Auth: "sha256"}).Config("x")
	if problem != "" || cfg.User != "u" || cfg.Auth != "sha256" || cfg.Priv != "aes128" {
		t.Errorf("v3: %+v %q", cfg, problem)
	}
}
