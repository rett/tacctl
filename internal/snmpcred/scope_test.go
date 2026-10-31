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
	prod := Creds{Users: []User{{"alice", "auth-pass-1", "priv-pass-2"}}, Default: "alice"}
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
	if got, err := LoadScope(dir, "lab"); err != nil || !same(got, lab) {
		t.Errorf("lab: %+v %v", got, err)
	}
	if got, err := LoadScope(dir, "prod"); err != nil || !same(got, prod) {
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
	if got, _ := LoadScope(dir, "lab2"); !same(got, lab) {
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

// A snmp.yaml written by 0.2.2 to 0.2.22 (version 1) loads as a pool of one
// user that is the default, a scope's file is read by the same reader, and
// nothing rewrites the file until a change saves it (as version 2).
func TestOldDefaultFileLoadsAsAPoolOfOne(t *testing.T) {
	dir := t.TempDir()
	old := "# tacctl SNMP credentials (the sysName name hint of 'tacctl device add'). Secret: 0600, never printed.\n" +
		"# Edit with 'tacctl config snmp community|v3-user|clear'.\nversion: 1\ncommunity: public-ish\nv3:\n  user: alice\n" +
		"  auth_passphrase: auth-pass-1\n  priv_passphrase: priv-pass-2\n"
	p := filepath.Join(dir, "snmp.yaml")
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	want := Creds{Community: "public-ish", Users: []User{{"alice", "auth-pass-1", "priv-pass-2"}}, Default: "alice"}
	if err != nil || !same(c, want) || c.Format != LegacyVersion {
		t.Fatalf("old file: %+v %v", c, err)
	}
	if data, _ := os.ReadFile(p); string(data) != old {
		t.Error("loading rewrote the file")
	}
	// Saved, it is version 1 again while it fits (a pool of one default
	// user), and reads back as the same pool.
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "version: 1") || !strings.Contains(string(data), "v3:") || strings.Contains(string(data), "users:") {
		t.Errorf("rewritten:\n%s", data)
	}
	if again, err := Load(p); err != nil || !same(again, want) || again.Format != LegacyVersion {
		t.Errorf("read back: %+v %v", again, err)
	}
	// A second user is what version 1 cannot hold: version 2.
	c.Put(User{"bob", "auth-pass-3", "priv-pass-4"})
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p)
	if !strings.Contains(string(data), "version: 2\n") || strings.Contains(string(data), "v3:") ||
		!strings.Contains(string(data), "users:") || !strings.Contains(string(data), "default: alice\n") {
		t.Errorf("rewritten with two users:\n%s", data)
	}
	if again, err := Load(p); err != nil || len(again.Users) != 2 || again.Default != "alice" || again.Format != Version {
		t.Errorf("read back: %+v %v", again, err)
	}
	// The same bytes as a scope's file.
	if err := os.MkdirAll(filepath.Join(dir, "snmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snmp", "lab.yaml"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadScope(filepath.Join(dir, "snmp"), "lab"); err != nil || !same(got, want) {
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
	def := Layer{Version: "v2c", Port: 1161, Auth: "sha256", Creds: Creds{Community: "default-comm", Users: []User{{"alice", "da", "dp"}}, Default: "alice"}}
	scope := Layer{Version: "v3", Timeout: 5, Creds: Creds{Users: []User{{"carol", "sa", "sp"}}, Default: "carol"}}

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
	if e.Community != "default-comm" || e.CommunityFrom != FromDefault {
		t.Errorf("community: %q %s", e.Community, e.CommunityFrom)
	}
	if e.User != "carol" || e.AuthPass != "sa" || e.PrivPass != "sp" || e.V3From != FromScope || e.CredFrom() != FromScope {
		t.Errorf("v3: %+v", e)
	}

	// A scope with nothing of its own inherits everything, and says so.
	e = Resolve(Layer{}, def)
	if e.Version != "v2c" || e.VersionFrom != FromDefault || e.CredFrom() != FromDefault || e.Community != "default-comm" || e.User != "alice" {
		t.Errorf("inherited: %+v", e)
	}
	if e2 := Resolve(Layer{}, def); e2 != e {
		t.Error("no scope differs from an empty scope")
	}

	// A scope that has users but no default takes the default level's user: a
	// pool alone chooses nobody.
	pool := Resolve(Layer{Version: "v3", Creds: Creds{Users: []User{{"carol", "sa", "sp"}}}}, def)
	if pool.User != "alice" || pool.V3From != FromDefault {
		t.Errorf("a pool without a default: %+v", pool)
	}

	// A scope whose default user lacks a passphrase does not borrow another
	// user's, nor the default level's user: the problem names the fix.
	partial := Resolve(Layer{Version: "v3", Name: "scope lab", Setter: "tacctl scope snmp lab", Creds: Creds{Users: []User{{Name: "carol"}}, Default: "carol"}}, def)
	if partial.User != "carol" || partial.AuthPass != "" || partial.HasV3() || partial.V3From != FromScope ||
		!strings.Contains(partial.V3Problem, "'carol' of scope lab has no passphrases ('tacctl scope snmp lab v3-user add carol' sets them)") {
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
	if problem != "no SNMPv3 user is the default ('tacctl scope snmp lab v3-user default <user>')" {
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
	cfg, problem = Resolve(Layer{Version: "v3", Creds: Creds{Users: []User{{"u", "a", "p"}}, Default: "u"}}, Layer{Auth: "sha256"}).Config("x")
	if problem != "" || cfg.User != "u" || cfg.Auth != "sha256" || cfg.Priv != "aes128" {
		t.Errorf("v3: %+v %q", cfg, problem)
	}
}

// A device's default may name a user of its own pool, its scope's or the
// default level's; a scope's and the default level's only their own. A
// chosen user that is missing is a problem that names the command that
// fixes it, never a fallback to the next default.
func TestResolveDeviceChosenUser(t *testing.T) {
	def := Layer{Version: "v3", Name: "the config", Setter: "tacctl config snmp",
		Creds: Creds{Users: []User{{"alice", "alice-auth", "alice-priv"}}, Default: "alice"}}
	scope := Layer{Name: "scope lab", Setter: "tacctl scope snmp lab",
		Creds: Creds{Users: []User{{"carol", "carol-auth", "carol-priv"}}, Default: "carol"}}
	dev := func(c Creds) Layer { return Layer{Name: "device sw1", Setter: "tacctl device snmp sw1", Creds: c} }

	// Told to use its scope's, and the config's, user.
	for name, want := range map[string]string{"carol": FromScope, "alice": FromDefault} {
		e := ResolveDevice(dev(Creds{Default: name}), scope, def)
		if e.User != name || e.V3From != want || e.DefaultFrom != FromDevice || e.V3Problem != "" || !e.HasV3() {
			t.Errorf("device chooses %s: %+v", name, e)
		}
	}
	// Its own pool, with a default of its own, wins over the scope's.
	e := ResolveDevice(dev(Creds{Users: []User{{"dave", "dave-auth", "dave-priv"}}, Default: "dave"}), scope, def)
	if e.User != "dave" || e.V3From != FromDevice || e.AuthPass != "dave-auth" {
		t.Errorf("own: %+v", e)
	}
	// Users in its own pool without a default choose nobody: the scope's
	// default applies.
	e = ResolveDevice(dev(Creds{Users: []User{{"dave", "dave-auth", "dave-priv"}}}), scope, def)
	if e.User != "carol" || e.DefaultFrom != FromScope {
		t.Errorf("a pool without a default: %+v", e)
	}
	// A missing user: an error, not the scope's default.
	e = ResolveDevice(dev(Creds{Default: "gone"}), scope, def)
	want := "the SNMPv3 user 'gone', the default of device sw1, is in no pool it may use (device sw1, scope lab, the config); " +
		"'tacctl device snmp sw1 v3-user add gone' adds it, 'tacctl device snmp sw1 v3-user default <user>' chooses another"
	if e.User != "gone" || e.HasV3() || e.AuthPass != "" || e.V3Problem != want || e.V3From != FromDevice {
		t.Errorf("missing: %+v\nwant %s", e, want)
	}
	if _, problem := e.Config("x"); problem != want {
		t.Errorf("config problem: %q", problem)
	}
	// A scope's default names its own pool only: the config's user is not
	// reachable from it, and neither is a scope's from the config's default.
	e = ResolveDevice(Layer{}, Layer{Name: "scope lab", Setter: "tacctl scope snmp lab", Creds: Creds{Default: "alice"}}, def)
	if e.HasV3() || !strings.Contains(e.V3Problem, "'alice', the default of scope lab, is in no pool it may use (scope lab)") {
		t.Errorf("scope default naming the config's user: %+v", e)
	}
	poolOnly := Layer{Creds: Creds{Users: []User{{"carol", "carol-auth", "carol-priv"}}}}
	e = ResolveDevice(Layer{}, poolOnly, Layer{Name: "the config", Creds: Creds{Users: []User{{"alice", "a", "b"}}, Default: "carol"}})
	if e.User != "carol" || e.HasV3() {
		t.Errorf("config default naming the scope's user: %+v", e)
	}
	// Incomplete: the user is found, one passphrase is not there.
	e = ResolveDevice(Layer{}, Layer{Name: "scope lab", Setter: "tacctl scope snmp lab", Creds: Creds{Users: []User{{Name: "carol", AuthPass: "x"}}, Default: "carol"}}, def)
	if e.HasV3() || e.V3From != FromScope || !strings.Contains(e.V3Problem, "has no privacy passphrase ('tacctl scope snmp lab v3-user add carol' sets them)") {
		t.Errorf("incomplete: %+v", e)
	}
}

func TestLayerEmpty(t *testing.T) {
	if !(Layer{Name: "scope lab", Setter: "x"}).Empty() {
		t.Error("a name is no setting")
	}
	if (Layer{Creds: Creds{Default: "a"}}).Empty() || (Layer{Port: 1}).Empty() {
		t.Error("a setting was ignored")
	}
}
