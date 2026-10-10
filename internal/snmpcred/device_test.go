package snmpcred

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/snmp"
)

// The per-device file (D72) never leaves its directory, whatever the name.
func TestDeviceFileNeverLeavesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"", ".", "..", "../x", "a/b", "a\\b", ".hidden", "-x", "x y", "a..b", "trailing.", strings.Repeat("a", 251), "a\x00b"} {
		if p, err := DeviceFile(dir, bad); err == nil {
			t.Errorf("DeviceFile(%q) = %q", bad, p)
		}
		if _, err := LoadDevice(dir, bad); err == nil {
			t.Errorf("LoadDevice(%q) accepted", bad)
		}
		if err := SaveDevice(dir, bad, Creds{Community: "x"}); err == nil {
			t.Errorf("SaveDevice(%q) accepted", bad)
		}
		if err := RemoveDevice(dir, bad); err == nil {
			t.Errorf("RemoveDevice(%q) accepted", bad)
		}
	}
	if err := RenameDevice(dir, "sw1", "../x"); err == nil {
		t.Error("RenameDevice to a path accepted")
	}
	for name, file := range map[string]string{
		"sw1": "sw1.yaml", "Core-SW1": "core-sw1.yaml", "sw1.site-a.example": "sw1.site-a.example.yaml", "a_b": "a_b.yaml",
		strings.Repeat("a", 250): strings.Repeat("a", 250) + ".yaml",
	} {
		p, err := DeviceFile(dir, name)
		if err != nil || p != filepath.Join(dir, "devices", file) {
			t.Errorf("DeviceFile(%q) = %q %v", name, p, err)
		}
	}
}

// 0600 in a 0700 directory, the format of snmp.yaml, a spelling of the name
// is the same file, and the last removal takes the directories with it.
func TestDeviceFilesModesAndRemoval(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snmp")
	if c, err := LoadDevice(dir, "sw1"); err != nil || !c.Empty() {
		t.Fatalf("missing: %+v %v", c, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sw1 := Creds{Community: "dev-community-1"}
	sw2 := Creds{User: "alice", AuthPass: "auth-pass-1", PrivPass: "priv-pass-2"}
	if err := SaveDevice(dir, "SW1", sw1); err != nil {
		t.Fatal(err)
	}
	if err := SaveDevice(dir, "sw2", sw2); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, filepath.Join(dir, "devices")} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi, err)
		}
	}
	for _, f := range []string{"sw1", "sw2"} {
		fi, err := os.Stat(filepath.Join(dir, "devices", f+".yaml"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
	if got, err := LoadDevice(dir, "sw1"); err != nil || got != sw1 {
		t.Errorf("sw1: %+v %v", got, err)
	}
	if got, err := LoadDevice(dir, "Sw1"); err != nil || got != sw1 {
		t.Errorf("Sw1 (another spelling): %+v %v", got, err)
	}
	if got, err := LoadDevice(dir, "sw2"); err != nil || got != sw2 {
		t.Errorf("sw2: %+v %v", got, err)
	}
	// The scope loader sees none of it: a scope named like a device has a
	// file of its own, and 'devices' is a scope name like any other.
	if c, err := LoadScope(dir, "sw1"); err != nil || !c.Empty() {
		t.Errorf("scope sw1: %+v %v", c, err)
	}
	if c, err := LoadScope(dir, "devices"); err != nil || !c.Empty() {
		t.Errorf("scope devices: %+v %v", c, err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "devices", "sw1.yaml"))
	if !strings.HasPrefix(string(data), DeviceHeader) || !strings.Contains(string(data), "version: 1") {
		t.Errorf("file:\n%s", data)
	}
	// A scope's removal leaves the devices alone.
	if err := SaveScope(dir, "lab", Creds{Community: "lab-c"}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveScope(dir, "lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "devices", "sw1.yaml")); err != nil {
		t.Errorf("a scope's removal took a device's file: %v", err)
	}
	// Saving nothing removes the file; the last one takes the directories.
	if err := SaveDevice(dir, "sw1", Creds{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "devices", "sw1.yaml")); !os.IsNotExist(err) {
		t.Errorf("sw1.yaml left: %v", err)
	}
	if err := RemoveDevice(dir, "sw2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("empty directory left: %v", err)
	}
	if err := RemoveDevice(dir, "sw2"); err != nil {
		t.Errorf("removing a missing file: %v", err)
	}
}

// A device's file is moved by a rename, never overwritten, and a rename of
// the spelling alone keeps it.
func TestRenameDevice(t *testing.T) {
	dir := t.TempDir()
	if err := SaveDevice(dir, "sw1", Creds{Community: "c-one"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveDevice(dir, "sw9", Creds{Community: "leftover"}); err != nil {
		t.Fatal(err)
	}
	err := RenameDevice(dir, "sw1", "sw9")
	if err == nil || !strings.Contains(err.Error(), "SNMP credentials for a device named 'sw9' are already on disk") {
		t.Fatalf("onto a leftover: %v", err)
	}
	for name, want := range map[string]string{"sw1": "c-one", "sw9": "leftover"} {
		if c, err := LoadDevice(dir, name); err != nil || c.Community != want {
			t.Errorf("%s: %q %v (nothing was touched)", name, c.Community, err)
		}
	}
	if err := RenameDevice(dir, "nosuch", "sw9"); err != nil {
		t.Errorf("no source file: %v", err)
	}
	if err := RenameDevice(dir, "sw1", "SW1"); err != nil {
		t.Errorf("spelling only: %v", err)
	}
	if c, err := LoadDevice(dir, "sw1"); err != nil || c.Community != "c-one" {
		t.Errorf("spelling only lost the file: %+v %v", c, err)
	}
	if err := RenameDevice(dir, "sw1", "core-sw1"); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadDevice(dir, "core-sw1"); err != nil || c.Community != "c-one" {
		t.Errorf("renamed: %+v %v", c, err)
	}
	if c, _ := LoadDevice(dir, "sw1"); !c.Empty() {
		t.Errorf("the old name still has it: %+v", c)
	}
}

func TestCheckNoDeviceFile(t *testing.T) {
	dir := t.TempDir()
	if err := CheckNoDeviceFile(dir, "sw1"); err != nil {
		t.Errorf("no file: %v", err)
	}
	if err := SaveDevice(dir, "sw1", Creds{Community: "x"}); err != nil {
		t.Fatal(err)
	}
	err := CheckNoDeviceFile(dir, "SW1")
	if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "devices", "sw1.yaml")) {
		t.Errorf("a leftover: %v", err)
	}
	if err := CheckNoDeviceFile(dir, "../x"); err == nil {
		t.Error("an invalid name passed")
	}
}

// The order is the device's value, then the scope's, then the default's,
// then the built-in, setting by setting; the v3 user and its passphrases
// come from one level.
func TestResolveDevice(t *testing.T) {
	def := Layer{Version: snmp.V2c, Port: 1161, Auth: snmp.AuthSHA256, Creds: Creds{Community: "def-c", User: "defuser", AuthPass: "def-auth-1", PrivPass: "def-priv-1"}}
	scope := Layer{Port: 2161, Timeout: 4, Creds: Creds{Community: "scope-c"}}
	dev := Layer{Version: snmp.V3, Timeout: 7, Creds: Creds{User: "devuser", AuthPass: "dev-auth-1", PrivPass: "dev-priv-1"}}
	e := ResolveDevice(dev, scope, def)
	if e.Version != snmp.V3 || e.VersionFrom != FromDevice {
		t.Errorf("version %q (%s)", e.Version, e.VersionFrom)
	}
	if e.Port != 2161 || e.PortFrom != FromScope {
		t.Errorf("port %d (%s)", e.Port, e.PortFrom)
	}
	if e.Timeout != 7 || e.TimeoutFrom != FromDevice {
		t.Errorf("timeout %d (%s)", e.Timeout, e.TimeoutFrom)
	}
	if e.Auth != snmp.AuthSHA256 || e.AuthFrom != FromDefault || e.Priv != snmp.PrivAES128 || e.PrivFrom != FromBuiltIn {
		t.Errorf("auth %q (%s), priv %q (%s)", e.Auth, e.AuthFrom, e.Priv, e.PrivFrom)
	}
	if e.Community != "scope-c" || e.CommunityFrom != FromScope {
		t.Errorf("community %q (%s)", e.Community, e.CommunityFrom)
	}
	if e.User != "devuser" || e.V3From != FromDevice || e.CredFrom() != FromDevice {
		t.Errorf("v3 %q (%s), cred %s", e.User, e.V3From, e.CredFrom())
	}
	// A user the device sets with half its passphrases is still the
	// device's whole: nothing is taken from the scope or the default.
	half := ResolveDevice(Layer{Creds: Creds{User: "u"}}, scope, def)
	if half.User != "u" || half.AuthPass != "" || half.V3From != FromDevice {
		t.Errorf("half: %+v", half)
	}
	// A zero device layer is the old Resolve.
	if got, want := ResolveDevice(Layer{}, scope, def), Resolve(scope, def); got != want {
		t.Errorf("zero device layer: %+v != %+v", got, want)
	}
	if e := Resolve(Layer{}, Layer{}); e.VersionFrom != NotSet || e.V3From != NotSet || e.PortFrom != FromBuiltIn {
		t.Errorf("nothing set: %+v", e)
	}
}
