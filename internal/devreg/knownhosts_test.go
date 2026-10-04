package devreg

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files")

// pinnedRegistry is a registry with two pinned devices, one unpinned and
// two pinned enrolled hosts.
func pinnedRegistry(t *testing.T) *File {
	t.Helper()
	ed, ec, rsa := testKey(t, "ed25519"), testKey(t, "ecdsa"), testKey(t, "rsa")
	f := Empty()
	f.Devices = []*Device{
		{Name: "core-sw1", Address: "10.99.0.1", Vendor: "cisco", LegacySSH: true, HostKeys: KeyStrings([]HostKey{rsa})},
		{Name: "lab-rtr2", Address: "192.0.2.7", Vendor: "juniper", Port: 830, HostKeys: KeyStrings([]HostKey{rsa, ed, ec})},
		{Name: "oob-con1", Address: "10.99.0.9", Vendor: "wti"},
	}
	f.SetHostKeys("web2", KeyStrings([]HostKey{ec}))
	f.SetHostKeys("web1", KeyStrings([]HostKey{ed}))
	return f
}

func TestKnownHostsGolden(t *testing.T) {
	got := pinnedRegistry(t).KnownHosts()
	golden := filepath.Join("testdata", "known_hosts.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("known_hosts:\n%s\nwant:\n%s", got, want)
	}
	// One line per pinned key, alias first, no port, no address.
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(string(got)), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		lines++
		if f := strings.Fields(l); len(f) != 3 || strings.ContainsAny(f[0], "[]:,") {
			t.Errorf("line %q", l)
		}
	}
	if lines != 6 || strings.Contains(string(got), "oob-con1") || strings.Contains(string(got), "10.99.0.1") {
		t.Errorf("%d lines:\n%s", lines, got)
	}
	if string(Empty().KnownHosts()) != KnownHostsHeader {
		t.Error("an empty registry is the header alone")
	}
}

func TestMutateRegeneratesKnownHosts(t *testing.T) {
	dir := t.TempDir()
	p, kh := filepath.Join(dir, "devices.yaml"), filepath.Join(dir, "known_hosts")
	reg := pinnedRegistry(t)
	if _, err := Mutate(p, kh, nil, func(f *File) error { *f = *reg.Clone(); return nil }); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(kh)
	if err != nil || string(got) != string(reg.KnownHosts()) {
		t.Fatalf("known_hosts %q %v", got, err)
	}
	st, _ := os.Stat(kh)
	if st.Mode().Perm() != KnownHostsMode {
		t.Errorf("mode %v", st.Mode())
	}
	// The registry reads back with the hosts' pins.
	back, err := Load(p)
	if err != nil || len(back.Hosts) != 2 || back.Hosts[0].Name != "web1" || len(back.HostKeysOf("WEB2")) != 1 {
		t.Fatalf("read back: %+v %v", back, err)
	}
	if !strings.Contains(mustRead(t, p), "hosts:\n  web1:\n    host_keys: [ssh-ed25519 ") {
		t.Errorf("devices.yaml:\n%s", mustRead(t, p))
	}
	// Unchanged: the file is left alone (same inode).
	before, _ := os.Stat(kh)
	if _, err := Mutate(p, kh, nil, func(*File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(kh)
	if !os.SameFile(before, after) {
		t.Error("an unchanged known_hosts was replaced")
	}
	// A wrong mode or a removed file is repaired by the next write, even one
	// that changes nothing in the registry.
	if err := os.Chmod(kh, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Mutate(p, kh, nil, func(*File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(kh); st.Mode().Perm() != KnownHostsMode {
		t.Errorf("mode not repaired: %v", st.Mode())
	}
	_ = os.Remove(kh)
	if _, err := Mutate(p, kh, nil, func(*File) error { return nil }); err != nil || mustRead(t, kh) != string(reg.KnownHosts()) {
		t.Errorf("not regenerated: %v", err)
	}
	// Removing a device and forgetting a host drop their lines.
	if _, err := Mutate(p, kh, nil, func(f *File) error {
		f.Remove("lab-rtr2")
		f.SetHostKeys("web1", nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if s := mustRead(t, kh); strings.Contains(s, "lab-rtr2") || strings.Contains(s, "web1") || !strings.Contains(s, "core-sw1 ssh-rsa ") || !strings.Contains(s, "web2 ") {
		t.Errorf("after removal:\n%s", s)
	}
	// A refused write leaves both files alone.
	kb, pb := mustRead(t, kh), mustRead(t, p)
	if _, err := Mutate(p, kh, nil, func(f *File) error { f.Devices[0].HostKeys = []string{"ssh-rsa junk"}; return nil }); err == nil {
		t.Error("an invalid key was written")
	}
	if mustRead(t, kh) != kb || mustRead(t, p) != pb {
		t.Error("a refused write changed a file")
	}
	// SyncKnownHosts regenerates it from the file (after a restore).
	if err := os.WriteFile(kh, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SyncKnownHosts(p, kh); err != nil || mustRead(t, kh) == "stale\n" || !strings.HasPrefix(mustRead(t, kh), KnownHostsHeader) {
		t.Errorf("sync: %v %q", err, mustRead(t, kh))
	}
}

func TestHostPinsValidation(t *testing.T) {
	ed := testKey(t, "ed25519")
	for name, text := range map[string]string{
		"not a mapping": "version: 1\nhosts: [a]\n",
		"unknown key":   "version: 1\nhosts:\n  web1: {keys: ['" + ed.String() + "']}\n",
		"bad key":       "version: 1\nhosts:\n  web1: {host_keys: ['ssh-ed25519 AAAA']}\n",
		"no keys":       "version: 1\nhosts:\n  web1: {host_keys: []}\n",
		"bad name":      "version: 1\nhosts:\n  'bad name': {host_keys: ['" + ed.String() + "']}\n",
	} {
		if _, err := parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f, err := parse([]byte("version: 1\nhosts:\n  web1: {host_keys: ['" + ed.String() + "']}\n"))
	if err != nil || len(f.HostKeysOf("web1")) != 1 {
		t.Errorf("valid: %v %v", f, err)
	}
	c := f.Clone()
	c.SetHostKeys("web1", nil)
	if len(f.HostKeysOf("web1")) != 1 || len(c.Hosts) != 0 {
		t.Error("Clone shares the pins")
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
