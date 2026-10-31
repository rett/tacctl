package blocks

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "blocks"))
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestWriteReadModesAndAtomicity(t *testing.T) {
	// A umask that would loosen the directories must not matter.
	old := setUmask(0o000)
	defer setUmask(old)

	s := newStore(t)
	lab := ScopeLevel("lab")
	if _, err := s.Read(lab, "juniper", "snmp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read of nothing: %v", err)
	}
	text := []byte("set snmp community lab-ro authorization read-only\n")
	if err := s.Write(lab, "juniper", "snmp", text); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read(lab, "juniper", "snmp")
	if err != nil || string(got) != string(text) {
		t.Fatalf("read back %q %v", got, err)
	}
	for _, d := range []string{"", "lab", "lab/juniper"} {
		if m := mode(t, filepath.Join(s.Dir, d)); m != 0o700 {
			t.Errorf("directory %q is %v", d, m)
		}
	}
	if m := mode(t, filepath.Join(s.Dir, "lab", "juniper", "snmp")); m != 0o600 {
		t.Errorf("file is %v", m)
	}

	// A second write replaces the file whole and leaves no temporary file.
	if err := s.Write(lab, "juniper", "snmp", []byte("# empty\n")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.Dir, "lab", "juniper"))
	if len(entries) != 1 || entries[0].Name() != "snmp" {
		t.Errorf("directory holds %v", entries)
	}
	if got, _ := s.Read(lab, "juniper", "snmp"); string(got) != "# empty\n" {
		t.Errorf("after the second write: %q", got)
	}

	// A failed write (the destination is a directory) keeps what was there
	// and leaves no temporary file.
	if err := os.Mkdir(filepath.Join(s.Dir, "lab", "juniper", "system"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(lab, "juniper", "system", []byte("x\n")); err == nil {
		t.Error("a write over a directory succeeded")
	}
	entries, _ = os.ReadDir(filepath.Join(s.Dir, "lab", "juniper"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
	if got, _ := s.Read(lab, "juniper", "snmp"); string(got) != "# empty\n" {
		t.Errorf("a failed write of another block changed this one: %q", got)
	}
}

func TestDeviceLevelLayoutAndLowerCase(t *testing.T) {
	s := newStore(t)
	dev := DeviceLevel("JSW1.Lab.Example.NET")
	if err := s.Write(dev, "juniper", "system", []byte("set system time-zone UTC\n")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.Dir, "_devices", "jsw1.lab.example.net", "juniper", "system")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("not at %s: %v", p, err)
	}
	if got, err := s.Read(DeviceLevel("jsw1.lab.example.net"), "juniper", "system"); err != nil || len(got) == 0 {
		t.Errorf("read by the lower case name: %q %v", got, err)
	}
	for _, d := range []string{"_devices", "_devices/jsw1.lab.example.net", "_devices/jsw1.lab.example.net/juniper"} {
		if m := mode(t, filepath.Join(s.Dir, d)); m != 0o700 {
			t.Errorf("directory %q is %v", d, m)
		}
	}
	if devs, _ := s.Devices(); !slices.Equal(devs, []string{"jsw1.lab.example.net"}) {
		t.Errorf("Devices = %q", devs)
	}
	// The device level is not a scope.
	if sc, _ := s.Scopes(); len(sc) != 0 {
		t.Errorf("Scopes = %q", sc)
	}
}

func TestNamesAreValidatedAndTraversalRefused(t *testing.T) {
	s := newStore(t)
	for _, tc := range []struct {
		name          string
		l             Level
		vendor, block string
		want          string
	}{
		{"scope traversal", ScopeLevel("../etc"), "juniper", "snmp", "Invalid scope name"},
		{"scope slash", ScopeLevel("a/b"), "juniper", "snmp", "Invalid scope name"},
		{"scope dot", ScopeLevel(".."), "juniper", "snmp", "Invalid scope name"},
		{"scope empty", ScopeLevel(""), "juniper", "snmp", "Invalid scope name"},
		{"scope digit first", ScopeLevel("1lab"), "juniper", "snmp", "Invalid scope name"},
		{"scope _devices", ScopeLevel("_devices"), "juniper", "snmp", "Invalid scope name"},
		{"scope underscore", ScopeLevel("_lab"), "juniper", "snmp", "Invalid scope name"},
		{"device traversal", DeviceLevel("../x"), "juniper", "snmp", "Invalid device name"},
		{"device dots", DeviceLevel("a..b"), "juniper", "snmp", "Invalid device name"},
		{"device slash", DeviceLevel("a/b"), "juniper", "snmp", "Invalid device name"},
		{"device leading dot", DeviceLevel(".hidden"), "juniper", "snmp", "Invalid device name"},
		{"device trailing dot", DeviceLevel("jsw1."), "juniper", "snmp", "Invalid device name"},
		{"both", Level{Scope: "lab", Device: "jsw1"}, "juniper", "snmp", "not both"},
		{"vendor wti", ScopeLevel("lab"), "wti", "snmp", "Unknown vendor 'wti'"},
		{"vendor traversal", ScopeLevel("lab"), "../juniper", "snmp", "Unknown vendor"},
		{"vendor upper", ScopeLevel("lab"), "Juniper", "snmp", "Unknown vendor"},
		{"block traversal", ScopeLevel("lab"), "juniper", "../snmp", "Invalid block name"},
		{"block upper", ScopeLevel("lab"), "juniper", "SNMP", "Invalid block name"},
		{"block long", ScopeLevel("lab"), "juniper", strings.Repeat("a", 33), "Invalid block name"},
		{"block empty", ScopeLevel("lab"), "juniper", "", "Invalid block name"},
		{"block unknown", ScopeLevel("lab"), "juniper", "ntp", "Unknown block 'ntp'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Write(tc.l, tc.vendor, tc.block, []byte("x\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Write: %v, want %q", err, tc.want)
			}
			if _, err := s.Read(tc.l, tc.vendor, tc.block); err == nil || errors.Is(err, ErrNotFound) {
				t.Errorf("Read: %v", err)
			}
			if err := s.Remove(tc.l, tc.vendor, tc.block); err == nil || errors.Is(err, ErrNotFound) {
				t.Errorf("Remove: %v", err)
			}
		})
	}
	if _, err := os.Stat(s.Dir); !os.IsNotExist(err) {
		t.Errorf("a refused name created %s", s.Dir)
	}
	// Both vendors and both blocks are accepted.
	for _, v := range []string{"juniper", "cisco"} {
		for _, b := range []string{"snmp", "system"} {
			if err := s.Write(ScopeLevel("lab"), v, b, []byte("# x\n")); err != nil {
				t.Errorf("%s/%s: %v", v, b, err)
			}
		}
	}
}

func TestSizeLimitAndNotRegular(t *testing.T) {
	s := newStore(t)
	lab := ScopeLevel("lab")
	if err := s.Write(lab, "juniper", "snmp", make([]byte, MaxSize+1)); err == nil || !strings.Contains(err.Error(), "at most 256 KiB") {
		t.Errorf("oversized write: %v", err)
	}
	if err := s.Write(lab, "juniper", "snmp", make([]byte, MaxSize)); err != nil {
		t.Errorf("a block of MaxSize: %v", err)
	}
	// A symbolic link in the place of a block is not read.
	out := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(out, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(s.Dir, "lab", "juniper", "system")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(lab, "juniper", "system"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("a link was read: %v", err)
	}
	if got, _ := s.List(lab, "juniper"); !slices.Equal(got, []string{"snmp"}) {
		t.Errorf("List = %q (a link is no block)", got)
	}
}

func TestListScopesVendorsRemove(t *testing.T) {
	s := newStore(t)
	if got, err := s.List(ScopeLevel("lab"), "juniper"); err != nil || got != nil {
		t.Errorf("List of nothing: %q %v", got, err)
	}
	if got, err := s.Scopes(); err != nil || got != nil {
		t.Errorf("Scopes of nothing: %q %v", got, err)
	}
	for _, w := range []struct{ scope, vendor, block string }{
		{"lab", "juniper", "system"}, {"lab", "juniper", "snmp"}, {"lab", "cisco", "snmp"}, {"dmz", "juniper", "snmp"},
	} {
		if err := s.Write(ScopeLevel(w.scope), w.vendor, w.block, []byte("# x\n")); err != nil {
			t.Fatal(err)
		}
	}
	// Strays are not blocks: a temporary file, an upper case name, a
	// directory.
	dir := filepath.Join(s.Dir, "lab", "juniper")
	for _, n := range []string{".snmp.123.tmp", "README"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(ScopeLevel("lab"), "juniper"); !slices.Equal(got, []string{"snmp", "system"}) {
		t.Errorf("List = %q", got)
	}
	if got, _ := s.Scopes(); !slices.Equal(got, []string{"dmz", "lab"}) {
		t.Errorf("Scopes = %q", got)
	}
	if got, _ := s.Vendors(ScopeLevel("lab")); !slices.Equal(got, []string{"juniper", "cisco"}) {
		t.Errorf("Vendors = %q", got)
	}

	if err := s.Remove(ScopeLevel("dmz"), "juniper", "snmp"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "dmz")); !os.IsNotExist(err) {
		t.Errorf("the emptied directories are left: %v", err)
	}
	if err := s.Remove(ScopeLevel("dmz"), "juniper", "snmp"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second remove: %v", err)
	}
	for _, w := range []struct{ vendor, block string }{{"juniper", "snmp"}, {"juniper", "system"}, {"cisco", "snmp"}} {
		if err := s.Remove(ScopeLevel("lab"), w.vendor, w.block); err != nil {
			t.Fatalf("%v: %v", w, err)
		}
	}
	// The stray files keep the directory; the root stays while it has any.
	if _, err := os.Stat(filepath.Join(s.Dir, "lab", "juniper", "README")); err != nil {
		t.Errorf("a stray file went: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(s.Dir, "lab")); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ScopeLevel("only"), "juniper", "snmp", []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ScopeLevel("only"), "juniper", "snmp"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Dir); !os.IsNotExist(err) {
		t.Errorf("the empty root is left: %v", err)
	}
}

func TestRenameRemoveAndCheckNoScope(t *testing.T) {
	s := newStore(t)
	if err := s.RenameScope("dmz", "edge"); err != nil {
		t.Errorf("rename of nothing: %v", err)
	}
	if err := s.CheckNoScope("dmz"); err != nil {
		t.Errorf("CheckNoScope of nothing: %v", err)
	}
	for _, sc := range []string{"dmz", "taken"} {
		if err := s.Write(ScopeLevel(sc), "juniper", "snmp", []byte("# "+sc+"\n")); err != nil {
			t.Fatal(err)
		}
	}
	if !s.HasScope("dmz") || s.HasScope("edge") {
		t.Error("HasScope")
	}
	if err := s.CheckNoScope("dmz"); err == nil || !strings.Contains(err.Error(), "already on disk") {
		t.Errorf("CheckNoScope of a scope with blocks: %v", err)
	}
	// Onto a directory that is there: refused, both untouched.
	if err := s.RenameScope("dmz", "taken"); err == nil || !strings.Contains(err.Error(), "already on disk") {
		t.Errorf("rename onto a leftover: %v", err)
	}
	if got, _ := s.Read(ScopeLevel("taken"), "juniper", "snmp"); string(got) != "# taken\n" {
		t.Errorf("the leftover was overwritten: %q", got)
	}
	if err := s.RenameScope("dmz", "edge"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Read(ScopeLevel("edge"), "juniper", "snmp"); string(got) != "# dmz\n" {
		t.Errorf("after the rename: %q", got)
	}
	if s.HasScope("dmz") {
		t.Error("the old directory is left")
	}
	if err := s.RenameScope("edge", "_devices"); err == nil {
		t.Error("a rename to '_devices' was accepted")
	}
	if err := s.RemoveScope("edge"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveScope("edge"); err != nil {
		t.Errorf("second RemoveScope: %v", err)
	}
	if got, _ := s.Scopes(); !slices.Equal(got, []string{"taken"}) {
		t.Errorf("Scopes = %q", got)
	}
}

func TestVerify(t *testing.T) {
	s := newStore(t)
	lab := ScopeLevel("lab")
	for _, b := range []string{"snmp", "system"} {
		if err := s.Write(lab, "juniper", b, []byte("# x\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Write(ScopeLevel("dmz"), "juniper", "snmp", []byte("# x\n")); err != nil {
		t.Fatal(err)
	}

	f, err := s.Verify(lab, "juniper", []string{"snmp", "system"})
	if err != nil || len(f) != 0 {
		t.Errorf("a consistent scope: %v %v", f, err)
	}
	// system on disk but not listed: ignored and reported.
	f, _ = s.Verify(lab, "juniper", []string{"snmp"})
	if len(f) != 1 || f[0].Kind != KindUnlisted || f[0].Block != "system" || !strings.Contains(f[0].Text, "is ignored") {
		t.Errorf("unlisted: %+v", f)
	}
	// listed but no file: a finding.
	f, _ = s.Verify(lab, "cisco", []string{"snmp", "snmp"})
	if len(f) != 1 || f[0].Kind != KindMissing || f[0].Block != "snmp" || f[0].Vendor != "cisco" {
		t.Errorf("missing (and a name listed twice once): %+v", f)
	}

	all, err := s.VerifyScopes(Manifest{
		"lab":   {"juniper": {"snmp"}},         // system is unlisted
		"gone":  {"juniper": {"snmp"}},         // no directory at all
		"dmz":   {"juniper": {"snmp"}},         // fine
		"other": {"cisco": {"system", "snmp"}}, // both missing
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range all {
		got = append(got, x.Kind+" "+x.Level.Scope+"/"+x.Vendor+"/"+x.Block)
	}
	want := []string{
		"missing gone/juniper/snmp",
		"unlisted lab/juniper/system",
		"missing other/cisco/system",
		"missing other/cisco/snmp",
	}
	if !slices.Equal(got, want) {
		t.Errorf("VerifyScopes:\n got %q\nwant %q", got, want)
	}
	// Nothing in the manifest: every file is unlisted.
	all, _ = s.VerifyScopes(nil)
	if len(all) != 3 {
		t.Errorf("an empty manifest: %+v", all)
	}
	for _, x := range all {
		if strings.Contains(x.Text, "community") {
			t.Errorf("a finding names a community: %q", x.Text)
		}
	}
}

// A scope called 'devices' is an ordinary scope: the device level's directory
// is '_devices', which no scope name can be, and the two never meet.
func TestScopeNamedDevicesIsLegalBesideTheDeviceLevel(t *testing.T) {
	s := newStore(t)
	sc := ScopeLevel("devices")
	if err := s.Write(sc, "juniper", "snmp", []byte("# scope\n")); err != nil {
		t.Fatal(err)
	}
	dev := DeviceLevel("devices")
	if err := s.Write(dev, "juniper", "snmp", []byte("# device\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Read(sc, "juniper", "snmp"); string(got) != "# scope\n" {
		t.Errorf("scope devices: %q", got)
	}
	if got, _ := s.Read(dev, "juniper", "snmp"); string(got) != "# device\n" {
		t.Errorf("device devices: %q", got)
	}
	if got, _ := s.Scopes(); !slices.Equal(got, []string{"devices"}) {
		t.Errorf("Scopes = %q", got)
	}
	if got, _ := s.Devices(); !slices.Equal(got, []string{"devices"}) {
		t.Errorf("Devices = %q", got)
	}
	if err := s.RenameScope("devices", "edge"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Read(dev, "juniper", "snmp"); string(got) != "# device\n" {
		t.Errorf("a scope rename touched the device: %q", got)
	}
	if err := s.RemoveScope("edge"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Read(dev, "juniper", "snmp"); string(got) != "# device\n" {
		t.Errorf("a scope removal touched the device: %q", got)
	}
}

func TestRenameRemoveAndCheckNoDevice(t *testing.T) {
	s := newStore(t)
	a, b := DeviceLevel("JSW1.lab.example.net"), DeviceLevel("jsw2.lab.example.net")
	for _, l := range []Level{a, b} {
		if err := s.Write(l, "juniper", "snmp", []byte("# "+l.Device+"\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Write(a, "cisco", "system", []byte("# cisco\n")); err != nil {
		t.Fatal(err)
	}
	if !s.HasDevice("jsw1.LAB.example.net") || s.HasDevice("jsw9.lab.example.net") || s.HasDevice("../x") {
		t.Error("HasDevice")
	}
	if err := s.CheckNoDevice("jsw9.lab.example.net"); err != nil {
		t.Errorf("a free name: %v", err)
	}
	if err := s.CheckNoDevice("jsw1.lab.example.net"); err == nil || !strings.Contains(err.Error(), "already on disk") {
		t.Errorf("a taken name: %v", err)
	}
	// Onto a leftover: refused, nothing touched.
	if err := s.RenameDevice("jsw1.lab.example.net", "JSW2.lab.example.net"); err == nil || !strings.Contains(err.Error(), "already on disk") {
		t.Errorf("rename onto a leftover: %v", err)
	}
	if got, _ := s.Read(b, "juniper", "snmp"); string(got) != "# jsw2.lab.example.net\n" {
		t.Errorf("the leftover was overwritten: %q", got)
	}
	// A change of spelling keeps the directory.
	if err := s.RenameDevice("jsw1.lab.example.net", "JSW1.LAB.example.net"); err != nil {
		t.Errorf("spelling only: %v", err)
	}
	// A device with no blocks, and an invalid name.
	if err := s.RenameDevice("jsw9.lab.example.net", "jsw8.lab.example.net"); err != nil {
		t.Errorf("no directory: %v", err)
	}
	if err := s.RenameDevice("jsw1.lab.example.net", "a/b"); err == nil {
		t.Error("an invalid new name was accepted")
	}
	if err := s.RenameDevice("jsw1.lab.example.net", "jsw3.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if s.HasDevice("jsw1.lab.example.net") {
		t.Error("the old directory is left")
	}
	for _, c := range []struct{ vendor, block, want string }{{"juniper", "snmp", "# JSW1.lab.example.net\n"}, {"cisco", "system", "# cisco\n"}} {
		if got, err := s.Read(DeviceLevel("jsw3.lab.example.net"), c.vendor, c.block); err != nil || string(got) != c.want {
			t.Errorf("%s/%s after the rename: %q %v", c.vendor, c.block, got, err)
		}
	}
	if m := mode(t, filepath.Join(s.Dir, "_devices", "jsw3.lab.example.net", "cisco")); m != 0o700 {
		t.Errorf("a moved directory is %v", m)
	}
	// Removal takes the device's files and nothing of the others, and the
	// device level's directory goes with the last device.
	if err := s.RemoveDevice("JSW3.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveDevice("jsw3.lab.example.net"); err != nil {
		t.Errorf("second RemoveDevice: %v", err)
	}
	if got, _ := s.Devices(); !slices.Equal(got, []string{"jsw2.lab.example.net"}) {
		t.Errorf("Devices = %q", got)
	}
	if err := s.RemoveDevice("jsw2.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.Dir); err == nil {
		t.Errorf("the empty store directory is left: %s", s.Dir)
	}
	if err := s.RemoveDevice("../x"); err == nil {
		t.Error("RemoveDevice accepted a path")
	}
}

func TestVerifyDevices(t *testing.T) {
	s := newStore(t)
	files := map[string][]string{ // device -> vendor/block
		"jsw1.lab.example.net": {"juniper/snmp", "juniper/system"},
		"jsw2.lab.example.net": {"juniper/snmp", "cisco/snmp"}, // cisco is not its vendor
		"gone.lab.example.net": {"juniper/snmp"},               // not in the registry
		"ios1.lab.example.net": {"cisco/system"},
	}
	for d, fs := range files {
		for _, f := range fs {
			v, b, _ := strings.Cut(f, "/")
			if err := s.Write(DeviceLevel(d), v, b, []byte("# x\n")); err != nil {
				t.Fatal(err)
			}
		}
	}
	reg := map[string]string{"jsw1.lab.example.net": "juniper", "jsw2.lab.example.net": "juniper", "ios1.lab.example.net": "cisco", "jsw3.lab.example.net": "juniper", "wti1.lab.example.net": "wti"}
	vendorOf := func(d string) (string, bool) { v, ok := reg[d]; return v, ok }

	f, err := s.VerifyDevices(Manifest{
		"jsw1.lab.example.net": {"juniper": {"snmp"}},         // system is unlisted
		"jsw2.lab.example.net": {"juniper": {"snmp"}},         // fine; its cisco directory is an orphan vendor
		"ios1.lab.example.net": {"cisco": {"system"}},         // fine
		"jsw3.lab.example.net": {"juniper": {"snmp", "snmp"}}, // no file: missing, once
		"wti1.lab.example.net": {"juniper": {"snmp"}},         // not a block vendor of a wti device
		"Gone.lab.example.net": {"juniper": {"snmp"}},         // upper case key, unregistered
	}, vendorOf)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range f {
		got = append(got, x.Kind+" "+x.Level.Device+"/"+x.Vendor+"/"+x.Block)
		if !x.Level.IsDevice() || strings.Contains(x.Text, "community") {
			t.Errorf("finding %+v", x)
		}
	}
	want := []string{
		"orphan-device gone.lab.example.net//",
		"unlisted jsw1.lab.example.net/juniper/system",
		"orphan-vendor jsw2.lab.example.net/cisco/",
		"missing jsw3.lab.example.net/juniper/snmp",
		"orphan-vendor wti1.lab.example.net/juniper/",
	}
	if !slices.Equal(got, want) {
		t.Errorf("VerifyDevices:\n got %q\nwant %q", got, want)
	}
	for _, x := range f {
		if x.Kind == KindMissing && !strings.Contains(x.Text, "blocks_device") {
			t.Errorf("a device finding names the scope key: %q", x.Text)
		}
	}
	// No manifest: only the files speak, and no registry knows nobody.
	f, _ = s.VerifyDevices(nil, nil)
	if len(f) != 4 {
		t.Errorf("an empty manifest and no registry: %+v", f)
	}
	for _, x := range f {
		if x.Kind != KindOrphanDevice {
			t.Errorf("%+v", x)
		}
	}
}

// A device's files are read whole, in the order of the vendors, and written
// under another name (a clone): never into a directory the name has, and a
// write that fails leaves nothing of the copy.
func TestReadAndWriteDevice(t *testing.T) {
	s := newStore(t)
	src := DeviceLevel("jsw1.lab.example.net")
	for _, f := range []File{{"juniper", "snmp", []byte("# j-snmp\n")}, {"juniper", "system", []byte("# j-system\n")}, {"cisco", "system", []byte("# c-system\n")}} {
		if err := s.Write(src, f.Vendor, f.Block, f.Data); err != nil {
			t.Fatal(err)
		}
	}
	files, err := s.ReadDevice("JSW1.lab.example.net")
	if err != nil || len(files) != 3 {
		t.Fatalf("ReadDevice = %v %v", files, err)
	}
	if got := files[0].Vendor + "/" + files[0].Block + "," + files[1].Vendor + "/" + files[1].Block + "," + files[2].Vendor + "/" + files[2].Block; got != "juniper/snmp,juniper/system,cisco/system" {
		t.Errorf("order: %s", got)
	}
	if none, err := s.ReadDevice("jsw9.lab.example.net"); err != nil || len(none) != 0 {
		t.Errorf("a device with no blocks: %v %v", none, err)
	}
	if err := s.WriteDevice("jsw2.lab.example.net", files); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		got, err := s.Read(DeviceLevel("jsw2.lab.example.net"), f.Vendor, f.Block)
		if err != nil || string(got) != string(f.Data) {
			t.Errorf("%s/%s: %q %v", f.Vendor, f.Block, got, err)
		}
	}
	if m := mode(t, filepath.Join(s.Dir, "_devices", "jsw2.lab.example.net", "cisco")); m != 0o700 {
		t.Errorf("a written directory is %v", m)
	}
	// The source is untouched, and a name that has blocks is never merged into.
	if !s.HasDevice("jsw1.lab.example.net") {
		t.Error("the source is gone")
	}
	if err := s.WriteDevice("jsw2.lab.example.net", files); err == nil || !strings.Contains(err.Error(), "already on disk") {
		t.Errorf("a second write: %v", err)
	}
	// An invalid name writes nothing; no files is nothing to do.
	if err := s.WriteDevice("a/b", files); err == nil {
		t.Error("an invalid name was accepted")
	}
	if err := s.WriteDevice("jsw3.lab.example.net", nil); err != nil || s.HasDevice("jsw3.lab.example.net") {
		t.Errorf("no files: %v", err)
	}
	// A file that cannot be written takes the others back.
	bad := append(slices.Clone(files), File{Vendor: "juniper", Block: "Bad Name", Data: []byte("x")})
	if err := s.WriteDevice("jsw4.lab.example.net", bad); err == nil {
		t.Error("an invalid block name was accepted")
	}
	if s.HasDevice("jsw4.lab.example.net") {
		t.Error("a failed copy left files")
	}
}
