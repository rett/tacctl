package devreg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sample = Header + `version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true, description: DC1 core}
  lab-rtr2: {address: 192.0.2.7, vendor: juniper, hostname: lab-rtr2.lab.example.net}
  oob-con1: {address: 10.99.0.9, vendor: wti}
`

func TestLoadSampleAndRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "devices.yaml")
	if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Devices) != 3 || f.StaleDays != 30 {
		t.Fatalf("loaded %+v", f)
	}
	d := f.Find("CORE-sw1")
	if d == nil || d.Address != "10.99.0.1" || !d.LegacySSH || d.Description != "DC1 core" || d.Vendor != "cisco" {
		t.Errorf("core-sw1 = %+v", d)
	}
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != sample {
		t.Errorf("round trip changed the file:\n%s", text)
	}
	if _, err := devicesFromText(t, text); err != nil {
		t.Error(err)
	}
}

func devicesFromText(t *testing.T, text []byte) (*File, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "d.yaml")
	if err := os.WriteFile(p, text, 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestAbsentAndEmptyFile(t *testing.T) {
	dir := t.TempDir()
	f, err := Load(filepath.Join(dir, "none.yaml"))
	if err != nil || len(f.Devices) != 0 || f.StaleDays != DefaultStaleDays {
		t.Errorf("absent: %+v, %v", f, err)
	}
	p := filepath.Join(dir, "empty.yaml")
	_ = os.WriteFile(p, nil, 0o600)
	if f, err = Load(p); err != nil || len(f.Devices) != 0 {
		t.Errorf("empty: %+v, %v", f, err)
	}
	text, err := Empty().Text()
	if err != nil || !strings.Contains(string(text), "devices: {}") {
		t.Errorf("empty registry text: %q, %v", text, err)
	}
}

func TestFieldsRoundTrip(t *testing.T) {
	f := Empty()
	f.GenericNames = []string{`lab-\d+`}
	f.StaleDays = 45
	f.Devices = []*Device{
		{Name: "v6-sw", Address: "2001:db8::1", Vendor: "other", Port: 830, Description: "it's \"quoted\": é",
			HostKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA=="}, Ack: []string{"generic-name"}},
		{Name: "yes", Address: "192.0.2.1", Vendor: "wti"},
		{Name: "123", Address: "192.0.2.2", Vendor: "other"},
		{Name: "sw1.site-a.example", Address: "192.0.2.3", Vendor: "juniper"},
		{Name: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".site-a.example", Address: "192.0.2.4", Vendor: "cisco"},
	}
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	g, err := devicesFromText(t, text)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if !reflect.DeepEqual(f, g) {
		t.Errorf("round trip:\nwant %+v\ngot  %+v\n%s", f, g, text)
	}
}

func TestLoadRefusals(t *testing.T) {
	cases := map[string]string{
		"not yaml":            "devices: [",
		"list at the top":     "- a\n",
		"unknown top key":     "version: 1\nextra: 1\n",
		"bad version":         "version: 2\n",
		"unknown device key":  "version: 1\ndevices:\n  a1: {address: 10.0.0.1, color: red}\n",
		"missing address":     "version: 1\ndevices:\n  a1: {vendor: cisco}\n",
		"bad address":         "version: 1\ndevices:\n  a1: {address: 10.0.0.0/24}\n",
		"non canonical addr":  "version: 1\ndevices:\n  a1: {address: 2001:DB8::1}\n",
		"bad vendor":          "version: 1\ndevices:\n  a1: {address: 10.0.0.1, vendor: linux}\n",
		"bad name":            "version: 1\ndevices:\n  -a: {address: 10.0.0.1}\n",
		"reserved name":       "version: 1\ndevices:\n  scope: {address: 10.0.0.1}\n",
		"duplicate names":     "version: 1\ndevices:\n  a1: {address: 10.0.0.1}\n  A1: {address: 10.0.0.2}\n",
		"duplicate addresses": "version: 1\ndevices:\n  a1: {address: 10.0.0.1}\n  a2: {address: 10.0.0.1}\n",
		"port is default":     "version: 1\ndevices:\n  a1: {address: 10.0.0.1, port: 22}\n",
		"port out of range":   "version: 1\ndevices:\n  a1: {address: 10.0.0.1, port: 70000}\n",
		"stale days":          "version: 1\nsettings: {stale_days: 0}\n",
		"unknown setting":     "version: 1\nsettings: {color: 1}\n",
		"bad pattern":         "version: 1\ngeneric_names: ['(']\n",
		"unknown ack":         "version: 1\ndevices:\n  a1: {address: 10.0.0.1, ack: [nonsense]}\n",
		"bad host key":        "version: 1\ndevices:\n  a1: {address: 10.0.0.1, host_keys: ['x y z']}\n",
		"login key":           "version: 1\ndevices:\n  a1: {address: 10.0.0.1, login: admin}\n",
		"devices not a map":   "version: 1\ndevices: [a]\n",
		"empty dotted part":   "version: 1\ndevices:\n  sw1..site-a.example: {address: 10.0.0.1}\n",
		"dotted part over 63": "version: 1\ndevices:\n  sw1." + strings.Repeat("x", 64) + ".example: {address: 10.0.0.1}\n",
		// Host names keep 63 characters (they are scope names too).
		"host name over 63": "version: 1\nhosts:\n  " + strings.Repeat("h", 64) + ": {address: 192.0.2.1}\n",
	}
	for name, text := range cases {
		p := filepath.Join(t.TempDir(), "devices.yaml")
		_ = os.WriteFile(p, []byte(text), 0o600)
		if f, err := Load(p); err == nil {
			t.Errorf("%s: accepted: %+v", name, f)
		} else if !strings.Contains(err.Error(), p) {
			t.Errorf("%s: the message does not name the file: %v", name, err)
		}
	}
}

func TestMutateWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state", "devices.yaml")
	snapshots := 0
	before := func() error { snapshots++; return nil }
	changed, err := Mutate(p, "", before, func(f *File) error {
		f.Devices = append(f.Devices, &Device{Name: "a1", Address: "10.0.0.1", Vendor: "other"})
		return nil
	})
	if err != nil || !changed || snapshots != 1 {
		t.Fatalf("changed %v, err %v, snapshots %d", changed, err, snapshots)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("devices.yaml: %v, %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", LockName)); err != nil {
		t.Error("no lock file: ", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "state", ".devices.*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	// No change: the file keeps its inode.
	before1, _ := os.Stat(p)
	changed, err = Mutate(p, "", nil, func(*File) error { return nil })
	after1, _ := os.Stat(p)
	if err != nil || changed || !os.SameFile(before1, after1) {
		t.Errorf("a no-op write replaced the file (changed %v, %v)", changed, err)
	}
	// An error from fn, or an invalid result, writes nothing.
	want, _ := os.ReadFile(p)
	for name, fn := range map[string]func(*File) error{
		"fn error": func(*File) error { return os.ErrInvalid },
		"duplicate address": func(f *File) error {
			f.Devices = append(f.Devices, &Device{Name: "a2", Address: "10.0.0.1", Vendor: "other"})
			return nil
		},
	} {
		if _, err := Mutate(p, "", nil, fn); err == nil {
			t.Errorf("%s: no error", name)
		}
		if got, _ := os.ReadFile(p); string(got) != string(want) {
			t.Errorf("%s: the file changed", name)
		}
	}
	// A failing snapshot blocks the write.
	if _, err := Mutate(p, "", func() error { return os.ErrPermission }, func(f *File) error { f.StaleDays = 5; return nil }); err == nil {
		t.Error("a failed snapshot did not stop the write")
	}
	if got, _ := os.ReadFile(p); string(got) != string(want) {
		t.Error("the file changed after a failed snapshot")
	}
}

func TestFindAndRemove(t *testing.T) {
	f := Empty()
	f.Devices = []*Device{{Name: "Core-SW1", Address: "10.0.0.1", Vendor: "other"}, {Name: "b", Address: "2001:db8::1", Vendor: "other"}}
	if f.Find("core-sw1") == nil || f.Find("nope") != nil {
		t.Error("Find is case-insensitive")
	}
	if f.FindAddress("2001:DB8:0::1") == nil || f.FindAddress("10.0.0.2") != nil || f.FindAddress("junk") != nil {
		t.Error("FindAddress compares canonical forms")
	}
	if !f.Remove("CORE-sw1") || f.Remove("core-sw1") || len(f.Devices) != 1 {
		t.Error("Remove")
	}
}
