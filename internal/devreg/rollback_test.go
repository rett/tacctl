package devreg

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// accepts022 is the device keys of parseDevice at the 0.2.2 tag (verified
// with 'git show 0.2.2:internal/devreg/file.go'): any other key under a
// device is "device '<name>': unknown key '<key>'."
func accepts022(text []byte) error {
	v, err := pyyaml.LoadBytes(text)
	if err != nil {
		return err
	}
	root, ok := v.(*yamlpy.Map)
	if !ok {
		return nil
	}
	known := []string{"address", "vendor", "hostname", "description", "port", "legacy_ssh", "host_keys", "ack"}
	devs, ok := root.Get("devices")
	if !ok || devs == nil {
		return nil
	}
	for name, dv := range devs.(*yamlpy.Map).All() {
		for k := range dv.(*yamlpy.Map).All() {
			if !slices.Contains(known, k) {
				return errors.New("device '" + name + "': unknown key '" + k + "'.")
			}
		}
	}
	return nil
}

func TestRollbackLocations(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.yaml")
	if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	// Locations on two of the three devices.
	if _, err := Mutate(p, "", nil, func(f *File) error {
		f.Find("core-sw1").Location = "Rack 4, DC1"
		f.Find("oob-con1").Location = "Room 17"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	with, _ := os.ReadFile(p)
	if err := accepts022(with); err == nil || !strings.Contains(err.Error(), "unknown key 'location'") {
		t.Fatalf("the 0.2.2 parser accepts a location: %v\n%s", err, with)
	}
	if names, err := Located(p); err != nil || !reflect.DeepEqual(names, []string{"core-sw1", "oob-con1"}) {
		t.Fatalf("Located: %q %v", names, err)
	}

	// The snapshot comes first.
	boom := errors.New("snapshot failed")
	if _, err := RollbackLocations(p, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("before's error: %v", err)
	}
	if now, _ := os.ReadFile(p); string(now) != string(with) {
		t.Fatal("the registry changed although the snapshot failed")
	}

	ran := 0
	cleared, err := RollbackLocations(p, func() error { ran++; return nil })
	if err != nil || ran != 1 || !reflect.DeepEqual(cleared, []string{"core-sw1", "oob-con1"}) {
		t.Fatalf("RollbackLocations: %q %v (snapshots %d)", cleared, err, ran)
	}
	got, _ := os.ReadFile(p)
	if err := accepts022(got); err != nil {
		t.Errorf("the 0.2.2 parser rejects the converted registry: %v\n%s", err, got)
	}
	// It is the file that never had a location, byte for byte.
	if string(got) != sample {
		t.Errorf("converted registry:\n%s\nwant:\n%s", got, sample)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v %v", fi, err)
	}

	// Idempotent: nothing to do, nothing written, no snapshot asked for.
	st1, _ := os.Stat(p)
	ran = 0
	cleared, err = RollbackLocations(p, func() error { ran++; return nil })
	if err != nil || len(cleared) != 0 || ran != 0 {
		t.Errorf("second run: %q %v (snapshots %d)", cleared, err, ran)
	}
	if st2, _ := os.Stat(p); !st2.ModTime().Equal(st1.ModTime()) {
		t.Error("the second run rewrote the registry")
	}

	// A missing registry is not created.
	missing := filepath.Join(dir, "sub", "devices.yaml")
	if cleared, err := RollbackLocations(missing, nil); err != nil || len(cleared) != 0 {
		t.Errorf("missing: %q %v", cleared, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a missing registry was created: %v", err)
	}
	// One that cannot be read is an error and is left as it is.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("devices: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RollbackLocations(bad, nil); err == nil {
		t.Error("an unreadable registry was converted")
	}
}
