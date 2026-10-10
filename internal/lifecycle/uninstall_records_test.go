package lifecycle_test

import (
	"os"
	"path/filepath"
	"testing"
)

// The device records of /var/lib/tacctl (the seen cache, the configuration
// pull records and their sections files, with the lock files) are tacctl's
// and go with it; the directory goes when that leaves it empty, and stays
// with a file that is not tacctl's.
func TestUninstallRemovesTheDeviceRecords(t *testing.T) {
	for _, withOther := range []bool{false, true} {
		o := newOhost(t)
		o.cloned()
		p := o.p
		ours := []string{
			p.SeenCache, filepath.Join(filepath.Dir(p.SeenCache), ".devices-seen.lock"),
			p.ConfigRecords, filepath.Join(filepath.Dir(p.ConfigRecords), ".devices-config.lock"),
			filepath.Join(p.ConfigDir, "core-sw1.yaml"), filepath.Join(p.ConfigDir, "edge-r1.yaml"),
		}
		for _, f := range ours {
			if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		other := filepath.Join(p.VarLib, "someone-elses")
		if withOther {
			if err := os.WriteFile(other, []byte("keep\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if code := uninstall(o, "--yes"); code != 0 {
			t.Fatalf("exit %d %s", code, o.stderr)
		}
		for _, f := range ours {
			if _, err := os.Lstat(f); err == nil {
				t.Errorf("withOther=%v: %s is left", withOther, f)
			}
		}
		if _, err := os.Stat(p.ConfigDir); err == nil {
			t.Errorf("withOther=%v: the sections directory is left", withOther)
		}
		_, err := os.Stat(p.VarLib)
		switch {
		case withOther && err != nil:
			t.Errorf("a file that is not tacctl's was removed with its directory: %v", err)
		case !withOther && err == nil:
			t.Errorf("the directory of an uninstall that left nothing in it is left")
		}
		if withOther {
			if _, err := os.Stat(other); err != nil {
				t.Errorf("the file that is not tacctl's: %v", err)
			}
		}
	}
}
