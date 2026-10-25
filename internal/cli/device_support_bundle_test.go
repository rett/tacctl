package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The values the fake device prints below are invented stand-ins for what a
// real device would print (a name, a user, a serial number, a time zone, an
// address); none of them may reach the bundle.
const (
	bundleVersion = "Hostname: edge-sw-77.corp.example.org\nModel: ex4200-24t\nJunos: 15.1R6-S4.2\nJUNOS Base OS boot [15.1R6-S4.2]\n"
	bundleChassis = "Hardware inventory:\nItem             Version  Part number  Serial number     Description\nChassis                                ZQ7700123456      EX4200-24T\n"
	bundleAuth    = "Current user: 'LAB-RW' login: 'zed' class 'LAB-RW'\nPermissions:\n    configure   -- Can enter configuration mode\n    all-control -- Can modify any configuration\n"
	bundleHistory = "0   2026-10-14 12:12:17 AKDT by zed via cli commit confirmed, rollback in 3mins\n    moved the uplink to 10.77.8.9\n1   2026-10-14 12:09:15 AKDT by root via other\n"
)

func bundleBox(t *testing.T) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.devices([3]string{"lab-edge-77", "192.168.1.20", "juniper"})
	b.answer("show version", bundleVersion)
	b.answer("show chassis hardware", bundleChassis)
	b.answer("show cli authorization", bundleAuth)
	b.answer("show system commit", bundleHistory)
	return b
}

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

func TestSupportBundleJunosIsScrubbedAndTheMapStaysApart(t *testing.T) {
	b := bundleBox(t)
	dir := filepath.Join(t.TempDir(), "bundle")
	out := b.run("device", "support-bundle", "lab-edge-77", "--out", dir)
	if b.sb.code != 0 || !strings.Contains(out, "Wrote ") {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	files := readTree(t, dir)
	if len(files) < 8 || files["README.txt"] == "" {
		t.Fatalf("files %v", files)
	}
	var all strings.Builder
	for n, text := range files {
		if strings.HasSuffix(n, ".map") {
			t.Errorf("the map is in the bundle: %s", n)
		}
		all.WriteString(text)
	}
	for _, real := range []string{"edge-sw-77", "lab-edge-77", "corp.example.org", "ZQ7700123456", "zed", "LAB-RW", "AKDT", "192.168.1.20", "10.77.8.9", "moved the uplink"} {
		if strings.Contains(all.String(), real) {
			t.Errorf("%q reached the bundle", real)
		}
	}
	for _, kept := range []string{"ex4200-24t", "15.1R6-S4.2", "all-control", "rollback in 3mins", "by root via other", "UTC"} {
		if !strings.Contains(all.String(), kept) {
			t.Errorf("%q is gone from the bundle", kept)
		}
	}
	// no configuration command is among the commands run
	if strings.Contains(files["README.txt"], "display set") || strings.Contains(files["README.txt"], "show configuration |  display") {
		t.Errorf("README lists a configuration read:\n%s", files["README.txt"])
	}
	// the map holds the real values, is private and is not inside the bundle
	st, err := os.Stat(dir + ".map")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("map mode %v", st.Mode().Perm())
	}
	m, _ := os.ReadFile(dir + ".map")
	for _, real := range []string{"edge-sw-77", "zed", "192.168.1.20"} {
		if !strings.Contains(string(m), real) {
			t.Errorf("the map lacks %q:\n%s", real, m)
		}
	}
	if al := b.auditLines("device support-bundle"); len(al) != 1 || !strings.Contains(al[0], "result=ok") || strings.Contains(al[0], "edge-sw-77") {
		t.Errorf("audit %q", al)
	}
}

func TestSupportBundleRefusals(t *testing.T) {
	b := bundleBox(t)
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"device", "support-bundle", "lab-edge-77", "--out", dir}, "is not empty"},
		{[]string{"device", "support-bundle", "lab-edge-77", "--vendor", "other"}, "--vendor takes cisco, juniper or wti"},
		{[]string{"device", "support-bundle", "lab-edge-77", "--vendor", "cisco", "--login", "admin"}, "--login is for Junos devices"},
		{[]string{"device", "support-bundle", "nope"}, "not found"},
		{[]string{"device", "support-bundle"}, "Usage: tacctl device support-bundle"},
	} {
		b.run(c.args...)
		if b.sb.code == 0 || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%v: exit %d %q", c.args, b.sb.code, b.sb.stderr())
		}
	}
	if b.pw.asked != 0 {
		t.Error("a password was asked for a refused line")
	}
}
