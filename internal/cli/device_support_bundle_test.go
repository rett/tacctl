package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devssh/fakedev"
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
	dir := b.sb.homePath("support-bundles/bundle")
	out := b.run("device", "support-bundle", "lab-edge-77", "--out", "bundle")
	if b.sb.code != 0 || !strings.Contains(out, "Wrote ") || !strings.Contains(out, " to "+dir+" ") || !strings.Contains(out, "in "+dir+".map ") {
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
	if fst, err := os.Stat(filepath.Dir(dir)); err != nil || fst.Mode().Perm() != 0o700 {
		t.Errorf("the support-bundles folder: %v, %v", fst, err)
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
	folder := b.sb.homePath("support-bundles")
	dir := filepath.Join(folder, "bundle")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// a map file (or a link) already beside the directory is never written over
	if err := os.Symlink("/nonexistent-target", filepath.Join(folder, "taken.map")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"device", "support-bundle", "lab-edge-77", "--out", "bundle"}, "exists"},
		{[]string{"device", "support-bundle", "lab-edge-77", "--vendor", "other"}, "--vendor takes cisco, juniper or wti"},
		{[]string{"device", "support-bundle", "lab-edge-77", "--vendor", "cisco", "--login", "admin"}, "--login is for Junos devices"},
		{[]string{"device", "support-bundle", "lab-edge-77", "--out", "taken"}, "exists"},
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

// --out is a name: a path, a tilde, a variable or a leading dot is refused
// with the rule, before anything is asked or written.
func TestSupportBundleOutIsAName(t *testing.T) {
	b := bundleBox(t)
	for _, name := range []string{"", "~", "~/x", "~alice", "$HOME", "a$b", "x/y", "/abs/x", ".", "..", "../x", ".hidden", "-x", "a b", "a\x00b", "é", strings.Repeat("a", 65)} {
		b.run("device", "support-bundle", "lab-edge-77", "--out", name)
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "is not a bundle name: --out names the bundle, not a path") ||
			!strings.Contains(b.sb.stderr(), "tacctl does not expand ~ or variables") {
			t.Errorf("--out %q: exit %d %q", name, b.sb.code, b.sb.stderr())
		}
	}
	if b.pw.asked != 0 {
		t.Error("a password was asked for a refused name")
	}
	if _, err := os.Lstat(b.sb.homePath("support-bundles")); err == nil {
		t.Error("a refused name made the folder")
	}
	for _, name := range []string{"a", "x.1_2-3", "0", strings.Repeat("a", 64)} {
		b.run("device", "support-bundle", "lab-edge-77", "--out", name)
		if b.sb.code != 0 {
			t.Errorf("--out %q: exit %d %q", name, b.sb.code, b.sb.stderr())
		}
	}
}

// Without --out the name is the device and the UTC time; the bundle is in the
// home's support-bundles folder.
func TestSupportBundleDefaultName(t *testing.T) {
	b := bundleBox(t)
	out := b.run("device", "support-bundle", "lab-edge-77")
	ents, err := os.ReadDir(b.sb.homePath("support-bundles"))
	if err != nil || len(ents) != 2 {
		t.Fatalf("%v %v: %q", ents, err, out)
	}
	for _, e := range ents {
		if !regexp.MustCompile(`^lab-edge-77-\d{8}-\d{6}(\.map)?$`).MatchString(e.Name()) {
			t.Errorf("default name %q", e.Name())
		}
	}
	for in, want := range map[string]string{
		"sw1":                   "sw1-20261012-131100",
		"sw1.example.net":       "sw1.example.net-20261012-131100",
		".odd name/é":           "odd-name---20261012-131100",
		"":                      "device-20261012-131100",
		strings.Repeat("n", 50): strings.Repeat("n", 40) + "-20261012-131100",
	} {
		if got := bundleDefaultName(in, time.Date(2026, 10, 12, 13, 11, 0, 0, time.UTC)); got != want || !bundleNameRE.MatchString(got) {
			t.Errorf("bundleDefaultName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The support-bundles folder may not lead out of the home, and nothing is
// written outside it.
func TestSupportBundleFolderThatLeavesTheHome(t *testing.T) {
	b := bundleBox(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, b.sb.homePath("support-bundles")); err != nil {
		t.Fatal(err)
	}
	b.run("device", "support-bundle", "lab-edge-77", "--out", "bundle")
	if b.sb.code == 0 || !strings.Contains(b.sb.stderr(), "not inside your home") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("written outside the home: %v", ents)
	}
	if b.pw.asked != 0 {
		t.Error("a password was asked for a refused line")
	}
}

// An IOS device that scrolls the echo of the long identity-lines command
// (on lines, as the tail only, or redrawn in place) leaves none of it in the
// file, and the model names and serial numbers of
// the inventory are told apart.
func TestSupportBundleIOSHasNoEchoOfTheCommandAndKeepsModels(t *testing.T) {
	for name, opt := range map[string]fakedev.Option{
		"lines":   fakedev.WithWrappedEcho(72),
		"tail":    fakedev.WithTailEcho(72),
		"redrawn": fakedev.WithRedrawnEcho(72),
	} {
		t.Run(name, func(t *testing.T) { iosEchoBundle(t, opt) })
	}
}

func iosEchoBundle(t *testing.T, opt fakedev.Option) {
	b := newPullBox(t, opt)
	if err := os.WriteFile(filepath.Join(b.dir, "prompt"), []byte("lab-c#"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"})
	b.answer("show version", "Cisco IOS Software, CSR1000V Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.9.4\nProcessor board ID 9999999999\n")
	b.answer("show inventory", "NAME: \"Chassis\", DESCR: \"Cisco CSR1000V Chassis\"\nPID: CSR1000V        , VID: V00  , SN: 9999999999\n")
	identity := "show running-config | include ^(hostname|ip domain|clock timezone|snmp-server location|snmp-server contact)"
	b.answer(identity, "hostname lab-c\nip domain name example.net\n")
	b.run("device", "support-bundle", "lab-c", "--out", "ios")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q", b.sb.code, b.sb.stderr())
	}
	files := readTree(t, b.sb.homePath("support-bundles/ios"))
	if got, want := files["07-identity-lines.txt"], "# "+identity+"\nhostname sw1\nip domain name example.net\n"; got != want {
		t.Errorf("identity lines:\n%q\nwant\n%q", got, want)
	}
	inv := files["02-inventory.txt"]
	if !strings.Contains(inv, "DESCR: \"Cisco CSR1000V Chassis\"") || !strings.Contains(inv, "PID: CSR1000V        , VID: V00  , SN: SN000001\n") || strings.Contains(inv, "9999999999") {
		t.Errorf("inventory:\n%s", inv)
	}
	if v := files["01-version.txt"]; !strings.Contains(v, "CSR1000V Software") || !strings.Contains(v, "Processor board ID SN000001\n") {
		t.Errorf("version:\n%s", v)
	}
}
