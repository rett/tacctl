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

// The per-device configuration syntax of D113 (docs/plans/0.2.5-plan.md):
// the optional 'ios_syntax:' key of a device in devices.yaml.

const sampleSyntax = Header + `version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true, ios_syntax: modern, description: DC1 core}
  lab-rtr1: {address: 192.0.2.7, vendor: cisco, ios_syntax: ios12}
  lab-rtr2: {address: 192.0.2.8, vendor: cisco}
`

func TestIOSSyntaxRoundTrip(t *testing.T) {
	f, _ := loadText(t, sampleSyntax)
	want := map[string]string{"core-sw1": SyntaxModern, "lab-rtr1": SyntaxIOS12, "lab-rtr2": ""}
	for name, w := range want {
		if d := f.Find(name); d == nil || d.IOSSyntax != w {
			t.Errorf("%s: %+v, want %q", name, d, w)
		}
	}
	text, err := f.Text()
	if err != nil || string(text) != sampleSyntax {
		t.Fatalf("round trip: %v\n%s", err, text)
	}
}

// A registry that sets nothing of the kind is written as before: the key
// appears only when something is set, and 'auto' in a file is read as the
// absence and not written back.
func TestIOSSyntaxUnsetIsByteIdentical(t *testing.T) {
	f, _ := loadText(t, sample)
	f.Find("core-sw1").IOSSyntax = SyntaxIOS12
	text, _ := f.Text()
	if !strings.Contains(string(text), "legacy_ssh: true, ios_syntax: ios12, description: DC1 core") {
		t.Errorf("set:\n%s", text)
	}
	f.Find("core-sw1").IOSSyntax = ""
	if text, _ = f.Text(); string(text) != sample {
		t.Errorf("cleared is not byte-identical:\n%s", text)
	}
	g, _ := loadText(t, strings.Replace(sample, "vendor: wti}", "vendor: wti, ios_syntax: auto}", 1))
	if d := g.Find("oob-con1"); d.IOSSyntax != "" {
		t.Errorf("auto read as %q", d.IOSSyntax)
	}
	if text, _ = g.Text(); string(text) != sample {
		t.Errorf("auto is written back:\n%s", text)
	}
}

func TestIOSSyntaxRefusals(t *testing.T) {
	for _, tc := range []struct{ val, want string }{
		{`ios15`, "invalid 'ios_syntax'"},
		{`""`, "invalid 'ios_syntax'"},
		{`true`, "invalid 'ios_syntax'"},
		{`12`, "invalid 'ios_syntax'"},
		{`Modern`, "invalid 'ios_syntax'"},
	} {
		text := strings.Replace(sample, "vendor: wti}", "vendor: wti, ios_syntax: "+tc.val+"}", 1)
		p := filepath.Join(t.TempDir(), "devices.yaml")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(strings.Join(msgs(err), " "), tc.want) {
			t.Errorf("ios_syntax %s: %v, want %q", tc.val, err, tc.want)
		}
	}
	if s, err := ValidateIOSSyntax("auto"); err != nil || s != "" {
		t.Errorf("auto: %q %v", s, err)
	}
	if _, err := ValidateIOSSyntax("ios15"); err == nil || !strings.Contains(err.Error(), "auto, ios12, modern") {
		t.Errorf("ios15: %v", err)
	}
}

// The setting is a Cisco setting everywhere a device is read or written: a
// registry file, an import and a save refuse a non-Cisco device that has one
// (only 'device add' and the verb used to), and a merge never carries a
// registered setting onto a device the file made another vendor.
func TestIOSSyntaxIsCiscoOnly(t *testing.T) {
	for _, vendor := range []string{"juniper", "wti", "other"} {
		text := strings.Replace(sample, "vendor: wti}", "vendor: "+vendor+", ios_syntax: ios12}", 1)
		p := filepath.Join(t.TempDir(), "devices.yaml")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(p)
		if err == nil || !strings.Contains(strings.Join(msgs(err), " "), "is a Cisco setting") {
			t.Errorf("load of vendor %s with ios_syntax: %v", vendor, err)
		}
		// The key before the vendor in the map reads the same.
		text = strings.Replace(sample, "vendor: wti}", "ios_syntax: modern, vendor: "+vendor+"}", 1)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(strings.Join(msgs(err), " "), "is a Cisco setting") {
			t.Errorf("load of ios_syntax before vendor %s: %v", vendor, err)
		}
	}
	// An import file with the key on a non-Cisco device is refused whole.
	f, _ := loadText(t, sampleSyntax)
	rows, err := ParseImport([]byte(Header + "version: 1\ndevices:\n  edge-j1: {address: 192.0.2.40, vendor: juniper, ios_syntax: modern}\n"))
	if err == nil {
		_, err = f.Import(rows, false, true, nil)
	}
	if err == nil || !strings.Contains(strings.Join(msgs(err), " "), "is a Cisco setting") {
		t.Errorf("import: %v", err)
	}
	if f.Find("edge-j1") != nil {
		t.Error("the refused import added the device")
	}
	// A save refuses it too.
	d := f.Find("core-sw1")
	d.Vendor = "juniper"
	if _, err := f.Text(); err == nil {
		t.Error("a Juniper device with a syntax was written")
	}
	d.Vendor = "cisco"
	// A file that moves a registered Cisco device to another vendor takes
	// the registered setting away with it.
	rows, err = ParseImport([]byte(Header + "version: 1\ndevices:\n  core-sw1: {address: 10.99.0.1, vendor: juniper}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("core-sw1"); got.Vendor != "juniper" || got.IOSSyntax != "" {
		t.Errorf("the merge kept the syntax of a device that is not Cisco: %+v", got)
	}
	if _, err := f.Text(); err != nil {
		t.Errorf("the merged registry cannot be written: %v", err)
	}
}

// An import of the registry's YAML carries the setting; a CSV row says
// nothing of it, and neither does a YAML file made before the key existed, so
// a merge keeps the registered one (the verb clears it).
func TestIOSSyntaxImportExport(t *testing.T) {
	f, _ := loadText(t, sampleSyntax)
	rows, err := ParseImport([]byte("name,address,vendor\ncore-sw1,10.99.0.1,cisco\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("core-sw1").IOSSyntax; got != SyntaxModern {
		t.Errorf("a CSV merge changed the setting to %q", got)
	}
	rows, err = ParseImport([]byte(sampleSyntax))
	if err != nil {
		t.Fatal(err)
	}
	g, _ := loadText(t, sample)
	if _, err := g.Import(rows, false, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := g.Find("lab-rtr1"); got == nil || got.IOSSyntax != SyntaxIOS12 {
		t.Errorf("YAML import: %+v", got)
	}
	rows, err = ParseImport([]byte(Header + "version: 1\ndevices:\n  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("core-sw1").IOSSyntax; got != SyntaxModern {
		t.Errorf("a YAML file without the key dropped the setting: %q", got)
	}
	// The YAML export is what the import reads; the JSON carries the key
	// only when set.
	text, _ := f.Text()
	if !strings.Contains(string(text), "ios_syntax: modern") {
		t.Errorf("export:\n%s", text)
	}
	devs := []Device{*f.Find("core-sw1"), *f.Find("lab-rtr2")}
	j, err := JSON(devs)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(j), `"ios_syntax"`); n != 1 || !strings.Contains(string(j), `"ios_syntax": "modern"`) {
		t.Errorf("JSON:\n%s", j)
	}
	if strings.Contains(string(CSV(devs)), "modern") {
		t.Errorf("the CSV carries the setting:\n%s", CSV(devs))
	}
}

// accepts024 is the device keys of 0.2.4's parseDevice (the 0.2.2 keys, the
// location of 0.2.3 and the snmp map): any other key under a device is
// "device '<name>': unknown key '<key>'.", which is why the rollback removes
// the key.
func accepts024(text []byte) error {
	v, err := pyyaml.LoadBytes(text)
	if err != nil {
		return err
	}
	root, ok := v.(*yamlpy.Map)
	if !ok {
		return nil
	}
	known := []string{"address", "vendor", "hostname", "description", "location", "port", "legacy_ssh", "snmp", "host_keys", "ack"}
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

func TestRollbackIOSSyntax(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.yaml")
	if err := os.WriteFile(p, []byte(sampleSyntax), 0o600); err != nil {
		t.Fatal(err)
	}
	with, _ := os.ReadFile(p)
	if err := accepts024(with); err == nil || !strings.Contains(err.Error(), "unknown key 'ios_syntax'") {
		t.Fatalf("the 0.2.4 parser accepts the key: %v", err)
	}
	if names, err := IOSSyntaxSet(p); err != nil || !reflect.DeepEqual(names, []string{"core-sw1", "lab-rtr1"}) {
		t.Fatalf("IOSSyntaxSet: %q %v", names, err)
	}
	// The snapshot comes first; its failure leaves the registry alone.
	boom := errors.New("snapshot failed")
	if _, err := RollbackIOSSyntax(p, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("before's error: %v", err)
	}
	if now, _ := os.ReadFile(p); string(now) != string(with) {
		t.Fatal("the registry changed although the snapshot failed")
	}
	ran := 0
	cleared, err := RollbackIOSSyntax(p, func() error { ran++; return nil })
	if err != nil || ran != 1 || !reflect.DeepEqual(cleared, []string{"core-sw1", "lab-rtr1"}) {
		t.Fatalf("RollbackIOSSyntax: %q %v (snapshots %d)", cleared, err, ran)
	}
	got, _ := os.ReadFile(p)
	if err := accepts024(got); err != nil {
		t.Errorf("the 0.2.4 parser rejects the converted registry: %v\n%s", err, got)
	}
	// Everything else of the device is kept.
	if !strings.Contains(string(got), "core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true, description: DC1 core}") {
		t.Errorf("converted registry:\n%s", got)
	}
	// Idempotent: nothing to do, nothing written, no snapshot asked for.
	ran = 0
	if cleared, err = RollbackIOSSyntax(p, func() error { ran++; return nil }); err != nil || len(cleared) != 0 || ran != 0 {
		t.Errorf("second run: %q %v (snapshots %d)", cleared, err, ran)
	}
	// A missing registry is not created.
	missing := filepath.Join(dir, "sub", "devices.yaml")
	if cleared, err := RollbackIOSSyntax(missing, nil); err != nil || len(cleared) != 0 {
		t.Errorf("missing: %q %v", cleared, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a missing registry was created: %v", err)
	}
}

// The key before 0.2.18 (D273): a registry that holds config_syntax is read
// as ios_syntax, and its next write stores ios_syntax. A device with both
// keys reads ios_syntax; when the two differ the load says so (Notes).
func TestIOSSyntaxOldKey(t *testing.T) {
	old := strings.ReplaceAll(sampleSyntax, "ios_syntax:", OldSyntaxKey+":")
	f, _ := loadText(t, old)
	if d := f.Find("core-sw1"); d == nil || d.IOSSyntax != SyntaxModern || len(f.Notes) != 0 || f.syntaxKeyed {
		t.Fatalf("old key: %+v %q", d, f.Notes)
	}
	if d := f.Find("lab-rtr1"); d == nil || d.IOSSyntax != SyntaxIOS12 {
		t.Errorf("lab-rtr1: %+v", d)
	}
	text, err := f.Text()
	if err != nil || string(text) != sampleSyntax {
		t.Errorf("rewrite: %v\n%s", err, text)
	}
	// Both keys, the same value: no note.
	both := strings.Replace(sampleSyntax, "ios_syntax: ios12}", "ios_syntax: ios12, "+OldSyntaxKey+": ios12}", 1)
	if f, _ := loadText(t, both); f.Find("lab-rtr1").IOSSyntax != SyntaxIOS12 || len(f.Notes) != 0 {
		t.Errorf("both, same: %q", f.Notes)
	}
	// Both keys, different values, in either order: ios_syntax wins.
	for _, text := range []string{
		strings.Replace(sampleSyntax, "ios_syntax: ios12}", "ios_syntax: ios12, "+OldSyntaxKey+": modern}", 1),
		strings.Replace(sampleSyntax, "ios_syntax: ios12}", OldSyntaxKey+": modern, ios_syntax: ios12}", 1),
	} {
		f, _ := loadText(t, text)
		if f.Find("lab-rtr1").IOSSyntax != SyntaxIOS12 || len(f.Notes) != 1 ||
			f.Notes[0] != "device 'lab-rtr1' has ios_syntax ios12 and config_syntax modern; ios_syntax is used, and the next change of the registry drops config_syntax." {
			t.Errorf("both, different: %q", f.Notes)
		}
		if out, err := f.Text(); err != nil || strings.Contains(string(out), OldSyntaxKey) {
			t.Errorf("rewrite keeps the old key: %v\n%s", err, out)
		}
	}
	// The old key is checked as the new one is.
	for _, bad := range []string{OldSyntaxKey + ": ios15", OldSyntaxKey + ": 3"} {
		if _, err := parse([]byte(strings.Replace(sampleSyntax, "ios_syntax: ios12", bad, 1))); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

// RollbackIOSSyntaxKey writes the setting under config_syntax, under the
// lock, and only when a device holds it under ios_syntax; this release reads
// the result as it was.
func TestRollbackIOSSyntaxKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yaml")
	if err := os.WriteFile(path, []byte(sampleSyntax), 0o600); err != nil {
		t.Fatal(err)
	}
	devs, err := SyntaxKeyed(path)
	if err != nil || len(devs) != 2 {
		t.Fatalf("SyntaxKeyed: %v %v", devs, err)
	}
	ran := 0
	names, err := RollbackIOSSyntaxKey(path, func() error { ran++; return nil })
	if err != nil || !slices.Equal(names, []string{"core-sw1", "lab-rtr1"}) || ran != 1 {
		t.Fatalf("rollback: %q %v ran %d", names, err, ran)
	}
	b, _ := os.ReadFile(path)
	if want := strings.ReplaceAll(sampleSyntax, "ios_syntax:", OldSyntaxKey+":"); string(b) != want {
		t.Errorf("written:\n%s\nwant:\n%s", b, want)
	}
	f, err := Load(path)
	if err != nil || f.Find("core-sw1").IOSSyntax != SyntaxModern || f.Find("lab-rtr1").IOSSyntax != SyntaxIOS12 {
		t.Errorf("reread: %v", err)
	}
	// Again: nothing to write, before does not run.
	if names, err := RollbackIOSSyntaxKey(path, func() error { ran++; return nil }); err != nil || names != nil || ran != 1 {
		t.Errorf("second: %q %v ran %d", names, err, ran)
	}
	missing := filepath.Join(t.TempDir(), "devices.yaml")
	if names, err := RollbackIOSSyntaxKey(missing, nil); err != nil || names != nil {
		t.Errorf("missing: %q %v", names, err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Error("a missing registry was created")
	}
}
