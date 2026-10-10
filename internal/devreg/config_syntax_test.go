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
// the optional 'config_syntax:' key of a device in devices.yaml.

const sampleSyntax = Header + `version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true, config_syntax: modern, description: DC1 core}
  lab-rtr1: {address: 192.0.2.7, vendor: cisco, config_syntax: ios12}
  lab-rtr2: {address: 192.0.2.8, vendor: cisco}
`

func TestConfigSyntaxRoundTrip(t *testing.T) {
	f, _ := loadText(t, sampleSyntax)
	want := map[string]string{"core-sw1": SyntaxModern, "lab-rtr1": SyntaxIOS12, "lab-rtr2": ""}
	for name, w := range want {
		if d := f.Find(name); d == nil || d.ConfigSyntax != w {
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
func TestConfigSyntaxUnsetIsByteIdentical(t *testing.T) {
	f, _ := loadText(t, sample)
	f.Find("core-sw1").ConfigSyntax = SyntaxIOS12
	text, _ := f.Text()
	if !strings.Contains(string(text), "legacy_ssh: true, config_syntax: ios12, description: DC1 core") {
		t.Errorf("set:\n%s", text)
	}
	f.Find("core-sw1").ConfigSyntax = ""
	if text, _ = f.Text(); string(text) != sample {
		t.Errorf("cleared is not byte-identical:\n%s", text)
	}
	g, _ := loadText(t, strings.Replace(sample, "vendor: wti}", "vendor: wti, config_syntax: auto}", 1))
	if d := g.Find("oob-con1"); d.ConfigSyntax != "" {
		t.Errorf("auto read as %q", d.ConfigSyntax)
	}
	if text, _ = g.Text(); string(text) != sample {
		t.Errorf("auto is written back:\n%s", text)
	}
}

func TestConfigSyntaxRefusals(t *testing.T) {
	for _, tc := range []struct{ val, want string }{
		{`ios15`, "invalid 'config_syntax'"},
		{`""`, "invalid 'config_syntax'"},
		{`true`, "invalid 'config_syntax'"},
		{`12`, "invalid 'config_syntax'"},
		{`Modern`, "invalid 'config_syntax'"},
	} {
		text := strings.Replace(sample, "vendor: wti}", "vendor: wti, config_syntax: "+tc.val+"}", 1)
		p := filepath.Join(t.TempDir(), "devices.yaml")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(strings.Join(msgs(err), " "), tc.want) {
			t.Errorf("config_syntax %s: %v, want %q", tc.val, err, tc.want)
		}
	}
	if s, err := ValidateConfigSyntax("auto"); err != nil || s != "" {
		t.Errorf("auto: %q %v", s, err)
	}
	if _, err := ValidateConfigSyntax("ios15"); err == nil || !strings.Contains(err.Error(), "auto, ios12, modern") {
		t.Errorf("ios15: %v", err)
	}
}

// An import of the registry's YAML carries the setting; a CSV row says
// nothing of it, and neither does a YAML file made before the key existed, so
// a merge keeps the registered one (the verb clears it).
func TestConfigSyntaxImportExport(t *testing.T) {
	f, _ := loadText(t, sampleSyntax)
	rows, err := ParseImport([]byte("name,address,vendor\ncore-sw1,10.99.0.1,cisco\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("core-sw1").ConfigSyntax; got != SyntaxModern {
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
	if got := g.Find("lab-rtr1"); got == nil || got.ConfigSyntax != SyntaxIOS12 {
		t.Errorf("YAML import: %+v", got)
	}
	rows, err = ParseImport([]byte(Header + "version: 1\ndevices:\n  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("core-sw1").ConfigSyntax; got != SyntaxModern {
		t.Errorf("a YAML file without the key dropped the setting: %q", got)
	}
	// The YAML export is what the import reads; the JSON carries the key
	// only when set.
	text, _ := f.Text()
	if !strings.Contains(string(text), "config_syntax: modern") {
		t.Errorf("export:\n%s", text)
	}
	devs := []Device{*f.Find("core-sw1"), *f.Find("lab-rtr2")}
	j, err := JSON(devs)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(j), `"config_syntax"`); n != 1 || !strings.Contains(string(j), `"config_syntax": "modern"`) {
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

func TestRollbackConfigSyntax(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.yaml")
	if err := os.WriteFile(p, []byte(sampleSyntax), 0o600); err != nil {
		t.Fatal(err)
	}
	with, _ := os.ReadFile(p)
	if err := accepts024(with); err == nil || !strings.Contains(err.Error(), "unknown key 'config_syntax'") {
		t.Fatalf("the 0.2.4 parser accepts the key: %v", err)
	}
	if names, err := ConfigSyntaxSet(p); err != nil || !reflect.DeepEqual(names, []string{"core-sw1", "lab-rtr1"}) {
		t.Fatalf("ConfigSyntaxSet: %q %v", names, err)
	}
	// The snapshot comes first; its failure leaves the registry alone.
	boom := errors.New("snapshot failed")
	if _, err := RollbackConfigSyntax(p, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("before's error: %v", err)
	}
	if now, _ := os.ReadFile(p); string(now) != string(with) {
		t.Fatal("the registry changed although the snapshot failed")
	}
	ran := 0
	cleared, err := RollbackConfigSyntax(p, func() error { ran++; return nil })
	if err != nil || ran != 1 || !reflect.DeepEqual(cleared, []string{"core-sw1", "lab-rtr1"}) {
		t.Fatalf("RollbackConfigSyntax: %q %v (snapshots %d)", cleared, err, ran)
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
	if cleared, err = RollbackConfigSyntax(p, func() error { ran++; return nil }); err != nil || len(cleared) != 0 || ran != 0 {
		t.Errorf("second run: %q %v (snapshots %d)", cleared, err, ran)
	}
	// A missing registry is not created.
	missing := filepath.Join(dir, "sub", "devices.yaml")
	if cleared, err := RollbackConfigSyntax(missing, nil); err != nil || len(cleared) != 0 {
		t.Errorf("missing: %q %v", cleared, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a missing registry was created: %v", err)
	}
}
