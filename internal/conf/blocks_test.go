package conf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// blocks.<scope>.<vendor> is the list of blocks in force: two name parts, a
// vendor the store accepts, a non-empty list of known block names.
func TestBlocksKeysInTheSchema(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, path := range []string{"blocks.lab.juniper", "blocks.lab.cisco", "blocks.my-scope_2.juniper"} {
		r, ok := s.RuleFor(path)
		if !ok || r.Type != TypeBlockList {
			t.Errorf("%s: %+v %v", path, r, ok)
		}
	}
	for _, path := range []string{"blocks", "blocks.", "blocks.lab", "blocks..juniper", "blocks.lab.juniper.snmp", "blocks.a.b.c.d"} {
		if r, ok := s.RuleFor(path); ok {
			t.Errorf("%s has a rule: %+v", path, r)
		}
	}
	if BlocksPath("lab", "juniper") != "blocks.lab.juniper" {
		t.Error("BlocksPath")
	}
}

func TestBlocksValidation(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, c := range []struct {
		path   string
		value  any
		isList bool
		want   string // a fragment of the reason; "" is accepted
	}{
		{"blocks.lab.juniper", []any{"snmp"}, true, ""},
		{"blocks.lab.juniper", []any{"snmp", "system"}, true, ""},
		{"blocks.lab.cisco", []any{"system"}, true, ""},
		{"blocks.lab.juniper", []any{}, true, "non-empty list of block names"},
		{"blocks.lab.juniper", []any{"snmp", "snmp"}, true, "element 1: 'snmp' is listed twice"},
		{"blocks.lab.juniper", []any{"ntp"}, true, "element 0: 'ntp' is not a block (one of: snmp, system)"},
		{"blocks.lab.juniper", []any{"../snmp"}, true, "is not a block"},
		{"blocks.lab.juniper", []any{7}, true, "element 0: must be a string"},
		{"blocks.lab.juniper", "snmp", false, "requires list input"},
		{"blocks.lab.wti", []any{"snmp"}, true, "must be one of the vendors juniper, cisco"},
		{"blocks.lab.Juniper", []any{"snmp"}, true, "must be one of the vendors"},
		{"blocks.devices.juniper", []any{"snmp"}, true, ""},
		{"blocks._devices.juniper", []any{"snmp"}, true, "Invalid scope name"},
		{"blocks.1lab.juniper", []any{"snmp"}, true, "Invalid scope name"},
	} {
		msg := s.Validate(c.path, c.value, c.isList)
		switch {
		case c.want == "" && msg != "":
			t.Errorf("%s %v: refused: %s", c.path, c.value, msg)
		case c.want != "" && !strings.Contains(msg, c.want):
			t.Errorf("%s %v: %q, want %q", c.path, c.value, msg, c.want)
		}
	}
}

// The manifest is written and read as a list, and 'config validate' (the
// file's check) reports a hand edit.
func TestBlocksManifestRoundTripAndFileCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	c := Load(path, DefaultBackends)
	if err := c.SetList(BlocksPath("lab", "juniper"), []string{"snmp", "system"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetList(BlocksPath("lab", "wti"), []string{"snmp"}); err == nil {
		t.Error("a vendor of no block was accepted")
	}
	text, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(text), "blocks:\n  lab:\n    juniper:\n    - snmp\n    - system\n") {
		t.Errorf("file:\n%s", text)
	}
	if got := c.GetList(BlocksPath("lab", "juniper")); !reflect.DeepEqual(got, []string{"snmp", "system"}) {
		t.Errorf("GetList = %q", got)
	}
	if got := c.GetKeys("blocks"); !reflect.DeepEqual(got, []string{"lab"}) {
		t.Errorf("GetKeys = %q", got)
	}
	s := NewSchema(DefaultBackends)
	if lines := s.ValidateFile(path); len(lines) != 0 {
		t.Errorf("a clean file: %q", lines)
	}
	bad := string(text) + "  dmz:\n    juniper:\n    - frobnicate\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	lines := s.ValidateFile(path)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "blocks.dmz.juniper: element 0: 'frobnicate' is not a block") {
		t.Errorf("hand edit: %q", lines)
	}
	if err := c.Unset(BlocksPath("lab", "juniper")); err != nil {
		t.Fatal(err)
	}
}

// A 0.2.6 binary does not know the family: a rollback removes it.
func TestBlocksFamilyIsAdded027(t *testing.T) {
	for _, k := range []string{"blocks.lab.juniper", "blocks.lab.cisco", "blocks"} {
		if !Added027Key(k) {
			t.Errorf("%s is not a 0.2.7 key", k)
		}
		if Added025Key(k) || Added024Key(k) || Added023Key(k) {
			t.Errorf("%s is in an older table", k)
		}
	}
	if Added027Key("breakglass_scope.lab.users") || Added027Key("blocksx.lab") {
		t.Error("another family is 0.2.7's")
	}
	if !Unknown023("blocks.lab.juniper") || !Unknown022("blocks.lab.juniper") {
		t.Error("an older release knows the manifest")
	}
}

func TestRollbackKeysHoldTheManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	text := "bcrypt:\n  cost: 11\nblocks:\n  lab:\n    juniper:\n    - snmp\n"
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	keys := c.RollbackKeys023()
	if !reflect.DeepEqual(keys, []string{"blocks.lab.juniper"}) {
		t.Fatalf("keys %q", keys)
	}
	if err := c.UnsetMany(keys); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !strings.HasSuffix(string(got), "bcrypt:\n  cost: 11\n") || strings.Contains(string(got), "blocks") {
		t.Errorf("after:\n%s", got)
	}
}

// blocks_device.<device>.<vendor> is the device-level list: the device's
// lower case name with every '.' as '~' is the one segment.
func TestBlocksDeviceKeysInTheSchema(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, path := range []string{"blocks_device.jsw1~lab~example~net.juniper", "blocks_device.sw-1.cisco", "blocks_device.a_b.juniper"} {
		r, ok := s.RuleFor(path)
		if !ok || r.Type != TypeBlockList {
			t.Errorf("%s: %+v %v", path, r, ok)
		}
	}
	for _, path := range []string{"blocks_device", "blocks_device.", "blocks_device.jsw1", "blocks_device..juniper", "blocks_device.jsw1.lab.juniper", "blocks_device.jsw1.juniper.snmp"} {
		if r, ok := s.RuleFor(path); ok {
			t.Errorf("%s has a rule: %+v", path, r)
		}
	}
	if got := BlocksDevicePath("JSW1.Lab.Example.NET", "juniper"); got != "blocks_device.jsw1~lab~example~net.juniper" {
		t.Errorf("BlocksDevicePath = %q", got)
	}
	if BlocksDeviceKey("jsw1") != "jsw1" || HoldDevice(BlocksDeviceKey("A.b")) != "a.b" {
		t.Error("BlocksDeviceKey")
	}
}

func TestBlocksDeviceValidation(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, c := range []struct {
		path   string
		value  any
		isList bool
		want   string // a fragment of the reason; "" is accepted
	}{
		{"blocks_device.jsw1~lab~example~net.juniper", []any{"snmp"}, true, ""},
		{"blocks_device.jsw1~lab~example~net.juniper", []any{"snmp", "system"}, true, ""},
		{"blocks_device.ios1.cisco", []any{"system"}, true, ""},
		{"blocks_device.jsw1.juniper", []any{}, true, "non-empty list of block names"},
		{"blocks_device.jsw1.juniper", []any{"snmp", "snmp"}, true, "element 1: 'snmp' is listed twice"},
		{"blocks_device.jsw1.juniper", []any{"ntp"}, true, "element 0: 'ntp' is not a block (one of: snmp, system)"},
		{"blocks_device.jsw1.juniper", "snmp", false, "requires list input"},
		{"blocks_device.jsw1.wti", []any{"snmp"}, true, "must be one of the vendors juniper, cisco (blocks_device.<device>.<vendor>)"},
		{"blocks_device.JSW1.juniper", []any{"snmp"}, true, "must be lower case (jsw1)"},
		{"blocks_device.jsw1~Lab.juniper", []any{"snmp"}, true, "must be lower case (jsw1~lab)"},
		{"blocks_device.jsw1~~lab.juniper", []any{"snmp"}, true, "Invalid device name"},
		{"blocks_device.~jsw1.juniper", []any{"snmp"}, true, "Invalid device name"},
		{"blocks_device.jsw1~.juniper", []any{"snmp"}, true, "Invalid device name"},
	} {
		msg := s.Validate(c.path, c.value, c.isList)
		switch {
		case c.want == "" && msg != "":
			t.Errorf("%s %v: refused: %s", c.path, c.value, msg)
		case c.want != "" && !strings.Contains(msg, c.want):
			t.Errorf("%s %v: %q, want %q", c.path, c.value, msg, c.want)
		}
	}
}

// The device-level keys are written and read as the scope's are, listed
// by device, moved to a new name and removed in one write each, and a
// hand edit with an upper case name is found by every spelling.
func TestBlocksDeviceManifestRoundTripMoveAndUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	c := Load(path, DefaultBackends)
	if err := c.SetList(BlocksPath("lab", "juniper"), []string{"snmp"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetList(BlocksDevicePath("jsw1.lab.example.net", "juniper"), []string{"snmp", "system"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetList(BlocksDevicePath("jsw1.lab.example.net", "cisco"), []string{"system"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetList(BlocksDevicePath("jsw2.lab.example.net", "juniper"), []string{"snmp"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetList("blocks_device.jsw1.wti", []string{"snmp"}); err == nil {
		t.Error("a vendor of no block was accepted")
	}
	text, _ := os.ReadFile(path)
	want := "blocks:\n  lab:\n    juniper:\n    - snmp\nblocks_device:\n  jsw1~lab~example~net:\n    juniper:\n    - snmp\n    - system\n    cisco:\n    - system\n  jsw2~lab~example~net:\n    juniper:\n    - snmp\n"
	if !strings.HasSuffix(string(text), want) {
		t.Errorf("file:\n%s", text)
	}
	if got := c.GetList(BlocksDevicePath("JSW1.lab.example.net", "juniper")); !reflect.DeepEqual(got, []string{"snmp", "system"}) {
		t.Errorf("GetList = %q", got)
	}
	if got := c.BlockDevices(); !reflect.DeepEqual(got, []string{"jsw1.lab.example.net", "jsw2.lab.example.net"}) {
		t.Errorf("BlockDevices = %q", got)
	}
	if lines := NewSchema(DefaultBackends).ValidateFile(path); len(lines) != 0 {
		t.Errorf("a clean file: %q", lines)
	}

	// Move: one write, the other devices and the scope untouched.
	if err := c.MoveBlockDevice("JSW1.lab.example.net", "jsw9.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if got := c.GetList(BlocksDevicePath("jsw9.lab.example.net", "cisco")); !reflect.DeepEqual(got, []string{"system"}) {
		t.Errorf("after the move: %q", got)
	}
	if got := c.GetList(BlocksDevicePath("jsw1.lab.example.net", "juniper")); got != nil {
		t.Errorf("the old key is left: %q", got)
	}
	if got := c.BlockDevices(); !reflect.DeepEqual(got, []string{"jsw2.lab.example.net", "jsw9.lab.example.net"}) {
		t.Errorf("BlockDevices after the move = %q", got)
	}
	// Onto another device's entries: refused, nothing written.
	before, _ := os.ReadFile(path)
	if err := c.MoveBlockDevice("jsw9.lab.example.net", "JSW2.lab.example.net"); err == nil || !strings.Contains(err.Error(), "already lists") {
		t.Errorf("move onto entries: %v", err)
	}
	// A spelling only, a device with none and an unknown one write nothing.
	for _, pair := range [][2]string{{"jsw9.lab.example.net", "JSW9.lab.example.net"}, {"jsw5.lab.example.net", "jsw6.lab.example.net"}} {
		if err := c.MoveBlockDevice(pair[0], pair[1]); err != nil {
			t.Errorf("%v: %v", pair, err)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("a no-op move wrote the file:\n%s", after)
	}

	// A hand edit with an upper case name is found and removed by any spelling.
	hand := string(before) + "  JSW7~Lab:\n    juniper:\n    - snmp\n"
	if err := os.WriteFile(path, []byte(hand), 0o600); err != nil {
		t.Fatal(err)
	}
	c = Load(path, DefaultBackends)
	if lines := NewSchema(DefaultBackends).ValidateFile(path); len(lines) != 1 || !strings.Contains(lines[0], "must be lower case (jsw7~lab)") {
		t.Errorf("hand edit: %q", lines)
	}
	if err := c.UnsetBlockDevice("jsw7.lab"); err != nil {
		t.Fatal(err)
	}
	if err := c.UnsetBlockDevice("JSW2.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if err := c.UnsetBlockDevice("jsw2.lab.example.net"); err != nil {
		t.Errorf("a second unset: %v", err)
	}
	if err := c.UnsetBlockDevice("jsw9.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "blocks_device") || !strings.Contains(string(got), "blocks:\n  lab:") {
		t.Errorf("after the unsets:\n%s", got)
	}
	if devs := c.BlockDevices(); len(devs) != 0 {
		t.Errorf("BlockDevices = %q", devs)
	}
}

// A 0.2.6 binary does not know the family either: a rollback removes it.
func TestBlocksDeviceFamilyIsAdded027(t *testing.T) {
	for _, k := range []string{"blocks_device.jsw1.juniper", "blocks_device"} {
		if !Added027Key(k) {
			t.Errorf("%s is not a 0.2.7 key", k)
		}
		if !Unknown023(k) || !Unknown022(k) {
			t.Errorf("an older release knows %s", k)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	text := "bcrypt:\n  cost: 11\nblocks_device:\n  jsw1~lab:\n    juniper:\n    - snmp\n"
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	keys := c.RollbackKeys023()
	if !reflect.DeepEqual(keys, []string{"blocks_device.jsw1~lab.juniper"}) {
		t.Fatalf("keys %q", keys)
	}
	if err := c.UnsetMany(keys); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !strings.HasSuffix(string(got), "bcrypt:\n  cost: 11\n") || strings.Contains(string(got), "blocks") {
		t.Errorf("after:\n%s", got)
	}
}
