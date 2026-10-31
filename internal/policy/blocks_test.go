package policy

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/conf"
)

// The blocks in force are written in the order of the known blocks, the key
// goes when the last block does, and a hand edit that is not a block is
// skipped by the readers.
func TestBlocksInForce(t *testing.T) {
	c, path := newConf(t, "")
	if got := BlockNames(c, "lab", "juniper"); got != nil {
		t.Fatalf("names of nothing: %q", got)
	}
	if err := SetBlockInForce(c, "lab", "juniper", "system", true); err != nil {
		t.Fatal(err)
	}
	if err := SetBlockInForce(c, "lab", "juniper", "snmp", true); err != nil {
		t.Fatal(err)
	}
	if err := SetBlockInForce(c, "lab", "juniper", "snmp", true); err != nil {
		t.Fatal(err)
	}
	if got := BlockNames(c, "lab", "juniper"); !reflect.DeepEqual(got, []string{"snmp", "system"}) {
		t.Errorf("names = %q (the order of blocks.KnownBlocks)", got)
	}
	if !BlockInForce(c, "lab", "juniper", "snmp") || BlockInForce(c, "lab", "cisco", "snmp") || BlockInForce(c, "dmz", "juniper", "snmp") {
		t.Error("BlockInForce")
	}
	if err := SetBlockInForce(c, "lab", "cisco", "snmp", true); err != nil {
		t.Fatal(err)
	}
	if err := SetBlockInForce(c, "dmz", "juniper", "snmp", true); err != nil {
		t.Fatal(err)
	}
	want := blocks.Manifest{
		"lab": {"juniper": {"snmp", "system"}, "cisco": {"snmp"}},
		"dmz": {"juniper": {"snmp"}},
	}
	if got := BlockManifest(c); !reflect.DeepEqual(got, want) {
		t.Errorf("manifest = %v, want %v", got, want)
	}
	if got := want.Names("lab", "cisco"); !reflect.DeepEqual(got, []string{"snmp"}) {
		t.Errorf("Manifest.Names = %q", got)
	}

	if err := SetBlockInForce(c, "lab", "juniper", "snmp", false); err != nil {
		t.Fatal(err)
	}
	if err := SetBlockInForce(c, "lab", "juniper", "snmp", false); err != nil {
		t.Fatal(err)
	}
	if got := BlockNames(c, "lab", "juniper"); !reflect.DeepEqual(got, []string{"system"}) {
		t.Errorf("after taking one out: %q", got)
	}
	for _, v := range []string{"juniper", "cisco"} {
		for _, b := range blocks.KnownBlocks {
			if err := SetBlockInForce(c, "lab", v, b, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := WriteBlockNames(c, "dmz", "juniper", nil); err != nil {
		t.Fatal(err)
	}
	if text, _ := os.ReadFile(path); strings.Contains(string(text), "blocks") {
		t.Errorf("the keys are left:\n%s", text)
	}
	if len(BlockManifest(c)) != 0 {
		t.Errorf("manifest = %v", BlockManifest(c))
	}
	if err := WriteBlockNames(c, "lab", "wti", []string{"snmp"}); err == nil {
		t.Error("a vendor of no block was written")
	}
	// A hand edit: unknown names and keys are skipped.
	if err := os.WriteFile(path, []byte("blocks:\n  lab:\n    juniper:\n    - snmp\n    - frob\n    - snmp\n    wti:\n    - snmp\n  devices:\n    juniper:\n    - snmp\n  1bad:\n    juniper:\n    - snmp\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c = conf.Load(path, conf.DefaultBackends)
	// A scope called 'devices' is a scope like any other.
	if got := BlockManifest(c); !reflect.DeepEqual(got, blocks.Manifest{"lab": {"juniper": {"snmp"}}, "devices": {"juniper": {"snmp"}}}) {
		t.Errorf("manifest of a hand edit = %v", got)
	}
}

// A device's blocks in force are written in the order of the known blocks
// under the device's lower case name with '.' as '~', and the key goes with
// the last block.
func TestDeviceBlocksInForce(t *testing.T) {
	c, path := newConf(t, "")
	const dev = "jsw1.lab.example.net"
	if got := DeviceBlockNames(c, dev, "juniper"); got != nil {
		t.Fatalf("names of nothing: %q", got)
	}
	for _, b := range []string{"system", "snmp", "snmp"} {
		if err := SetDeviceBlockInForce(c, "JSW1.Lab.Example.NET", "juniper", b, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := DeviceBlockNames(c, dev, "juniper"); !reflect.DeepEqual(got, []string{"snmp", "system"}) {
		t.Errorf("names = %q (the order of blocks.KnownBlocks)", got)
	}
	if text, _ := os.ReadFile(path); !strings.Contains(string(text), "blocks_device:\n  jsw1~lab~example~net:\n    juniper:\n    - snmp\n    - system\n") {
		t.Errorf("file:\n%s", text)
	}
	if !DeviceBlockInForce(c, "JSW1.lab.example.net", "juniper", "snmp") || DeviceBlockInForce(c, dev, "cisco", "snmp") || DeviceBlockInForce(c, "jsw2.lab.example.net", "juniper", "snmp") {
		t.Error("DeviceBlockInForce")
	}
	// The scope's list is another key.
	if BlockInForce(c, "jsw1", "juniper", "snmp") || len(BlockManifest(c)) != 0 {
		t.Error("a device's block is a scope's")
	}
	if err := SetDeviceBlockInForce(c, dev, "cisco", "system", true); err != nil {
		t.Fatal(err)
	}
	if err := SetDeviceBlockInForce(c, "jsw2.lab.example.net", "juniper", "snmp", true); err != nil {
		t.Fatal(err)
	}
	want := blocks.Manifest{
		dev:                    {"juniper": {"snmp", "system"}, "cisco": {"system"}},
		"jsw2.lab.example.net": {"juniper": {"snmp"}},
	}
	if got := DeviceBlockManifest(c); !reflect.DeepEqual(got, want) {
		t.Errorf("manifest = %v, want %v", got, want)
	}

	// A copy gives the other name the same lists and leaves the source's
	// and the others' as they are; a device with none copies nothing.
	if err := CopyDeviceBlocks(c, dev, "jsw5.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if got := DeviceBlockManifest(c); !reflect.DeepEqual(got, blocks.Manifest{
		dev:                    {"juniper": {"snmp", "system"}, "cisco": {"system"}},
		"jsw2.lab.example.net": {"juniper": {"snmp"}},
		"jsw5.lab.example.net": {"juniper": {"snmp", "system"}, "cisco": {"system"}},
	}) {
		t.Errorf("manifest after a copy = %v", got)
	}
	if err := CopyDeviceBlocks(c, "jsw6.lab.example.net", "jsw7.lab.example.net"); err != nil || DeviceBlockInForce(c, "jsw7.lab.example.net", "juniper", "snmp") {
		t.Errorf("a copy of nothing: %v", err)
	}
	if err := ForgetDeviceBlocks(c, "jsw5.lab.example.net"); err != nil {
		t.Fatal(err)
	}

	if err := MoveDeviceBlocks(c, dev, "jsw3.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if got := DeviceBlockNames(c, "jsw3.lab.example.net", "juniper"); !reflect.DeepEqual(got, []string{"snmp", "system"}) {
		t.Errorf("after the move: %q", got)
	}
	if DeviceBlockInForce(c, dev, "juniper", "snmp") {
		t.Error("the old name still has blocks")
	}
	if err := ForgetDeviceBlocks(c, "jsw3.lab.example.net"); err != nil {
		t.Fatal(err)
	}
	if err := SetDeviceBlockInForce(c, "jsw2.lab.example.net", "juniper", "snmp", false); err != nil {
		t.Fatal(err)
	}
	if text, _ := os.ReadFile(path); strings.Contains(string(text), "blocks") {
		t.Errorf("the keys are left:\n%s", text)
	}
	if err := WriteDeviceBlockNames(c, dev, "wti", []string{"snmp"}); err == nil {
		t.Error("a vendor of no block was written")
	}
	if err := WriteDeviceBlockNames(c, "a..b", "juniper", []string{"snmp"}); err == nil {
		t.Error("an invalid device name was written")
	}
	// A hand edit: unknown names, vendors and devices are skipped.
	if err := os.WriteFile(path, []byte("blocks_device:\n  jsw1~lab:\n    juniper:\n    - snmp\n    - frob\n    wti:\n    - snmp\n  bad..name:\n    juniper:\n    - snmp\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c = conf.Load(path, conf.DefaultBackends)
	if got := DeviceBlockManifest(c); !reflect.DeepEqual(got, blocks.Manifest{"jsw1.lab": {"juniper": {"snmp"}}}) {
		t.Errorf("manifest of a hand edit = %v", got)
	}
}
