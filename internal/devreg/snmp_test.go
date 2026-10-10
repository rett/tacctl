package devreg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The per-device SNMP settings of D72 (docs/plans/0.2.4-plan.md): the
// optional 'snmp:' map of a device in devices.yaml.

const sampleSNMP = Header + `version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true, description: DC1 core}
  lab-rtr2:
    address: 192.0.2.7
    vendor: juniper
    location: Rack 4
    snmp:
      version: v3
      port: 1161
      timeout: 4
      clients: [192.0.2.0/24, 198.51.100.7/32]
  oob-con1:
    address: 10.99.0.9
    vendor: wti
    snmp: {version: v2c}
`

func loadText(t *testing.T, text string) (*File, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "devices.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v\n%s", err, text)
	}
	return f, p
}

func TestSNMPMapRoundTrip(t *testing.T) {
	f, _ := loadText(t, sampleSNMP)
	want := map[string]SNMP{
		"core-sw1": {},
		"lab-rtr2": {Version: "v3", Port: 1161, Timeout: 4, Clients: []string{"192.0.2.0/24", "198.51.100.7/32"}},
		"oob-con1": {Version: "v2c"},
	}
	for name, w := range want {
		if d := f.Find(name); d == nil || !reflect.DeepEqual(d.SNMP, w) {
			t.Errorf("%s: %+v, want %+v", name, d, w)
		}
	}
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != sampleSNMP {
		t.Errorf("round trip changed the file:\n%s", text)
	}
}

// A registry that sets nothing of the kind is written exactly as 0.2.3
// wrote it: the map appears only when something is set, and a map left
// empty is not written.
func TestSNMPMapUnsetIsByteIdentical(t *testing.T) {
	f, _ := loadText(t, sample)
	text, err := f.Text()
	if err != nil || string(text) != sample {
		t.Fatalf("round trip: %v\n%s", err, text)
	}
	f.Find("core-sw1").SNMP = SNMP{Version: "v2c"}
	if text, _ = f.Text(); !strings.Contains(string(text), "snmp: {version: v2c}") {
		t.Errorf("set:\n%s", text)
	}
	f.Find("core-sw1").SNMP = SNMP{}
	if text, _ = f.Text(); string(text) != sample {
		t.Errorf("cleared is not byte-identical:\n%s", text)
	}
	// An empty map in a file is read as nothing and not written back.
	g, _ := loadText(t, strings.Replace(sample, "vendor: wti}", "vendor: wti, snmp: {}}", 1))
	if text, _ = g.Text(); string(text) != sample {
		t.Errorf("empty map:\n%s", text)
	}
}

func TestSNMPMapRefusals(t *testing.T) {
	for _, tc := range []struct{ snmp, want string }{
		{`{version: v1}`, "Invalid snmp version 'v1'"},
		{`{version: ""}`, "snmp: invalid 'version'"},
		{`{version: 2}`, "snmp: invalid 'version'"},
		{`{port: 0}`, "snmp: invalid 'port'"},
		{`{port: 70000}`, "Invalid snmp port 70000"},
		{`{port: "161"}`, "snmp: invalid 'port'"},
		{`{timeout: 0}`, "snmp: invalid 'timeout'"},
		{`{timeout: 11}`, "Invalid snmp timeout 11"},
		{`{clients: [0.0.0.0/0]}`, "would allow every address"},
		{`{clients: [10.0.0.1/8]}`, "canonical form"},
		{`{clients: ["2001:db8::/32"]}`, "IPv6"},
		{`{clients: [10.0.0.0/8, 10.0.0.0/8]}`, "listed twice"},
		{`{clients: [x]}`, "not a valid CIDR"},
		{`{clients: 10.0.0.0/8}`, "snmp: invalid 'clients'"},
		{`{community: secret}`, "snmp: unknown key 'community'"},
		{`{v3: {user: x}}`, "snmp: unknown key 'v3'"},
		{`[v2c]`, "snmp must be a mapping"},
		{`v2c`, "snmp must be a mapping"},
	} {
		p := filepath.Join(t.TempDir(), "devices.yaml")
		text := Header + "version: 1\nsettings: {stale_days: 30}\ndevices:\n  sw1: {address: 10.99.0.1, vendor: cisco, snmp: " + tc.snmp + "}\n"
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("snmp: %s: %v, want %q", tc.snmp, err, tc.want)
		}
	}
	// Too many ranges.
	d := Device{Name: "sw1", Address: "10.99.0.1", Vendor: "cisco"}
	for i := 0; i <= cidr.MaxSNMPClients; i++ {
		d.SNMP.Clients = append(d.SNMP.Clients, "10.0."+itoa(i)+".0/24")
	}
	if err := d.validate(); err == nil || !strings.Contains(err.Error(), "At most 32 snmp client ranges") {
		t.Errorf("33 ranges: %v", err)
	}
	d.SNMP.Clients = d.SNMP.Clients[:cidr.MaxSNMPClients]
	if err := d.validate(); err != nil {
		t.Errorf("32 ranges: %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// The bounds are the scope's (internal/snmp's, cidr's).
func TestSNMPBoundsMatchTheScopes(t *testing.T) {
	if SNMPMinTimeout != snmp.MinTimeout || SNMPMaxTimeout != snmp.MaxTimeout {
		t.Errorf("timeout %d-%d, snmp package %d-%d", SNMPMinTimeout, SNMPMaxTimeout, snmp.MinTimeout, snmp.MaxTimeout)
	}
	if SNMPVersionV2c != snmp.V2c || SNMPVersionV3 != snmp.V3 {
		t.Errorf("versions %q %q", SNMPVersionV2c, SNMPVersionV3)
	}
}

func TestSNMPCloneIsDeep(t *testing.T) {
	d := Device{Name: "sw1", Address: "10.99.0.1", Vendor: "cisco", SNMP: SNMP{Version: "v2c", Clients: []string{"10.0.0.0/8"}}}
	c := d.Clone()
	c.SNMP.Clients[0] = "192.0.2.0/24"
	c.SNMP.Version = "v3"
	if d.SNMP.Clients[0] != "10.0.0.0/8" || d.SNMP.Version != "v2c" {
		t.Errorf("clone shares: %+v", d.SNMP)
	}
	f := &File{StaleDays: 30, Devices: []*Device{&d}}
	fc := f.Clone()
	fc.Devices[0].SNMP.Clients[0] = "x"
	if d.SNMP.Clients[0] != "10.0.0.0/8" {
		t.Error("File.Clone shares the clients")
	}
}

// An import never drops a device's own settings (a CSV row has no place for
// them, a YAML file without the map is not a request to clear them); a
// file's map replaces them.
func TestImportKeepsSNMP(t *testing.T) {
	f, _ := loadText(t, sampleSNMP)
	rows, err := ParseImport([]byte("name,address,vendor\nlab-rtr2,192.0.2.7,juniper\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("lab-rtr2").SNMP; got.Version != "v3" || len(got.Clients) != 2 {
		t.Errorf("CSV import: %+v", got)
	}
	rows, err = ParseImport([]byte(Header + "version: 1\ndevices:\n  lab-rtr2: {address: 192.0.2.7, vendor: juniper, description: new}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("lab-rtr2"); got.Description != "new" || got.SNMP.Version != "v3" {
		t.Errorf("YAML without a map: %+v", got)
	}
	rows, err = ParseImport([]byte(Header + "version: 1\ndevices:\n  lab-rtr2: {address: 192.0.2.7, vendor: juniper, snmp: {version: v2c}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Find("lab-rtr2").SNMP; !reflect.DeepEqual(got, SNMP{Version: "v2c"}) {
		t.Errorf("YAML with a map: %+v", got)
	}
}

func TestJSONDeviceSNMP(t *testing.T) {
	f, _ := loadText(t, sampleSNMP)
	var devs []Device
	for _, d := range f.Devices {
		devs = append(devs, *d)
	}
	b, err := JSON(devs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Count(s, `"snmp"`) != 2 || !strings.Contains(s, `"clients": [`) || strings.Contains(s, "community") {
		t.Errorf("json:\n%s", s)
	}
}

// known023Keys are the device keys parseDevice of the 0.2.3 tag accepts
// (anything else is "device 'x': unknown key 'k'."). Where the tag is in the
// repository they are read from its source (the cases of the switch of
// parseDevice up to its default branch) and held to the fixed list; without
// the tag the fixed list is used.
func known023Keys(t *testing.T) []string {
	t.Helper()
	fixed := []string{"address", "vendor", "hostname", "description", "location", "port", "legacy_ssh", "host_keys", "ack"}
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"-C", "../..", "show", "0.2.3:internal/devreg/file.go"}})
	if err != nil || res.Code != 0 {
		t.Log("the 0.2.3 tag is not in this repository: the fixed list of keys stands")
		return fixed
	}
	src := string(res.Stdout)
	i := strings.Index(src, "func parseDevice(")
	if i < 0 {
		t.Fatal("parseDevice is not in the 0.2.3 source")
	}
	body := src[i:]
	end := strings.Index(body, "default:")
	if end < 0 || !strings.Contains(body[end:], "unknown key") {
		t.Fatal("the 0.2.3 parseDevice has no 'unknown key' default branch")
	}
	var keys []string
	for _, line := range strings.Split(body[:end], "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "case ")
		if !ok {
			continue
		}
		for _, w := range strings.Split(strings.TrimSuffix(rest, ":"), ",") {
			if k, err := strconv.Unquote(strings.TrimSpace(w)); err == nil {
				keys = append(keys, k)
			}
		}
	}
	slices.Sort(keys)
	want := slices.Clone(fixed)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("the 0.2.3 tag accepts the device keys %v, the test's list is %v", keys, want)
	}
	return keys
}

// A registry with the map is refused by 0.2.3's parser, and one without it
// is read: the reason a rollback to 0.2.3 has to remove the map.
func TestTheOldParserRefusesTheSNMPMap(t *testing.T) {
	known := known023Keys(t)
	if slices.Contains(known, "snmp") {
		t.Fatal("0.2.3 knows the key 'snmp'")
	}
	if err := accepts023(known, []byte(sampleSNMP)); err == nil || !strings.Contains(err.Error(), "unknown key 'snmp'") {
		t.Errorf("a registry with the map: %v", err)
	}
	if err := accepts023(known, []byte(sample)); err != nil {
		t.Errorf("a registry without it: %v", err)
	}
	// What 0.2.4 writes with no map set is what 0.2.3 reads.
	f, _ := loadText(t, sampleSNMP)
	for _, d := range f.Devices {
		d.SNMP = SNMP{}
	}
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	if err := accepts023(known, text); err != nil {
		t.Errorf("a registry with the maps cleared: %v\n%s", err, text)
	}
}

// accepts023 is parseDevice of the 0.2.3 tag's key check over a registry
// text.
func accepts023(known []string, text []byte) error {
	v, err := pyyaml.LoadBytes(text)
	if err != nil {
		return err
	}
	devs, ok := v.(*yamlpy.Map).Get("devices")
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

// 0.2.3 reads a device with the keys it knows: a rollback to it clears
// the map and leaves the rest of the file as it was.
func TestRollbackSNMP(t *testing.T) {
	known := known023Keys(t)
	_, p := loadText(t, sampleSNMP)
	raw, _ := os.ReadFile(p)
	if err := accepts023(known, raw); err == nil {
		t.Fatal("the sample should not read as 0.2.3's")
	}
	names, err := SNMPOverridden(p)
	if err != nil || !reflect.DeepEqual(names, []string{"lab-rtr2", "oob-con1"}) {
		t.Fatalf("overridden: %v %v", names, err)
	}
	snaps := 0
	cleared, err := RollbackSNMP(p, func() error { snaps++; return nil })
	if err != nil || !reflect.DeepEqual(cleared, []string{"lab-rtr2", "oob-con1"}) || snaps != 1 {
		t.Fatalf("rollback: %v %v (%d snapshots)", cleared, err, snaps)
	}
	raw, _ = os.ReadFile(p)
	if err := accepts023(known, raw); err != nil {
		t.Errorf("0.2.3 would refuse the result: %v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), "location: Rack 4") {
		t.Errorf("the rest of the file changed:\n%s", raw)
	}
	// Nothing left: not written, no snapshot; a missing file is not created.
	if cleared, err = RollbackSNMP(p, func() error { snaps++; return nil }); err != nil || cleared != nil || snaps != 1 {
		t.Errorf("second rollback: %v %v (%d snapshots)", cleared, err, snaps)
	}
	missing := filepath.Join(t.TempDir(), "none.yaml")
	if cleared, err = RollbackSNMP(missing, nil); err != nil || cleared != nil {
		t.Errorf("missing: %v %v", cleared, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a missing file was created: %v", err)
	}
}
