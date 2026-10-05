package devreg

import (
	"reflect"
	"strings"
	"testing"
)

func base() *File {
	f := Empty()
	f.Devices = []*Device{
		{Name: "core-sw1", Address: "10.99.0.1", Vendor: "cisco", Hostname: "core.example.net", LegacySSH: true, Ack: []string{"generic-name"},
			HostKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA=="}},
		{Name: "oob-con1", Address: "10.99.0.9", Vendor: "wti"},
	}
	return f
}

func TestParseImportCSV(t *testing.T) {
	rows, err := ParseImport([]byte("# devices\nName, Address, Vendor\n\ncore-sw1,10.99.0.1,Cisco\nlab-rtr2, 192.0.2.7 ,juniper,830,\"Lab, router\"\nplain,2001:DB8::9\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("%+v", rows)
	}
	want := Device{Name: "lab-rtr2", Address: "192.0.2.7", Vendor: "juniper", Port: 830, Description: "Lab, router"}
	if !rows[1].CSV || rows[1].Line != 5 || !reflect.DeepEqual(rows[1].Device, want) {
		t.Errorf("row 2 = %+v", rows[1])
	}
	if rows[0].Device.Vendor != "cisco" || rows[2].Device.Address != "2001:db8::9" || rows[2].Device.Vendor != "other" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestParseImportCSVErrorsAreAllReported(t *testing.T) {
	_, err := ParseImport([]byte("a1,10.0.0.1,arista\nb2,10.0.0.0/24\nonly-name\nc3,10.0.0.3,cisco,99999\n-bad,10.0.0.4\nd4,10.0.0.5,cisco,23,admin,extra\n"))
	if err == nil {
		t.Fatal("accepted")
	}
	text := err.Error()
	for _, want := range []string{"line 1: ", "line 2: ", "line 3: expected name,address", "line 4: ", "line 5: ", "line 6: "} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if _, err := ParseImport([]byte("# nothing\n\n")); err == nil {
		t.Error("an empty file is an error")
	}
}

func TestParseImportYAML(t *testing.T) {
	rows, err := ParseImport([]byte(sample))
	if err != nil || len(rows) != 3 || rows[0].CSV || rows[0].Device.LegacySSH != true || rows[1].Device.Hostname != "lab-rtr2.lab.example.net" {
		t.Errorf("%+v, %v", rows, err)
	}
	if _, err := ParseImport([]byte("version: 1\ndevices:\n  a1: {address: bogus}\n")); err == nil {
		t.Error("a bad YAML entry was accepted")
	}
}

func TestImportMerge(t *testing.T) {
	f := base()
	rows, _ := ParseImport([]byte("core-sw1,10.99.0.1,cisco\nOOB-CON1,10.99.0.9,juniper,830,console\nnew-sw,10.99.0.20,cisco\n"))
	res, err := f.Import(rows, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res, ImportResult{Added: []string{"new-sw"}, Updated: []string{"oob-con1"}, Unchanged: []string{"core-sw1"}}) {
		t.Errorf("%+v", res)
	}
	core := f.Find("core-sw1")
	if core.Hostname != "core.example.net" || !core.LegacySSH || len(core.HostKeys) != 1 || len(core.Ack) != 1 {
		t.Errorf("a CSV row cleared what it cannot say: %+v", core)
	}
	oob := f.Find("oob-con1")
	if oob.Name != "oob-con1" || oob.Vendor != "juniper" || oob.Port != 830 || oob.Description != "console" {
		t.Errorf("oob-con1 = %+v", oob)
	}
	if len(f.Devices) != 3 {
		t.Errorf("%d devices", len(f.Devices))
	}
}

func TestImportReplaceCheckAndAddressChange(t *testing.T) {
	f := base()
	rows, _ := ParseImport([]byte("core-sw1,10.99.0.77,cisco\n"))
	res, err := f.Import(rows, true, false, nil)
	if err != nil || !reflect.DeepEqual(res.Removed, []string{"oob-con1"}) || !reflect.DeepEqual(res.Updated, []string{"core-sw1"}) {
		t.Fatalf("%+v, %v", res, err)
	}
	if len(f.Devices) != 1 || f.Devices[0].Address != "10.99.0.77" || len(f.Devices[0].HostKeys) != 0 {
		t.Errorf("a new address keeps no pinned keys: %+v", f.Devices[0])
	}
	// --check works on a clone: the caller's file is untouched.
	g := base()
	if _, err := g.Clone().Import(rows, true, false, nil); err != nil || len(g.Devices) != 2 {
		t.Error("a clone was imported into the original")
	}
}

func TestImportRefusals(t *testing.T) {
	hostsIn := []Entry{{Source: SourceHost, Device: Device{Name: "web1", Address: "192.0.2.10"}}}
	cases := map[string]struct {
		csv  string
		want string
	}{
		"duplicate in file":   {"a1,10.0.0.1\nA1,10.0.0.2\n", "appears twice"},
		"same address twice":  {"a1,10.0.0.1\na2,10.0.0.1\n", "would be registered as both"},
		"address of a device": {"a1,10.99.0.1\n", "would be registered as both 'core-sw1' and 'a1'"},
		"host name":           {"WEB1,10.0.0.1\n", "is an enrolled host"},
		"host address":        {"a1,192.0.2.10\n", "belongs to the enrolled host 'web1'"},
		"generic":             {"switch,10.0.0.1\n", "generic name"},
		"reserved":            {"scope,10.0.0.1\n", "tacctl word"},
	}
	for name, c := range cases {
		f := base()
		rows, err := ParseImport([]byte(c.csv))
		if err != nil { // the CSV reader already refuses a name that cannot be one
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v, want %q", name, err, c.want)
			}
			continue
		}
		before := f.Clone()
		if _, err := f.Import(rows, false, false, hostsIn); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		if !reflect.DeepEqual(f, before) {
			t.Errorf("%s: a refused import changed the registry", name)
		}
	}
	// --allow-generic lets the name in.
	f := base()
	rows, _ := ParseImport([]byte("switch,10.0.0.1\n"))
	if _, err := f.Import(rows, false, true, nil); err != nil || f.Find("switch") == nil {
		t.Errorf("allow-generic: %v", err)
	}
	// A swap of two addresses is fine when both rows are in the file.
	f = base()
	rows, _ = ParseImport([]byte("core-sw1,10.99.0.9\noob-con1,10.99.0.1\n"))
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Errorf("swap: %v", err)
	}
}

func TestExports(t *testing.T) {
	f := base()
	f.Devices[0].Description = "DC1 core, east"
	f.Devices[0].Port = 830
	csvText := string(CSV([]Device{*f.Devices[0], *f.Devices[1]}))
	if csvText != "name,address,vendor,port,description\ncore-sw1,10.99.0.1,cisco,830,\"DC1 core, east\"\noob-con1,10.99.0.9,wti,,\n" {
		t.Errorf("csv:\n%s", csvText)
	}
	// The export reads back as an import.
	g := Empty()
	rows, err := ParseImport([]byte(csvText))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Import(rows, false, false, nil); err != nil || g.Find("core-sw1").Description != "DC1 core, east" || g.Find("core-sw1").Port != 830 {
		t.Errorf("round trip: %v %+v", err, g.Find("core-sw1"))
	}
	js, err := JSON([]Device{*f.Devices[1]})
	if err != nil || !strings.Contains(string(js), `"port": 22`) || !strings.Contains(string(js), `"name": "oob-con1"`) {
		t.Errorf("json: %s %v", js, err)
	}
	if js, _ := JSON(nil); string(js) != "[]\n" {
		t.Errorf("empty json = %q", js)
	}
}
