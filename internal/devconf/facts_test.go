package devconf

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The release of a Junos configuration is its 'set version' statement.
func TestJunosRelease(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"a pull", capture(t, "juniper/lab-superuser/display-set.txt"), "25.4R1-S2.3"},
		{"the statement alone", "set version 11.4R7.5\r\n", "11.4R7.5"},
		{"quoted", "set version \"12.1X46-D10\"\n", "12.1X46-D10"},
		{"no statement", "set system host-name a\nset system services ssh\n", ""},
		{"a statement that only starts like it", "set system version 1.0\nset versioned x y\n", ""},
		{"an error text", "error: permission denied\n", ""},
		{"empty", "", ""},
	} {
		if got := JunosRelease(cleanText(c.in)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestJunosVersion(t *testing.T) {
	for _, c := range []struct{ name, in, release, model string }{
		{"EX4300", capture(t, "juniper/facts-ex4300/show-version.txt"), "25.4R1-S2.3", "ex4300-48mp"},
		{"two routing engines: the first", "re0:\nModel: mx480\nJunos: 21.4R3.15\nre1:\nModel: mx480\nJunos: 21.4R3.9\n", "21.4R3.15", "mx480"},
		{"12.3 has no Junos line", "fpc0:\n----\nHostname: a\nModel: ex4200-24t\nJUNOS Base OS boot [12.3R9.4]\nJUNOS Base OS Software Suite [12.3R9.4]\n", "12.3R9.4", "ex4200-24t"},
		{"the Junos line wins", "JUNOS Base OS boot [12.3R9.4]\nJunos: 15.1R6-S4\n", "15.1R6-S4", ""},
		{"the host line is not the release", "Hostname: a\nJunos host: 25.4R1\n", "", ""},
		{"a refusal", "error: command is not valid\n", "", ""},
		{"empty", "", "", ""},
	} {
		rel, model := JunosVersion(c.in)
		if rel != c.release || model != c.model {
			t.Errorf("%s: %q %q, want %q %q", c.name, rel, model, c.release, c.model)
		}
	}
}

func TestJunosChassis(t *testing.T) {
	for _, c := range []struct{ name, in, model, serial string }{
		{"EX4300", capture(t, "juniper/facts-ex4300/show-chassis-hardware.txt"), "EX4300-48MP", "FXYZ00000001"},
		{"a pull over NETCONF (CRLF and a prompt line)", "\r\nHardware inventory:\r\nItem             Version  Part number  Serial number     Description\r\n" +
			"Chassis                                JN00000000AB      MX480\r\nMidplane         REV 04   750-000000   ABCD0000          MX480 Midplane\r\n", "MX480", "JN00000000AB"},
		{"a virtual chassis with no serial number", "Hardware inventory:\nItem             Version  Part number  Serial number     Description\n" +
			"Chassis                                                  VMX\nRouting Engine 0                                         RE-VMX\n", "VMX", ""},
		{"a serial number that fills its column", "Item             Version  Part number  Serial number     Description\n" +
			"Chassis" + strings.Repeat(" ", 32) + "VC1234567890ABCDEF Virtual Chassis\n", "Virtual Chassis", "VC1234567890ABCDEF"},
		{"no header: serial and description", "Chassis      FXYZ00000009   EX2300-24T\n", "EX2300-24T", "FXYZ00000009"},
		{"no header: description alone", "Chassis      VM-HOST\n", "VM-HOST", ""},
		{"a row that is not the chassis", "Item  Serial number  Description\nChassisX 1 2\nFPC 0   FXYZ1  EX\n", "", ""},
		{"a refusal", "error: permission denied\n", "", ""},
		{"a syntax error", "                                  ^\nsyntax error, expecting <command>.\n", "", ""},
		{"empty", "", "", ""},
	} {
		model, serial := JunosChassis(cleanText(c.in))
		if model != c.model || serial != c.serial {
			t.Errorf("%s: %q %q, want %q %q", c.name, model, serial, c.model, c.serial)
		}
	}
}

func TestIOSRelease(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"IOSv", capture(t, "ios/facts-iosv/show-version-include-version.txt"), "15.6(2)T"},
		{"CSR1000V: the IOS line, not the XE build's padded number", capture(t, "ios-xe/facts-csr1000v/show-version-include-version.txt"), "16.7.1"},
		{"7200: not the boot loader or the midplane", capture(t, "ios/facts-7200/show-version-include-version.txt"), "12.4(15)SW"},
		{"XE line only", "Cisco IOS XE Software, Version 16.07.01\n", "16.07.01"},
		{"an ASA", "Cisco Adaptive Security Appliance Software Version 9.8(4)\n", "9.8(4)"},
		{"a bare Version is no image line", "Version 15.0(1)M\n", ""},
		{"a hardware line only", "6 slot VXR midplane, Version 2.1\n", ""},
		{"a licence line only", "This product contains cryptographic features; GPL Version 2.0 applies\n", ""},
		{"the loader alone", "ROM: System Bootstrap, Version 12.4(13r)T\nBOOTLDR: 7200 Software, Version 12.2(44)SE\n", ""},
		{"a refusal", "% Invalid input detected at '^' marker.\n", ""},
		{"empty", "", ""},
	} {
		if got := IOSRelease(cleanText(c.in)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIOSInventory(t *testing.T) {
	for _, c := range []struct{ name, in, model, serial string }{
		{"IOSv", capture(t, "ios/facts-iosv/show-inventory.txt"), "IOSv", "FXYZ0000001"},
		{"CSR1000V: the first entry, not the route processor's", capture(t, "ios-xe/facts-csr1000v/show-inventory.txt"), "CSR1000V", "FXYZ0000002"},
		{"7200", capture(t, "ios/facts-7200/show-inventory.txt"), "CISCO7206VXR", "FXYZ0000004"},
		{"an entry with no serial number", "NAME: \"Chassis\", DESCR: \"x\"\nPID: WS-C2960-24TT-L , VID: V02  , SN:            \n", "WS-C2960-24TT-L", ""},
		{"a PID with no VID", "NAME: \"1\", DESCR: \"x\"\nPID: ASA5505, VID: , SN: JMX0000X00A\n", "ASA5505", "JMX0000X00A"},
		{"no entry", "\n", "", ""},
		{"a refusal", "% Invalid input detected at '^' marker.\n", "", ""},
		{"empty", "", "", ""},
	} {
		model, serial := IOSInventory(cleanText(c.in))
		if model != c.model || serial != c.serial {
			t.Errorf("%s: %q %q, want %q %q", c.name, model, serial, c.model, c.serial)
		}
	}
}

// A fact is one clean line: control characters are shown as '?', blanks
// collapse and the length is bounded.
func TestCleanFacts(t *testing.T) {
	got := CleanFacts(Facts{Release: " 15.6(2)T\x01 ", Model: "A\n  B", Serial: strings.Repeat("x", 300)})
	if got.Release != "15.6(2)T?" || got.Model != "A? B" || len(got.Serial) != maxFact {
		t.Errorf("%+v", got)
	}
	if !(Facts{}).Empty() || (Facts{Serial: "a"}).Empty() {
		t.Error("Empty")
	}
}

// The reader keeps the release the text carries, and a pull that carries
// none leaves it empty without failing.
func TestReaderWithFacts(t *testing.T) {
	ctx := context.Background()
	jcmd := "show configuration | display inheritance no-comments | display set"
	jread, err := ReaderWithFacts("juniper")
	if err != nil {
		t.Fatal(err)
	}
	_, _, f, err := jread(ctx, &fakeRunner{out: map[string]string{jcmd: "set version 25.4R1-S2.3\nset system a b\n"}})
	if err != nil || f.Release != "25.4R1-S2.3" {
		t.Errorf("junos: %+v %v", f, err)
	}
	_, _, f, err = jread(ctx, &fakeRunner{out: map[string]string{jcmd: "set system a b\n"}})
	if err != nil || f != (Facts{}) {
		t.Errorf("junos, no statement: %+v %v", f, err)
	}
	iread, _ := ReaderWithFacts("cisco")
	out := map[string]string{VersionCommand: capture(t, "ios-xe/facts-csr1000v/show-version-include-version.txt"), "show running-config": "version 16.7\n"}
	_, version, f, err := iread(ctx, &fakeRunner{out: out})
	if err != nil || f.Release != "16.7.1" || version != "Cisco IOS XE Software, Version 16.07.01" {
		t.Errorf("ios: %+v %q %v", f, version, err)
	}
	out[VersionCommand] = "% Invalid input detected at '^' marker.\n"
	_, version, f, err = iread(ctx, &fakeRunner{out: out})
	if err != nil || f != (Facts{}) || version != "" {
		t.Errorf("ios, refused: %+v %q %v", f, version, err)
	}
}

// ReadFacts reads the one more command of each vendor and never fails.
func TestReadFacts(t *testing.T) {
	ctx := context.Background()
	hw := capture(t, "juniper/facts-ex4300/show-chassis-hardware.txt")
	sv := capture(t, "juniper/facts-ex4300/show-version.txt")
	t.Run("junos with the release read", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: hw}}
		got := ReadFacts(ctx, f, "juniper", Facts{Release: "25.4R1-S2.3"})
		// show version is asked all the same: it names the running release
		if got != (Facts{Release: "25.4R1-S2.3", Model: "EX4300-48MP", Serial: "FXYZ00000001"}) ||
			!slices.Equal(f.ran, []string{JunosChassisCommand, JunosVersionCommand}) {
			t.Errorf("%+v %v", got, f.ran)
		}
	})
	t.Run("junos without a set version statement", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: hw, JunosVersionCommand: sv}}
		got := ReadFacts(ctx, f, "junos", Facts{})
		// the chassis description stays the model
		if got != (Facts{Release: "25.4R1-S2.3", Model: "EX4300-48MP", Serial: "FXYZ00000001"}) ||
			!slices.Equal(f.ran, []string{JunosChassisCommand, JunosVersionCommand}) {
			t.Errorf("%+v %v", got, f.ran)
		}
	})
	t.Run("junos: the running release is show version's, not the configuration's", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: hw, JunosVersionCommand: "Model: ex4300-48mp\nJunos: 21.4R3\n"}}
		got := ReadFacts(ctx, f, "juniper", Facts{Release: "15.1R7"})
		if got.Release != "21.4R3" || got.Model != "EX4300-48MP" {
			t.Errorf("%+v", got)
		}
	})
	t.Run("junos: show version's Model: when the chassis gave none", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: "error: permission denied\n", JunosVersionCommand: sv}}
		got := ReadFacts(ctx, f, "juniper", Facts{})
		if got != (Facts{Release: "25.4R1-S2.3", Model: "ex4300-48mp"}) {
			t.Errorf("%+v", got)
		}
	})
	t.Run("junos: show version refused keeps the configuration's release", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: hw}, errs: map[string]error{JunosVersionCommand: errors.New("denied")}}
		if got := ReadFacts(ctx, f, "juniper", Facts{Release: "15.1R7"}); got.Release != "15.1R7" || got.Model != "EX4300-48MP" {
			t.Errorf("%+v", got)
		}
	})
	t.Run("junos refuses both", func(t *testing.T) {
		f := &fakeRunner{errs: map[string]error{JunosChassisCommand: errors.New("denied"), JunosVersionCommand: errors.New("denied")}}
		if got := ReadFacts(ctx, f, "junos", Facts{}); got != (Facts{}) {
			t.Errorf("%+v", got)
		}
	})
	t.Run("junos answers an error text", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: "error: permission denied\n", JunosVersionCommand: "syntax error\n"}}
		if got := ReadFacts(ctx, f, "junos", Facts{Release: "11.4R7.5"}); got != (Facts{Release: "11.4R7.5"}) {
			t.Errorf("%+v", got)
		}
	})
	t.Run("ios", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{IOSInventoryCommand: capture(t, "ios/facts-iosv/show-inventory.txt")}}
		got := ReadFacts(ctx, f, "cisco", Facts{Release: "15.6(2)T"})
		if got != (Facts{Release: "15.6(2)T", Model: "IOSv", Serial: "FXYZ0000001"}) || !slices.Equal(f.ran, []string{IOSInventoryCommand}) {
			t.Errorf("%+v %v", got, f.ran)
		}
	})
	t.Run("ios refuses it", func(t *testing.T) {
		for _, f := range []*fakeRunner{
			{out: map[string]string{IOSInventoryCommand: "% Invalid input detected at '^' marker.\n"}},
			{errs: map[string]error{IOSInventoryCommand: errors.New("closed")}},
			{out: map[string]string{}},
		} {
			if got := ReadFacts(ctx, f, "ios-xe", Facts{Release: "16.7.1"}); got != (Facts{Release: "16.7.1"}) {
				t.Errorf("%+v", got)
			}
		}
	})
	t.Run("wti and an unknown vendor: nothing is run", func(t *testing.T) {
		f := &fakeRunner{}
		if got := ReadFacts(ctx, f, "wti", Facts{Release: "8.10"}); got != (Facts{Release: "8.10"}) || len(f.ran) != 0 {
			t.Errorf("%+v %v", got, f.ran)
		}
		if got := ReadFacts(ctx, f, "other", Facts{}); got != (Facts{}) || len(f.ran) != 0 {
			t.Errorf("%+v %v", got, f.ran)
		}
	})
	t.Run("a cancelled context runs nothing", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: hw}}
		if got := ReadFacts(cctx, f, "junos", Facts{}); got != (Facts{}) || len(f.ran) != 0 {
			t.Errorf("%+v %v", got, f.ran)
		}
	})
}

// The record keeps the facts in the records file, omits them when empty and
// loads a record written before they existed.
func TestRecordFactsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := Store{Records: filepath.Join(dir, "devices-config.json"), Dir: filepath.Join(dir, "device-config")}
	recs := NewRecords()
	recs.Put("sw1", Record{Vendor: "juniper", Result: ResultOK, Pulled: time.Unix(1700000000, 0).UTC(),
		Release: "25.4R1-S2.3", Model: "EX4300-48MP", Serial: "FXYZ00000001"})
	recs.Put("rt1", Record{Vendor: "cisco", Result: ResultOK, Release: "15.6(2)T"})
	recs.Put("old", Record{Vendor: "cisco", Result: ResultOK})
	if err := s.Save(recs); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := got.Of("sw1"); r == nil || r.Release != "25.4R1-S2.3" || r.Model != "EX4300-48MP" || r.Serial != "FXYZ00000001" {
		t.Errorf("sw1: %+v", r)
	}
	if r, _ := got.Of("rt1"); r == nil || r.Release != "15.6(2)T" || r.Model != "" || r.Serial != "" {
		t.Errorf("rt1: %+v", r)
	}
	raw, _ := os.ReadFile(s.Records)
	var doc struct {
		Devices map[string]map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"release", "model", "serial"} {
		if _, ok := doc.Devices["old"][k]; ok {
			t.Errorf("an empty %s is written: %v", k, doc.Devices["old"])
		}
	}
	if _, ok := doc.Devices["rt1"]["model"]; ok {
		t.Error("an empty model is written")
	}
	// a file of the release before the facts loads, with the fields empty
	legacy := `{"version":1,"devices":{"x":{"vendor":"cisco","result":"ok","os":"Cisco IOS Software, Version 15.6(2)T","secrets_visible":false}}}`
	if err := os.WriteFile(s.Records, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := got.Of("x"); !ok || r.Result != ResultOK || r.Release != "" || r.Model != "" || r.Serial != "" {
		t.Errorf("legacy record: %+v", r)
	}
}

// JunosHostName is the device's own name: host-name, with domain-name
// appended when the name has no dot; text a device controls is made safe.
func TestJunosHostName(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"both", "set system host-name sw1\nset system domain-name lab.example.net\n", "sw1.lab.example.net"},
		{"bare", "set system host-name sw1\n", "sw1"},
		{"a fqdn is kept", "set system host-name sw1.a.example.net\nset system domain-name b.example.net\n", "sw1.a.example.net"},
		{"quoted", `set system host-name "sw1"` + "\n" + `set system domain-name "lab.example.net"` + "\n", "sw1.lab.example.net"},
		{"none", "set system domain-name lab.example.net\nset snmp location x\n", ""},
		{"the first wins", "set system host-name a\nset system host-name b\n", "a"},
		{"not a group's", "set groups g system host-name evil\n", ""},
		{"control characters", "set system host-name \"a\x1b[2Jb\"\n", "a?[2Jb"},
	} {
		if got := JunosHostName(c.in); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	ext, err := ExtractWith("juniper", "set system host-name sw1\nset system domain-name lab.example.net\nset snmp location x\n", Options{})
	if err != nil || ext.Hostname != "sw1.lab.example.net" {
		t.Errorf("ExtractWith: %q %v", ext.Hostname, err)
	}
}

// IOSHostName is the top-level 'hostname' line of a running configuration
// (0.2.17 D263): the first one, not an indented line of a submode, with no
// domain appended; the extraction keeps it on the record as Junos's.
func TestIOSHostName(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"plain", "!\nhostname Core-SW1\nip domain name lab.example.net\n", "Core-SW1"},
		{"crlf", "hostname sw2\r\n", "sw2"},
		{"none", "!\nip domain name lab.example.net\n", ""},
		{"indented is not the device's", " hostname evil\nhostname sw3\n", "sw3"},
		{"the first wins", "hostname a\nhostname b\n", "a"},
		{"control characters", "hostname a\x1bb\n", "a?b"},
	} {
		if got := IOSHostName(c.in); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	ext, err := ExtractWith("cisco", "Building configuration...\n!\nhostname rtr1\n!\nend\n", Options{})
	if err != nil || ext.Hostname != "rtr1" {
		t.Errorf("ExtractWith: %q %v", ext.Hostname, err)
	}
}
