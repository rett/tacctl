package blocks

import (
	"strings"
	"testing"
)

// A scope's block states only what is the same for every device of the scope
// (0.2.19): a source address or an interface is one device's own, so only the
// device's block states it, and the loopback by its convention name is the
// one value a scope's block may state (with a note).
func TestADeviceLocalValueIsTheDevicesOwn(t *testing.T) {
	for _, c := range []struct {
		name, text string
		lint       func(string, Layer) []Finding
		scopeError bool
		scopeNote  string
	}{
		{"junos ntp source-address", "set system ntp source-address 192.0.2.10\n", func(s string, l Layer) []Finding { _, fs := LintSystem(s, l); return fs }, true, ""},
		{"junos trap source-address", "set snmp trap-options source-address 192.0.2.10\n", func(s string, l Layer) []Finding { _, fs := Lint(s, l); return fs }, true, ""},
		{"junos trap source lo0", "set snmp trap-options source-address lo0\n", func(s string, l Layer) []Finding { _, fs := Lint(s, l); return fs }, false, "loopback every device"},
		{"ios trap-source Vlan10", "snmp-server trap-source Vlan10\n", func(s string, l Layer) []Finding { _, fs := LintIOSSNMP(s, l); return fs }, true, ""},
		{"ios trap-source Loopback0", "snmp-server trap-source Loopback0\n", func(s string, l Layer) []Finding { _, fs := LintIOSSNMP(s, l); return fs }, false, "loopback every device"},
		{"ios ntp source Vlan10", "ntp server 192.0.2.123 source Vlan10\n", func(s string, l Layer) []Finding { _, fs := LintIOSSystem(s, l); return fs }, true, ""},
		{"ios ntp source Loopback0", "ntp server 192.0.2.123 source Loopback0\n", func(s string, l Layer) []Finding { _, fs := LintIOSSystem(s, l); return fs }, false, "loopback every device"},
	} {
		layers := []Layer{LayerDefault, LayerScope}
		if !c.scopeError {
			layers = layers[1:] // the default block states no value of these at all
		}
		for _, layer := range layers {
			fs := c.lint(c.text, layer)
			got := false
			for _, f := range fs {
				// the default block has no value for these at all (its own error)
				got = got || f.Severity == SevError && (strings.Contains(f.Text, "names an address or an interface of one device") || layer == LayerDefault)
			}
			if c.scopeError && !got {
				t.Errorf("%s at layer %v: not refused: %v", c.name, layer, fs)
			}
			if !c.scopeError && got {
				t.Errorf("%s at layer %v: refused: %v", c.name, layer, fs)
			}
			if c.scopeNote != "" && layer == LayerScope && !hasFinding(fs, SevNote, 1, c.scopeNote) {
				t.Errorf("%s: no note: %v", c.name, fs)
			}
		}
		for _, f := range c.lint(c.text, LayerDevice) {
			if f.Severity == SevError {
				t.Errorf("%s at the device layer: %v", c.name, f)
			}
		}
	}
}

// A scope's draft from a device leaves out what names the device itself, and
// the draft lints at the scope level.
func TestAScopesAdoptDraftLeavesOutDeviceLocalValues(t *testing.T) {
	res := AdoptSNMP("set snmp community lab-ro authorization read-only\nset snmp community lab-ro clients 192.0.2.0/24\nset snmp trap-options source-address 192.0.2.1\n", AdoptOwn{}, nil, nil, LayerScope)
	if strings.Contains(res.Text, "source-address") || len(res.Left) == 0 || !strings.Contains(strings.Join(res.Left, "\n"), "trap-options source-address") {
		t.Errorf("junos snmp: %q %v", res.Text, res.Left)
	}
	if _, fs := Lint(res.Text, LayerScope); HasErrors(fs) {
		t.Errorf("junos snmp draft: %v", fs)
	}
	res = AdoptSystem("set system time-zone UTC\nset system ntp source-address 192.0.2.1\n", nil, nil, LayerScope)
	if strings.Contains(res.Text, "source-address") || !strings.Contains(strings.Join(res.Left, "\n"), "ntp source-address") {
		t.Errorf("junos system: %q %v", res.Text, res.Left)
	}
	if _, fs := LintSystem(res.Text, LayerScope); HasErrors(fs) {
		t.Errorf("junos system draft: %v", fs)
	}
	res = AdoptIOSSNMP("snmp-server trap-source Vlan10\n", AdoptOwn{}, nil, nil, LayerScope)
	if res.Text != "" || len(res.Left) == 0 {
		t.Errorf("ios snmp: %q %v", res.Text, res.Left)
	}
	res = AdoptIOSSystem("ntp server 192.0.2.123 source Vlan10\n", nil, nil, LayerScope)
	if strings.Contains(res.Text, "Vlan10") || !strings.Contains(res.Text, "ntp server 192.0.2.123") || len(res.Left) == 0 {
		t.Errorf("ios system: %q %v", res.Text, res.Left)
	}
	if _, fs := LintIOSSystem(res.Text, LayerScope); HasErrors(fs) {
		t.Errorf("ios system draft: %v", fs)
	}
	// the same read at the device level keeps them
	res = AdoptIOSSystem("ntp server 192.0.2.123 source Vlan10\n", nil, nil, LayerDevice)
	if !strings.Contains(res.Text, "Vlan10") {
		t.Errorf("device draft lost the source: %q", res.Text)
	}
}
