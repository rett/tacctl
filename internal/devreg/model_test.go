package devreg

import (
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	good := []string{"core-sw1", "a", "Core.SW_1", "9lives", strings.Repeat("a", 63)}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) = %v", n, err)
		}
	}
	bad := []string{"", "-lead", ".lead", "_x", "has space", "semi;colon", "slash/x", "é", strings.Repeat("a", 64), "a\nb"}
	for _, n := range bad {
		if err := ValidateName(n); err == nil {
			t.Errorf("ValidateName(%q) accepted", n)
		}
	}
	for _, n := range []string{"local", "all", "scope", "SSH", "Device", "shell"} {
		err := ValidateName(n)
		if err == nil || !strings.Contains(err.Error(), "tacctl word") {
			t.Errorf("reserved %q: %v", n, err)
		}
	}
}

func TestNormalizeAddress(t *testing.T) {
	good := map[string]string{
		"10.99.0.1":                 "10.99.0.1",
		"2001:DB8:0:0:0:0:0:1":      "2001:db8::1",
		"2001:db8::1":               "2001:db8::1",
		"fe80:0000:0000:0000::0001": "fe80::1",
	}
	for in, want := range good {
		if got, err := NormalizeAddress(in); err != nil || got != want {
			t.Errorf("NormalizeAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "10.99.0.0/24", "10.99.0.1/32", "256.1.1.1", "1.2.3", "web1", "0.0.0.0", "::", "fe80::1%eth0", "01.2.3.4", " 1.2.3.4", "1.2.3.4 "} {
		if got, err := NormalizeAddress(in); err == nil {
			t.Errorf("NormalizeAddress(%q) = %q, accepted", in, got)
		}
	}
}

func TestValidateFields(t *testing.T) {
	if n, err := ValidatePort("22"); err != nil || n != 0 {
		t.Errorf("port 22 = %d, %v (the default is stored as 0)", n, err)
	}
	if n, err := ValidatePort("830"); err != nil || n != 830 {
		t.Errorf("port 830 = %d, %v", n, err)
	}
	for _, p := range []string{"0", "65536", "-1", "x", "", "080", "22.0"} {
		if _, err := ValidatePort(p); err == nil {
			t.Errorf("port %q accepted", p)
		}
	}
	for _, v := range []string{"cisco", "juniper", "wti", "other"} {
		if err := ValidateVendor(v); err != nil {
			t.Errorf("vendor %q: %v", v, err)
		}
	}
	for _, v := range []string{"linux", "Cisco", "", "arista"} {
		if err := ValidateVendor(v); err == nil {
			t.Errorf("vendor %q accepted", v)
		}
	}
	for _, h := range []string{"lab-rtr2.lab.example.net", "sw1", "a.b.", "10.0.0.1"} {
		if err := ValidateHostname(h); err != nil {
			t.Errorf("hostname %q: %v", h, err)
		}
	}
	for _, h := range []string{"", "-a", "a..b", "a b", "a_b.example", strings.Repeat("a", 64) + ".net", strings.Repeat("a.", 130)} {
		if err := ValidateHostname(h); err == nil {
			t.Errorf("hostname %q accepted", h)
		}
	}
	if err := ValidateDescription(strings.Repeat("é", 120)); err != nil {
		t.Errorf("120 characters: %v", err)
	}
	for _, d := range []string{strings.Repeat("a", 121), "a\nb", "tab\there", "bell\a"} {
		if err := ValidateDescription(d); err == nil {
			t.Errorf("description %q accepted", d)
		}
	}
}

func TestGenericNames(t *testing.T) {
	for _, n := range []string{"switch", "Switch", "SWITCH12", "router", "router2", "cisco", "Juniper", "wti", "default", "localhost",
		"localhost.localdomain", "ubuntu", "Debian", "raspberrypi", "ip-10-0-0-1", "host", "server", "device"} {
		if !IsGeneric(n, nil) {
			t.Errorf("%q is not generic", n)
		}
	}
	for _, n := range []string{"core-sw1", "switch-a", "ip-10-0-0", "router-lab", "ubuntu2204", "dc1-switch", "my-cisco"} {
		if IsGeneric(n, nil) {
			t.Errorf("%q is generic", n)
		}
	}
	if IsGeneric("lab-box", nil) || !IsGeneric("lab-box", []string{`lab-.*`}) || !IsGeneric("LAB-1", []string{`lab-\d`}) {
		t.Error("extension patterns are matched whole and case-insensitively")
	}
	if IsGeneric("xswitchx", []string{`switch`}) {
		t.Error("a pattern must match the whole name")
	}
}

func TestGenericRefusalText(t *testing.T) {
	err := GenericRefusal("switch", "cisco", "tacctl device add switch 1.2.3.4 --allow-generic")
	text := err.Error()
	for _, want := range []string{"'switch' is a generic name", "hostname <name>", "attribute 32", "--allow-generic"} {
		if !strings.Contains(text, want) {
			t.Errorf("refusal lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Junos") {
		t.Error("a Cisco device is not told the Junos command")
	}
	all := GenericRefusal("switch", "other", "").Error()
	for _, want := range []string{"Cisco", "Junos", "WTI", "hostnamectl"} {
		if !strings.Contains(all, want) {
			t.Errorf("vendor-less refusal lacks %q", want)
		}
	}
}
