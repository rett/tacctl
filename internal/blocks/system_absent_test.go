package blocks

import (
	"strings"
	"testing"
)

func TestJunosAbsentParsesAndRoundTrips(t *testing.T) {
	text := "set system time-zone UTC\nabsent system services telnet\nabsent system services web-management\ndelete system services ftp\n"
	b, fs := LintSystem(text, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if got := SystemAbsent(b); strings.Join(got, "|") != "system services telnet|system services web-management" {
		t.Errorf("absent: %v", got)
	}
	for _, s := range SystemStatements(b) {
		if strings.Contains(s, "services") {
			t.Errorf("an absent service is a statement: %q", s)
		}
	}
	out := b.String(false)
	for _, want := range []string{"absent system services telnet\n", "absent system services web-management\n", "delete system services ftp\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("String lacks %q:\n%s", want, out)
		}
	}
	b2, fs2 := LintSystem(out, LayerScope)
	if HasErrors(fs2) || b2.String(false) != out {
		t.Errorf("round trip:\n%s\n%s", out, b2.String(false))
	}
	if b.Empty() {
		t.Error("a block of absent lines is empty")
	}
}

func TestJunosAbsentRefusals(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"absent system services ssh\n", "this statement is not one of"},
		{"absent system services netconf\n", "this statement is not one of"},
		{"absent system services telnet connection-limit 5\n", "this statement is not one of"},
		{"absent system ntp\n", "'absent system' takes services"},
		{"absent services telnet\n", "only 'absent system services"},
		{"absent system services telnet\nabsent system services telnet\n", "stated twice"},
		{"set system services telnet\n", "'absent system services <service>'"},
		{"delete system services ssh\n", "a delete line names the statement's identity"},
	} {
		_, fs := LintSystem(c.text, LayerScope)
		if !anyFindingHas(fs, SevError, c.want) {
			t.Errorf("%q: want error %q, got:\n%s", c.text, c.want, dump(fs))
		}
	}
}

func TestJunosAbsentLayers(t *testing.T) {
	scope, _ := ParseSystem("absent system services telnet\nabsent system services ftp\n")
	dev, _ := ParseSystem("delete system services telnet\n")
	got := ResolveSystem(nil, scope, dev)
	if a := SystemAbsent(got); strings.Join(a, "|") != "system services ftp" {
		t.Errorf("the device's delete line did not take telnet out: %v", a)
	}
	// the device's own absent adds to the scope's
	dev2, _ := ParseSystem("absent system services finger\n")
	if a := SystemAbsent(ResolveSystem(nil, scope, dev2)); len(a) != 3 {
		t.Errorf("layers: %v", a)
	}
}

func TestIOSAbsentParsesAndRoundTrips(t *testing.T) {
	text := "ip domain name lab.example.net\nabsent ip http server\nabsent service tcp-small-servers\nno ip http secure-server\n"
	b, fs := LintIOSSystem(text, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if got := IOSSystemAbsent(b); strings.Join(got, "|") != "ip http server|service tcp-small-servers" {
		t.Errorf("absent: %v", got)
	}
	for _, s := range IOSSystemStatements(b) {
		if strings.Contains(s, "http") || strings.Contains(s, "small") {
			t.Errorf("an absent service is a statement: %q", s)
		}
	}
	out := b.String(false)
	b2, fs2 := LintIOSSystem(out, LayerScope)
	if HasErrors(fs2) || b2.String(false) != out {
		t.Errorf("round trip:\n%s\n%s", out, b2.String(false))
	}
	for _, c := range []struct{ text, want string }{
		{"absent ip ssh version\n", "'absent' takes"},
		{"absent ip source-route\n", "'absent' takes"},
		{"absent ip http server\nabsent ip http server\n", "stated twice"},
	} {
		if _, fs := LintIOSSystem(c.text, LayerScope); !anyFindingHas(fs, SevError, c.want) {
			t.Errorf("%q: %s", c.text, dump(fs))
		}
	}
	// a device's no line takes the scope's marker out
	dev, _ := ParseIOSSystem("no ip http server\n")
	scope, _ := ParseIOSSystem("absent ip http server\nabsent ip finger\n")
	if a := IOSSystemAbsent(ResolveIOSSystem(nil, scope, dev)); strings.Join(a, "|") != "ip finger" {
		t.Errorf("layers: %v", a)
	}
}
