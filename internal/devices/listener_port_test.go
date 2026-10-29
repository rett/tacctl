package devices

// The server's port in the walkthroughs and in what a pull is compared with:
// a TACACS+ listener that is not on 49 (Data.TACACSPort) and RADIUS ones that
// are not on 1812 and 1813. With the default listeners nothing differs from
// what was always rendered (the goldens of TestRenderGoldens and
// TestManagedGoldens, which this file does not touch).

import (
	"bytes"
	"strings"
	"testing"
)

// movedData is the data of a walkthrough for a TACACS+ listener on tcp :4949
// and RADIUS ones on udp :11812 and :11813.
func movedData(t *testing.T, vendor, scope string, protocol string) Data {
	t.Helper()
	m, c := fixture(t, "store.multiscope.yaml", "")
	n := "VTY-ACL"
	if vendor == "juniper" {
		n = "MGMT-ACL"
	}
	d := Data{Model: m, Conf: c, TemplateDir: t.TempDir(), ServerIP: "10.0.0.42", ACL: MgmtACL{Name: n}, TACACSPort: "4949"}
	if protocol == RADIUS {
		d.Radius = &Radius{AuthPort: "11812", AcctPort: "11813", Secret: m.Scope(scope).Secret, VendorSent: "scope"}
	}
	return d
}

// moveListeners puts the listeners of d on tcp :4949 and, for a RADIUS
// device, udp :11812 and :11813 (moved) or back on their defaults.
func (d *Data) moveListeners(moved bool) {
	d.TACACSPort = ""
	if moved {
		d.TACACSPort = "4949"
	}
	if d.Radius != nil {
		d.Radius.AuthPort, d.Radius.AcctPort = "1812", "1813"
		if moved {
			d.Radius.AuthPort, d.Radius.AcctPort = "11812", "11813"
		}
	}
}

func renderOf(t *testing.T, req Request, d Data) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, req, d); err != nil {
		t.Fatal(err)
	}
	return reANSI.ReplaceAllString(buf.String(), "")
}

// Every vendor's walkthrough against a golden of its own, for a server on
// tcp :4949 (TACACS+) and udp :11812/:11813 (RADIUS, which names the TACACS+
// port where it says what the protocol is not).
func TestRenderGoldensMovedListener(t *testing.T) {
	for _, g := range []struct {
		golden, vendor string
		legacy         bool
		protocol       string
	}{
		{"cisco-lab.tcp4949.conf", "cisco", false, TACACS},
		{"cisco-legacy-lab.tcp4949.conf", "cisco", true, TACACS},
		{"juniper-lab.tcp4949.conf", "juniper", false, TACACS},
		{"wti-lab.tcp4949.conf", "wti", false, TACACS},
		{"cisco-radius-lab.udp11812.conf", "cisco", false, RADIUS},
		{"juniper-radius-lab.udp11812.conf", "juniper", false, RADIUS},
		{"wti-radius-lab.udp11812.conf", "wti", false, RADIUS},
	} {
		source := SourceDefault
		if g.protocol == RADIUS {
			source = SourceFlag
		}
		d := movedData(t, g.vendor, "lab", g.protocol)
		golden(t, g.golden, renderOf(t, Request{Vendor: g.vendor, Scope: "lab", Legacy: g.legacy, Protocol: g.protocol, Source: source}, d))
	}
}

// The port is written where each vendor's configuration takes one, and only
// for a listener that is not on the default: 49, the empty value and a value
// that is no port render what the walkthroughs always did.
func TestTACACSPortIsWrittenOnlyWhenMoved(t *testing.T) {
	for _, c := range []struct {
		vendor string
		legacy bool
		moved  string // what a listener on 4949 adds
	}{
		{"cisco", false, "tacacs server TACACS\n  address ipv4 10.0.0.42\n  port 4949\n  key "},
		{"cisco", true, "tacacs-server host 10.0.0.42 single-connection port 4949 timeout 5 key "},
		{"juniper", false, "set system tacplus-server 10.0.0.42 port 4949\n"},
		{"wti", false, "7. Authentication Port        : 4949\n"},
	} {
		req := Request{Vendor: c.vendor, Scope: "lab", Legacy: c.legacy, Protocol: TACACS, Source: SourceDefault}
		d := movedData(t, c.vendor, "lab", TACACS)
		if out := renderOf(t, req, d); !strings.Contains(out, c.moved) {
			t.Errorf("%s legacy=%v: no %q in\n%s", c.vendor, c.legacy, c.moved, out)
		}
		d.TACACSPort = ""
		want := renderOf(t, req, d)
		for _, v := range []string{"49", "0", "70000", "x", "-1"} {
			d.TACACSPort = v
			if got := renderOf(t, req, d); got != want {
				t.Errorf("%s legacy=%v: TACACSPort %q differs from the default:\n%s", c.vendor, c.legacy, v, firstDiff(got, want))
			}
		}
	}
}

// The strict Junos filter accepts the server's replies from the listener's
// port: its name when it is 49, the number when it is not.
func TestStrictFilterRepliesFromTheTACACSPort(t *testing.T) {
	d := strictData(t, "192.0.2.1", "192.0.2.5", []string{"10.0.0.0/8"}, SNMPInput{})
	d.AuthServer = "198.51.100.9"
	if got := mgmtBlock(d); !strings.Contains(got, "term permit-auth-replies from source-port tacacs\n") {
		t.Errorf("default:\n%s", got)
	}
	d.TACACSPort = "4949"
	block := mgmtBlock(d)
	if !strings.Contains(block, "term permit-auth-replies from source-port 4949\n") || strings.Contains(block, "source-port tacacs") {
		t.Errorf("moved:\n%s", block)
	}
	golden(t, "mgmtfilter.strict.server-tcp4949.txt", block+"\n")
}

// What a pull is compared with (Managed) carries the port too: the server
// block's leaf on IOS, the host line of IOS 12.x, the tacplus-server leaf on
// Junos and the unit's Authentication Port; the default renders no port
// statement but the unit's, which always had one.
func TestManagedCarriesTheTACACSPort(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range []variant{variants[0], variants[1], variants[3], variants[5]} {
		req, d := managedProfiles()[0].input(m, c, v)
		def := managedText(mustManaged(t, req, d))
		d.TACACSPort = "4949"
		moved := managedText(mustManaged(t, req, d))
		golden(t, "managed."+v.name+".lab.tcp4949.txt", moved)
		if def == moved {
			t.Errorf("%s: the moved listener changes nothing", v.name)
		}
		if strings.Contains(def, "4949") || !strings.Contains(moved, "4949") {
			t.Errorf("%s: default %v moved %v", v.name, strings.Contains(def, "4949"), strings.Contains(moved, "4949"))
		}
	}
	// the unit's statement is the default's 49 for a server on it
	req, d := managedProfiles()[0].input(m, c, variants[5])
	if text := managedText(mustManaged(t, req, d)); !strings.Contains(text, "| tacacs port 49\n") {
		t.Errorf("wti default:\n%s", text)
	}
	// a RADIUS unit takes the RADIUS ports, whatever the TACACS+ one is
	req, d = managedProfiles()[0].input(m, c, variants[6])
	d.TACACSPort = "4949"
	d.Radius.AuthPort, d.Radius.AcctPort = "11812", "11813"
	text := managedText(mustManaged(t, req, d))
	if !strings.Contains(text, "| radius port 11812\n") || !strings.Contains(text, "| radius accounting-port 11813\n") || strings.Contains(text, "4949") {
		t.Errorf("wti radius:\n%s", text)
	}
}
