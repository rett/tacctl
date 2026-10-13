package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// wtiWithRules appends the commands to the rendering's list (the lines of a
// permit list with services, or a plain entry).
func wtiWithRules(rules ...string) func([]devices.Section) []devices.Section {
	return func(exp []devices.Section) []devices.Section {
		out := slices.Clone(exp)
		for i, s := range out {
			if s.Name != devconf.SectionMgmtACL {
				continue
			}
			c := s
			c.Lines = slices.Clone(s.Lines)
			c.Secret = slices.Clone(s.Secret)
			for _, r := range rules {
				c.Lines = append(c.Lines, r)
				c.Secret = append(c.Secret, false)
			}
			out[i] = c
		}
		return out
	}
}

// A plain entry of the permit list renders as a rule for every protocol and
// port, and the report says how many there are when the list is pasted.
func TestWTIPlainPermitsAreNoted(t *testing.T) {
	c := wtiCase{name: "plain", edits: [][2]string{{wtiRWSet, wtiRWUnset}},
		exp: wtiWithRules("iptables -A INPUT -s 10.2.0.0/16 -j ACCEPT", "iptables -A INPUT -s 10.3.0.0/16 -j ACCEPT")}
	p := planWTICase(t, c, "")
	if p.d.WTI.Block == nil {
		t.Fatalf("no block: %+v", p.d.Of(devconf.SectionMgmtACL))
	}
	var note string
	for _, n := range p.d.Notes {
		if strings.Contains(n, "plain permit") {
			note = n
		}
	}
	for _, want := range []string{"2 plain permits of the rendered list allow every protocol and port",
		"(10.2.0.0/16, 10.3.0.0/16)", "<cidr>:tcp/22 in the management permit list restricts a permit to ssh"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note %q lacks %q", note, want)
		}
	}

	// one is singular
	c.exp = wtiWithRules("iptables -A INPUT -s 10.2.0.0/16 -j ACCEPT")
	p = planWTICase(t, c, "")
	if !slices.ContainsFunc(p.d.Notes, func(n string) bool {
		return strings.HasPrefix(n, "1 plain permit of the rendered list allows every protocol and port")
	}) {
		t.Errorf("notes: %q", p.d.Notes)
	}

	// no plain entry, no note; a rule with a protocol is no plain entry
	c.exp = wtiWithRules("iptables -A INPUT -p udp -s 10.2.0.0/16 -j ACCEPT", "iptables -A INPUT -p tcp -s 10.2.0.0/16 --dport 20:30 -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 10.2.0.0/16 -p icmp -j ACCEPT")
	p = planWTICase(t, c, "")
	for _, n := range p.d.Notes {
		if strings.Contains(n, "plain permit") {
			t.Errorf("a note without a plain entry: %q", n)
		}
	}

	// an unchanged list (nothing to paste) has no note
	exp := wtiLabRendering(t)
	cur, err := devconf.Extract("wti", wtiDocument(t, [][2]string{{wtiRWSet, wtiRWUnset}}), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Plan("wti", exp, cur, devconf.Extracted{}, wtiOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range d.Notes {
		if strings.Contains(n, "plain permit") {
			t.Errorf("a note for a list that matches: %q", n)
		}
	}
}

// The check that tacctl's own ssh stays reachable reads every shape of rule
// that lets tcp 22 through: the port, a range that holds it, every tcp port
// and every protocol.
func TestWTIPermitsReadsServiceRules(t *testing.T) {
	for _, c := range []struct {
		rule string
		addr string
		want bool
	}{
		{"iptables -A INPUT -p tcp -s 10.0.0.42/32 --dport 22 -j ACCEPT", "10.0.0.42", true},
		{"iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT", "10.0.0.42", true},
		{"iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT", "192.0.2.1", false},
		{"iptables -A INPUT -p tcp -s 10.0.0.0/8 -j ACCEPT", "10.0.0.42", true},
		{"iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 20:30 -j ACCEPT", "10.0.0.42", true},
		{"iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22:30 -j ACCEPT", "10.0.0.42", true},
		{"iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 23:30 -j ACCEPT", "10.0.0.42", false},
		{"iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 443 -j ACCEPT", "10.0.0.42", false},
		{"iptables -A INPUT -p udp -s 10.0.0.0/8 -j ACCEPT", "10.0.0.42", false},
		{"iptables -A INPUT -p udp -s 10.0.0.0/8 --dport 22 -j ACCEPT", "10.0.0.42", false},
		{"iptables -A INPUT -i eth0 -s 10.0.0.0/8 -p icmp -j ACCEPT", "10.0.0.42", false},
		{"iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j DROP", "10.0.0.42", false},
		{"iptables -A INPUT -i lo -j ACCEPT", "10.0.0.42", false},
	} {
		if got := wtiPermits([]string{c.rule}, c.addr); got != c.want {
			t.Errorf("%s for %s: %v", c.rule, c.addr, got)
		}
	}
}
