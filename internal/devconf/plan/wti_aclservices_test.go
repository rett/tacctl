package plan

import (
	"encoding/json"
	"slices"
	"strconv"
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

// reportHead is the lines of a report before its first blank comment line (the
// box, the basis, the notices that go first).
func reportHead(out string) string {
	head, _, _ := strings.Cut(out, "\n#\n")
	return head
}

// A plain entry of the permit list renders as a rule for every protocol and
// port, and the report names the sources in a WARNING line of its header when
// the list is pasted (not among the notes at the bottom).
func TestWTIPlainPermitsAreWarnedAtTheTop(t *testing.T) {
	c := wtiCase{name: "plain", edits: [][2]string{{wtiRWSet, wtiRWUnset}},
		exp: wtiWithRules("iptables -A INPUT -s 10.2.0.0/16 -j ACCEPT", "iptables -A INPUT -s 10.3.0.0/16 -j ACCEPT")}
	p := planWTICase(t, c, "")
	if p.d.WTI.Block == nil {
		t.Fatalf("no block: %+v", p.d.Of(devconf.SectionMgmtACL))
	}
	out := Block(p.d, p.h, Wrapper{})
	head := reportHead(out)
	var warn string
	for _, l := range strings.Split(head, "\n") {
		if strings.HasPrefix(l, "# WARNING: 2 plain permits") {
			warn = l
		}
	}
	if warn == "" {
		t.Fatalf("no plain-permit WARNING in the header:\n%s", head)
	}
	// the report wraps it; read the whole sentence from the header
	flat := strings.Join(strings.Fields(strings.ReplaceAll(head, "\n# ", " ")), " ")
	for _, want := range []string{"2 plain permits of the rendered list allow every protocol and port",
		"(10.2.0.0/16, 10.3.0.0/16)", "<cidr>:tcp/22 in the management permit list restricts a permit to ssh"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the header lacks %q:\n%s", want, head)
		}
	}
	// said once, and no longer a note at the bottom
	if n := strings.Count(out, "plain permit"); n != 1 {
		t.Errorf("%d mentions of the plain permits in the output, want 1:\n%s", n, out)
	}
	for _, n := range p.d.Notes {
		if strings.Contains(n, "plain permit") {
			t.Errorf("a note: %q", n)
		}
	}
	// the JSON form carries it first among the warnings
	js, err := JSON(p.d, p.h, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Warnings) == 0 || !strings.HasPrefix(doc.Warnings[0], "2 plain permits of the rendered list allow every protocol and port") {
		t.Errorf("warnings: %q", doc.Warnings)
	}

	// one is singular
	c.exp = wtiWithRules("iptables -A INPUT -s 10.2.0.0/16 -j ACCEPT")
	p = planWTICase(t, c, "")
	if h := reportHead(Block(p.d, p.h, Wrapper{})); !strings.Contains(h, "# WARNING: 1 plain permit of the rendered list allows every protocol and port") {
		t.Errorf("header:\n%s", h)
	}

	// no plain entry, no warning; a rule with a protocol is no plain entry
	c.exp = wtiWithRules("iptables -A INPUT -p udp -s 10.2.0.0/16 -j ACCEPT", "iptables -A INPUT -p tcp -s 10.2.0.0/16 --dport 20:30 -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 10.2.0.0/16 -p icmp -j ACCEPT")
	p = planWTICase(t, c, "")
	if out := Block(p.d, p.h, Wrapper{}); strings.Contains(out, "plain permit") {
		t.Errorf("a warning without a plain entry:\n%s", out)
	}

	// an unchanged list (nothing to paste) has no warning
	exp := wtiLabRendering(t)
	cur, err := devconf.Extract("wti", wtiDocument(t, [][2]string{{wtiRWSet, wtiRWUnset}}), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Plan("wti", exp, cur, devconf.Extracted{}, wtiOptions())
	if err != nil {
		t.Fatal(err)
	}
	if out := Block(d, wtiHeader("same"), Wrapper{}); strings.Contains(out, "plain permit") {
		t.Errorf("a warning for a list that matches:\n%s", out)
	}
}

// A plan whose rendered list has plain permits, but whose IP tables paste is
// refused (the list does not fit), pastes none of them and warns of none.
func TestWTIPlainPermitsRefusedBlockHasNoWarning(t *testing.T) {
	rules := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		rules = append(rules, "iptables -A INPUT -s 10.20."+strconv.Itoa(i)+".0/24 -j ACCEPT")
	}
	c := wtiCase{name: "plain-over", edits: [][2]string{{wtiRWSet, wtiRWUnset}}, exp: wtiWithRules(rules...)}
	p := planWTICase(t, c, "")
	if p.d.WTI.Block != nil {
		t.Skip("the list fits; the refusal is not reached")
	}
	if out := Block(p.d, p.h, Wrapper{}); strings.Contains(out, "plain permit") {
		t.Errorf("a warning for a refused paste:\n%s", out)
	}
}

// The back-out of a plan puts the unit's own list back: when that list has
// plain permits the back-out says so in its header, and when it has none it
// says nothing.
func TestWTIBackoutWarnsOfPlainPermitsItPutsBack(t *testing.T) {
	const plain = "9.  iptables -A INPUT -s 10.0.30.0/24 -j ACCEPT"
	c := wtiCase{name: "backout-plain", edits: [][2]string{{wtiRWSet, wtiRWUnset}, {wtiEntry9, plain}}}
	p := planWTICase(t, c, "")
	if p.d.WTI.Block == nil {
		t.Fatalf("no block: %+v", p.d.Of(devconf.SectionMgmtACL))
	}
	bo, err := Backout(p.d, p.h, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(bo, "\n#\n")
	flat := strings.Join(strings.Fields(strings.ReplaceAll(head, "\n# ", " ")), " ")
	for _, want := range []string{"WARNING: 1 plain permit of the list this back-out puts back allows every protocol and port",
		"(10.0.30.0/24)", "restricts a permit to ssh"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the back-out's header lacks %q:\n%s", want, head)
		}
	}
	// the plan's own list has no plain entry here
	if strings.Contains(Block(p.d, p.h, Wrapper{}), "# WARNING: 1 plain permit of the rendered list") {
		t.Errorf("the plan warns of a plain permit its list does not have")
	}

	// a unit's list without plain entries: no warning in the back-out
	c = wtiCase{name: "backout-none", edits: [][2]string{{wtiRWSet, wtiRWUnset}, {wtiEntry9, wtiEntry9Changed}}}
	p = planWTICase(t, c, "")
	bo, err = Backout(p.d, p.h, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bo, "plain permit") {
		t.Errorf("a back-out warning without a plain permit:\n%s", bo)
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
