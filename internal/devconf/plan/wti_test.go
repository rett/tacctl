package plan

// The plan of a WTI unit (0.2.7): goldens of the whole output, the JSON and
// the back-out for a unit made from the captured lab unit
// (tests/fixtures/devconf/wti/lab-unit) with a few of its screens edited, and
// the properties every output has: the only lines that are not comments are
// the lines of the one <iptables> block between its banners, a secret is
// never typed without --secrets, and a plan that is applied to the unit
// leaves nothing to plan.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/wti"
	"github.com/rett/tacctl/internal/devices"
)

const (
	wtiSecretValue    = "lab-secret-0123456789abcdef"
	wtiCommunityValue = "SENTINELro9f3a"
	wtiRWValue        = "SENTINELrw9f3a"
	wtiOtherValue     = "SENTINELother9f3a"
)

// the screens' lines the cases edit.
const (
	wtiSecondaryEmpty   = "3.  Secondary host/address:\n"
	wtiSecondarySet     = "3.  Secondary host/address:     192.0.2.50\n"
	wtiFallbackOK       = "6.  Fallback Local:             On (Transport failure)"
	wtiFallbackAll      = "6.  Fallback Local:             On (All failures)"
	wtiRWSet            = "8. Read/Write Community:   rw-community"
	wtiRWUnset          = "8. Read/Write Community:   (undefined)"
	wtiEntry9           = "9.  iptables -A INPUT -s 10.0.30.0/24 -p tcp --dport 22 -j ACCEPT"
	wtiEntry9Changed    = "9.  iptables -A INPUT -s 10.0.31.0/24 -p tcp --dport 22 -j ACCEPT"
	wtiEntry3           = "3.  iptables -A INPUT -s 10.1.100.0/23 -p tcp --dport 22 -j ACCEPT"
	wtiEntry4           = "4.  iptables -A INPUT -s 10.0.20.0/24 -p tcp --dport 22 -j ACCEPT"
	wtiEntry3Swapped    = "3.  iptables -A INPUT -s 10.0.20.0/24 -p tcp --dport 22 -j ACCEPT"
	wtiEntry4Swapped    = "4.  iptables -A INPUT -s 10.1.100.0/23 -p tcp --dport 22 -j ACCEPT"
	wtiSecretDefined    = "4.  Secret Word:                (defined)"
	wtiSecretUndefined  = "4.  Secret Word:                (undefined)"
	wtiPrimary          = "2.  Primary host/address:       192.0.2.42"
	wtiPrimaryOther     = "2.  Primary host/address:       192.0.2.99"
	wtiROCommunity      = "7. Read-Only Community:    ro-community"
	wtiROCommunityOther = "7. Read-Only Community:    SENTINELother9f3a"
	wtiRadiusOff        = "1.  Enable:                     Off\n2.  Primary Host/Address:       (undefined)"
	wtiRadiusOn         = "1.  Enable:                     On\n2.  Primary Host/Address:       198.51.100.9"
)

var wtiTail = []string{
	"21. iptables -A INPUT -j DROP", "22. iptables -A OUTPUT -j ACCEPT", "23. iptables -P INPUT DROP",
	"24. iptables -P OUTPUT DROP", "25. iptables -P FORWARD DROP",
}

// wtiCase is one unit of the goldens: the lab unit's document with edits, the
// options, and an edit of the rendering.
type wtiCase struct {
	name  string
	edits [][2]string
	opt   func(*Options)
	exp   func([]devices.Section) []devices.Section
	// variants are the secrets options planned beside the default
	variants []string
}

// wtiEdits are the edits of a document, each applied once.
func wtiDocument(t testing.TB, edits [][2]string) string {
	t.Helper()
	doc := capture(t, "wti/lab-unit/document.txt")
	for _, e := range edits {
		if strings.Count(doc, e[0]) != 1 {
			t.Fatalf("the lab unit's document has %d of %q, want 1", strings.Count(doc, e[0]), e[0])
		}
		doc = strings.Replace(doc, e[0], e[1], 1)
	}
	// the unit's communities are strings no other text holds, so that a
	// test can tell a value from a word of a key
	doc = regexp.MustCompile(`(?m)(Community:\s+)ro-community$`).ReplaceAllString(doc, "${1}"+wtiCommunityValue)
	doc = regexp.MustCompile(`(?m)(Read/Write Community:\s+)rw-community$`).ReplaceAllString(doc, "${1}"+wtiRWValue)
	return doc
}

func emptySlots(lines ...string) [][2]string {
	var out [][2]string
	for _, l := range lines {
		n, _, _ := strings.Cut(l, " ")
		out = append(out, [2]string{l, n})
	}
	return out
}

func wtiCases() []wtiCase {
	irregular := [][2]string{{wtiSecondaryEmpty, wtiSecondarySet}, {wtiFallbackOK, wtiFallbackAll}}
	consistent := [][2]string{{wtiRWSet, wtiRWUnset}}
	entry := [][2]string{{wtiEntry9, wtiEntry9Changed}}
	return []wtiCase{
		{name: "consistent", edits: consistent},
		{name: "three-irregularities", edits: irregular},
		{name: "iptables-tail", edits: slices.Concat(irregular, entry)},
		{name: "iptables-notail", edits: slices.Concat(consistent, entry, emptySlots(wtiTail...))},
		{name: "iptables-reordered", edits: slices.Concat(consistent, [][2]string{{wtiEntry3, wtiEntry3Swapped}, {wtiEntry4, wtiEntry4Swapped}})},
		{name: "iptables-empty", edits: slices.Concat(consistent, emptySlots(wtiTail...), [][2]string{
			{"1.  iptables -A INPUT -i lo -j ACCEPT", "1."},
			{"2.  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", "2."},
			{wtiEntry3, "3."}, {wtiEntry4, "4."},
			{"5.  iptables -A INPUT -s 10.0.28.34 -p tcp --dport 22 -j ACCEPT", "5."},
			{"6.  iptables -A INPUT -s 10.0.28.34 -p udp --dport 161:162 -j ACCEPT", "6."},
			{"7.  iptables -A INPUT -s 10.0.28.36 -p tcp --dport 22 -j ACCEPT", "7."},
			{"8.  iptables -A INPUT -s 10.0.28.36 -p udp --dport 161:162 -j ACCEPT", "8."},
			{wtiEntry9, "9."},
			{"10. iptables -A INPUT -s 10.0.40.0/24 -p tcp --dport 22 -j ACCEPT", "10."},
			{"11. iptables -A INPUT -s 10.0.50.0/24 -p tcp --dport 22 -j ACCEPT", "11."},
			{"12. iptables -A INPUT -s 10.0.60.0/24 -p tcp --dport 22 -j ACCEPT", "12."},
			{"13. iptables -A INPUT -s 10.0.70.0/24 -p tcp --dport 22 -j ACCEPT", "13."},
			{"14. iptables -A INPUT -s 10.0.90.0/24 -p tcp --dport 22 -j ACCEPT", "14."},
			{"15. iptables -A INPUT -s 10.0.120.0/24 -p tcp --dport 22 -j ACCEPT", "15."},
			{"16. iptables -A INPUT -s 192.0.2.14 -p udp --dport 161:162 -j ACCEPT", "16."},
			{"17. iptables -A INPUT -s 10.1.101.0/24 -p udp --dport 161 -j ACCEPT", "17."},
			{"18. iptables -A INPUT -i eth0 -s 10.1.100.0/23 -p icmp -j ACCEPT", "18."},
			{"19. iptables -A INPUT -i eth0 -s 10.0.0.0/16 -p icmp -j ACCEPT", "19."},
			{"20. iptables -A INPUT -i eth0 -s 192.0.2.14 -p icmp -j ACCEPT", "20."},
		})},
		{name: "from-refused", edits: slices.Concat(irregular, entry), opt: func(o *Options) { o.From = "198.51.100.77" }},
		{name: "from-permitted", edits: slices.Concat(irregular, entry), opt: func(o *Options) { o.From = "10.0.20.15" }},
		{name: "over-48", edits: consistent, exp: wtiWithPermits(30)},
		{name: "secrets", edits: [][2]string{{wtiSecretDefined, wtiSecretUndefined}, {wtiPrimary, wtiPrimaryOther}, {wtiROCommunity, wtiROCommunityOther}, {wtiRWSet, wtiRWUnset}},
			variants: []string{"nosecrets", "secrets"}},
		{name: "secrets-rotate", edits: consistent, opt: func(o *Options) { o.Secrets = true }},
		{name: "radius-on", edits: slices.Concat(consistent, [][2]string{{wtiRadiusOff, wtiRadiusOn}})},
		{name: "converge", edits: nil, opt: func(o *Options) { o.Converge = true }},
		{name: "converge-radius-on", edits: slices.Concat(consistent, [][2]string{{wtiRadiusOff, wtiRadiusOn}}), opt: func(o *Options) { o.Converge = true }},
		{name: "converge-deferred", edits: irregular, opt: func(o *Options) { o.Converge = true }},
		{name: "no-list-server-unknown", edits: consistent, exp: dropSection(devconf.SectionMgmtACL),
			opt: func(o *Options) {
				o.WTI.Server, o.WTI.ListWhy = "", "tacctl server address is not known (pass --source <address>)"
			}},
	}
}

// wtiWithPermits adds n permitted networks to the rendering's list, before
// its ICMP lines.
func wtiWithPermits(n int) func([]devices.Section) []devices.Section {
	return func(exp []devices.Section) []devices.Section {
		out := slices.Clone(exp)
		for i, s := range out {
			if s.Name != devconf.SectionMgmtACL {
				continue
			}
			c := s
			c.Lines = slices.Clone(s.Lines)
			c.Secret = slices.Clone(s.Secret)
			for k := 0; k < n; k++ {
				c.Lines = append(c.Lines, fmt.Sprintf("iptables -A INPUT -s 10.2.%d.0/24 -p tcp --dport 22 -j ACCEPT", k))
				c.Secret = append(c.Secret, false)
			}
			out[i] = c
		}
		return out
	}
}

func dropSection(name string) func([]devices.Section) []devices.Section {
	return func(exp []devices.Section) []devices.Section {
		var out []devices.Section
		for _, s := range exp {
			if s.Name != name {
				out = append(out, s)
			}
		}
		return out
	}
}

// wtiLabRendering is the lab unit's rendering with the community the document
// holds.
func wtiLabRendering(t testing.TB) []devices.Section {
	t.Helper()
	exp := expectedSections(t, "wti/lab-unit/expected.txt")
	for i, s := range exp {
		for j, l := range s.Lines {
			if l == "snmp ro-community ro-community" {
				exp[i].Lines[j] = "snmp ro-community " + wtiCommunityValue
			}
		}
	}
	return exp
}

func wtiHeader(name string) Header {
	return Header{Device: "lab-unit", Address: "192.0.2.21", Scope: "lab", Vendor: "wti", Protocol: "TACACS+",
		Pulled: tPull, PulledBy: "alice", Transport: "ssh", SecretsVisible: true, Now: tNow, Version: "0.2.7", User: "alice", StaleDays: 7,
		Unit: &UnitInfo{Version: "8.10", SiteID: "wti.site.example.net", OtherSessions: 1}}
}

func wtiOptions() Options {
	n := 1
	return Options{Scope: "lab", WTI: WTIFacts{Server: "10.0.28.34", OtherSessions: &n}}
}

// wtiPlanned is a planned case: the rendering, the pulled extraction, the
// delta and the header.
type wtiPlanned struct {
	name string
	exp  []devices.Section
	cur  devconf.Extracted
	d    Delta
	h    Header
	opt  Options
}

func planWTICase(t testing.TB, c wtiCase, variant string) wtiPlanned {
	t.Helper()
	exp := wtiLabRendering(t)
	if c.exp != nil {
		exp = c.exp(exp)
	}
	cur, err := devconf.Extract("wti", wtiDocument(t, c.edits), exp...)
	if err != nil {
		t.Fatal(err)
	}
	opt := wtiOptions()
	if c.opt != nil {
		c.opt(&opt)
	}
	switch variant {
	case "secrets":
		opt.Secrets = true
	case "nosecrets":
		opt.NoSecrets = true
	}
	d, err := Plan("wti", exp, cur, devconf.Extracted{}, opt)
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	name := c.name
	if variant != "" {
		name += "." + variant
	}
	return wtiPlanned{name: name, exp: exp, cur: cur, d: d, h: wtiHeader(name), opt: opt}
}

func allWTIPlans(t testing.TB) []wtiPlanned {
	t.Helper()
	var out []wtiPlanned
	for _, c := range wtiCases() {
		out = append(out, planWTICase(t, c, ""))
		for _, v := range c.variants {
			out = append(out, planWTICase(t, c, v))
		}
	}
	return out
}

// wtiGoldenFiles are the goldens of the unit's plans: the whole output, the
// JSON and the back-out of each case, and the cover page of a mixed run.
func wtiGoldenFiles(t testing.TB) []goldenFile {
	t.Helper()
	var out []goldenFile
	w := Wrapper{}
	for _, p := range allWTIPlans(t) {
		out = append(out, goldenFile{"wti." + p.name + ".output.txt", Block(p.d, p.h, w)})
		js, err := JSON(p.d, p.h, w)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, goldenFile{"wti." + p.name + ".json", string(js) + "\n"})
		if bo, err := Backout(p.d, p.h, w); err == nil {
			out = append(out, goldenFile{"wti." + p.name + ".backout.txt", bo})
		} else if !errors.Is(err, ErrNoBackout) {
			t.Fatal(err)
		}
	}
	return append(out, wtiCoverFiles(t)...)
}

// wtiCoverFiles are the cover page of a Junos device and units, one of them
// not pulled.
func wtiCoverFiles(t testing.TB) []goldenFile {
	t.Helper()
	f := fixtureByName(t, "juniper.synthetic-lab")
	exp, cur, plain := f.load(t)
	jd, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	sts := []DeviceStatus{StatusFor(jd, f.header())}
	plans := allWTIPlans(t)
	for _, name := range []string{"consistent", "three-irregularities", "iptables-tail", "from-refused", "over-48"} {
		for _, p := range plans {
			if p.name == name {
				h := p.h
				h.Device = "unit-" + name
				sts = append(sts, StatusFor(p.d, h))
			}
		}
	}
	sts = append(sts, CannotPlan(Header{Device: "unit-not-pulled", Scope: "lab", Vendor: "wti"}, "not pulled"))
	js, err := json.MarshalIndent(sts, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return []goldenFile{{"wti.cover.txt", Cover(sts)}, {"wti.cover.json", string(js) + "\n"}}
}

func TestWTIGoldens(t *testing.T) {
	for _, f := range wtiGoldenFiles(t) {
		golden(t, f.name, f.content)
	}
}

var reWTIBlockOnly = regexp.MustCompile(`^(</?iptables>|iptables -[AP] .{1,250})$`)

// Every non-comment line of a whole unit's output lies inside the IP tables
// banners and is a line of the block.
func TestWTIOnlyTheBlockIsNotAComment(t *testing.T) {
	for _, p := range allWTIPlans(t) {
		outs := map[string]string{"output": Block(p.d, p.h, Wrapper{})}
		if bo, err := Backout(p.d, p.h, Wrapper{}); err == nil {
			outs["backout"] = bo
		}
		for what, out := range outs {
			inside := false
			for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
				switch {
				case strings.HasPrefix(l, "##### IP TABLES") || strings.HasPrefix(l, "##### BACK-OUT, IP TABLES"):
					inside = true
				case strings.HasPrefix(l, "##### END OF IP TABLES"):
					inside = false
				case strings.HasPrefix(l, "#"):
				case !inside:
					t.Errorf("%s %s: %q is not a comment and not inside the IP tables banners", p.name, what, l)
				case !reWTIBlockOnly.MatchString(l):
					t.Errorf("%s %s: %q is not a line of the block", p.name, what, l)
				}
			}
			if err := CheckRegion("wti", strings.Split(strings.TrimRight(out, "\n"), "\n")); err != nil {
				t.Errorf("%s %s: %v", p.name, what, err)
			}
		}
		// the region the CLI checks, and the cleanup's
		var texts []string
		for _, l := range RegionLines(p.d, p.h, Wrapper{}) {
			texts = append(texts, l.Text)
		}
		if len(texts) > 1 {
			if err := CheckRegion("wti", texts); err != nil {
				t.Errorf("%s: region: %v", p.name, err)
			}
		}
	}
}

// A secret is never typed without --secrets, and with it the sensitivity
// line says so; the JSON holds no value in any case.
func TestWTINeverTypesASecretWithoutTheFlag(t *testing.T) {
	values := []string{wtiSecretValue, wtiCommunityValue, wtiOtherValue, wtiRWValue}
	for _, p := range allWTIPlans(t) {
		out := Block(p.d, p.h, Wrapper{})
		bo, _ := Backout(p.d, p.h, Wrapper{})
		js, err := JSON(p.d, p.h, Wrapper{})
		if err != nil {
			t.Fatal(err)
		}
		if p.opt.Secrets {
			if !p.d.HoldsSecret() {
				t.Errorf("%s: --secrets and no secret typed", p.name)
				continue
			}
			if !strings.Contains(out, "THIS OUTPUT HOLDS THE ") || !strings.Contains(out, "OF SCOPE lab") {
				t.Errorf("%s: a secret is typed and the output does not say so:\n%s", p.name, out)
			}
			if !strings.Contains(out, wtiSecretValue) && !strings.Contains(out, wtiCommunityValue) {
				t.Errorf("%s: --secrets typed no value", p.name)
			}
		} else {
			for _, v := range values {
				if strings.Contains(out, v) {
					t.Errorf("%s: %q is in the output without --secrets", p.name, v)
				}
			}
			if p.d.HoldsSecret() || strings.Contains(out, "THIS OUTPUT HOLDS") {
				t.Errorf("%s: holds a secret without --secrets", p.name)
			}
		}
		for _, v := range []string{wtiSecretValue, wtiOtherValue, wtiRWValue} {
			if strings.Contains(string(js), v) || strings.Contains(bo, v) {
				t.Errorf("%s: %q in the JSON or the back-out", p.name, v)
			}
		}
		if strings.Contains(string(js), wtiCommunityValue) || strings.Contains(bo, wtiCommunityValue) {
			t.Errorf("%s: the community in the JSON or the back-out", p.name)
		}
	}
}

// Applying a plan to the unit's pulled sections leaves nothing the plan
// could fix: the compared sections are ok afterwards.
func TestWTIPlanConverges(t *testing.T) {
	for _, p := range allWTIPlans(t) {
		if p.d.Empty() {
			continue
		}
		got := applyWTI(t, p)
		rs, err := devconf.CompareAll(p.exp, got)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			sp := p.d.Of(r.Name)
			if r.Name == devconf.SectionBreakGlass || sp.State != StatePlanned {
				continue
			}
			for _, l := range r.Lines {
				if l.Op == devconf.OpMissing || l.Op == devconf.OpOrder {
					t.Errorf("%s: after the plan, section %s still has %c %s", p.name, r.Name, l.Op, l.Text)
				}
				if l.Op == devconf.OpExtra && !l.Unmanaged && r.Name == devconf.SectionMgmtACL {
					t.Errorf("%s: after the plan the list still has the extra %s", p.name, l.Text)
				}
			}
		}
	}
}

// applyWTI applies a plan's steps and block to the pulled sections: the
// in-memory editor of a unit.
func applyWTI(t testing.TB, p wtiPlanned) devconf.Extracted {
	t.Helper()
	out := devconf.Extracted{Vendor: devconf.FamilyWTI, SecretsVisible: true, Sections: map[string]devices.Section{}}
	for n, s := range p.cur.Sections {
		c := s
		c.Lines = slices.Clone(s.Lines)
		c.Secret = nil
		out.Sections[n] = c
	}
	rendered := map[string]string{}
	for _, s := range p.exp {
		for _, l := range s.Lines {
			c := wti.ParseLine(l)
			if c.Form == wti.FormSecret {
				rendered[c.Key] = l
			} else if c.Key != "" {
				rendered[c.Key] = c.Key + " " + c.Value
			}
		}
	}
	for _, st := range p.d.WTI.Steps {
		sec := out.Sections[st.Section]
		var keep []string
		for _, l := range sec.Lines {
			if wtiKeyOf(l) != st.Key {
				keep = append(keep, l)
			}
		}
		if !st.Clear {
			line := st.Key + " " + st.Value
			if st.Secret {
				line = rendered[st.Key]
			}
			keep = append(keep, line)
		}
		sec.Lines = keep
		out.Sections[st.Section] = sec
	}
	if b := p.d.WTI.Block; b != nil {
		sec := out.Sections[devconf.SectionMgmtACL]
		sec.Lines = slices.Concat(b.Commands, b.Tail)
		out.Sections[devconf.SectionMgmtACL] = sec
	}
	return out
}

// A unit's plan of a section the unit has not, a plan with neither flag
// for a secret: the errors.
func TestWTIRefusesSectionsTheUnitHasNot(t *testing.T) {
	exp := wtiLabRendering(t)
	cur, err := devconf.Extract("wti", wtiDocument(t, nil), exp...)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"roles", "system"} {
		o := wtiOptions()
		o.Sections = []string{s}
		if _, err := Plan("wti", exp, cur, devconf.Extracted{}, o); !errors.Is(err, ErrUsage) {
			t.Errorf("--section %s: %v", s, err)
		}
	}
	for _, s := range []string{"netconf", "breakglass"} {
		o := wtiOptions()
		o.Sections = []string{s}
		if _, err := Plan("wti", exp, cur, devconf.Extracted{}, o); !errors.Is(err, ErrNeverEmitted) {
			t.Errorf("--section %s: %v", s, err)
		}
	}
	o := wtiOptions()
	o.Secrets, o.NoSecrets = true, true
	if _, err := Plan("wti", exp, cur, devconf.Extracted{}, o); !errors.Is(err, ErrUsage) {
		t.Errorf("both secret flags: %v", err)
	}
	d, err := Plan("wti", exp, cur, devconf.Extracted{}, wtiOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Plain(d, wtiHeader("x"), Wrapper{}); !errors.Is(err, ErrWTIPlain) {
		t.Errorf("Plain: %v", err)
	}
}

// --section limits a unit's plan to the sections named.
func TestWTISectionSelects(t *testing.T) {
	c := wtiCases()[2] // iptables-tail: aaa, snmp (finding) and mgmt-acl
	exp := wtiLabRendering(t)
	cur, err := devconf.Extract("wti", wtiDocument(t, c.edits), exp...)
	if err != nil {
		t.Fatal(err)
	}
	for _, sel := range []struct {
		sections []string
		want     []string
	}{
		{[]string{"aaa"}, []string{"aaa"}},
		{[]string{"mgmt-acl"}, []string{"mgmt-acl"}},
		{[]string{"snmp"}, nil},
		{[]string{"aaa", "mgmt-acl"}, []string{"aaa", "mgmt-acl"}},
	} {
		o := wtiOptions()
		o.Sections = sel.sections
		d, err := Plan("wti", exp, cur, devconf.Extracted{}, o)
		if err != nil {
			t.Fatal(err)
		}
		if got := d.Planned(); !slices.Equal(got, sel.want) {
			t.Errorf("--section %v: planned %v, want %v", sel.sections, got, sel.want)
		}
	}
}

// The steps' order: the lock-out safe order of the design, page 25 first,
// the secret first on the AAA page and its switch last.
func TestWTIStepOrder(t *testing.T) {
	c := wtiCases()[11] // secrets: the secret, the primary host and the community
	p := planWTICase(t, wtiCase{name: "order", edits: [][2]string{{wtiSecretDefined, wtiSecretUndefined}, {wtiPrimary, wtiPrimaryOther},
		{wtiROCommunity, wtiROCommunityOther}, {wtiFallbackOK, wtiFallbackAll}, {wtiRWSet, wtiRWUnset}}}, "")
	_ = c
	var got []string
	for _, s := range p.d.WTI.Steps {
		got = append(got, s.Key)
	}
	want := []string{"snmp ro-community", "tacacs secret", "tacacs primary", "tacacs fallback-local"}
	if !slices.Equal(got, want) {
		t.Errorf("steps %v, want %v", got, want)
	}
	// the secret is typed by its placeholder
	for _, s := range p.d.WTI.Steps {
		if s.Secret && !strings.HasPrefix(s.Enter, "<the scope's ") {
			t.Errorf("step %s enters %q", s.Key, s.Enter)
		}
	}
}

// A refused IP tables section says why and the rest still plans; each guard
// of the design has a case.
func TestWTIListGuards(t *testing.T) {
	byName := map[string]wtiPlanned{}
	for _, p := range allWTIPlans(t) {
		byName[p.name] = p
	}
	check := func(name, want string) {
		t.Helper()
		p := byName[name]
		sp := p.d.Of(devconf.SectionMgmtACL)
		if sp.State != StateSkipped || !strings.Contains(sp.Why, want) {
			t.Errorf("%s: mgmt-acl %s %q, want a refusal naming %q", name, sp.State, sp.Why, want)
		}
		if p.d.WTI.Block != nil {
			t.Errorf("%s: a block of a refused list", name)
		}
		out := Block(p.d, p.h, Wrapper{})
		if strings.Contains(out, "<iptables>") {
			t.Errorf("%s: a block in the output of a refused list", name)
		}
	}
	check("from-refused", "198.51.100.77 is not permitted")
	check("over-48", "55 entries")
	check("no-list-server-unknown", "cannot be built")
	// the rest still plans: the AAA step of the three irregularities
	if p := byName["from-refused"]; len(p.d.WTI.Steps) != 1 || p.d.Of(devconf.SectionAAA).State != StatePlanned {
		t.Errorf("from-refused: the steps %v", p.d.WTI.Steps)
	}
	// permitted --from: planned
	if p := byName["from-permitted"]; p.d.WTI.Block == nil {
		t.Errorf("from-permitted: no block")
	}
	// a list without a tail says so, and a list with one keeps it
	if p := byName["iptables-notail"]; p.d.WTI.Block == nil || len(p.d.WTI.Block.Tail) != 0 ||
		!slices.Contains(p.d.Warnings, devconf.NoteWTINoTail) {
		t.Errorf("iptables-notail: %+v %v", p.d.WTI.Block, p.d.Warnings)
	}
	if p := byName["iptables-tail"]; p.d.WTI.Block == nil || len(p.d.WTI.Block.Tail) != 5 ||
		!slices.Equal(p.d.WTI.Block.Tail[len(p.d.WTI.Block.Tail)-1:], []string{"iptables -P FORWARD DROP"}) {
		t.Errorf("iptables-tail: %+v", p.d.WTI.Block)
	}
	// the other sessions are a warning, never a refusal
	if p := byName["iptables-tail"]; !slices.ContainsFunc(p.d.Warnings, func(w string) bool { return strings.Contains(w, "1 other session") }) {
		t.Errorf("no warning of the other session: %v", p.d.Warnings)
	}
	// an empty list is replaced and its back-out clears the slots
	p := byName["iptables-empty"]
	bo, err := Backout(p.d, p.h, Wrapper{})
	if err != nil || !strings.Contains(bo, "<SPACE><CR>") || strings.Contains(bo, "<iptables>") {
		t.Errorf("iptables-empty back-out: %v\n%s", err, bo)
	}
}

// --converge offers the read/write community and the other protocol's
// switch only, and only for a unit with nothing else to type.
func TestWTIConverge(t *testing.T) {
	by := map[string]wtiPlanned{}
	for _, p := range allWTIPlans(t) {
		by[p.name] = p
	}
	p := by["converge"]
	if len(p.d.WTI.CleanupSteps) != 1 || p.d.WTI.CleanupSteps[0].Keys != "/N 25 8" || p.d.WTI.CleanupSteps[0].Enter != "<SPACE><CR>" {
		t.Errorf("converge: %+v", p.d.WTI.CleanupSteps)
	}
	p = by["converge-radius-on"]
	var keys []string
	for _, s := range p.d.WTI.CleanupSteps {
		keys = append(keys, s.Keys)
	}
	if !slices.Equal(keys, []string{"/N 29 1"}) {
		t.Errorf("converge-radius-on: %v", keys)
	}
	if p := by["converge-deferred"]; p.d.Cleanup.Deferred == "" || !p.d.Cleanup.Empty() {
		t.Errorf("converge-deferred: %+v", p.d.Cleanup)
	}
}

// Every statement of a unit's plan reads in plain words, and no step is
// typed for a statement the ownership table does not own.
func TestWTIStepsAreOwned(t *testing.T) {
	for _, p := range allWTIPlans(t) {
		for _, st := range p.d.WTI.Steps {
			if row := WTIRowID(st.Section, st.Key+" "+st.Value, p.d.WTI.Proto); row == "" || strings.Contains(row, "unrendered") || strings.Contains(row, "inactive") {
				t.Errorf("%s: step %s %s is of row %q", p.name, st.Key, st.Value, row)
			}
		}
		for _, it := range p.d.Items {
			if it.Words == "" || it.Severity == "" {
				t.Errorf("%s: item %+v", p.name, it)
			}
		}
	}
}

// Each setting of the unit's pages that differs from the rendering is one
// step, and the steps, applied to the pulled sections, leave nothing to plan.
func TestWTIEachSettingIsPlanned(t *testing.T) {
	tacacs := "TACACS: [Shared]\n\n"
	for _, c := range []struct {
		name  string
		edits [][2]string
		key   string
		enter string
	}{
		{"tacacs enable", [][2]string{{tacacs + "1.  Enable:                     On", tacacs + "1.  Enable:                     Off"}}, "tacacs enable", "2 (On)"},
		{"tacacs primary", [][2]string{{wtiPrimary, "2.  Primary host/address:       192.0.2.77"}}, "tacacs primary", "1 (IPv4), then 192.0.2.42"},
		{"tacacs fallback-timer", [][2]string{{"5.  Fallback Timer:             15 Sec", "5.  Fallback Timer:             30 Sec"}}, "tacacs fallback-timer", "15"},
		{"tacacs fallback-local", [][2]string{{wtiFallbackOK, "6.  Fallback Local:             Off"}}, "tacacs fallback-local", "3 (On (Transport failure))"},
		{"tacacs port", [][2]string{{"7.  Authentication Port:        49", "7.  Authentication Port:        4949"}}, "tacacs port", "49"},
		{"tacacs default-access", [][2]string{{"8.  Default User Access:        On", "8.  Default User Access:        Off"}}, "tacacs default-access", "On"},
		{"tacacs account-module", [][2]string{{"9.  Account Management Module:  Enabled", "9.  Account Management Module:  Disabled"}}, "tacacs account-module", "2 (Enabled)"},
		{"tacacs session-module", [][2]string{{"10  Session Management Module:  Enabled", "10  Session Management Module:  Disabled"}}, "tacacs session-module", "2 (Enabled)"},
		{"tacacs service-name", [][2]string{{"11. Service Name:               wti", "11. Service Name:               shell"}}, "tacacs service-name", "wti"},
		{"tacacs debug", [][2]string{{"12. Debug:                      Off\n13. Ping Test\n\n\nEnter: #<CR> to change,\n       <ESC> to return to previous menu ... \n# page: /N > 28 > 8", "12. Debug:                      On\n13. Ping Test\n\n\nEnter: #<CR> to change,\n       <ESC> to return to previous menu ... \n# page: /N > 28 > 8"}}, "tacacs debug", "1 (Off)"},
		{"tacacs default-level", [][2]string{{"2.  Access Level:         View Only\n3.  Port Access:          (defined)\n4.  Service Access:       Serial Port, Telnet/SSH, Web, RESTful API\n\n\nEnter: #<CR> to change,\n       <ESC> to return to previous menu ... \n# page: /N > 29\n", "2.  Access Level:         User\n3.  Port Access:          (defined)\n4.  Service Access:       Serial Port, Telnet/SSH, Web, RESTful API\n\n\nEnter: #<CR> to change,\n       <ESC> to return to previous menu ... \n# page: /N > 29\n"}}, "tacacs default-level", "View Only"},
		{"snmp enable", [][2]string{{"1. Enable:                 On", "1. Enable:                 Off"}}, "snmp enable", "2 (On)"},
		{"snmp version", [][2]string{{"2. Version:                V1/V2 Only", "2. Version:                V3"}}, "snmp version", "1 (V1/V2 Only)"},
		{"snmp read-only", [][2]string{{"3. Read Only:              Yes", "3. Read Only:              No"}}, "snmp read-only", "Yes"},
		{"snmp contact", [][2]string{{"5. Contact:                Example NOC", "5. Contact:                Other NOC"}}, "snmp contact", "Example NOC"},
		{"snmp location", [][2]string{{"6. SNMP Location:          Example City", "6. SNMP Location:          Elsewhere"}}, "snmp location", "Example City"},
		{"snmp ro-community", [][2]string{{wtiROCommunity, wtiROCommunityOther}}, "snmp ro-community", "<the scope's SNMP community: tacctl scope snmp lab show --reveal>"},
		{"tacacs secret", [][2]string{{wtiSecretDefined, wtiSecretUndefined}}, "tacacs secret", "<the scope's TACACS+ secret: tacctl scope secret show lab>"},
	} {
		edits := slices.Concat([][2]string{{wtiRWSet, wtiRWUnset}}, c.edits)
		p := planWTICase(t, wtiCase{name: c.name, edits: edits}, "")
		if len(p.d.WTI.Steps) != 1 {
			t.Errorf("%s: %d steps, want 1: %v", c.name, len(p.d.WTI.Steps), p.d.WTI.Steps)
			continue
		}
		st := p.d.WTI.Steps[0]
		if st.Key != c.key || !strings.HasSuffix(st.Enter, c.enter) {
			t.Errorf("%s: step %s -> %q, want %s -> %q", c.name, st.Key, st.Enter, c.key, c.enter)
		}
		if st.Was == "" || st.Keys == "" || st.Label == "" {
			t.Errorf("%s: step %+v", c.name, st)
		}
		if len(p.d.Items) != 1 || !p.d.Items[0].Fixed {
			t.Errorf("%s: items %+v", c.name, p.d.Items)
		}
		got := applyWTI(t, p)
		rs, err := devconf.CompareAll(p.exp, got)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			if r.Name == devconf.SectionBreakGlass {
				continue
			}
			if r.State == devconf.StateDiffers || r.State == devconf.StateMissing {
				t.Errorf("%s: after the step %s is %s: %v", c.name, r.Name, r.State, r.Lines)
			}
		}
	}
}
