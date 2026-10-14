package plan

// The shape of a delta (plan D135): the same change has the same shape on
// every device, the order of the delta does not matter, and no secret and no
// per-device value is in a shape's text.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// shapeGolden compares got with tests/fixtures/golden/shape.<name> (-update
// rewrites it).
func shapeGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join(goldenDir, "shape."+name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (go test -run %s -update writes it)", err, t.Name())
	}
	if got != string(want) {
		t.Errorf("shape.%s differs from the golden:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// secretValuesOf returns the values a delta's lines and a rendering hold: the
// words of a value-carrying line that its elided form does not have, and the
// words of a rendered secret statement that its elided stem does not have.
func secretValuesOf(t testing.TB, vendor string, d Delta, exp []devices.Section) []string {
	t.Helper()
	var out []string
	diff := func(full, shown string) {
		sw := splitTokens(shown)
		for _, w := range splitTokens(full) {
			if !slices.Contains(sw, w) && !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
	}
	for _, l := range d.Lines {
		if l.Secret && l.HasValue {
			diff(l.Text, l.Elided)
		}
	}
	for _, s := range exp {
		for i, line := range s.Lines {
			if i >= len(s.Secret) || !s.Secret[i] {
				continue
			}
			stems, err := devconf.ElideIn(vendor, []string{line}, []bool{true}, s.Lines)
			if err != nil {
				t.Fatal(err)
			}
			// a line can expand to several statements: what none of
			// them has is the value
			diff(line, strings.Join(stems, " "))
		}
	}
	return out
}

// identityValuesOf returns the per-device values (the masking table's) of a
// delta's lines and a rendering.
func identityValuesOf(d Delta, exp []devices.Section) []string {
	var out []string
	add := func(family, text string) {
		masked := maskShapeLine(family, text)
		if masked == text {
			return
		}
		toks, mt := splitTokens(text), splitTokens(masked)
		n := len(mt) - 1 // the position of <v>
		if n >= 0 && n < len(toks) {
			out = append(out, strings.Join(toks[n:], " "))
		}
	}
	for _, l := range d.Lines {
		add(d.Vendor, l.Text)
	}
	for _, s := range exp {
		for _, line := range s.Lines {
			add(d.Vendor, strings.TrimSpace(line))
		}
	}
	return out
}

// TestShapeHoldsNoSecret is the canary of D135: every secret value of the
// inputs, and every per-device value the table masks, is searched for in the
// shape's text; one found fails.
func TestShapeHoldsNoSecret(t *testing.T) {
	checked, secrets, idents := 0, 0, 0
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, v := range []struct {
			name string
			mut  func(*Options)
		}{
			{"default", func(*Options) {}},
			{"secrets", func(o *Options) { o.Secrets = true }},
			{"nosecrets", func(o *Options) { o.NoSecrets = true }},
		} {
			opt := f.options()
			v.mut(&opt)
			d, err := Plan(f.vendor, exp, cur, plain, opt)
			if err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
			hash, lines := Shape(d)
			text := strings.Join(lines, "\n")
			// the values come from the by-value plan, which holds them all
			vd := d
			if !opt.Secrets {
				o := f.options()
				o.Secrets = true
				if vd, err = Plan(f.vendor, exp, cur, plain, o); err != nil {
					t.Fatal(err)
				}
			}
			vals := secretValuesOf(t, f.vendor, vd, exp)
			secrets += len(vals)
			for _, s := range vals {
				if len(s) >= 4 && strings.Contains(text, s) {
					t.Errorf("%s (%s): a secret value %q is in the shape:\n%s", f.name, v.name, s, text)
				}
			}
			ids := identityValuesOf(vd, exp)
			idents += len(ids)
			for _, s := range ids {
				if strings.Contains(text, s) {
					t.Errorf("%s (%s): the per-device value %q is in the shape", f.name, v.name, s)
				}
			}
			if len(d.Lines) > 0 && len(hash) != shapeHashChars {
				t.Errorf("%s: hash %q", f.name, hash)
			}
			checked++
		}
	}
	// a canary the planner would not have given: a secret line with no
	// elided form, a per-device value in every place the table names
	d := Delta{Vendor: devconf.FamilyJunos, Lines: []Line{
		{Section: "aaa", Op: OpSet, Text: "set system tacplus-server 192.0.2.8 secret CANARY1", Secret: true, HasValue: true},
		{Section: "aaa", Op: OpSet, Text: "set system tacplus-server 192.0.2.8 source-address 192.0.2.77"},
		{Section: "snmp", Op: OpSet, Text: `set snmp location "CANARY2 Row 4"`},
		{Section: "snmp", Op: OpSet, Text: "set snmp contact CANARY3"},
		{Section: "snmp", Op: OpSet, Text: `set snmp description "CANARY4 edge"`},
		{Section: "system", Op: OpSet, Text: `set system login message "CANARY5\nunauthorized use"`},
		{Section: "system", Op: OpSet, Text: `set system host-name CANARY6`},
		{Section: "snmp", Op: OpSet, Text: "set snmp community CANARY7 authorization read-only", Secret: true, HasValue: true,
			Elided: "set snmp community <secret:1> authorization read-only"},
	}}
	_, lines := Shape(d)
	text := strings.Join(lines, "\n")
	for _, c := range []string{"CANARY1", "CANARY2", "CANARY3", "CANARY4", "CANARY5", "CANARY6", "CANARY7", "192.0.2.77"} {
		if strings.Contains(text, c) {
			t.Errorf("%s is in the shape:\n%s", c, text)
		}
	}
	if !strings.Contains(text, "<secret:1>") {
		t.Errorf("a community's label was not kept:\n%s", text)
	}
	if checked < 20 || secrets < 5 || idents < 3 {
		t.Errorf("the canary looked at too little: %d plans, %d secret values, %d per-device values", checked, secrets, idents)
	}
}

// The same change on two devices is one shape, whatever order the lines are
// in and whichever values the device has of its own.
func TestShapeIsTheChange(t *testing.T) {
	line := func(sec, text string) Line { return Line{Section: sec, Op: OpSet, Text: text} }
	base := []Line{
		line("roles", "set system login class NET-OPS permissions all"),
		line("roles", "set system login user alice class NET-OPS"),
		line("snmp", `set snmp location "Rack 4"`),
		line("snmp", "set snmp contact noc"),
		{Section: "aaa", Op: OpDelete, Text: "delete system authentication-order"},
		line("aaa", "set system authentication-order [ password tacplus ]"),
	}
	d1 := Delta{Vendor: devconf.FamilyJunos, Lines: base}
	h1, l1 := Shape(d1)

	// another device: the same statements in another order, other values
	rev := slices.Clone(base)
	slices.Reverse(rev)
	// the section order of Lines is the plan's, but a reversed list also
	// has the sections reversed: Shape orders them itself
	rev[2].Text = `set snmp location "Closet 9"`
	rev[3].Text = "set snmp contact other-team"
	d2 := Delta{Vendor: devconf.FamilyJunos, Lines: rev}
	h2, l2 := Shape(d2)
	if h1 != h2 || !slices.Equal(l1, l2) {
		t.Errorf("one change, two shapes:\n%s\n%s", strings.Join(l1, "\n"), strings.Join(l2, "\n"))
	}

	// a different statement, a missing one, another section: other shapes
	for name, mut := range map[string]func([]Line) []Line{
		"other statement": func(ls []Line) []Line { ls[0].Text = "set system login class NET-OPS permissions view"; return ls },
		"fewer":           func(ls []Line) []Line { return ls[1:] },
		"other op": func(ls []Line) []Line {
			ls[0].Op, ls[0].Text = OpDelete, "delete system login class NET-OPS permissions all"
			return ls
		},
		"other section": func(ls []Line) []Line { ls[0].Section = "aaa"; return ls },
		"an extra":      func(ls []Line) []Line { return append(ls, line("snmp", "set snmp contact")) },
	} {
		h, _ := Shape(Delta{Vendor: devconf.FamilyJunos, Lines: mut(slices.Clone(base))})
		if h == h1 {
			t.Errorf("%s: the shape did not change", name)
		}
	}

	// a repeated line is one statement
	h3, _ := Shape(Delta{Vendor: devconf.FamilyJunos, Lines: append(slices.Clone(base), base[0])})
	if h3 != h1 {
		t.Error("a repeated statement changes the shape")
	}
	// the section names are part of it, in plan order
	if want := []string{"[roles]", "[aaa]", "[snmp]"}; !slices.Equal(headers(l1), want) {
		t.Errorf("sections %v, want %v", headers(l1), want)
	}
	// the hash is of the lines, and stored lines re-file to it
	if got := ShapeHash(l1); got != h1 || !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(h1) {
		t.Errorf("ShapeHash %q, shape %q", got, h1)
	}
}

func headers(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "[") {
			out = append(out, l)
		}
	}
	return out
}

// An IOS delta keeps its order (an access list's order is the change), with
// the submode header in front of a line.
func TestShapeIOS(t *testing.T) {
	d := Delta{Vendor: devconf.FamilyIOS, Lines: []Line{
		{Section: "snmp", Op: OpLine, Text: "permit 192.0.2.0 0.0.0.255", Context: []string{"ip access-list standard SNMP-RO"}},
		{Section: "snmp", Op: OpLine, Text: "permit 10.0.0.0 0.255.255.255", Context: []string{"ip access-list standard SNMP-RO"}},
		{Section: "snmp", Op: OpLine, Text: "snmp-server location Rack 4"},
		{Section: "aaa", Op: OpNo, Text: "aaa authentication enable default group tacacs+ enable"},
	}}
	_, lines := Shape(d)
	want := []string{
		"[aaa]",
		"no aaa authentication enable default group tacacs+ enable",
		"[snmp]",
		"ip access-list standard SNMP-RO > permit 192.0.2.0 0.0.0.255",
		"ip access-list standard SNMP-RO > permit 10.0.0.0 0.255.255.255",
		"snmp-server location <v>",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	swapped := d
	swapped.Lines = slices.Clone(d.Lines)
	swapped.Lines[0], swapped.Lines[1] = swapped.Lines[1], swapped.Lines[0]
	h1, _ := Shape(d)
	h2, _ := Shape(swapped)
	if h1 == h2 {
		t.Error("an access list's order is not in the shape")
	}
}

// A delta with nothing to send, and a WTI unit's plan, have no shape.
func TestShapeNone(t *testing.T) {
	for name, d := range map[string]Delta{
		"empty": {Vendor: devconf.FamilyJunos},
		"wti":   {Vendor: devconf.FamilyWTI, Lines: []Line{{Section: "aaa", Op: OpStep, Text: "x"}}},
		"wtiplan": {Vendor: devconf.FamilyJunos, WTI: &WTIPlan{},
			Lines: []Line{{Section: "aaa", Op: OpSet, Text: "set x"}}},
	} {
		if h, l := Shape(d); h != "" || l != nil {
			t.Errorf("%s: shape %q %v", name, h, l)
		}
	}
	if ShapeHash(nil) != "" {
		t.Error("a hash of no lines")
	}
}

// Secret lines that did not say where the value is are not merged: a change
// of one secret and a change of two have different shapes.
func TestShapeCountsSecretStatements(t *testing.T) {
	secret := func(text string) Line {
		return Line{Section: "aaa", Op: OpSet, Text: text, Secret: true, HasValue: true}
	}
	one := Delta{Vendor: devconf.FamilyJunos, Lines: []Line{secret("set system tacplus-server 192.0.2.8 secret AAAA")}}
	two := Delta{Vendor: devconf.FamilyJunos, Lines: []Line{
		secret("set system tacplus-server 192.0.2.8 secret AAAA"),
		secret("set system radius-server 192.0.2.8 secret BBBB"),
	}}
	three := Delta{Vendor: devconf.FamilyJunos, Lines: []Line{
		secret("set system tacplus-server 192.0.2.8 secret AAAA"),
		secret("set system radius-server 192.0.2.8 secret BBBB"),
		secret("set system tacplus-server 192.0.2.9 secret CCCC"),
	}}
	h1, l1 := Shape(one)
	h2, l2 := Shape(two)
	h3, l3 := Shape(three)
	if h1 == h2 || h2 == h3 || h1 == h3 {
		t.Errorf("one, two and three secret statements share a shape: %s %s %s", h1, h2, h3)
	}
	if len(l1) != 2 || len(l2) != 3 || len(l3) != 4 {
		t.Errorf("lines: %q %q %q", l1, l2, l3)
	}
	for _, l := range append(append(l1, l2...), l3...) {
		if strings.Contains(l, "AAAA") || strings.Contains(l, "BBBB") || strings.Contains(l, "CCCC") {
			t.Errorf("a secret in %q", l)
		}
	}
	// a plain line is still dropped when repeated
	dup := Delta{Vendor: devconf.FamilyJunos, Lines: []Line{
		{Section: "aaa", Op: OpSet, Text: "set system tacplus-server 192.0.2.8 single-connection"},
		{Section: "aaa", Op: OpSet, Text: "set system tacplus-server 192.0.2.8 single-connection"},
	}}
	if _, l := Shape(dup); len(l) != 2 {
		t.Errorf("a repeated line is kept: %q", l)
	}
}

func TestShapeMasksTable(t *testing.T) {
	for _, r := range ShapeMasks() {
		if r.Family == "" || r.Prefix == "" || r.Why == "" {
			t.Errorf("incomplete row %+v", r)
		}
	}
	// a delete of the leaf holds no value to mask
	if got := maskShapeLine(devconf.FamilyJunos, "delete snmp location"); got != "delete snmp location" {
		t.Errorf("%q", got)
	}
	if got := maskShapeLine(devconf.FamilyJunos, `set snmp location "Rack 4, Row 2"`); got != "set snmp location <v>" {
		t.Errorf("%q", got)
	}
	if got := maskShapeLine(devconf.FamilyJunos, `set system tacplus-server 192.0.2.8 source-address 192.0.2.9`); got != "set system tacplus-server 192.0.2.8 source-address <v>" {
		t.Errorf("%q", got)
	}
}

// The goldens: the shape of every fixture's plan, per vendor, in the order
// of the fixtures. A change of a masking rule or of the hash shows here.
func TestShapeGoldens(t *testing.T) {
	out := map[string]*strings.Builder{"juniper": {}, "cisco": {}}
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		d, err := Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		hash, lines := Shape(d)
		b := out[f.vendor]
		b.WriteString("# " + f.name + "\n")
		if hash == "" {
			b.WriteString("no shape\n\n")
			continue
		}
		b.WriteString("shape " + hash + " algo " + string(rune('0'+ShapeAlgo)) + "\n")
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
		b.WriteString("\n")
	}
	for vendor, b := range out {
		shapeGolden(t, vendor+".txt", b.String())
	}
}
