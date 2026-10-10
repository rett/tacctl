package plan

// The tests of the Opus review of WP13.1 (docs: opus-review-plan.md): one
// per finding that is not about the block's layout.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// HIGH 3: a list entry's flag goes with the entry; the editor makes the
// device's own behaviour plain (the flag alone is a node of its own).
func TestFlagDeletesTakeTheEntry(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, add("set snmp client-list TACCTL-SNMP 203.0.113.0/24 restrict"), Options{})
	wantLine(t, d, "snmp", "delete snmp client-list TACCTL-SNMP 203.0.113.0/24")
	noLine(t, d, "snmp", "restrict")

	d = planJ(t, f, add("set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 192.0.2.66/32 except"), Options{})
	wantLine(t, d, "mgmt-acl", "delete firewall family inet filter MGMT-ACL term permit-mgmt from source-address 192.0.2.66/32")
	noLine(t, d, "mgmt-acl", "except")

	d = planJ(t, f, add("set snmp community example-community clients 10.0.0.0/8 restrict"), Options{})
	wantLine(t, d, "snmp", "delete snmp community <secret> clients 10.0.0.0/8")
	var real string
	for _, l := range d.Lines {
		if l.HasValue && strings.HasPrefix(l.Text, "delete snmp community ") {
			real = l.Text
		}
	}
	if real != "delete snmp community lab-ro-community clients 10.0.0.0/8" {
		t.Errorf("community delete: %q", real)
	}

	// the editor: deleting the flag alone leaves the entry (a permit)
	c := ParseJunos("set snmp client-list L 10.0.0.0/8 restrict\nset snmp client-list L 192.0.2.0/24\n")
	if err := c.Apply([]Line{{Op: OpDelete, Text: "delete snmp client-list L 10.0.0.0/8 restrict"}}); err != nil {
		t.Fatal(err)
	}
	if got := c.Text(); got != "set snmp client-list L 10.0.0.0/8\nset snmp client-list L 192.0.2.0/24\n" {
		t.Errorf("flag-only delete:\n%s", got)
	}
	if err := c.Apply([]Line{{Op: OpDelete, Text: "delete snmp client-list L 10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if got := c.Text(); got != "set snmp client-list L 192.0.2.0/24\n" {
		t.Errorf("entry delete:\n%s", got)
	}
}

// HIGH 6: tacctl's accounting destination is the protocol word; another
// server's block under it is not tacctl's.
func TestAccountingDestinationsOfOtherServersAreKept(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, addMany(
		`set system accounting destination radius server 203.0.113.7 secret "$9$ZZZZZZZZ"`,
		"set system accounting destination tacplus server 203.0.113.8 port 49",
		"set system accounting destination radius"), Options{})
	wantLine(t, d, "aaa", "delete system accounting destination radius")
	for _, l := range lines(d, "aaa") {
		if strings.HasPrefix(l, "delete system accounting destination") && l != "delete system accounting destination radius" {
			t.Errorf("another server's destination is deleted: %q", l)
		}
	}
	wantKept(t, d, "aaa", "destination radius server 203.0.113.7")
	wantKept(t, d, "aaa", "destination tacplus server 203.0.113.8 port 49")
}

// HIGH 7: only 'privilege exec' is tacctl's.
func TestOnlyPrivilegeExecIsOwned(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-12x")
	d := planI(t, f, func(c *IOSConfig) {
		c.typeGlobal("privilege configure level 7 snmp-server")
		c.typeGlobal("privilege interface level 7 shutdown")
		c.typeGlobal("privilege exec level 7 fuzz thing")
	}, Options{})
	noLine(t, d, "roles", "privilege configure")
	noLine(t, d, "roles", "privilege interface")
	wantLine(t, d, "roles", "no privilege exec level 7 fuzz thing")
}

// BLOCKER 2: the lines are never removed and the rendered header is never
// typed; a device whose lines have a leaf gets the rendered one under its
// own range, and the back-out types the old leaf again.
func TestLoginLeavesAreNeverRemovedNorCreated(t *testing.T) {
	for _, name := range []string{"cisco.reference-bare", "cisco.reference-lab", "cisco.reference-12x", "cisco.real-12.4-7200", "cisco.xe-reference-16"} {
		f := fixtureNamed(t, name)
		for _, mut := range []func(c *IOSConfig){nil, func(c *IOSConfig) {
			for i := range c.blocks {
				if strings.HasPrefix(c.blocks[i].lines[0], "line vty") {
					c.blocks[i].lines = append(c.blocks[i].lines, " login local")
				}
			}
		}} {
			d := planI(t, f, mut, Options{})
			for _, l := range d.Lines {
				if l.Op == OpNo && strings.HasPrefix(l.Text, "line ") {
					t.Errorf("%s: %q", name, l.Text)
				}
				if len(l.Context) > 0 && l.Context[0] == "line vty 0 15" && f.name == "cisco.reference-bare" {
					t.Errorf("%s: the rendered header is typed on a device that has lines 0 to 4 only", name)
				}
			}
			for _, b := range iosBackout(d) {
				if b.Op == OpNo && strings.HasPrefix(b.Text, "line ") {
					t.Errorf("%s: back-out %q", name, b.Text)
				}
			}
		}
	}
}

// HIGH 5: command authorization is the last of the block, with a warning;
// the lines of the unit before it are typed while the server still leaves
// the pasting user alone.
func TestCommandAuthorizationIsLast(t *testing.T) {
	for _, name := range []string{"cisco.reference-bare", "cisco.reference-lab"} {
		f := fixtureNamed(t, name)
		d := planI(t, f, func(c *IOSConfig) {
			if name == "cisco.reference-lab" {
				c.noGlobal("aaa authorization commands 15 default local group LAB-TACACS")
				c.noGlobal("aaa authorization config-commands")
				c.noGlobal("privilege exec level 7 clear counters")
			}
		}, Options{})
		var lateStart = -1
		for i, l := range d.Lines {
			if lateAAA(l) && lateStart < 0 {
				lateStart = i
			}
			if lateStart >= 0 && !lateAAA(l) {
				t.Errorf("%s: %q after command authorization", name, l.Text)
			}
		}
		if lateStart < 0 {
			t.Fatalf("%s: no command authorization in the plan", name)
		}
		if !slices.ContainsFunc(d.Warnings, func(w string) bool {
			return strings.Contains(w, "command authorization") && strings.Contains(w, "user the server knows")
		}) {
			t.Errorf("%s: no warning: %v", name, d.Warnings)
		}
		// the roles line of the second case comes before it in the block
		if name == "cisco.reference-lab" {
			wantLine(t, d, "roles", "privilege exec level 7 clear counters")
		}
		// the block says where it starts
		var reg []string
		for _, l := range RegionLines(d, f.header(), Wrapper{}) {
			reg = append(reg, l.Text)
		}
		li := slices.Index(reg, "! aaa: command authorization, last on purpose")
		pi := slices.IndexFunc(reg, func(s string) bool { return strings.HasPrefix(s, "privilege exec ") })
		if li < 0 || name == "cisco.reference-lab" && pi > li {
			t.Errorf("%s: the late group (%d) is not after the roles lines (%d)", name, li, pi)
		}
	}
}

// MEDIUM 9 and 10: no back-out line holds an elided secret, and a value that
// is not found is a placeholder.
func TestBackoutNeverHoldsAnElidedSecret(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-12x")
	d := planI(t, f, func(c *IOSConfig) {
		for i := range c.blocks {
			if strings.HasPrefix(c.blocks[i].lines[0], "tacacs-server host 192.0.2.10") {
				c.blocks[i].lines[0] = "tacacs-server host 192.0.2.10 timeout 3 key 7 0822455D0A16"
			}
		}
	}, Options{})
	var typed bool
	for _, l := range d.Lines {
		if strings.HasPrefix(l.Text, "tacacs-server host 192.0.2.10") && l.Op == OpLine {
			typed = true
			if !l.HasValue {
				t.Errorf("the rendered line has no value: %q", l.Text)
			}
		}
	}
	if !typed {
		t.Fatalf("the server line is not retyped:\n%s", d.Display())
	}
	var comment bool
	for _, u := range iosBackout(d) {
		if u.Op == OpComment {
			comment = strings.Contains(u.Text, "original secret")
			continue
		}
		s := u.Text
		if strings.Contains(s, "<secret>") || strings.HasSuffix(s, " key") {
			t.Errorf("a back-out line holds an elided secret: %q", s)
		}
	}
	if !comment {
		t.Errorf("no note to type the original secret again")
	}
	// MEDIUM 10: an entry the rendering's raw text lacks is a placeholder
	p := &planner{opt: Options{}}
	l := p.iosAdd(iosEntry{stem: "tacacs server TACACS > key", ctx: []string{"tacacs server TACACS"}, leaf: "key", secret: true, noRaw: true})
	if l.HasValue || !strings.Contains(l.Text, "<SECRET>") {
		t.Errorf("a value that is not known is %q (value %v)", l.Text, l.HasValue)
	}
}

// MEDIUM 14: a deactivated statement of tacctl's is a finding, never an
// emitted 'activate'; a deactivated extra that the plan deletes is not
// listed.
func TestDeactivatedStatements(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, func(c *JunosConfig) {
		c.Add("deactivate system tacplus-server 192.0.2.10")
		c.Add("set firewall family inet filter MGMT-ACL term zz-extra then accept")
		c.Add("deactivate firewall family inet filter MGMT-ACL term zz-extra")
		c.Add("deactivate system tacplus-options")
	}, Options{})
	if !slices.ContainsFunc(d.Warnings, func(w string) bool {
		return strings.Contains(w, "deactivated") && strings.Contains(w, "activate system tacplus-server 192.0.2.10")
	}) {
		t.Errorf("no finding for tacctl's deactivated server: %v", d.Warnings)
	}
	for _, l := range d.Lines {
		if strings.Contains(l.Text, "activate") {
			t.Errorf("an activate is emitted: %q", l.Text)
		}
	}
	for _, k := range d.Kept {
		if strings.Contains(k.Text, "term zz-extra") {
			t.Errorf("a deactivated term the plan deletes is listed: %+v", k)
		}
	}
	wantKept(t, d, "aaa", "deactivate system tacplus-options")
	wantLine(t, d, "mgmt-acl", "delete firewall family inet filter MGMT-ACL term zz-extra")
}

// MEDIUM 16: the kinds of skip.
func TestSkipKinds(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	en := enClass(t, expectedSections(t, synthExpected))
	d := planJ(t, f, add("set snmp location \"X\""), Options{Class: en, Writable: map[string]bool{"snmp": false, "aaa": true, "mgmt-acl": true, "roles": true}})
	if got := d.Of("snmp"); got.Kind != KindNotWritable && got.Kind != KindClassSkip {
		t.Errorf("snmp: %+v", got)
	}
	d = planJ(t, f, nil, Options{Writable: map[string]bool{"snmp": false}})
	if got := d.Of("snmp"); got.Kind != KindNotWritable {
		t.Errorf("writable: %+v", got)
	}
	// class
	d = planJ(t, f, func(c *JunosConfig) {
		c.Add("set system accounting events interactive-commands")
		c.Add("set snmp location \"X\"")
	}, Options{Class: en})
	for _, s := range d.Skipped {
		if s.Kind != KindClassSkip {
			t.Errorf("class skip kind: %+v", s)
		}
	}
	if d.Of("aaa").Kind != KindClassSkip && d.Of("snmp").Kind != KindClassSkip {
		t.Errorf("sections: %+v %+v", d.Of("aaa"), d.Of("snmp"))
	}
	// refused: inherited; not plannable: an older record
	exp := expectedSections(t, f.expected)
	base := ParseJunos(capture(t, f.raw))
	withExtra := ParseJunos(base.Text())
	withExtra.Add("set system accounting events interactive-commands")
	cur, _ := devconf.Extract("juniper", withExtra.Text(), exp...)
	plain, _ := devconf.Extract("juniper", base.Text(), exp...)
	d, err := Plan("juniper", exp, cur, plain, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Of("aaa"); got.Kind != KindRefused {
		t.Errorf("inherited: %+v", got)
	}
	fb := fixtureNamed(t, "cisco.reference-bare")
	expb := expectedSections(t, fb.expected)
	old := devconf.Extracted{Vendor: "ios", SecretsVisible: true, Sections: map[string]devices.Section{
		"aaa": {Name: "aaa", Lines: []string{"aaa authentication login default local"}, Secret: []bool{false}}}}
	d, err = Plan("cisco", expb, old, old, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Of("aaa"); got.Kind != KindNotPlannable {
		t.Errorf("older record: %+v", got)
	}
	// the JSON carries it
	js, _ := JSON(d, fb.header(), Wrapper{})
	var out struct {
		Skipped []struct{ Section, Kind, Why string }
	}
	if err := json.Unmarshal(js, &out); err != nil || len(out.Skipped) == 0 || out.Skipped[0].Kind != KindNotPlannable {
		t.Errorf("json skipped: %v %+v", err, out.Skipped)
	}
}

// LOW: nothing prints a value with %v.
func TestFormatsElide(t *testing.T) {
	f := fixtureNamed(t, "juniper.lab-superuser")
	d := planJ(t, f, nil, Options{})
	fi := fixtureNamed(t, "cisco.reference-bare")
	exp, cur, _ := fi.load(t)
	di, err := Plan("cisco", exp, cur, cur, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{d, di, d.Lines, di.Lines, d.Lines[0], &d} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			out := fmt.Sprintf(verb, v)
			for _, s := range secretValues {
				if strings.Contains(out, s) {
					t.Errorf("%s of %T holds %q", verb, v, s)
				}
			}
		}
	}
	// the Delta's own text is its display
	if fmt.Sprint(d) != d.Display() {
		t.Errorf("String is not Display")
	}
}

// LOW: the comment of the confirmed commit holds no character that closes
// it, and N is within what the setting allows.
func TestCommitCommentIsEscaped(t *testing.T) {
	f := fixtureNamed(t, "juniper.lab-superuser")
	d := planJ(t, f, nil, Options{})
	h := f.header()
	h.Device = "sw\"1;\n#x"
	h.User = `al"ice\`
	for _, n := range []int{0, 5, 61, 600, -3} {
		b := Block(d, h, Wrapper{ConfirmMinutes: n})
		var commit string
		for _, l := range strings.Split(b, "\n") {
			if strings.HasPrefix(l, "commit confirmed ") {
				commit = l
			}
		}
		if commit == "" {
			t.Fatalf("no commit confirmed line:\n%s", b)
		}
		if strings.Count(commit, `"`) != 2 || strings.ContainsAny(commit, `\;`) {
			t.Errorf("unsafe comment: %q", commit)
		}
		want := n
		switch {
		case n <= 0:
			want = 5
		case n > 60:
			want = 60
		}
		if !strings.HasPrefix(commit, fmt.Sprintf("commit confirmed %d comment", want)) {
			t.Errorf("N %d: %q", n, commit)
		}
	}
}

// LOW: the class filter applies to the order findings too.
func TestOrderFindingsFollowTheClass(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	mut := func(c *JunosConfig) {
		c.delete([]string{"system", "authentication-order"})
		c.Add("set system authentication-order tacplus")
		c.Add("set system authentication-order password")
	}
	d := planJ(t, f, mut, Options{})
	wantLine(t, d, "aaa", "delete system authentication-order")
	blind := &Class{Name: "VIEW-CLASS", Permissions: []string{"view", "firewall-control"}}
	d = planJ(t, f, mut, Options{Class: blind})
	noLine(t, d, "aaa", "authentication-order")
}

// LOW: a secret statement the plan deletes by name holds no value and is no
// placeholder: the header does not ask for a value to be put in.
func TestSecretExtraIsNoPlaceholder(t *testing.T) {
	_, d := v3Device(t, `set snmp v3 usm local-engine user tacctl-ro privacy-aes256 privacy-key "$9$EXTRAEXTRA1"`)
	if d.Counts.Placeholders != 0 || d.Counts.SecretsByValue != 0 {
		t.Errorf("counts: %+v", d.Counts)
	}
	h := Header{Device: "sw", Scope: "prod", Vendor: "juniper", Protocol: "TACACS+", Pulled: tPull, Now: tNow, SecretsVisible: true}
	if b := Block(d, h, Wrapper{}); strings.Contains(b, "<SECRET>") || strings.Contains(b, "VALUE NEEDED") {
		t.Errorf("the block asks for a value it does not hold:\n%s", b)
	}
}

// LOW: an IPv6 --from is not checked against an IPv4 filter, with a warning.
func TestIPv6FromIsNotChecked(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, add("set firewall family inet filter MGMT-ACL term zz-extra then accept"), Options{From: "2001:db8::10"})
	if d.Of("mgmt-acl").State != StatePlanned {
		t.Errorf("mgmt-acl: %+v", d.Of("mgmt-acl"))
	}
	if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "IPv6") }) {
		t.Errorf("no warning: %v", d.Warnings)
	}
	fi := fixtureNamed(t, "cisco.reference-lab")
	d = planI(t, fi, func(c *IOSConfig) {
		blk := c.blockFor("ip access-list standard VTY-ACL")
		blk.lines = slices.Insert(blk.lines, 1, " permit 203.0.113.9")
	}, Options{From: "2001:db8::10"})
	if d.Of("mgmt-acl").State != StatePlanned || !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "IPv6") }) {
		t.Errorf("ios: %+v %v", d.Of("mgmt-acl"), d.Warnings)
	}
}

// BLOCKER 2: a line header is on the never list as a 'no'.
func TestNoLineIsNeverEmitted(t *testing.T) {
	if id, bad := neverMatch("ios", Line{Op: OpNo, Text: "line vty 0 15"}); !bad || id != "ios.no-line" {
		t.Errorf("no line vty 0 15: %q %v", id, bad)
	}
	if _, bad := neverMatch("ios", Line{Op: OpNo, Context: []string{"line vty 0 4"}, Text: "login authentication default"}); bad {
		t.Errorf("a 'no' of a leaf under a line header is refused")
	}
}

// LOW: the plan is the same every time (no map order in the output).
func TestPlanIsDeterministic(t *testing.T) {
	// two filters and two ACLs rendered
	exp := []devices.Section{{Name: "mgmt-acl", Lines: []string{
		"set firewall family inet filter F-B term t1 then accept",
		"set firewall family inet filter F-A term t1 then accept",
		"set firewall family inet filter F-A term t2 then discard",
		"set firewall family inet filter F-B term t2 then discard",
	}, Secret: make([]bool, 4)}}
	dev := "set firewall family inet filter F-A term t2 then discard\nset firewall family inet filter F-A term t1 then accept\n" +
		"set firewall family inet filter F-B term t2 then discard\nset firewall family inet filter F-B term t1 then accept\n" +
		"set interfaces lo0 unit 0 family inet filter input F-A\n"
	cur, err := devconf.Extract("juniper", "set version 25.4\n"+dev, exp...)
	if err != nil {
		t.Fatal(err)
	}
	first := ""
	for i := 0; i < 50; i++ {
		d, err := Plan("juniper", exp, cur, cur, Options{})
		if err != nil {
			t.Fatal(err)
		}
		got := d.Display() + fmt.Sprint(d.Warnings, d.Sections)
		if i == 0 {
			first = got
			if !strings.Contains(first, "insert") {
				t.Fatalf("the case plans no insert:\n%s", first)
			}
		} else if got != first {
			t.Fatalf("run %d differs:\n%s\n---\n%s", i, got, first)
		}
	}
	// IOS: two rendered ACLs and a binding check over both
	iexp := []devices.Section{{Name: "mgmt-acl", Lines: []string{
		"ip access-list standard A-ONE", "  permit 192.0.2.1", "  deny   any",
		"ip access-list standard A-TWO", "  permit 192.0.2.2", "  deny   any",
		"line vty 0 15", "  access-class A-ONE in",
	}, Secret: make([]bool, 7)}}
	itext := "version 15.2\nhostname r\nip access-list standard A-ONE\n deny any\n permit 192.0.2.1\nip access-list standard A-TWO\n deny any\n permit 192.0.2.2\nline vty 0 4\n access-class A-ONE in\nend\n"
	icur, err := devconf.Extract("cisco", itext, iexp...)
	if err != nil {
		t.Fatal(err)
	}
	first = ""
	for i := 0; i < 50; i++ {
		d, err := Plan("cisco", iexp, icur, icur, Options{From: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		got := d.Display() + fmt.Sprint(d.Warnings)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("ios run %d differs:\n%s\n---\n%s", i, got, first)
		}
	}
}
