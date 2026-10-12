package plan

// One test per row of the ownership tables (plan §4, §4b): the table says
// what is owned, these say what the planner does with an extra of each. A
// row without a case fails TestEveryRowHasACase.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

func fixtureNamed(t testing.TB, name string) fixture {
	t.Helper()
	for _, f := range fixtures(t) {
		if f.name == name {
			return f
		}
	}
	t.Fatalf("no fixture %q", name)
	return fixture{}
}

// planJ plans a mutated copy of a Junos fixture.
func planJ(t *testing.T, f fixture, mut func(c *JunosConfig), opt Options) Delta {
	t.Helper()
	exp := expectedSections(t, f.expected)
	c := ParseJunos(capture(t, f.raw))
	if mut != nil {
		mut(c)
	}
	return planText(t, f, exp, c.Text(), opt)
}

func planI(t *testing.T, f fixture, mut func(c *IOSConfig), opt Options) Delta {
	t.Helper()
	exp := expectedSections(t, f.expected)
	c := ParseIOS(capture(t, f.raw))
	if mut != nil {
		mut(c)
	}
	return planText(t, f, exp, c.Text(), opt)
}

func planText(t *testing.T, f fixture, exp []devices.Section, text string, opt Options) Delta {
	t.Helper()
	cur, err := devconf.Extract(f.vendor, text, exp...)
	if err != nil {
		t.Fatal(err)
	}
	if opt.Class == nil {
		opt.Class = f.class
	}
	if opt.Syntax == "" {
		opt.Syntax = f.syntax()
	}
	d, err := Plan(f.vendor, exp, cur, cur, opt)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// lines returns the text (elided) of a section's lines, with 'no ' for IOS
// removals and the submode header in front of a context line ('ctx > leaf').
func lines(d Delta, section string) []string {
	var out []string
	for _, l := range d.Lines {
		if section != "" && l.Section != section {
			continue
		}
		s := l.Shown()
		if l.Op == OpNo {
			s = "no " + s
		}
		if len(l.Context) > 0 {
			s = strings.Join(l.Context, " > ") + " > " + s
		}
		out = append(out, s)
	}
	return out
}

func wantLine(t *testing.T, d Delta, section, line string) {
	t.Helper()
	if !slices.Contains(lines(d, section), line) {
		t.Errorf("[%s] lacks %q; has:\n%s", section, line, strings.Join(lines(d, section), "\n"))
	}
}

func noLine(t *testing.T, d Delta, section, substr string) {
	t.Helper()
	for _, l := range lines(d, section) {
		if strings.Contains(l, substr) {
			t.Errorf("[%s] has %q, which it must not: %q", section, substr, l)
		}
	}
}

func wantKept(t *testing.T, d Delta, section, substr string) {
	t.Helper()
	for _, k := range d.Kept {
		if k.Section == section && strings.Contains(k.Text, substr) {
			return
		}
	}
	t.Errorf("kept lacks %q in %s: %+v", substr, section, d.Kept)
}

func add(s string) func(c *JunosConfig) {
	return func(c *JunosConfig) { _ = c.Apply([]Line{{Op: OpSet, Text: s}}) }
}

func addMany(ss ...string) func(c *JunosConfig) {
	return func(c *JunosConfig) {
		for _, s := range ss {
			_ = c.Apply([]Line{{Op: OpSet, Text: s}})
		}
	}
}

// goldenSections reads a managed golden of tests/fixtures/golden.
func goldenSections(t *testing.T, name string) []devices.Section {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, name))
	if err != nil {
		t.Skip("no managed goldens in this tree")
	}
	var out []devices.Section
	var cur *devices.Section
	for _, l := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(l, "["):
			n, rest, _ := strings.Cut(strings.TrimPrefix(l, "["), "]")
			if strings.TrimSpace(rest) == "not rendered" {
				cur = nil
				continue
			}
			out = append(out, devices.Section{Name: n})
			cur = &out[len(out)-1]
		case (strings.HasPrefix(l, "| ") || strings.HasPrefix(l, "* ")) && cur != nil:
			cur.Lines = append(cur.Lines, l[2:])
			cur.Secret = append(cur.Secret, l[0] == '*')
		}
	}
	return out
}

// v3Device is a Junos device that holds exactly what managed.juniper.prod
// renders (SNMPv3), the passwords as a device prints them.
func v3Device(t *testing.T, extra ...string) (devices.Section, Delta) {
	t.Helper()
	exp := goldenSections(t, "managed.juniper.prod.txt")
	var b strings.Builder
	for _, s := range exp {
		if s.Name == "breakglass" {
			continue
		}
		for _, l := range s.Lines {
			l = strings.ReplaceAll(l, "authentication-password \"auth-pass-0123\"", "authentication-key \"$9$EXAMPLEAUTH1\"")
			l = strings.ReplaceAll(l, "privacy-password \"priv-pass-4567\"", "privacy-key \"$9$EXAMPLEPRIV1\"")
			l = strings.ReplaceAll(l, "secret lab-secret-0123456789abcdef", "secret \"$9$EXAMPLEEXAMPLE\"")
			b.WriteString(l + "\n")
		}
	}
	for _, e := range extra {
		b.WriteString(e + "\n")
	}
	cur, err := devconf.Extract("juniper", b.String(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Plan("juniper", exp, cur, cur, Options{Scope: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	return devices.Section{}, d
}

type rowCase func(t *testing.T)

// The cases of the Junos rows.
var junosRowCases = map[string]rowCase{
	"junos.roles.class": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, addMany("set system login class RO-CLASS permissions all",
			`set system login class RO-CLASS allow-commands "show x"`), Options{})
		wantLine(t, d, "roles", "delete system login class RO-CLASS permissions all")
		wantLine(t, d, "roles", `delete system login class RO-CLASS allow-commands "show x"`)
		noLine(t, d, "roles", "OPS-NOC")
	},
	"junos.roles.user-class": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add("set system login user RO-CLASS class OP-CLASS"), Options{})
		wantLine(t, d, "roles", "set system login user RO-CLASS class RO-CLASS")
		noLine(t, d, "roles", "delete")
	},
	"junos.aaa.order": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, func(c *JunosConfig) {
			c.delete([]string{"system", "authentication-order"})
			c.Add("set system authentication-order tacplus")
			c.Add("set system authentication-order password")
		}, Options{})
		ls := lines(d, "aaa")
		i := slices.Index(ls, "delete system authentication-order")
		if i < 0 || i+1 >= len(ls) || ls[i+1] != "set system authentication-order [ password tacplus ]" {
			t.Errorf("the order is not delete directly followed by its set: %q", ls)
		}
	},
	"junos.aaa.events": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add("set system accounting events interactive-commands"), Options{})
		wantLine(t, d, "aaa", "delete system accounting events interactive-commands")
	},
	"junos.aaa.destination": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add("set system accounting destination radius"), Options{})
		wantLine(t, d, "aaa", "delete system accounting destination radius")
	},
	"junos.aaa.tacplus": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, addMany("set system tacplus-server 192.0.2.10 source-address 192.0.2.77",
			"set system tacplus-server 192.0.2.10 timeout 9"), Options{})
		noLine(t, d, "aaa", "source-address")
		noLine(t, d, "aaa", "timeout")
		wantKept(t, d, "aaa", "tacplus-server 192.0.2.10 source-address 192.0.2.77")
		wantKept(t, d, "aaa", "tacplus-server 192.0.2.99 secret")
	},
	"junos.aaa.radius": func(t *testing.T) {
		exp := goldenSections(t, "managed.juniper-radius.lab.txt")
		var b strings.Builder
		for _, s := range exp {
			if s.Name == "breakglass" {
				continue
			}
			for _, l := range s.Lines {
				b.WriteString(strings.ReplaceAll(l, "secret lab-secret-0123456789abcdef", `secret "$9$EXAMPLEEXAMPLE"`) + "\n")
			}
		}
		b.WriteString("set system radius-server 10.0.0.42 source-address 192.0.2.77\n")
		b.WriteString("set system radius-server 10.0.0.42 timeout 9\n")
		b.WriteString("set system radius-server 10.0.0.43 secret \"$9$OTHEROTHER\"\n")
		cur, err := devconf.Extract("juniper", b.String(), exp...)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Plan("juniper", exp, cur, cur, Options{})
		if err != nil {
			t.Fatal(err)
		}
		noLine(t, d, "aaa", "delete system radius-server")
		wantKept(t, d, "aaa", "radius-server 10.0.0.42 source-address 192.0.2.77")
		wantKept(t, d, "aaa", "radius-server 10.0.0.42 timeout 9")
		wantKept(t, d, "aaa", "radius-server 10.0.0.43 secret")
	},
	"junos.snmp.client-list": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add("set snmp client-list TACCTL-SNMP 203.0.113.9/32"), Options{})
		wantLine(t, d, "snmp", "delete snmp client-list TACCTL-SNMP 203.0.113.9/32")
	},
	"junos.snmp.community": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add("set snmp community example-community clients 203.0.113.0/24"), Options{})
		// the community's name is elided in the comparison: the delete acts
		// on the rendered community, and says so
		wantLine(t, d, "snmp", "delete snmp community <secret> clients 203.0.113.0/24")
		if len(d.Unattributed) != 1 {
			t.Errorf("unattributed: %v", d.Unattributed)
		}
		var holds bool
		for _, l := range d.Lines {
			if strings.HasPrefix(l.Text, "delete snmp community lab-ro-community clients") && l.HasValue && l.Secret {
				holds = true
			}
		}
		if !holds {
			t.Errorf("the delete line does not carry the rendered community's name: %s", d.Display())
		}
		// the other communities of the device stay
		wantKept(t, d, "snmp", "snmp trap-group")
	},
	"junos.snmp.v3-user": func(t *testing.T) {
		_, d := v3Device(t, `set snmp v3 usm local-engine user tacctl-ro privacy-aes256 privacy-key "$9$EXTRAEXTRA1"`)
		wantLine(t, d, "snmp", "delete snmp v3 usm local-engine user tacctl-ro privacy-aes256 privacy-key")
		noLine(t, d, "snmp", "set ")
	},
	"junos.snmp.v3-group": func(t *testing.T) {
		_, d := v3Device(t, "set snmp v3 vacm security-to-group security-model usm security-name tacctl-ro group OTHER-GROUP")
		wantLine(t, d, "snmp", "delete snmp v3 vacm security-to-group security-model usm security-name tacctl-ro group OTHER-GROUP")
	},
	"junos.snmp.v3-access": func(t *testing.T) {
		_, d := v3Device(t, "set snmp v3 vacm access group TACCTL-GROUP default-context-prefix security-model usm security-level authentication read-view OTHER-VIEW")
		wantLine(t, d, "snmp", "delete snmp v3 vacm access group TACCTL-GROUP default-context-prefix security-model usm security-level authentication read-view OTHER-VIEW")
	},
	"junos.snmp.view": func(t *testing.T) {
		_, d := v3Device(t, "set snmp view TACCTL-VIEW oid .2 include", "set snmp view OTHER-VIEW oid .3 include")
		wantLine(t, d, "snmp", "delete snmp view TACCTL-VIEW oid .2 include")
		noLine(t, d, "snmp", "OTHER-VIEW")
		wantKept(t, d, "snmp", "snmp view OTHER-VIEW")
	},
	"junos.snmp.location": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add(`set snmp location "Elsewhere"`), Options{})
		wantLine(t, d, "snmp", `set snmp location "Rack 4, DC1"`)
		noLine(t, d, "snmp", "delete snmp location")
	},
	"junos.snmp.contact": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add(`set snmp contact "Someone"`), Options{})
		wantLine(t, d, "snmp", `set snmp contact "NOC <noc@example.net>"`)
		noLine(t, d, "snmp", "delete snmp contact")
	},
	"junos.snmp.description": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, add(`set snmp description "Old"`), Options{})
		wantLine(t, d, "snmp", `set snmp description "Core switch"`)
		noLine(t, d, "snmp", "delete snmp description")
	},
	"junos.mgmt-acl.filter": func(t *testing.T) {
		f := fixtureNamed(t, "juniper.synthetic-lab")
		d := planJ(t, f, func(c *JunosConfig) {
			c.Add("set firewall family inet filter MGMT-ACL term zz-extra then accept")
			c.Add("set firewall family inet filter MGMT-ACL term zz-extra from protocol tcp")
			c.Add("set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 203.0.113.0/24")
			moveNamedTermToEnd(c, "permit-mgmt")
		}, Options{})
		wantLine(t, d, "mgmt-acl", "delete firewall family inet filter MGMT-ACL term zz-extra")
		wantLine(t, d, "mgmt-acl", "delete firewall family inet filter MGMT-ACL term permit-mgmt from source-address 203.0.113.0/24")
		var inserts int
		for _, l := range d.Lines {
			if l.Op == OpInsert {
				inserts++
			}
		}
		if inserts == 0 {
			t.Errorf("no insert for a moved term:\n%s", d.Display())
		}
		// the other filter of the device is not touched
		noLine(t, d, "mgmt-acl", "PROTECT-RE")
	},
}

// The cases of the IOS rows (the reference-lab fixture unless said).
var iosRowCases = map[string]rowCase{
	"ios.aaa.method-list": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("aaa authentication login default group LAB-TACACS local") }, Options{})
		wantLine(t, d, "aaa", "aaa authentication login default local group LAB-TACACS")
		noLine(t, d, "aaa", "no aaa authentication")
	},
	"ios.aaa.commands-level": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("aaa authorization commands 5 default local group LAB-TACACS") }, Options{})
		wantLine(t, d, "aaa", "no aaa authorization commands 5 default local group LAB-TACACS")
		if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "level 5") }) {
			t.Errorf("no warning naming the level: %v", d.Warnings)
		}
		// a list of another name is not tacctl's
		d = planI(t, f, func(c *IOSConfig) { c.typeGlobal("aaa authorization commands 5 VTY local group LAB-TACACS") }, Options{})
		noLine(t, d, "aaa", "no aaa authorization")
	},
	"ios.aaa.config-commands": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) { c.noGlobal("aaa authorization config-commands") }, Options{})
		wantLine(t, d, "aaa", "aaa authorization config-commands")
	},
	"ios.aaa.server-block": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			blk := c.blockFor("tacacs server TACACS")
			typeChild(blk, []string{"tacacs server TACACS"}, "timeout 10")
			typeChild(blk, []string{"tacacs server TACACS"}, "retransmit 3")
		}, Options{})
		wantLine(t, d, "aaa", "tacacs server TACACS > timeout 5")
		noLine(t, d, "aaa", "no timeout")
		wantKept(t, d, "aaa", "tacacs server TACACS > retransmit 3")
	},
	"ios.aaa.radius-block": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.xe-reference-16")
		d := planI(t, f, func(c *IOSConfig) {
			blk := c.blockFor("radius server RADIUS")
			typeChild(blk, []string{"radius server RADIUS"}, "timeout 9")
			typeChild(blk, []string{"radius server RADIUS"}, "deadtime 3")
		}, Options{})
		wantLine(t, d, "aaa", "radius server RADIUS > timeout 5")
		noLine(t, d, "aaa", "no timeout")
		wantKept(t, d, "aaa", "radius server RADIUS > deadtime 3")
	},
	"ios.aaa.legacy-host": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-12x")
		d := planI(t, f, func(c *IOSConfig) {
			for i := range c.blocks {
				if strings.HasPrefix(c.blocks[i].lines[0], "tacacs-server host 192.0.2.10") {
					c.blocks[i].lines[0] = "tacacs-server host 192.0.2.10 single-connection timeout 9 key 7 0822455D0A16"
				}
			}
			c.typeGlobal("tacacs-server host 192.0.2.77 key 7 0822455D0A16")
		}, Options{})
		var typed bool
		for _, l := range d.Lines {
			if strings.HasPrefix(l.Text, "tacacs-server host 192.0.2.10") && l.Op == OpLine {
				typed = true
			}
		}
		if !typed {
			t.Errorf("the server line is not retyped:\n%s", d.Display())
		}
		noLine(t, d, "aaa", "no tacacs-server")
		wantKept(t, d, "aaa", "tacacs-server host 192.0.2.77")
	},
	"ios.aaa.legacy-radius-host": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.xe-reference-16")
		d := planI(t, f, func(c *IOSConfig) {
			for i := range c.blocks {
				if strings.HasPrefix(c.blocks[i].lines[0], "radius server ") {
					c.blocks[i].lines = []string{"radius-server host 192.0.2.10 auth-port 1812 acct-port 1813 key 7 0822455D0A16"}
				}
			}
			c.typeGlobal("radius-server host 192.0.2.77 key 7 0822455D0A16")
		}, Options{Scope: "lab"})
		wantLine(t, d, "aaa", "no radius-server host 192.0.2.10 auth-port 1812 acct-port 1813")
		wantKept(t, d, "aaa", "radius-server host 192.0.2.77")
	},
	"ios.aaa.group": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			typeChild(c.blockFor("aaa group server tacacs+ LAB-TACACS"), []string{"aaa group server tacacs+ LAB-TACACS"}, "server name OTHER")
		}, Options{})
		wantLine(t, d, "aaa", "aaa group server tacacs+ LAB-TACACS > no server name OTHER")
	},
	"ios.aaa.radius-group": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.xe-reference-16")
		d := planI(t, f, func(c *IOSConfig) {
			typeChild(c.blockFor("aaa group server radius LAB-RADIUS"), []string{"aaa group server radius LAB-RADIUS"}, "server name OTHER")
		}, Options{})
		wantLine(t, d, "aaa", "aaa group server radius LAB-RADIUS > no server name OTHER")
	},
	"ios.aaa.console-list": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			c.typeGlobal("aaa authentication login CONSOLE group LAB-TACACS local")
			c.typeGlobal("aaa authentication login OTHER local")
		}, Options{})
		wantLine(t, d, "aaa", "aaa authentication login CONSOLE local")
		noLine(t, d, "aaa", "no aaa authentication")
		wantKept(t, d, "aaa", "aaa authentication login OTHER local")
	},
	"ios.aaa.enable-list": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		// the standard has no enable list: the one that asks the server is
		// removed by its full statement, a list of another name is kept
		d := planI(t, f, func(c *IOSConfig) {
			c.typeGlobal("aaa authentication enable default group LAB-TACACS enable")
			c.typeGlobal("aaa authentication enable OTHER enable")
		}, Options{})
		wantLine(t, d, "aaa", "no aaa authentication enable default group LAB-TACACS enable")
		for _, l := range lines(d, "aaa") {
			if strings.HasPrefix(l, "aaa authentication enable") {
				t.Errorf("the plan types an enable list: %q", l)
			}
			if strings.Contains(l, "OTHER") {
				t.Errorf("the named list is touched: %q", l)
			}
		}
		wantKept(t, d, "aaa", "aaa authentication enable OTHER enable")
		var undo []string
		for _, l := range d.Lines {
			if l.Op == OpNo && l.Text == "aaa authentication enable default group LAB-TACACS enable" {
				for _, u := range l.Undo {
					undo = append(undo, u.Text)
				}
			}
		}
		if !slices.Equal(undo, []string{"aaa authentication enable default group LAB-TACACS enable"}) {
			t.Errorf("undo: %q", undo)
		}
		// 'default enable' is what IOS does with no list: not an extra, no line
		d = planI(t, f, func(c *IOSConfig) {
			c.typeGlobal("aaa authentication enable default enable")
		}, Options{})
		noLine(t, d, "aaa", "authentication enable")
		for _, k := range d.Kept {
			if strings.Contains(k.Text, "authentication enable") {
				t.Errorf("kept: %+v", k)
			}
		}
		for _, e := range d.Extras {
			if strings.Contains(e.Text, "authentication enable") {
				t.Errorf("extra: %+v", e)
			}
		}
	},
	"ios.aaa.session-id": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			c.noGlobal("aaa session-id common")
			c.typeGlobal("aaa session-id unique")
		}, Options{})
		wantLine(t, d, "aaa", "aaa session-id common")
		noLine(t, d, "aaa", "no aaa session-id")
	},
	"ios.aaa.source-interface": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		// the scope sets one: a device's other interface is replaced in place
		exp := expectedSections(t, f.expected)
		for i := range exp {
			if exp[i].Name == "aaa" {
				exp[i].Lines = append(exp[i].Lines, "ip tacacs source-interface Loopback7")
				exp[i].Secret = append(exp[i].Secret, false)
			}
		}
		c := ParseIOS(capture(t, f.raw))
		c.typeGlobal("ip tacacs source-interface Loopback9")
		d := planText(t, f, exp, c.Text(), Options{})
		wantLine(t, d, "aaa", "ip tacacs source-interface Loopback7")
		noLine(t, d, "aaa", "no ip tacacs source-interface")
		// the scope sets none: the device's own is not compared, not kept, not
		// removed (the fixture's device has Loopback0)
		d = planI(t, f, nil, Options{})
		noLine(t, d, "aaa", "source-interface")
		for _, k := range d.Kept {
			if strings.Contains(k.Text, "source-interface") {
				t.Errorf("the device's source interface is listed: %+v", k)
			}
		}
	},
	"ios.aaa.console-leaf": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		// no explicit leaf: typed under the header the device has, taken off
		// again by the back-out
		d := planI(t, f, nil, Options{})
		wantLine(t, d, "aaa", "line con 0 > login authentication CONSOLE")
		// an explicit method is replaced, and typed again by the back-out
		d = planI(t, f, func(c *IOSConfig) {
			blk := c.blockFor("line con 0")
			blk.lines = append(blk.lines, " login local")
		}, Options{})
		wantLine(t, d, "aaa", "line con 0 > login authentication CONSOLE")
		var undo []string
		for _, l := range d.Lines {
			if l.Section == "aaa" && l.Text == "login authentication CONSOLE" {
				for _, u := range l.Undo {
					undo = append(undo, strings.Join(u.Context, " > ")+" > "+u.Text)
				}
			}
		}
		if !slices.Equal(undo, []string{"line con 0 > login local"}) {
			t.Errorf("undo: %q", undo)
		}
		// the console's leaf is typed after roles, snmp and mgmt-acl
		idx := func(section string) int {
			return slices.IndexFunc(d.Lines, func(l Line) bool { return l.Section == section })
		}
		var at int
		for i, l := range d.Lines {
			if l.Leaf && l.Context[0] == "line con 0" {
				at = i
			}
		}
		if idx("roles") >= 0 && (at <= idx("roles") || at <= idx("snmp") || at <= idx("mgmt-acl")) {
			t.Errorf("the console's leaf is not after roles, snmp and mgmt-acl:\n%s", d.Display())
		}
	},
	"ios.aaa.vty-leaf": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			blk := c.blockFor("line vty 0 4")
			blk.lines = append(blk.lines, " login local")
		}, Options{})
		wantLine(t, d, "aaa", "line vty 0 4 > login authentication default")
		noLine(t, d, "aaa", "line vty 0 15")
	},
	"ios.roles.privilege": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			c.typeGlobal("privilege exec level 7 fuzz thing")
			c.typeGlobal("privilege exec level 9 other thing")
			c.noGlobal("privilege exec level 7 undebug all")
		}, Options{})
		ls := lines(d, "roles")
		if len(ls) < 2 || ls[0] != "no privilege exec level 7 fuzz thing" || ls[len(ls)-1] != "privilege exec level 7 undebug all" {
			t.Errorf("the no lines do not come first: %q", ls)
		}
		noLine(t, d, "roles", "level 9")
		wantKept(t, d, "roles", "privilege exec level 9 other thing")
	},
	"ios.snmp.community": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, nil, Options{})
		var note bool
		for _, k := range d.Kept {
			if strings.Contains(k.Text, "snmp-server community <secret>") && strings.Contains(k.Note, "not compared") {
				note = true
			}
		}
		if !note {
			t.Errorf("the extra community is not kept with its note: %+v", d.Kept)
		}
		noLine(t, d, "snmp", "no snmp-server community")
		// the rendered community missing is pasted by value
		d = planI(t, f, func(c *IOSConfig) {
			c.noGlobal("snmp-server community example-community")
			c.noGlobal("snmp-server community other-example")
		}, Options{})
		wantLine(t, d, "snmp", "snmp-server community <secret> RO TACCTL-SNMP")
		found := false
		for _, l := range d.Lines {
			if l.Text == "snmp-server community lab-ro-community RO TACCTL-SNMP" && l.HasValue {
				found = true
			}
		}
		if !found {
			t.Errorf("the community is not pasted by value:\n%s", d.Display())
		}
	},
	"ios.snmp.location": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server location Elsewhere") }, Options{})
		wantLine(t, d, "snmp", "snmp-server location Rack 4, DC1")
		noLine(t, d, "snmp", "no snmp-server location")
	},
	"ios.snmp.contact": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server contact Someone") }, Options{})
		wantLine(t, d, "snmp", "snmp-server contact NOC <noc@example.net>")
		noLine(t, d, "snmp", "no snmp-server contact")
	},
	"ios.snmp.acl": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			blk := c.blockFor("ip access-list standard TACCTL-SNMP")
			blk.lines = slices.Insert(blk.lines, 1, " permit 203.0.113.9")
		}, Options{})
		wantLine(t, d, "snmp", "ip access-list standard TACCTL-SNMP > no permit 203.0.113.9")
	},
	"ios.mgmt-acl.acl": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		// a new entry that has to stand before the deny: the deny is removed
		// first and typed again after it (a standard list ends in an implicit
		// deny, so nothing opens), the extra goes after the new entries
		d := planI(t, f, func(c *IOSConfig) {
			blk := c.blockFor("ip access-list standard VTY-ACL")
			blk.lines = slices.Delete(blk.lines, 3, 4) // the third permit
			blk.lines = append(blk.lines[:3:3], append([]string{" permit 203.0.113.9"}, blk.lines[3:]...)...)
		}, Options{})
		ls := lines(d, "mgmt-acl")
		if len(ls) != 4 || !strings.HasSuffix(ls[0], "no deny any log") || !strings.HasSuffix(ls[1], "permit 192.0.2.0 0.0.0.255") ||
			!strings.HasSuffix(ls[2], "deny any log") || !strings.HasSuffix(ls[3], "no permit 203.0.113.9") {
			t.Errorf("the ACL plan is not removal of the later entries, adds, extras:\n%s", strings.Join(ls, "\n"))
		}
		// the binding is never emitted
		d = planI(t, f, func(c *IOSConfig) {
			for i := range c.blocks {
				if strings.HasPrefix(c.blocks[i].lines[0], "line vty") {
					c.blocks[i].lines = c.blocks[i].lines[:1]
				}
			}
		}, Options{})
		noLine(t, d, "mgmt-acl", "access-class")
		if len(d.Withheld) == 0 {
			t.Errorf("the binding is not named as the operator's step")
		}
	},
}

func TestEveryRowHasACase(t *testing.T) {
	for _, r := range junosOwned {
		if junosRowCases[r.ID] == nil {
			t.Errorf("Junos row %s has no case", r.ID)
		}
	}
	for _, r := range iosOwned {
		if iosRowCases[r.ID] == nil {
			t.Errorf("IOS row %s has no case", r.ID)
		}
	}
	for id := range junosRowCases {
		if !slices.ContainsFunc(junosOwned, func(r OwnedRow) bool { return r.ID == id }) {
			t.Errorf("case %s names no Junos row", id)
		}
	}
	for id := range iosRowCases {
		if !slices.ContainsFunc(iosOwned, func(r OwnedRow) bool { return r.ID == id }) {
			t.Errorf("case %s names no IOS row", id)
		}
	}
}

func TestOwnedRows(t *testing.T) {
	for id, c := range junosRowCases {
		t.Run(id, c)
	}
	for id, c := range iosRowCases {
		t.Run(id, c)
	}
}
