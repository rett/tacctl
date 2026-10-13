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
		d := planJ(t, f, func(c *JunosConfig) {
			add("set snmp community lab-ro-community clients 203.0.113.0/24")(c)
			add("set snmp community other-example clients 192.0.2.10/32")(c)
		}, Options{})
		// the community's name is shown as its label: a stray leaf of the
		// rendered community is deleted under its own name, another
		// community's is kept
		wantLine(t, d, "snmp", "delete snmp community <secret:1> clients 203.0.113.0/24")
		noLine(t, d, "snmp", "delete snmp community <other:")
		wantKept(t, d, "snmp", "snmp community <other:1> clients 192.0.2.10/32")
		if len(d.Unattributed) != 0 {
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
	"junos.snmp.block-community": func(t *testing.T) {
		// a community of the scope's snmp block is owned whole: a stray leaf
		// goes, under the block community's own name; tacctl's own community
		// and the device's other one are not touched
		d := planJ(t, blockFixture(t), addMany("set snmp community nms-ro clients 203.0.113.0/24",
			"set snmp community other-example clients 203.0.113.9/32"), blockOpt)
		wantLine(t, d, "snmp", "delete snmp community <secret:2> clients 203.0.113.0/24")
		noLine(t, d, "snmp", "<secret:1>")
		noLine(t, d, "snmp", "<other:")
		wantKept(t, d, "snmp", "snmp community <other:1> clients 203.0.113.9/32")
	},
	"junos.snmp.trap-group": func(t *testing.T) {
		// a trap group the block names is owned whole, another is the
		// device's own
		d := planJ(t, blockFixture(t), addMany("set snmp trap-group nms-traps targets 203.0.113.9",
			"set snmp trap-group other-example targets 203.0.113.9"), blockOpt)
		wantLine(t, d, "snmp", "delete snmp trap-group <secret:3> targets 203.0.113.9")
		noLine(t, d, "snmp", "<other:")
		wantKept(t, d, "snmp", "snmp trap-group <other:1> targets 203.0.113.9")
	},
	"junos.snmp.trap-options": func(t *testing.T) {
		// the leaf the block sets is replaced as rendered, the device's own
		// other leaf stays
		f := blockFixture(t)
		d := planJ(t, f, func(c *JunosConfig) {
			c.Remove("set snmp trap-options agent-address outgoing-interface")
		}, blockOpt)
		wantLine(t, d, "snmp", "set snmp trap-options agent-address outgoing-interface")
		noLine(t, d, "snmp", "source-address")
		noLine(t, d, "snmp", "delete")
		wantKept(t, d, "snmp", "snmp trap-options source-address 192.0.2.250")
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
	// 0.2.7: the system block. Each single-valued statement is replaced in
	// place, each list statement adds, and nothing is ever deleted.
	"junos.system.login-message": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system login message")(c)
			c.Add(`set system login message "Another banner"`)
		}, nil, systemOpt)
		wantLine(t, d, "system", `set system login message `+fixtureMessage)
		noLine(t, d, "system", "delete")
		noLine(t, d, "system", "Another")
		for _, k := range d.Kept {
			if k.Section == "system" {
				t.Errorf("kept: %+v", k)
			}
		}
	},
	"junos.system.domain-name": func(t *testing.T) {
		d, _ := planSystem(t, add("set system domain-name other.example.net"), nil, systemOpt)
		wantLine(t, d, "system", "set system domain-name lab.example.net")
		noLine(t, d, "system", "delete")
	},
	"junos.system.time-zone": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system time-zone")(c)
			c.Add("set system time-zone America/New_York")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system time-zone UTC")
		noLine(t, d, "system", "delete")
	},
	"junos.system.ntp-boot-server": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp boot-server")(c)
			c.Add("set system ntp boot-server 192.0.2.99")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system ntp boot-server 192.0.2.123")
		noLine(t, d, "system", "delete")
	},
	"junos.system.ntp-source-address": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp source-address")(c)
			c.Add("set system ntp source-address 192.0.2.99")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system ntp source-address 192.0.2.250")
		noLine(t, d, "system", "delete")
	},
	"junos.system.ntp-server-version": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp server 192.0.2.123 version")(c)
			c.Add("set system ntp server 192.0.2.123 version 3")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system ntp server 192.0.2.123 version 4")
		noLine(t, d, "system", "delete")
	},
	"junos.system.ntp-server-key": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp server 192.0.2.123 key")(c)
			c.Add("set system ntp server 192.0.2.123 key 2")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system ntp server 192.0.2.123 key 1")
		noLine(t, d, "system", "delete")
	},
	"junos.system.ntp-server-routing-instance": func(t *testing.T) {
		f := systemFixture(t)
		sec := systemSectionOf(t, "set system ntp server 192.0.2.123 routing-instance mgmt\n")
		d, _ := planSystem(t, add("set system ntp server 192.0.2.123 routing-instance other"),
			withSystem(expectedSections(t, f.expected), sec), systemOpt)
		wantLine(t, d, "system", "set system ntp server 192.0.2.123 routing-instance mgmt")
		noLine(t, d, "system", "delete")
	},
	"junos.system.domain-search": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system domain-search")(c)
			c.Add("set system domain-search example.net")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system domain-search lab.example.net")
		noLine(t, d, "system", "delete")
		wantKept(t, d, "system", "system domain-search example.net")
	},
	"junos.system.name-server": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system name-server")(c)
			c.Add("set system name-server 198.51.100.53")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system name-server 192.0.2.53")
		noLine(t, d, "system", "delete")
		wantKept(t, d, "system", "system name-server 198.51.100.53")
	},
	"junos.system.ntp-server": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp server")(c)
			c.Add("set system ntp server ntp.example.net")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system ntp server 192.0.2.123 prefer")
		noLine(t, d, "system", "delete")
		wantKept(t, d, "system", "system ntp server ntp.example.net")
	},
	"junos.system.ntp-key": func(t *testing.T) {
		// typed (by value) only where the device has no key of the number
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp authentication-key")(c)
			c.Add(`set system ntp authentication-key 9 value "$9$OTHEROTHEROTHER"`)
		}, nil, systemOpt)
		var key Line
		for _, l := range d.Lines {
			if strings.Contains(l.Text, "ntp authentication-key") {
				key = l
			}
		}
		if key.Text != "set system ntp authentication-key 1 type md5 value ntp-key-0123456789" || !key.HasValue || key.Shown() != "set system ntp authentication-key 1 value <secret>" {
			t.Errorf("the key line: %+v", key)
		}
		noLine(t, d, "system", "delete")
		wantKept(t, d, "system", "system ntp authentication-key 9 value")
		// the device's key of the number, of another type, is left as it is
		d, _ = planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp authentication-key")(c)
			c.Add("set system ntp authentication-key 1 type sha1")
			c.Add(`set system ntp authentication-key 1 value "$9$OTHEROTHEROTHER"`)
		}, nil, systemOpt)
		noLine(t, d, "system", "authentication-key")
	},
	"junos.system.ntp-trusted-key": func(t *testing.T) {
		d, _ := planSystem(t, func(c *JunosConfig) {
			dropPrefix("system ntp trusted-key")(c)
			c.Add("set system ntp trusted-key 9")
		}, nil, systemOpt)
		wantLine(t, d, "system", "set system ntp trusted-key 1")
		noLine(t, d, "system", "delete")
		wantKept(t, d, "system", "system ntp trusted-key 9")
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
			if strings.Contains(k.Text, "snmp-server community <other:1>") {
				note = true
			}
		}
		if !note {
			t.Errorf("the extra community is not kept with its note: %+v", d.Kept)
		}
		noLine(t, d, "snmp", "no snmp-server community")
		// the rendered community missing is pasted by value
		d = planI(t, f, func(c *IOSConfig) {
			c.noGlobal("snmp-server community lab-ro-community")
			c.noGlobal("snmp-server community other-example")
		}, Options{})
		wantLine(t, d, "snmp", "snmp-server community <secret:1> RO TACCTL-SNMP")
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
	// 0.2.7: the objects of a scope's IOS snmp block (blocks_cisco_test.go has
	// the rest of what the planner does with them)
	"ios.snmp.block-community": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-block")
		// missing: typed by value, under the block's mark
		d := planI(t, f, func(c *IOSConfig) { c.noGlobal("snmp-server community poller-ro") }, Options{Scope: "lab"})
		wantLine(t, d, "snmp", "snmp-server community <secret:2> RO POLLERS")
		if got := realTexts(d); !slices.Contains(got, "snmp-server community poller-ro RO POLLERS") {
			t.Errorf("by value: %q", got)
		}
		// another access: retyped in place, never removed
		d = planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server community poller-ro RW POLLERS") }, Options{Scope: "lab"})
		wantLine(t, d, "snmp", "snmp-server community <secret:2> RO POLLERS")
		noLine(t, d, "snmp", "no snmp-server community")
		// a device's own community is kept
		wantKept(t, d, "snmp", "snmp-server community <other:1> RO TACCTL-SNMP")
	},
	"ios.snmp.block-acl": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-block")
		d := planI(t, f, func(c *IOSConfig) {
			blk := c.blockFor("ip access-list standard POLLERS")
			blk.lines = append(blk.lines, " permit 203.0.113.9")
		}, Options{Scope: "lab"})
		wantLine(t, d, "snmp", "ip access-list standard POLLERS > no permit 203.0.113.9")
		// a list the block does not define (another community's) is kept
		d = planI(t, f, func(c *IOSConfig) {
			c.typeGlobal("snmp-server community device-own RO DEVICE-LIST")
			c.typeGlobal("ip access-list standard DEVICE-LIST")
			c.blockFor("ip access-list standard DEVICE-LIST").lines = append(c.blockFor("ip access-list standard DEVICE-LIST").lines, " permit 203.0.113.9")
		}, Options{Scope: "lab"})
		noLine(t, d, "snmp", "DEVICE-LIST")
	},
	"ios.snmp.block-host": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-block")
		d := planI(t, f, func(c *IOSConfig) { c.noGlobal("snmp-server host 192.0.2.61") }, Options{Scope: "lab"})
		wantLine(t, d, "snmp", "snmp-server host 192.0.2.61 version 2c <secret:3>")
		// the same host and community with another version: retyped in
		// place, nothing removed; the device's other host is kept
		d = planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server host 192.0.2.61 poller-traps udp-port 1162") }, Options{Scope: "lab"})
		wantLine(t, d, "snmp", "snmp-server host 192.0.2.61 version 2c <secret:3>")
		noLine(t, d, "snmp", "no snmp-server host")
		wantKept(t, d, "snmp", "snmp-server host 192.0.2.50 version 2c <other:2>")
	},
	"ios.snmp.block-traps": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-block")
		// the device enables the type in the expanded form: nothing to type
		d := planI(t, f, nil, Options{Scope: "lab"})
		noLine(t, d, "snmp", "enable traps")
		// it lacks the line: typed; the device's other lines are kept
		d = planI(t, f, func(c *IOSConfig) {
			c.noGlobal("snmp-server enable traps snmp")
			c.typeGlobal("snmp-server enable traps tty")
		}, Options{Scope: "lab"})
		wantLine(t, d, "snmp", "snmp-server enable traps snmp linkdown linkup")
		noLine(t, d, "snmp", "no snmp-server enable traps")
		wantKept(t, d, "snmp", "snmp-server enable traps tty")
	},
	// 0.2.7: the trap source and the system block of a scope (system_ios_test.go
	// has the rest of what the planner does with them)
	"ios.snmp.block-trap-source": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		// another interface: retyped in place, nothing removed
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server trap-source Loopback1") }, Options{Scope: "lab"})
		wantLine(t, d, "snmp", "snmp-server trap-source Loopback0")
		noLine(t, d, "snmp", "no snmp-server trap-source")
		// the device's own, with the block stating none, is kept
		f = fixtureNamed(t, "cisco.reference-lab")
		d = planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server trap-source Loopback1") }, Options{Scope: "lab"})
		noLine(t, d, "snmp", "trap-source")
		wantKept(t, d, "snmp", "snmp-server trap-source loopback1")
	},
	"ios.system.banner": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		d := planI(t, f, func(c *IOSConfig) { c.typeBanner("banner login ^C\nAnother banner\n^C") }, Options{Scope: "lab"})
		wantLine(t, d, "system", "banner login ^\nAuthorized use only.\n! Activity is logged.\n^")
		noLine(t, d, "system", "no banner login")
		noLine(t, d, "system", "Another")
		for _, k := range d.Kept {
			if k.Section == "system" && strings.Contains(k.Text, "banner") {
				t.Errorf("kept: %+v", k)
			}
		}
		// the banner of the device is no text anywhere in the plan's reports
		if strings.Contains(d.Display(), "Another") {
			t.Errorf("the device's banner is shown:\n%s", d.Display())
		}
	},
	"ios.system.domain-name": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("ip domain name other.example.net") }, Options{Scope: "lab"})
		wantLine(t, d, "system", "ip domain name lab.example.net")
		noLine(t, d, "system", "no ip domain name")
	},
	"ios.system.timezone": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("clock timezone PST -8 0") }, Options{Scope: "lab"})
		wantLine(t, d, "system", "clock timezone CET 1")
		noLine(t, d, "system", "no clock timezone")
	},
	"ios.system.ntp-authenticate": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		d := planI(t, f, func(c *IOSConfig) { c.noGlobal("ntp authenticate") }, Options{Scope: "lab"})
		wantLine(t, d, "system", "ntp authenticate")
		noLine(t, d, "system", "no ntp authenticate")
		// the device has it and the block says nothing: nothing is typed
		d = planI(t, f, nil, Options{Scope: "lab"})
		noLine(t, d, "system", "ntp authenticate")
	},
	"ios.system.domain-list": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		d := planI(t, f, func(c *IOSConfig) { c.noGlobal("ip domain list lab.example.net") }, Options{Scope: "lab"})
		wantLine(t, d, "system", "ip domain list lab.example.net")
		noLine(t, d, "system", "no ip domain list")
		wantKept(t, d, "system", "ip domain list other.example.net")
	},
	"ios.system.name-server": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		d := planI(t, f, func(c *IOSConfig) { c.noGlobal("ip name-server 192.0.2.53 192.0.2.54") }, Options{Scope: "lab"})
		wantLine(t, d, "system", "ip name-server 192.0.2.53")
		wantLine(t, d, "system", "ip name-server 192.0.2.54")
		noLine(t, d, "system", "no ip name-server")
		wantKept(t, d, "system", "ip name-server 198.51.100.53")
	},
	"ios.system.ntp-server": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		// the same host with other options: retyped in place, nothing removed
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("ntp server 192.0.2.123 version 3") }, Options{Scope: "lab"})
		wantLine(t, d, "system", "ntp server 192.0.2.123 version 4 key 5 prefer")
		noLine(t, d, "system", "no ntp server")
		// the device's other server is kept
		wantKept(t, d, "system", "ntp server 198.51.100.123")
	},
	"ios.system.ntp-key": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		// typed (by value) only where the device has no key of the number
		d := planI(t, f, func(c *IOSConfig) {
			c.noGlobal("ntp authentication-key 5 md5 0822455D0A16 7")
			c.typeGlobal("ntp authentication-key 9 md5 OTHEROTHER 7")
		}, Options{Scope: "lab"})
		var key Line
		for _, l := range d.Lines {
			if strings.Contains(l.Text, "ntp authentication-key") {
				key = l
			}
		}
		if key.Text != "ntp authentication-key 5 md5 lab-ntp-key-0123" || !key.HasValue || key.Shown() != "ntp authentication-key 5 <secret>" {
			t.Errorf("the key line: %+v", key)
		}
		noLine(t, d, "system", "no ntp authentication-key")
		wantKept(t, d, "system", "ntp authentication-key 9")
		// the device's key of the number, of another algorithm, is left as it is
		d = planI(t, f, func(c *IOSConfig) { c.typeGlobal("ntp authentication-key 5 md5 OTHEROTHER 7") }, Options{Scope: "lab"})
		noLine(t, d, "system", "authentication-key")
	},
	"ios.system.ntp-trusted-key": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		d := planI(t, f, func(c *IOSConfig) {
			c.noGlobal("ntp trusted-key 5")
			c.typeGlobal("ntp trusted-key 9")
		}, Options{Scope: "lab"})
		wantLine(t, d, "system", "ntp trusted-key 5")
		noLine(t, d, "system", "no ntp trusted-key")
		wantKept(t, d, "system", "ntp trusted-key 9")
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
