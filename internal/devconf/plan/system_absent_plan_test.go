package plan

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// The 'absent' lines of the system blocks (0.2.19): the services a block
// requires to be absent. The device that holds one gets one delete (Junos) or
// no (IOS) of the whole statement, whatever sits under it; the other services
// of the device are left alone.

// junosAbsentSection is the Junos system section of a block, the 'absent'
// lines included.
func junosAbsentSection(t testing.TB, text string) devices.Section {
	t.Helper()
	sec := systemSectionOf(t, text)
	b, fs := blocks.LintSystem(text, blocks.LayerDevice)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	sec.Forbid = blocks.SystemAbsent(blocks.ResolveSystem(nil, b, nil))
	return sec
}

func junosAbsentCase(service string) func(t *testing.T) {
	return func(t *testing.T) {
		f := systemFixture(t)
		exp := withSystem(expectedSections(t, f.expected), junosAbsentSection(t, "absent system services "+service+"\n"))
		d, text := planSystem(t, func(c *JunosConfig) {
			c.Add("set system services " + service)
			c.Add("set system services " + service + " connection-limit 5")
			c.Add("set system services ssh")
		}, exp, systemOpt)
		wantLine(t, d, "system", "delete system services "+service)
		if n := strings.Count(strings.Join(lines(d, "system"), "\n"), "delete system services "+service); n != 1 {
			t.Errorf("%d deletes of the service:\n%s", n, strings.Join(lines(d, "system"), "\n"))
		}
		noLine(t, d, "system", "services ssh")
		noLine(t, d, "system", "set system services")
		systemConverges(t, f, exp, text, d)
		// the device that holds none has nothing planned
		d2, _ := planSystem(t, nil, exp, systemOpt)
		noLine(t, d2, "system", "services")
		// the allow-list admits exactly this delete, with the rendering
		allow := Allow{Vendor: "juniper", Expected: exp}
		if err := allow.Check("delete system services " + service); err != nil {
			t.Errorf("the delete is refused: %v", err)
		}
		if err := allow.CheckDelta(d); err != nil {
			t.Errorf("the plan is refused by the allow-list: %v", err)
		}
		for _, other := range []string{"delete system services ssh", "delete system services netconf", "delete system services", "set system services " + service,
			"delete system services " + service + " connection-limit"} {
			if err := allow.Check(other); err == nil {
				t.Errorf("%q is allowed", other)
			}
		}
		// without the marker in the rendering the delete is refused
		if err := (Allow{Vendor: "juniper", Expected: expectedSections(t, f.expected)}).Check("delete system services " + service); err == nil {
			t.Error("a delete of a service the rendering does not forbid is allowed")
		}
	}
}

func iosAbsentSection(t testing.TB, text string) devices.Section {
	t.Helper()
	sec := iosSystemSectionOf(t, text)
	b, fs := blocks.LintIOSSystem(text, blocks.LayerDevice)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	sec.Forbid = blocks.IOSSystemAbsent(blocks.ResolveIOSSystem(nil, b, nil))
	return sec
}

func iosAbsentCase(statement string) func(t *testing.T) {
	return func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		exp := withSystem(expectedSections(t, f.expected), iosAbsentSection(t, "absent "+statement+"\n"))
		c := ParseIOS(capture(t, f.raw))
		c.typeGlobal(statement)
		text := c.Text()
		cur, err := devconf.Extract(f.vendor, text, exp...)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Plan(f.vendor, exp, cur, cur, Options{Scope: "lab", Class: f.class, Syntax: f.syntax()})
		if err != nil {
			t.Fatal(err)
		}
		wantLine(t, d, "system", "no "+statement)
		if n := strings.Count(strings.Join(lines(d, "system"), "\n"), "no "+statement); n != 1 {
			t.Errorf("%d removals:\n%s", n, strings.Join(lines(d, "system"), "\n"))
		}
		// pasted, the section reads ok
		c = ParseIOS(text)
		if err := c.Apply(d.Lines); err != nil {
			t.Fatal(err)
		}
		cur, err = devconf.Extract(f.vendor, c.Text(), exp...)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := devconf.CompareAll(exp, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			if r.Name == devconf.SectionSystem && r.State != devconf.StateOK {
				t.Errorf("system reads %s after the plan:\n%v", r.State, r.Lines)
			}
		}
		// a device that holds none has nothing planned
		d2, err := Plan(f.vendor, exp, mustExtract(t, f, exp, capture(t, f.raw)), mustExtract(t, f, exp, capture(t, f.raw)), Options{Scope: "lab", Class: f.class, Syntax: f.syntax()})
		if err != nil {
			t.Fatal(err)
		}
		noLine(t, d2, "system", "no "+statement)
	}
}

func mustExtract(t testing.TB, f fixture, exp []devices.Section, text string) devconf.Extracted {
	t.Helper()
	x, err := devconf.Extract(f.vendor, ParseIOS(text).Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func init() {
	for _, s := range []string{"telnet", "ftp", "finger", "xnm-clear-text", "web-management"} {
		junosRowCases["junos.system.absent-"+s] = junosAbsentCase(s)
		allowedRowCases["junos.system.absent-"+s] = allowedCase{
			ok:  []string{"delete system services " + s},
			bad: []string{"delete system services", "delete system services ssh", "delete system services " + s + " connection-limit", "set system services " + s},
		}
	}
	for id, stmt := range map[string]string{
		"ios.system.absent-http-server":        "ip http server",
		"ios.system.absent-http-secure-server": "ip http secure-server",
		"ios.system.absent-tcp-small-servers":  "service tcp-small-servers",
		"ios.system.absent-udp-small-servers":  "service udp-small-servers",
		"ios.system.absent-finger":             "ip finger",
		"ios.system.absent-service-finger":     "service finger",
	} {
		iosRowCases[id] = iosAbsentCase(stmt)
	}
}
