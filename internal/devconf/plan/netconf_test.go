package plan

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// The NETCONF service section (D145-D148 of docs/plans/0.2.10-plan.md): the
// synthetic lab device holds 'system services netconf ssh'.

func netconfEnable(lines ...string) devices.Section {
	if len(lines) == 0 {
		lines = []string{"set system services netconf ssh"}
	}
	return devices.Section{Name: devconf.SectionNetconf, Lines: lines, Secret: make([]bool, len(lines))}
}

func netconfAbsent() devices.Section {
	return devices.Section{Name: devconf.SectionNetconf, Absent: true}
}

// planWithNetconf plans a mutated copy of the synthetic lab with the netconf
// section of the rendering replaced (a zero Section: left as the fixture
// has it, which is no section: leave).
func planWithNetconf(t *testing.T, sec devices.Section, mut func(c *JunosConfig), opt Options) (Delta, []devices.Section) {
	t.Helper()
	f := fixtureNamed(t, "juniper.synthetic-lab")
	exp := slices.DeleteFunc(slices.Clone(expectedSections(t, f.expected)), func(s devices.Section) bool {
		return s.Name == devconf.SectionNetconf
	})
	if sec.Name != "" {
		exp = append(exp, sec)
	}
	c := ParseJunos(capture(t, f.raw))
	if mut != nil {
		mut(c)
	}
	return planText(t, f, exp, c.Text(), opt), exp
}

func dropNetconf(c *JunosConfig) {
	_ = c.Apply([]Line{{Op: OpDelete, Text: "delete system services netconf"}})
}

func TestNetconfEnableConverged(t *testing.T) {
	d, _ := planWithNetconf(t, netconfEnable(), nil, Options{})
	if sp := d.Of(devconf.SectionNetconf); sp.State != StateNoChange {
		t.Errorf("an enabled service the device has: %+v", sp)
	}
	if len(lines(d, devconf.SectionNetconf)) != 0 {
		t.Errorf("lines for a converged service: %q", lines(d, devconf.SectionNetconf))
	}
}

func TestNetconfEnableMissing(t *testing.T) {
	d, exp := planWithNetconf(t, netconfEnable(), dropNetconf, Options{})
	if sp := d.Of(devconf.SectionNetconf); sp.State != StatePlanned {
		t.Fatalf("not planned: %+v", sp)
	}
	wantLine(t, d, devconf.SectionNetconf, "set system services netconf ssh")
	noLine(t, d, devconf.SectionNetconf, "delete")
	if !TouchesNetconf(d) {
		t.Error("TouchesNetconf is false for a delta that sets the service")
	}
	if err := (Allow{Expected: exp}).CheckDelta(d); err != nil {
		t.Errorf("the allow-list refuses the plan's own lines: %v", err)
	}
	var back []string
	for _, l := range d.Backout {
		back = append(back, l.Text)
	}
	if !slices.ContainsFunc(back, func(s string) bool { return strings.HasPrefix(s, "delete system services netconf") }) {
		t.Errorf("the back-out does not remove what the plan added: %q", back)
	}
	// the order of the plan: the section sits before mgmt-acl
	order := d.order()
	if i, j := slices.Index(order, devconf.SectionNetconf), slices.Index(order, "mgmt-acl"); i < 0 || j < i {
		t.Errorf("netconf is not before mgmt-acl: %q", order)
	}
}

func TestNetconfEnableWithLimits(t *testing.T) {
	sec := netconfEnable("set system services netconf ssh connection-limit 5", "set system services netconf ssh rate-limit 10")
	d, exp := planWithNetconf(t, sec, addMany(
		"set system services netconf ssh connection-limit 10",
		"set system services netconf traceoptions flag all"), Options{})
	wantLine(t, d, devconf.SectionNetconf, "set system services netconf ssh connection-limit 5")
	wantLine(t, d, devconf.SectionNetconf, "set system services netconf ssh rate-limit 10")
	// the device's value is replaced in place, and what the setting does not
	// state is the device's own
	noLine(t, d, devconf.SectionNetconf, "delete")
	wantKept(t, d, devconf.SectionNetconf, "traceoptions")
	if err := (Allow{Expected: exp}).CheckDelta(d); err != nil {
		t.Errorf("the allow-list refuses the plan's own lines: %v", err)
	}
}

func TestNetconfEnableChildrenSatisfyTheBareStatement(t *testing.T) {
	// the device prints only 'ssh connection-limit 3', never a bare 'ssh'
	d, _ := planWithNetconf(t, netconfEnable(), func(c *JunosConfig) {
		dropNetconf(c)
		add("set system services netconf ssh connection-limit 3")(c)
	}, Options{})
	if sp := d.Of(devconf.SectionNetconf); sp.State != StateNoChange {
		t.Errorf("the bare statement is asked for beside a child: %+v (%q)", sp, lines(d, devconf.SectionNetconf))
	}
	wantKept(t, d, devconf.SectionNetconf, "connection-limit 3")
}

func TestNetconfDisable(t *testing.T) {
	d, exp := planWithNetconf(t, netconfAbsent(), addMany(
		"set system services netconf ssh connection-limit 5",
		"set system services netconf traceoptions flag all"), Options{})
	got := lines(d, devconf.SectionNetconf)
	if len(got) != 1 || got[0] != "delete system services netconf" {
		t.Fatalf("a disabled service is not one delete: %q", got)
	}
	if !TouchesNetconf(d) {
		t.Error("TouchesNetconf is false for the delete of the service")
	}
	if err := (Allow{Expected: exp}).CheckDelta(d); err != nil {
		t.Errorf("the allow-list refuses the plan's own line: %v", err)
	}
	var found bool
	for _, l := range d.Lines {
		if l.Section == devconf.SectionNetconf && len(l.For) >= 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("the delete does not name the statements it answers: %+v", d.Lines)
	}
	if len(d.Warnings) == 0 {
		t.Error("no warning that the service ends for every NETCONF client")
	}
	// what it takes away comes back with the back-out
	var back []string
	for _, l := range d.Backout {
		back = append(back, l.Text)
	}
	if !slices.Contains(back, "set system services netconf ssh") {
		t.Errorf("the back-out does not type the service again: %q", back)
	}
}

func TestNetconfDisableAbsent(t *testing.T) {
	d, _ := planWithNetconf(t, netconfAbsent(), dropNetconf, Options{})
	if sp := d.Of(devconf.SectionNetconf); sp.State != StateNoChange {
		t.Errorf("a service that is not there: %+v", sp)
	}
	if TouchesNetconf(d) {
		t.Error("TouchesNetconf is true for a delta with no netconf line")
	}
}

// The report says what is not planned: the NETCONF step is among them only
// where the setting leaves the service alone.
func TestNetconfReportNamesWhatIsNotPlanned(t *testing.T) {
	const left = "Not planned: netconf, breakglass (walkthrough Steps 6 and 7)."
	const planned = "Not planned: breakglass (walkthrough Step 7)."
	for name, tc := range map[string]struct {
		sec       devices.Section
		want, not string
	}{
		"leave":   {devices.Section{}, left, planned},
		"enable":  {netconfEnable(), planned, left},
		"disable": {netconfAbsent(), planned, left},
	} {
		d, _ := planWithNetconf(t, tc.sec, nil, Options{})
		rep := strings.Join(strings.Fields(strings.ReplaceAll(Report(d, Header{}, Wrapper{}), "\n#", "\n")), " ")
		if !strings.Contains(rep, tc.want) || strings.Contains(rep, tc.not) {
			t.Errorf("%s: the report's line of what is not planned:\n%s", name, rep)
		}
	}
}

func TestNetconfLeaveIsAsBefore(t *testing.T) {
	// the device holds the service and the rendering says nothing of it
	d, _ := planWithNetconf(t, devices.Section{}, nil, Options{})
	if sp := d.Of(devconf.SectionNetconf); sp.State != StateNever {
		t.Errorf("a scope that leaves the service: %+v", sp)
	}
	if len(lines(d, devconf.SectionNetconf)) != 0 || TouchesNetconf(d) {
		t.Error("a scope that leaves the service plans a line of it")
	}
	if slices.Contains(d.order(), devconf.SectionNetconf) {
		t.Errorf("the section is in the order of a plan that has none: %q", d.order())
	}
	f := fixtureNamed(t, "juniper.synthetic-lab")
	exp := expectedSections(t, f.expected)
	cur, err := devconf.Extract(f.vendor, capture(t, f.raw), exp...)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Plan(f.vendor, exp, cur, cur, Options{Sections: []string{"netconf"}})
	if !errors.Is(err, ErrNeverEmitted) {
		t.Errorf("--section netconf with the service left alone: %v", err)
	}
}

func TestNetconfSelectedBySection(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	exp := append(slices.Clone(expectedSections(t, f.expected)), netconfEnable())
	c := ParseJunos(capture(t, f.raw))
	dropNetconf(c)
	d := planText(t, f, exp, c.Text(), Options{Sections: []string{"netconf"}})
	if got := d.Planned(); !slices.Equal(got, []string{"netconf"}) {
		t.Errorf("--section netconf plans %q", got)
	}
}

// Two devices that need the same change to the service have one shape, in
// the order of a plan (netconf before mgmt-acl), and a device that needs
// another change has another.
func TestNetconfShape(t *testing.T) {
	enable := netconfEnable("set system services netconf ssh connection-limit 5")
	a, _ := planWithNetconf(t, enable, dropNetconf, Options{})
	b, _ := planWithNetconf(t, enable, func(c *JunosConfig) {
		dropNetconf(c)
		add("set system services netconf traceoptions flag all")(c)
	}, Options{})
	ha, la := Shape(a)
	hb, _ := Shape(b)
	if ha == "" || ha != hb {
		t.Errorf("the same change has two shapes: %q %q", ha, hb)
	}
	if !slices.Contains(la, "[netconf]") || !slices.Contains(la, "set system services netconf ssh connection-limit 5") {
		t.Errorf("the shape's lines: %q", la)
	}
	c, _ := planWithNetconf(t, netconfEnable("set system services netconf ssh connection-limit 6"), dropNetconf, Options{})
	if hc, _ := Shape(c); hc == ha {
		t.Error("a limit of another value has the same shape")
	}
	off, _ := planWithNetconf(t, netconfAbsent(), nil, Options{})
	if h, lines := Shape(off); h == "" || h == ha || !slices.Contains(lines, "delete system services netconf") {
		t.Errorf("the shape of a disable: %q %q", h, lines)
	}
}

func TestNetconfAllowList(t *testing.T) {
	enable := []devices.Section{netconfEnable("set system services netconf ssh connection-limit 5")}
	absent := []devices.Section{netconfAbsent()}
	for _, c := range []struct {
		name string
		exp  []devices.Section
		line string
		ok   bool
	}{
		{"rendered limit", enable, "set system services netconf ssh connection-limit 5", true},
		{"another value", enable, "set system services netconf ssh connection-limit 6", false},
		{"bare ssh not rendered", enable, "set system services netconf ssh", false},
		{"the rate limit not rendered", enable, "set system services netconf ssh rate-limit 10", false},
		{"delete while enabled", enable, "delete system services netconf", false},
		{"delete a limit", enable, "delete system services netconf ssh connection-limit", false},
		{"a trace option", enable, "set system services netconf traceoptions flag all", false},
		{"the port", enable, "set system services netconf ssh port 830", false},
		{"delete when disabled", absent, "delete system services netconf", true},
		{"delete ssh when disabled", absent, "delete system services netconf ssh", false},
		{"delete the services", absent, "delete system services", false},
		{"delete ssh service", absent, "delete system services ssh", false},
		{"set when disabled", absent, "set system services netconf ssh", false},
		{"no rendering", nil, "set system services netconf ssh", false},
		{"no netconf section", []devices.Section{{Name: "aaa", Lines: []string{"set system tacplus-server 192.0.2.10 secret x"}}}, "delete system services netconf", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := Allow{Vendor: "juniper", Expected: c.exp}.Check(c.line)
			if c.ok && err != nil {
				t.Errorf("%s refused: %v", c.line, err)
			}
			if !c.ok && err == nil {
				t.Errorf("%s allowed", c.line)
			}
			if !c.ok && err != nil && !errors.Is(err, ErrNotAllowed) {
				t.Errorf("%s: %v is not ErrNotAllowed", c.line, err)
			}
		})
	}
	// a section that is not planned allows nothing under the service
	err := Allow{Vendor: "juniper", Expected: absent, Sections: []string{"snmp"}}.Check("delete system services netconf")
	if err == nil {
		t.Error("the delete is allowed with the netconf section not planned")
	}
}

func TestNetconfStatementAllowed(t *testing.T) {
	for line, want := range map[string]bool{
		"set system services netconf ssh":                          true,
		"set system services netconf ssh connection-limit 1":       true,
		"set system services netconf ssh connection-limit 250":     true,
		"set system services netconf ssh rate-limit 10":            true,
		"delete system services netconf":                           true,
		"set system services netconf ssh connection-limit 0":       false,
		"set system services netconf ssh connection-limit 251":     false,
		"set system services netconf ssh connection-limit 05":      false,
		"set system services netconf ssh connection-limit five":    false,
		"set system services netconf ssh connection-limit":         false,
		"set system services netconf ssh port 830":                 false,
		"set system services netconf rfc-compliant":                false,
		"set system services netconf":                              false,
		"delete system services netconf ssh":                       false,
		"delete system services netconf ssh connection-limit":      false,
		"delete system services":                                   false,
		"insert system services netconf ssh before ssh":            false,
		"set system services ssh":                                  false,
		"set system services netconfx ssh":                         false,
		"deactivate system services netconf":                       false,
		"set system services netconf ssh connection-limit 5 extra": false,
	} {
		if got := NetconfStatementAllowed(line); got != want {
			t.Errorf("NetconfStatementAllowed(%q) = %v, want %v", line, got, want)
		}
	}
}

func init() {
	// the rows of the NETCONF service (owned.go): one case each
	junosRowCases["junos.netconf.ssh"] = func(t *testing.T) {
		d, _ := planWithNetconf(t, netconfEnable(), func(c *JunosConfig) {
			dropNetconf(c)
			add("set system services netconf ssh port 830")(c)
		}, Options{})
		// the device's port beside a missing bare statement: the child
		// satisfies it, nothing is typed and nothing removed
		noLine(t, d, devconf.SectionNetconf, "delete")
		wantKept(t, d, devconf.SectionNetconf, "ssh port 830")
		d, _ = planWithNetconf(t, netconfEnable(), dropNetconf, Options{})
		wantLine(t, d, devconf.SectionNetconf, "set system services netconf ssh")
	}
	junosRowCases["junos.netconf.connection-limit"] = func(t *testing.T) {
		d, _ := planWithNetconf(t, netconfEnable("set system services netconf ssh connection-limit 5"),
			add("set system services netconf ssh connection-limit 10"), Options{})
		wantLine(t, d, devconf.SectionNetconf, "set system services netconf ssh connection-limit 5")
		noLine(t, d, devconf.SectionNetconf, "delete")
		// a limit the setting states none of is the device's own
		d, _ = planWithNetconf(t, netconfEnable(), add("set system services netconf ssh connection-limit 10"), Options{})
		noLine(t, d, devconf.SectionNetconf, "connection-limit")
		wantKept(t, d, devconf.SectionNetconf, "connection-limit 10")
	}
	junosRowCases["junos.netconf.rate-limit"] = func(t *testing.T) {
		d, _ := planWithNetconf(t, netconfEnable("set system services netconf ssh rate-limit 4"),
			add("set system services netconf ssh rate-limit 9"), Options{})
		wantLine(t, d, devconf.SectionNetconf, "set system services netconf ssh rate-limit 4")
		noLine(t, d, devconf.SectionNetconf, "delete")
		d, _ = planWithNetconf(t, netconfEnable(), add("set system services netconf ssh rate-limit 9"), Options{})
		noLine(t, d, devconf.SectionNetconf, "rate-limit")
		wantKept(t, d, devconf.SectionNetconf, "rate-limit 9")
	}
	// Alone, the tables admit none of them: the statements are the setting's
	// (TestNetconfAllowList holds them against the rendering).
	for _, id := range []string{"junos.netconf.ssh", "junos.netconf.connection-limit", "junos.netconf.rate-limit"} {
		allowedRowCases[id] = allowedCase{bad: []string{
			"set system services netconf ssh",
			"set system services netconf ssh connection-limit 5",
			"delete system services netconf ssh connection-limit",
			"delete system services netconf",
		}}
	}
}
