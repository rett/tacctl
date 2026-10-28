package plan

// The management filter modes of a Junos scope (0.2.20): the plan moves the
// filter between ssh-only and strict in both directions, the comparison reads
// a pulled filter against the mode's rendering, the report lists what stops,
// the lock-out check holds for the strict filter, and the apply allow-list
// admits what the strict rendering says.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/model"
)

const (
	sshOnly = devices.MgmtModeSSHOnly
	strict  = devices.MgmtModeStrict
)

// modeList is a permit list with plain entries, entries with services and an
// IPv6 entry; the server is 192.0.2.42.
var modeList = []string{"10.1.100.0/23", "198.51.100.0/24:tcp/22,udp/161", "203.0.113.0/24:tcp/22,icmp", "2001:db8::/64"}

// managed renders the Junos sections of the lab scope in a mode.
func managedMode(t *testing.T, mode string, list []string) []devices.Section {
	t.Helper()
	return managedModeAuth(t, mode, list, "")
}

// managedModeAuth is managedMode for a walkthrough told to authenticate
// against authServer (--server).
func managedModeAuth(t *testing.T, mode string, list []string, authServer string) []devices.Section {
	t.Helper()
	dir := t.TempDir()
	store, err := os.ReadFile("../../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "store.yaml"), store, 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, err := model.LoadStore(filepath.Join(dir, "store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := conf.Load(filepath.Join(dir, "tacctl.yaml"), []string{"tacacs", "radius"})
	d := devices.Data{Model: m, Conf: cfg, ServerIP: "192.0.2.42", AuthServer: authServer,
		ACL: devices.MgmtACL{Name: "MGMT-ACL", CIDRs: list, Mode: mode},
		SNMP: devices.SNMPInput{Scope: "lab", Version: "v2c", Community: "example-ro", CredFrom: "scope",
			Contact: "NOC", Location: "Lab rack 2", Ranges: []string{"192.0.2.99/32"}}}
	secs, err := devices.Managed(devices.Request{Vendor: "juniper", Scope: "lab", Protocol: devices.TACACS, Source: devices.SourceDefault}, d)
	if err != nil {
		t.Fatal(err)
	}
	return secs
}

// deviceOf is what a device that holds the sections prints: every statement,
// and the lo0 application when applied says so.
func deviceOf(secs []devices.Section, applied bool) string {
	var b strings.Builder
	for _, s := range secs {
		for _, l := range s.Lines {
			b.WriteString(l + "\n")
		}
	}
	if applied {
		b.WriteString("set interfaces lo0 unit 0 family inet filter input MGMT-ACL\n")
	}
	return b.String()
}

func mgmtSection(secs []devices.Section) []string {
	for _, s := range secs {
		if s.Name == "mgmt-acl" {
			return s.Lines
		}
	}
	return nil
}

func planMode(t *testing.T, exp []devices.Section, device string, opt Options) Delta {
	t.Helper()
	cur, err := devconf.Extract("juniper", device, exp...)
	if err != nil {
		t.Fatal(err)
	}
	if opt.Sections == nil {
		opt.Sections = []string{"mgmt-acl"}
	}
	opt.Scope = "lab"
	d, err := Plan("juniper", exp, cur, cur, opt)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func warned(d Delta, substr string) bool {
	return slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, substr) })
}

// A device that holds a rendering is what the plan of that rendering finds
// nothing to change in, in either mode: nothing to paste, no finding.
func TestMgmtModeAConvergedDevicePlansNothing(t *testing.T) {
	for _, mode := range []string{sshOnly, strict} {
		exp := managedMode(t, mode, modeList)
		d := planMode(t, exp, deviceOf(exp, true), Options{MgmtMode: mode, From: "192.0.2.42"})
		if got := lines(d, "mgmt-acl"); len(got) != 0 || len(d.Warnings) != 0 {
			t.Errorf("%s: lines %q warnings %q", mode, got, d.Warnings)
		}
	}
}

// ssh-only to strict: the deny-mgmt and default-accept terms go, the leaves
// permit-mgmt had for ssh and 830 go, the service terms come, the order is the
// rendering's; and the report lists what stops.
func TestMgmtModePlansSSHOnlyToStrict(t *testing.T) {
	ssh, st := managedMode(t, sshOnly, modeList), managedMode(t, strict, modeList)
	d := planMode(t, st, deviceOf(ssh, false), Options{MgmtMode: strict})
	if s := d.Of("mgmt-acl"); s.State != StatePlanned {
		t.Fatalf("mgmt-acl: %+v", s)
	}
	f := "firewall family inet filter MGMT-ACL term "
	for _, want := range []string{
		"delete " + f + "deny-mgmt",
		"delete " + f + "default-accept",
		"delete " + f + "permit-mgmt from protocol tcp",
		"delete " + f + "permit-mgmt from destination-port ssh",
		"delete " + f + "permit-mgmt from destination-port 830",
		"delete " + f + "permit-mgmt from source-address 198.51.100.0/24",
		"set " + f + "permit-tcp-22 from source-address 198.51.100.0/24",
		"set " + f + "permit-tcp-22 from destination-port ssh",
		"set " + f + "permit-tcp-22 then accept",
		"set " + f + "permit-udp-161 from destination-port snmp",
		"set " + f + "permit-icmp from protocol icmp",
	} {
		wantLine(t, d, "mgmt-acl", want)
	}
	for _, l := range lines(d, "mgmt-acl") {
		if strings.Contains(l, "default-accept then") && strings.HasPrefix(l, "set ") {
			t.Errorf("the plan sets the default-accept term: %q", l)
		}
	}
	for _, w := range []string{"is strict: it has no default-accept term. Once it is applied to lo0", "BGP, OSPF, IS-IS, VRRP, LDP, BFD", "(the SNMP clients still poll)", "TACACS+ and RADIUS replies from servers that are not in the list", "NTP, syslog and DHCP", "SNMP from sources outside the list",
		"192.0.2.42/32, 10.1.100.0/23", "Keep a console session open"} {
		if !warned(d, w) {
			t.Errorf("the report lacks %q: %q", w, d.Warnings)
		}
	}
	// the paste leaves the device with exactly the strict filter
	cfg := ParseJunos(deviceOf(ssh, false))
	if err := cfg.Apply(lineOps(d, "mgmt-acl")); err != nil {
		t.Fatal(err)
	}
	after := planMode(t, st, cfg.Text(), Options{MgmtMode: strict})
	if got := lines(after, "mgmt-acl"); len(got) != 0 {
		t.Errorf("after the paste the plan still has:\n%s", strings.Join(got, "\n"))
	}
	if filterTermsOf(cfg.Text(), "MGMT-ACL") != filterTermsOf(deviceOf(st, false), "MGMT-ACL") {
		t.Errorf("the terms after the paste differ from the strict filter:\n%s\nwant\n%s", filterTermsOf(cfg.Text(), "MGMT-ACL"), filterTermsOf(deviceOf(st, false), "MGMT-ACL"))
	}
}

// filterTermsOf is the term names of a filter in the order of their
// statements, from set lines.
func filterTermsOf(text, filter string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		t := splitTokens(l)
		if len(t) > 7 && t[0] == "set" && t[1] == "firewall" && t[4] == "filter" && t[5] == filter && t[6] == "term" && !slices.Contains(out, t[7]) {
			out = append(out, t[7])
		}
	}
	return strings.Join(out, " ")
}

// strict to ssh-only: the service terms go, the default-accept and deny-mgmt
// terms and permit-mgmt's leaves return, and the report says what is accepted
// again.
func TestMgmtModePlansStrictToSSHOnly(t *testing.T) {
	ssh, st := managedMode(t, sshOnly, modeList), managedMode(t, strict, modeList)
	d := planMode(t, ssh, deviceOf(st, false), Options{MgmtMode: sshOnly})
	f := "firewall family inet filter MGMT-ACL term "
	for _, want := range []string{
		"delete " + f + "permit-tcp-22", "delete " + f + "permit-udp-161", "delete " + f + "permit-icmp",
		"set " + f + "permit-mgmt from protocol tcp",
		"set " + f + "deny-mgmt then discard",
		"set " + f + "default-accept then accept",
	} {
		wantLine(t, d, "mgmt-acl", want)
	}
	if !warned(d, "has no default-accept term, so it drops by default") || !warned(d, "the plan adds the default-accept term") ||
		!warned(d, "tacctl scope mgmt-acl lab mode strict") {
		t.Errorf("the report: %q", d.Warnings)
	}
	cfg := ParseJunos(deviceOf(st, false))
	if err := cfg.Apply(lineOps(d, "mgmt-acl")); err != nil {
		t.Fatal(err)
	}
	if got := lines(planMode(t, ssh, cfg.Text(), Options{MgmtMode: sshOnly}), "mgmt-acl"); len(got) != 0 {
		t.Errorf("after the paste the plan still has:\n%s", strings.Join(got, "\n"))
	}
}

// lineOps are a section's lines as the statements the simulator applies.
func lineOps(d Delta, section string) []Line {
	var out []Line
	for _, l := range d.Lines {
		if l.Section == section {
			out = append(out, l)
		}
	}
	return out
}

// The comparison reads a pulled filter against the rendering of the mode: the
// strict filter is the same as itself, and differs from the ssh-only
// rendering, and the other way round; the ssh-only filter is untouched by the
// new mode.
func TestMgmtModeCompareReadsTheRightMode(t *testing.T) {
	ssh, st := managedMode(t, sshOnly, modeList), managedMode(t, strict, modeList)
	state := func(exp []devices.Section, device string) string {
		cur, err := devconf.Extract("juniper", device, exp...)
		if err != nil {
			t.Fatal(err)
		}
		res, err := devconf.CompareAll(exp, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res {
			if r.Name == "mgmt-acl" {
				return string(r.State)
			}
		}
		return "none"
	}
	if got := state(st, deviceOf(st, true)); got != "ok" {
		t.Errorf("strict against strict: %s", got)
	}
	if got := state(ssh, deviceOf(ssh, true)); got != "ok" {
		t.Errorf("ssh-only against ssh-only: %s", got)
	}
	if got := state(ssh, deviceOf(st, true)); got == "ok" {
		t.Errorf("a strict filter reads as the ssh-only one")
	}
	if got := state(st, deviceOf(ssh, true)); got == "ok" {
		t.Errorf("an ssh-only filter reads as the strict one")
	}
}

// A site's own deny-by-default filter named like tacctl's is not made
// accept-by-default without a word: the ssh-only plan says it adds the
// default-accept term and names the strict mode.
func TestMgmtModeSSHOnlyPlanOverASitesDenyByDefaultFilter(t *testing.T) {
	ssh := managedMode(t, sshOnly, []string{"10.1.100.0/23"})
	site := "set firewall family inet filter MGMT-ACL term site-allow from source-address 10.1.100.0/23\n" +
		"set firewall family inet filter MGMT-ACL term site-allow then accept\n"
	d := planMode(t, ssh, site, Options{MgmtMode: sshOnly})
	if !warned(d, "has no default-accept term, so it drops by default (a strict filter, or the site's own)") {
		t.Errorf("warnings: %q", d.Warnings)
	}
	wantLine(t, d, "mgmt-acl", "delete firewall family inet filter MGMT-ACL term site-allow")
	// the same site filter against the strict rendering of its permit list
	// is the strict plan's: it still says what stops (the device accepts by
	// default only where it has a default-accept term, and this one has none)
	st := managedMode(t, strict, []string{"10.1.100.0/23"})
	d = planMode(t, st, site, Options{MgmtMode: strict})
	if warned(d, "is strict: it has no default-accept term") {
		t.Errorf("a device that drops by default is told what stops: %q", d.Warnings)
	}
	// a device with no filter at all: strict says what stops once applied
	d = planMode(t, st, "set system host-name jsw1\n", Options{MgmtMode: strict})
	if !warned(d, "is strict: it has no default-accept term") {
		t.Errorf("no filter yet: %q", d.Warnings)
	}
}

// The lock-out check of the strict filter: a filter applied on lo0 is not
// replaced by one that would not permit --from. The address must be a source
// that is accepted for ssh: permit-mgmt, or a service term that holds tcp/22.
func TestMgmtModeStrictRefusesAFilterThatWouldNotPermitFrom(t *testing.T) {
	ssh, st := managedMode(t, sshOnly, modeList), managedMode(t, strict, modeList)
	device := deviceOf(ssh, true)
	for _, c := range []struct {
		from    string
		refused bool
		why     string
	}{
		{"192.0.2.42", false, "the server's own address heads permit-mgmt"},
		{"10.1.101.7", false, "inside a plain entry"},
		{"198.51.100.9", false, "inside permit-tcp-22"},
		{"203.0.113.9", false, "inside permit-tcp-22 (the icmp term of that entry is another term)"},
		{"203.0.113.9", false, ""},
		{"192.0.2.99", true, "an SNMP client is no source of the strict filter's ssh"},
		{"192.0.2.200", true, "outside the list"},
	} {
		d := planMode(t, st, device, Options{MgmtMode: strict, From: c.from})
		got := d.Of("mgmt-acl")
		if c.refused != (got.State == StateSkipped) || (c.refused && !strings.Contains(got.Why, "strict filter that is accepted for ssh")) {
			t.Errorf("--from %s (%s): %+v", c.from, c.why, got)
		}
	}
	// the same plan with the ssh-only text of the check is unchanged
	d := planMode(t, ssh, deviceOf(managedMode(t, sshOnly, []string{"10.1.100.0/23"}), true), Options{MgmtMode: sshOnly, From: "192.0.2.200"})
	if got := d.Of("mgmt-acl"); got.State != StateSkipped || !strings.Contains(got.Why, "permit-mgmt source of the rendered filter") {
		t.Errorf("ssh-only refusal: %+v", got)
	}
	// a service that does not hold tcp/22 is not a way in
	udp := managedMode(t, strict, []string{"10.1.100.0/23", "198.51.100.0/24:udp/161"})
	d = planMode(t, udp, deviceOf(ssh, true), Options{MgmtMode: strict, From: "198.51.100.9"})
	if got := d.Of("mgmt-acl"); got.State != StateSkipped {
		t.Errorf("a source with udp/161 only: %+v", got)
	}
	// a range that holds 22, and tcp with every port, are
	for _, entry := range []string{"198.51.100.0/24:tcp/20-25", "198.51.100.0/24:tcp/*"} {
		e := managedMode(t, strict, []string{"10.1.100.0/23", entry})
		d = planMode(t, e, deviceOf(ssh, true), Options{MgmtMode: strict, From: "198.51.100.9"})
		if got := d.Of("mgmt-acl"); got.State != StatePlanned {
			t.Errorf("%s: %+v", entry, got)
		}
	}
	// without --from: a warning, the section stays, and it says what stops
	d = planMode(t, st, device, Options{MgmtMode: strict})
	if d.Of("mgmt-acl").State != StatePlanned || !warned(d, "--from was not given: check that the address you are logged in from is inside a source of the strict filter") ||
		!warned(d, "The device applies it to lo0 already, so from the commit") {
		t.Errorf("no --from: %+v %q", d.Of("mgmt-acl"), d.Warnings)
	}
	// a filter that is not applied on lo0 has no check, and a move that
	// leaves lo0 alone is no refusal
	d = planMode(t, st, deviceOf(ssh, false), Options{MgmtMode: strict, From: "192.0.2.200"})
	if d.Of("mgmt-acl").State != StatePlanned {
		t.Errorf("not applied on lo0: %+v", d.Of("mgmt-acl"))
	}
	// an IPv6 --from is not checked against the family inet filter
	d = planMode(t, st, device, Options{MgmtMode: strict, From: "2001:db8::5"})
	if d.Of("mgmt-acl").State != StatePlanned || !warned(d, "IPv6 address") {
		t.Errorf("IPv6: %+v %q", d.Of("mgmt-acl"), d.Warnings)
	}
}

// What the strict rendering says is what an apply may type: every statement
// of the section passes the allow-list, and so do the deletes and the inserts
// of the plan that moves the filter, in both directions.
func TestMgmtModeAllowListAdmitsTheStrictStatements(t *testing.T) {
	ssh, st := managedMode(t, sshOnly, modeList), managedMode(t, strict, modeList)
	for _, c := range []struct {
		name       string
		exp        []devices.Section
		device     string
		mode       string
		wantInsert bool
	}{
		{"to strict", st, deviceOf(ssh, false), strict, false},
		{"to ssh-only", ssh, deviceOf(st, false), sshOnly, false},
	} {
		a := Allow{Vendor: "juniper", Expected: c.exp, Login: "invoking-login"}
		for _, l := range mgmtSection(c.exp) {
			if err := a.Check(l); err != nil {
				t.Errorf("%s: the rendering's own statement %q: %v", c.name, l, err)
			}
		}
		d := planMode(t, c.exp, c.device, Options{MgmtMode: c.mode})
		if len(lines(d, "mgmt-acl")) == 0 {
			t.Fatalf("%s: no plan", c.name)
		}
		if err := a.CheckDelta(d); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// a term the rendering does not name is not admitted
	a := Allow{Vendor: "juniper", Expected: st, Login: "invoking-login"}
	if err := a.Check("set firewall family inet filter OTHER term permit-tcp-22 then accept"); err == nil {
		t.Error("a filter the rendering does not name is allowed")
	}
	if err := a.Check("delete firewall family inet filter MGMT-ACL term default-accept"); err != nil {
		t.Errorf("the delete of a term of the filter: %v", err)
	}
	if err := a.Check("insert firewall family inet filter MGMT-ACL term permit-icmp after term permit-tcp-22"); err != nil {
		t.Errorf("the insert of a term of the filter: %v", err)
	}
}

// The back-out of a move between the modes puts the device's filter back.
func TestMgmtModeBackoutPutsTheFilterBack(t *testing.T) {
	ssh, st := managedMode(t, sshOnly, modeList), managedMode(t, strict, modeList)
	for _, c := range []struct {
		name         string
		exp          []devices.Section
		device, mode string
		back         []string
	}{
		{"to strict", st, deviceOf(ssh, false), strict, []string{"term deny-mgmt then discard", "term default-accept then accept", "delete firewall family inet filter MGMT-ACL term permit-tcp-22"}},
		{"to ssh-only", ssh, deviceOf(st, false), sshOnly, []string{"term permit-tcp-22 then accept", "delete firewall family inet filter MGMT-ACL term default-accept"}},
	} {
		d := planMode(t, c.exp, c.device, Options{MgmtMode: c.mode})
		h := fixtureNamed(t, "juniper.synthetic-lab").header()
		text, err := Backout(d, h, Wrapper{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, want := range c.back {
			if !strings.Contains(text, want) {
				t.Errorf("%s: the back-out lacks %q:\n%s", c.name, want, text)
			}
		}
	}
}

// The strict filter accepts the server the device authenticates against: with
// --server it is permit-mgmt's second source, the plan sets it, the report
// names it among the sources the filter accepts, and the lock-out check
// reads it as a source accepted for ssh, as it reads the first. A device that
// holds the rendering plans nothing.
func TestMgmtModeStrictAcceptsTheAuthenticationServer(t *testing.T) {
	const auth = "198.51.100.9"
	ssh, st := managedModeAuth(t, sshOnly, modeList, auth), managedModeAuth(t, strict, modeList, auth)
	f := "firewall family inet filter MGMT-ACL term permit-mgmt from source-address "
	var want []string
	for _, l := range mgmtSection(st) {
		if strings.HasPrefix(l, "set "+f) {
			want = append(want, strings.TrimPrefix(l, "set "+f))
		}
	}
	if len(want) < 3 || want[0] != "192.0.2.42/32" || want[1] != auth+"/32" {
		t.Fatalf("permit-mgmt sources: %q", want)
	}
	d := planMode(t, st, deviceOf(ssh, true), Options{MgmtMode: strict, From: auth})
	if got := d.Of("mgmt-acl"); got.State != StatePlanned {
		t.Errorf("--from the authentication server: %+v", got)
	}
	wantLine(t, d, "mgmt-acl", "set "+f+auth+"/32")
	if !warned(d, "192.0.2.42/32, "+auth+"/32, 10.1.100.0/23") {
		t.Errorf("the report does not name the sources: %q", d.Warnings)
	}
	// the other address of the walkthrough is accepted the same way
	d = planMode(t, st, deviceOf(ssh, true), Options{MgmtMode: strict, From: "192.0.2.42"})
	if got := d.Of("mgmt-acl"); got.State != StatePlanned {
		t.Errorf("--from the source: %+v", got)
	}
	if got := lines(planMode(t, st, deviceOf(st, true), Options{MgmtMode: strict, From: auth}), "mgmt-acl"); len(got) != 0 {
		t.Errorf("a device that holds the rendering plans %q", got)
	}
	// the move back deletes it with the rest of the strict terms' sources
	back := planMode(t, ssh, deviceOf(st, false), Options{MgmtMode: sshOnly})
	wantLine(t, back, "mgmt-acl", "delete "+f+auth+"/32")
}
