package plan

// The allow-list tripwire (plan D133): derived from the ownership tables, one
// case per owned row (as owned_test.go), and a never list that no table can
// open. TestEveryRowHasAnAllowedCase fails for a row without a case.

import (
	"errors"
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

// allowedCase is what a row admits and what it refuses, as Junos statements
// with the tables alone (a '$' is any name).
type allowedCase struct {
	ok  []string
	bad []string
}

var allowedRowCases = map[string]allowedCase{
	"junos.roles.class": {
		ok:  []string{`set system login class NET-OPS permissions all`, `set system login class NET-OPS idle-timeout 30`, `delete system login class NET-OPS allow-commands "show .*"`},
		bad: []string{`delete system login class NET-OPS`, `set system login class`},
	},
	"junos.roles.user-class": {
		ok:  []string{`set system login user alice class NET-OPS`},
		bad: []string{`delete system login user alice class`, `set system login user alice full-name "Alice"`, `delete system login user alice`},
	},
	"junos.aaa.order": {
		ok:  []string{`delete system authentication-order`, `set system authentication-order [ password tacplus ]`, `set system authentication-order tacplus`},
		bad: []string{`delete system`, `set system authentication-retries 3`},
	},
	"junos.aaa.events": {
		ok:  []string{`set system accounting events [ login change-log ]`, `delete system accounting events interactive-commands`},
		bad: []string{`set system accounting events login deeper`},
	},
	"junos.aaa.destination": {
		ok:  []string{`set system accounting destination tacplus`, `delete system accounting destination radius`},
		bad: []string{`delete system accounting`, `set system accounting destination tacplus server 192.0.2.8`},
	},
	"junos.aaa.tacplus": {
		ok:  []string{`set system tacplus-server 192.0.2.8 secret VALUE`, `set system tacplus-server 192.0.2.8 single-connection`, `delete system tacplus-server 192.0.2.8 source-address`},
		bad: []string{`delete system tacplus-server 192.0.2.8`, `delete system tacplus-server`, `set system tacplus-options service-deny`},
	},
	"junos.aaa.radius": {
		ok:  []string{`set system radius-server 192.0.2.8 port 1812`, `set system radius-server 192.0.2.8 accounting-port 1813`, `delete system radius-server 192.0.2.8 timeout`},
		bad: []string{`delete system radius-server 192.0.2.8`, `delete system radius-server`},
	},
	"junos.snmp.client-list": {
		ok:  []string{`set snmp client-list MGMT 192.0.2.0/24`, `delete snmp client-list MGMT 10.0.0.0/8`},
		bad: []string{`delete snmp client-list MGMT`, `delete snmp`},
	},
	"junos.snmp.community": {
		ok:  []string{`set snmp community pubstr authorization read-only`, `set snmp community pubstr client-list-name MGMT`, `delete snmp community pubstr clients 10.0.0.0/8`},
		bad: []string{`delete snmp community pubstr`},
	},
	"junos.snmp.block-community": {
		ok:  []string{`set snmp community pubstr clients 192.0.2.0/24 restrict`, `delete snmp community pubstr clients 10.0.0.0/8`},
		bad: []string{`delete snmp community pubstr`, `delete snmp community`},
	},
	"junos.snmp.trap-group": {
		ok:  []string{`set snmp trap-group TG version v2`, `set snmp trap-group TG targets 192.0.2.9`, `delete snmp trap-group TG categories link`},
		bad: []string{`delete snmp trap-group TG`},
	},
	"junos.snmp.trap-options": {
		ok:  []string{`set snmp trap-options source-address 192.0.2.1`},
		bad: []string{`delete snmp trap-options source-address`},
	},
	"junos.snmp.v3-user": {
		ok:  []string{`set snmp v3 usm local-engine user mon authentication-sha authentication-password VALUE`, `delete snmp v3 usm local-engine user mon privacy-none`},
		bad: []string{`delete snmp v3 usm local-engine user mon`, `delete snmp v3`},
	},
	"junos.snmp.v3-group": {
		ok:  []string{`set snmp v3 vacm security-to-group security-model usm security-name mon group MONGRP`},
		bad: []string{`delete snmp v3 vacm security-to-group security-model usm security-name mon`},
	},
	"junos.snmp.v3-access": {
		ok:  []string{`set snmp v3 vacm access group MONGRP default-context-prefix security-model usm security-level authentication read-view ALL`},
		bad: []string{`delete snmp v3 vacm access group MONGRP`},
	},
	"junos.snmp.view": {
		ok:  []string{`set snmp view ALL oid .1 include`, `delete snmp view ALL oid .1.3 include`},
		bad: []string{`delete snmp view ALL`},
	},
	"junos.snmp.location": {
		ok:  []string{`set snmp location "Rack 4"`},
		bad: []string{`delete snmp location`, `delete snmp location "Rack 4"`},
	},
	"junos.snmp.contact": {
		ok:  []string{`set snmp contact noc`},
		bad: []string{`delete snmp contact`},
	},
	"junos.snmp.description": {
		ok:  []string{`set snmp description "edge switch"`},
		bad: []string{`delete snmp description`},
	},
	"junos.system.login-message": {
		ok:  []string{`set system login message "Authorized use only"`},
		bad: []string{`delete system login message`},
	},
	"junos.system.domain-name": {
		ok:  []string{`set system domain-name example.net`},
		bad: []string{`delete system domain-name`},
	},
	"junos.system.time-zone": {
		ok:  []string{`set system time-zone UTC`},
		bad: []string{`delete system time-zone`},
	},
	"junos.system.ntp-boot-server": {
		ok:  []string{`set system ntp boot-server 192.0.2.123`},
		bad: []string{`delete system ntp boot-server`},
	},
	"junos.system.ntp-source-address": {
		ok:  []string{`set system ntp source-address 192.0.2.1`},
		bad: []string{`delete system ntp source-address`},
	},
	"junos.system.ntp-server-version": {
		ok:  []string{`set system ntp server 192.0.2.123 version 4`},
		bad: []string{`delete system ntp server 192.0.2.123 version`},
	},
	"junos.system.ntp-server-key": {
		ok:  []string{`set system ntp server 192.0.2.123 key 7`},
		bad: []string{`delete system ntp server 192.0.2.123 key`},
	},
	"junos.system.ntp-server-routing-instance": {
		ok:  []string{`set system ntp server 192.0.2.123 routing-instance mgmt`},
		bad: []string{`delete system ntp server 192.0.2.123 routing-instance`},
	},
	"junos.system.domain-search": {
		ok:  []string{`set system domain-search example.net`},
		bad: []string{`delete system domain-search example.net`},
	},
	"junos.system.name-server": {
		ok:  []string{`set system name-server 192.0.2.53`},
		bad: []string{`delete system name-server 192.0.2.53`},
	},
	"junos.system.ntp-server": {
		ok:  []string{`set system ntp server 192.0.2.123`, `set system ntp server 192.0.2.123 prefer`},
		bad: []string{`delete system ntp server 192.0.2.123`},
	},
	"junos.system.ntp-key": {
		ok:  []string{`set system ntp authentication-key 7 type md5`, `set system ntp authentication-key 7 value VALUE`},
		bad: []string{`delete system ntp authentication-key 7`},
	},
	"junos.system.ntp-trusted-key": {
		ok:  []string{`set system ntp trusted-key 7`},
		bad: []string{`delete system ntp trusted-key 7`},
	},
	"junos.mgmt-acl.filter": {
		ok: []string{
			`set firewall family inet filter MGMT term permit-mgmt from source-address 192.0.2.0/24`,
			`delete firewall family inet filter MGMT term old`,
			`insert firewall family inet filter MGMT term permit-mgmt before term deny-mgmt`,
			`insert firewall family inet filter MGMT term permit-mgmt after term deny-snmp`,
		},
		bad: []string{`delete firewall family inet filter MGMT`, `delete firewall`, `set firewall family inet6 filter MGMT term t then accept`},
	},
}

func TestEveryRowHasAnAllowedCase(t *testing.T) {
	for _, r := range junosOwned {
		if _, ok := allowedRowCases[r.ID]; !ok {
			t.Errorf("Junos row %s has no allow-list case", r.ID)
		}
	}
	for id := range allowedRowCases {
		if !slices.ContainsFunc(junosOwned, func(r OwnedRow) bool { return r.ID == id }) {
			t.Errorf("case %s names no Junos row", id)
		}
	}
}

func TestAllowedPerOwnedRow(t *testing.T) {
	for _, r := range junosOwned {
		c := allowedRowCases[r.ID]
		t.Run(r.ID, func(t *testing.T) {
			for _, s := range c.ok {
				if err := Allowed("juniper", s); err != nil {
					t.Errorf("%s refused: %v", s, err)
				}
				if err := (Allow{Vendor: "juniper", Sections: []string{r.Section}}).Check(s); err != nil {
					t.Errorf("%s refused with section %s only: %v", s, r.Section, err)
				}
				// without the row's section it is outside the planned
				// hierarchies, wherever else the same path might be owned
				other := slices.DeleteFunc(slices.Clone(PlanOrder(devconf.FamilyJunos)), func(n string) bool { return n == r.Section })
				if err := (Allow{Vendor: "juniper", Sections: other}).Check(s); err == nil {
					// another section may own the same hierarchy (a block
					// row shares a pattern with a structured one)
					shared := false
					for _, o := range junosOwned {
						if o.Section != r.Section && slices.Contains(other, o.Section) {
							if _, _, ok := matchPrefix(strings.Fields(o.Pattern), splitTokens(s)[1:]); ok {
								shared = true
							}
						}
					}
					if !shared {
						t.Errorf("%s allowed without section %s", s, r.Section)
					}
				}
			}
			for _, s := range c.bad {
				err := Allowed("juniper", s)
				if err == nil {
					t.Errorf("%s allowed", s)
				} else if !errors.Is(err, ErrNotAllowed) {
					t.Errorf("%s: %v is not ErrNotAllowed", s, err)
				}
			}
		})
	}
}

// The tables drive the list: a row added to junosOwned is allowed with no
// other change, and a statement outside every row is refused.
func TestAllowedFollowsTheTables(t *testing.T) {
	const stmt = "set snmp future-leaf FL1 option on"
	if err := Allowed("juniper", stmt); err == nil {
		t.Fatalf("%s allowed before its row exists", stmt)
	}
	saved := junosOwned
	t.Cleanup(func() { junosOwned = saved })
	junosOwned = append(slices.Clone(junosOwned),
		OwnedRow{ID: "junos.snmp.future", Section: "snmp", Pattern: "snmp future-leaf $", Mode: ModeWhole})
	if err := Allowed("juniper", stmt); err != nil {
		t.Errorf("a new row does not admit its statement: %v", err)
	}
	// the section decides too
	if err := (Allow{Vendor: "juniper", Sections: []string{"roles"}}).Check(stmt); err == nil {
		t.Error("a statement of an unplanned section is allowed")
	}
}

// The never list holds whatever the tables say: each statement is refused
// with its hierarchy named by a row, and with a row of the tables that would
// own it.
func TestAllowedNeverList(t *testing.T) {
	never := []string{
		`set system root-authentication encrypted-password HASH`,
		`delete system root-authentication`,
		`set system services ssh root-login allow`,
		`delete system services netconf`,
		`set interfaces lo0 unit 0 family inet filter input MGMT`,
		`set interfaces ge-0/0/0 description uplink`,
		`set groups g1 system login message x`,
		`set apply-groups g1`,
		`set system login user alice authentication encrypted-password HASH`,
		`set system login user alice authentication ssh-rsa KEY`,
		`set system login user root class super-user`,
		`set system login user root authentication plain-text-password`,
	}
	saved := junosOwned
	t.Cleanup(func() { junosOwned = saved })
	// open a hierarchy for each of them in the tables
	rows := slices.Clone(junosOwned)
	for i, s := range never {
		toks := splitTokens(s)[1:]
		n := min(len(toks), 3)
		rows = append(rows, OwnedRow{ID: "junos.test." + string(rune('a'+i)), Section: "roles", Pattern: strings.Join(toks[:n], " "), Mode: ModeWhole})
	}
	rows = append(rows, OwnedRow{ID: "junos.test.user", Section: "roles", Pattern: "system login user $", Mode: ModeWhole})
	rows = append(rows, OwnedRow{ID: "junos.test.services", Section: "roles", Pattern: "system services", Mode: ModeWhole})
	junosOwned = rows
	a := Allow{Vendor: "juniper"}
	for _, s := range never {
		err := a.Check(s)
		var ae *AllowError
		if !errors.As(err, &ae) {
			t.Errorf("%s: allowed or not an AllowError: %v", s, err)
			continue
		}
		if !ae.Never {
			t.Errorf("%s: refused, but not by the never list: %v", s, err)
		}
	}
	// the invoking login, and a name that is not the login
	b := Allow{Vendor: "juniper", Login: "alice"}
	err := b.Check("set system login user alice class NET-OPS")
	var ae *AllowError
	if !errors.As(err, &ae) || !ae.Never {
		t.Errorf("the invoking login's user: %v", err)
	}
	if err := b.Check("set system login user bob class NET-OPS"); err != nil {
		t.Errorf("another user's class leaf: %v", err)
	}
}

// Junos completes a unique abbreviation: nothing after the class name of a
// template user, and no abbreviation of a word the plan never writes.
func TestAllowedAbbreviationsAfterAnOwnedPrefix(t *testing.T) {
	for _, s := range []string{
		`set system login user tmpl class super-user authentication encrypted-password X`,
		`set system login user tmpl class super-user auth encrypted-password X`,
		`set system login user tmpl class super-user authen encrypted-password X`,
		`set system login user tmpl class super-user uid 0`,
		`set system login user tmpl class super-user ui 0`,
		`set system login user tmpl class super-user full-name x`,
		`set system login user tmpl auth encrypted-password X`,
		`set system login user tmpl uid 0`,
		`set system login user tmpl u 0`,
	} {
		if err := Allowed("juniper", s); err == nil {
			t.Errorf("%s allowed", s)
		}
	}
	// the user-class row has no more words than the class's name
	for _, r := range junosOwned {
		if r.ID == "junos.roles.user-class" && r.Depth != 6 {
			t.Errorf("the user-class row has depth %d, want 6", r.Depth)
		}
	}
	// a template user's class (a class named like the beginning of a
	// never word included) and the class's leaves are as before
	for _, s := range []string{
		`set system login user tmpl class super-user`,
		`set system login user tmpl class a`,
		`set system login class NET-OPS permissions all`,
		`set system login class NET-OPS allow-commands "show .*"`,
	} {
		if err := Allowed("juniper", s); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
}

// The invoking login's class: a lock-out the planner's own guards cover for
// what the rendering sets, and nothing else.
func TestAllowLoginClass(t *testing.T) {
	exp := []devices.Section{{Name: "roles", Lines: []string{
		"set system login class NET-OPS permissions [ view configure ]",
		"set system login class NET-OPS idle-timeout 30",
		"set system login class OTHER permissions all",
		"set system login user alice class NET-OPS",
	}}}
	a := Allow{Vendor: "juniper", Expected: exp, LoginClass: "NET-OPS"}
	for _, s := range []string{
		"set system login class NET-OPS permissions [ view configure ]",
		"set system login class NET-OPS idle-timeout 30",
		"set system login class OTHER permissions all",
		"set system login user alice class NET-OPS",
	} {
		if err := a.Check(s); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
	for _, s := range []string{
		"set system login class NET-OPS idle-timeout 1",
		"set system login class NET-OPS deny-commands .*",
		"set system login class NET-OPS permissions all",
		`delete system login class NET-OPS allow-commands "show .*"`,
		"delete system login class NET-OPS permissions",
		"delete system login class NET-OPS idle-timeout 30",
	} {
		err := a.Check(s)
		var ae *AllowError
		if !errors.As(err, &ae) {
			t.Errorf("%s: allowed or not an AllowError: %v", s, err)
			continue
		}
		if !ae.Never || !strings.Contains(ae.Why, "lock") {
			t.Errorf("%s: not a never refusal naming the lock-out: %+v", s, ae)
		}
	}
	// without it the same statements pass
	b := Allow{Vendor: "juniper", Expected: exp}
	if err := b.Check("set system login class NET-OPS idle-timeout 1"); err != nil {
		t.Errorf("no login class: %v", err)
	}
}

// A single quote is not a Junos quote.
func TestAllowedSingleQuote(t *testing.T) {
	for _, s := range []string{
		`set snmp location 'Rack 4'`,
		`set snmp location it's`,
		`set system login message "a" 'b; delete system'`,
	} {
		err := Allowed("juniper", s)
		var ae *AllowError
		if !errors.As(err, &ae) {
			t.Errorf("%s: allowed or not an AllowError: %v", s, err)
		}
	}
	// inside double quotes it is text
	if err := Allowed("juniper", `set snmp location "it's Rack 4"`); err != nil {
		t.Errorf("an apostrophe in double quotes: %v", err)
	}
}

// The tables alone admit any name: a caller that types must hold the
// rendering, and Ready says whether it does.
func TestAllowReady(t *testing.T) {
	if err := (Allow{Vendor: "juniper"}).Ready(); !errors.Is(err, ErrNoExpected) {
		t.Errorf("no rendering: %v", err)
	}
	if err := (Allow{Vendor: "juniper", Sections: []string{"snmp"}, Expected: []devices.Section{}}).Ready(); !errors.Is(err, ErrNoExpected) {
		t.Errorf("an empty rendering: %v", err)
	}
	if err := (Allow{Vendor: "juniper", Sections: []string{}}).Ready(); err != nil {
		t.Errorf("no section planned: %v", err)
	}
	exp := []devices.Section{{Name: "snmp", Lines: []string{"set snmp contact x"}}}
	if err := (Allow{Vendor: "juniper", Expected: exp}).Ready(); err != nil {
		t.Errorf("a rendering: %v", err)
	}
	// CheckDelta fails closed with no rendering
	d := Delta{Vendor: "juniper", Sections: []SectionPlan{{Name: "roles", State: StatePlanned}},
		Lines: []Line{{Section: "roles", Op: OpSet, Text: "set system login user stranger class NET-OPS"}}}
	if err := (Allow{}).CheckDelta(d); !errors.Is(err, ErrNoExpected) {
		t.Errorf("a delta with no rendering: %v", err)
	}
}

// Syntax the allow-list does not take, and statements that are not a change.
func TestAllowedSyntax(t *testing.T) {
	for _, s := range []string{
		"", "# a comment", "set", "delete", "commit", "rollback 0", "load set terminal", "activate snmp",
		"deactivate snmp community x", "request system reboot",
		"set snmp location x; delete snmp", "set snmp location x | no-more", "set snmp location {x}",
		" set snmp location x", "set snmp location\tx",
		// marks of an elided secret, and the placeholder of --no-secrets
		"set system tacplus-server 192.0.2.8 secret <secret>",
		"set snmp community <secret:1> authorization read-only",
		"set system tacplus-server 192.0.2.8 secret <SECRET>",
	} {
		if err := Allowed("juniper", s); err == nil {
			t.Errorf("%q allowed", s)
		}
	}
	for _, v := range []string{"cisco", "ios", "wti", "", "nonsense"} {
		if err := Allowed(v, "set snmp location x"); err == nil {
			t.Errorf("vendor %q has an allow-list", v)
		}
	}
	if err := Allowed("junos", "set snmp location x"); err != nil {
		t.Errorf("the family name: %v", err)
	}
	// a section that is never emitted plans nothing, whatever is named
	if err := (Allow{Vendor: "juniper", Sections: []string{"netconf", "breakglass"}}).Check("set snmp location x"); err == nil {
		t.Error("a never-emitted section admits a statement")
	}
}

// An error holds no value: a refused statement is shown by its hierarchy,
// a secret masked.
func TestAllowErrorHoldsNoValue(t *testing.T) {
	for _, s := range []string{
		`set system root-authentication encrypted-password CANARYHASH`,
		`set system login user alice authentication encrypted-password CANARYHASH`,
		`delete snmp community CANARYNAME`,
		`set groups g1 snmp community CANARYNAME`,
		`set interfaces ge-0/0/0 description CANARYHASH`,
		`set protocols bgp group g authentication-key CANARYHASH`,
		`set vlans v1 description CANARYHASH`,
	} {
		err := Allowed("juniper", s)
		if err == nil {
			t.Errorf("%s allowed", s)
			continue
		}
		if strings.Contains(err.Error(), "CANARY") {
			t.Errorf("the error holds a value: %v", err)
		}
	}
}

// With the rendering and the login: a name must be one the rendering
// names; a statement the rendering emits is allowed whatever the tables say;
// and the plan's own lines of every fixture pass.
func TestAllowWithTheRendering(t *testing.T) {
	exp := expectedSections(t, synthExpected)
	a := Allow{Vendor: "juniper", Expected: exp, Login: "alice"}

	var class, user string
	for _, s := range exp {
		for _, l := range s.Lines {
			if f := strings.Fields(l); len(f) == 7 && f[1] == "system" && f[2] == "login" && f[3] == "user" && f[5] == "class" {
				class, user = f[6], f[4]
			}
		}
	}
	if class == "" {
		t.Fatal("no template user in the rendering")
	}
	if err := a.Check("set system login user " + user + " class " + class); err != nil {
		t.Errorf("a template user's class: %v", err)
	}
	for _, s := range []string{
		"set system login user stranger class " + class,
		"set system login class NOT-RENDERED permissions all",
		"delete system login class NOT-RENDERED allow-commands x",
		"set system tacplus-server 203.0.113.99 single-connection",
		"set firewall family inet filter NOT-RENDERED term t then accept",
	} {
		if err := a.Check(s); err == nil {
			t.Errorf("%s allowed against the rendering", s)
		}
		if err := Allowed("juniper", s); err != nil {
			t.Errorf("%s refused by the tables alone: %v", s, err)
		}
	}

	// a statement the tables do not own but the rendering emits
	odd := []devices.Section{{Name: "roles", Lines: []string{"set system login idle-timeout 30"}}}
	if err := (Allow{Vendor: "juniper", Expected: odd, Sections: []string{"roles"}}).Check("set system login idle-timeout 30"); err != nil {
		t.Errorf("a rendered statement: %v", err)
	}
	if err := (Allow{Vendor: "juniper", Expected: odd, Sections: []string{"roles"}}).Check("set system login idle-timeout 31"); err == nil {
		t.Error("another value of a rendered statement is allowed")
	}
	if err := Allowed("juniper", "set system login idle-timeout 30"); err == nil {
		t.Error("an unowned statement is allowed without the rendering")
	}
}

// Every statement the planner produces for the fixtures, with the secrets by
// value, passes the allow-list built from the same inputs: the list does not
// refuse what the plan needs, and the tables alone admit it too.
func TestAllowedAdmitsEveryPlannedLine(t *testing.T) {
	n := 0
	for _, f := range fixtures(t) {
		if f.vendor != "juniper" {
			continue
		}
		exp, cur, plain := f.load(t)
		opt := f.options()
		opt.Secrets = true
		d, err := Plan(f.vendor, exp, cur, plain, opt)
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		a := Allow{Expected: exp, Login: "invoking-login"}
		if err := a.CheckDelta(d); err != nil {
			t.Errorf("%s: %v", f.name, err)
		}
		for i, l := range d.Lines {
			if err := Allowed("juniper", l.Text); err != nil {
				t.Errorf("%s line %d (tables alone): %v", f.name, i+1, err)
			}
			n++
		}
		// a line whose section is not planned is refused
		if len(d.Lines) > 0 {
			o := d
			o.Sections = nil
			if err := a.CheckDelta(o); err == nil {
				t.Errorf("%s: a delta with no planned section passes", f.name)
			}
		}
	}
	if n < 50 {
		t.Errorf("only %d planned lines were checked", n)
	}
}

// A --no-secrets plan holds the placeholder in a line of a secret: it is
// never sent.
func TestAllowedRefusesPlaceholders(t *testing.T) {
	f := fixtureNamed(t, "juniper.lab-superuser")
	exp, cur, plain := f.load(t)
	opt := f.options()
	opt.NoSecrets = true
	d, err := Plan(f.vendor, exp, cur, plain, opt)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range d.Lines {
		if strings.Contains(l.Text, "<SECRET>") {
			found = true
			if err := Allowed("juniper", l.Text); err == nil {
				t.Errorf("%s allowed", l.Text)
			}
		}
	}
	if !found {
		t.Skip("the fixture has no placeholder line")
	}
}

func TestAllowCheckDeltaRefusesOtherVendors(t *testing.T) {
	if err := (Allow{}).CheckDelta(Delta{Vendor: devconf.FamilyIOS}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("an IOS delta: %v", err)
	}
}

// The gate table of 0.2.8 is consumed through devices.Data.Release: whatever
// release is recorded, what devices.Managed renders for the device is what
// the allow-list built from it admits, and the global idle-timeout the
// release lacks is not among the planned sections' statements.
func TestAllowedAdmitsTheRenderingOfEveryRelease(t *testing.T) {
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
	for _, release := range []string{"", "11.4R7.5", "15.1R7-S9", "16.1R1", "25.4R1-S2.3"} {
		d := devices.Data{Model: m, Conf: cfg, ServerIP: "192.0.2.42", Release: release,
			ACL: devices.MgmtACL{Name: "MGMT-ACL", CIDRs: []string{"10.1.100.0/23", "10.0.20.0/24"}},
			SNMP: devices.SNMPInput{Scope: "lab", Version: "v2c", Community: "ro-community", CredFrom: "scope",
				Contact: "Example NOC", Location: "Example City", Ranges: []string{"10.1.101.0/24"}}}
		secs, err := devices.Managed(devices.Request{Vendor: "juniper", Scope: "lab", Protocol: devices.TACACS, Source: devices.SourceDefault}, d)
		if err != nil {
			t.Fatalf("release %q: %v", release, err)
		}
		a := Allow{Vendor: "juniper", Expected: secs, Login: "invoking-login"}
		n := 0
		for _, s := range secs {
			if !slices.Contains(PlanOrder(devconf.FamilyJunos), s.Name) {
				continue
			}
			for _, l := range s.Lines {
				if err := a.Check(l); err != nil {
					t.Errorf("release %q [%s]: %v", release, s.Name, err)
				}
				if strings.HasPrefix(l, "set system login idle-timeout ") ||
					strings.HasPrefix(l, "set system login class ") && strings.Contains(l, " idle-timeout ") {
					t.Errorf("release %q [%s]: a gated statement is planned: %s", release, s.Name, l)
				}
				n++
			}
		}
		if n < 20 {
			t.Errorf("release %q: only %d statements", release, n)
		}
	}
}
