package devices

import (
	"slices"
	"strings"
	"testing"
)

// The NETCONF service setting (D145, D146 of docs/plans/0.2.10-plan.md) in
// the walkthrough and in the managed sections.

func TestManagedNetconfSetting(t *testing.T) {
	m, c := managedWorld(t)
	lab := managedProfiles()[0]
	req, base := lab.input(m, c, variants[3])
	if req.Vendor != "juniper" {
		t.Fatalf("the profile is a %s device", req.Vendor)
	}

	for _, tc := range []struct {
		name    string
		set     NetconfSetting
		section bool
		absent  bool
		lines   []string
		live    []string
		missing []string
	}{
		{name: "leave"},
		{name: "enable", set: NetconfSetting{State: NetconfEnable}, section: true,
			lines: []string{"set system services netconf ssh"}, live: []string{"set system services netconf ssh"}},
		{name: "enable with limits", set: NetconfSetting{State: NetconfEnable, ConnectionLimit: 5, RateLimit: 10}, section: true,
			lines: []string{"set system services netconf ssh connection-limit 5", "set system services netconf ssh rate-limit 10"},
			live:  []string{"set system services netconf ssh connection-limit 5", "set system services netconf ssh rate-limit 10"}},
		{name: "enable with a rate limit", set: NetconfSetting{State: NetconfEnable, RateLimit: 3}, section: true,
			lines: []string{"set system services netconf ssh rate-limit 3"}, live: []string{"set system services netconf ssh rate-limit 3"}},
		{name: "disable", set: NetconfSetting{State: NetconfDisable}, section: true, absent: true,
			live: []string{"delete system services netconf"}},
		// limits mean nothing to a service that is not enabled
		{name: "disable with limits", set: NetconfSetting{State: NetconfDisable, ConnectionLimit: 5}, section: true, absent: true,
			live: []string{"delete system services netconf"}},
		{name: "limits of a service left alone", set: NetconfSetting{ConnectionLimit: 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.Netconf = tc.set
			secs := mustManaged(t, req, d)
			sec, ok := sectionOf(secs, "netconf")
			if ok != tc.section {
				t.Fatalf("section present %v, want %v (%+v)", ok, tc.section, sec)
			}
			if sec.Absent != tc.absent {
				t.Errorf("Absent %v, want %v", sec.Absent, tc.absent)
			}
			if !slices.Equal(sec.Lines, tc.lines) {
				t.Errorf("lines %q, want %q", sec.Lines, tc.lines)
			}
			if len(sec.Secret) != len(sec.Lines) || slices.Contains(sec.Secret, true) {
				t.Errorf("secret marks %v for %q", sec.Secret, sec.Lines)
			}
			// the walkthrough carries the statement live, and the step stays
			// commented for a scope that leaves the service alone
			live, commented := walkBody(t, renderText(t, req, d))
			for _, l := range tc.live {
				if !live[l] {
					t.Errorf("%q is not a live line of the walkthrough", l)
				}
			}
			if tc.name == "leave" && live["set system services netconf ssh"] {
				t.Error("a service left alone is live in the walkthrough")
			}
			if tc.name == "leave" && !commented["set system services netconf ssh"] && !commented["  set system services netconf ssh"] {
				// the step's text is the commented form of the statement
				text := renderText(t, req, d)
				if !strings.Contains(text, "#   set system services netconf ssh") {
					t.Error("the commented NETCONF step is gone")
				}
			}
		})
	}
}

// A Cisco device has no such setting: its NETCONF step does not follow it.
func TestManagedNetconfSettingIsJunosOnly(t *testing.T) {
	m, c := managedWorld(t)
	for _, p := range managedProfiles() {
		req, d := p.input(m, c, variants[3])
		if req.Vendor == "juniper" {
			continue
		}
		before := mustManaged(t, req, d)
		d.Netconf = NetconfSetting{State: NetconfEnable, ConnectionLimit: 5}
		after := mustManaged(t, req, d)
		if len(before) != len(after) {
			t.Fatalf("%s: the setting changes the sections of a %s device", p.scope, req.Vendor)
		}
		for i := range before {
			if !slices.Equal(before[i].Lines, after[i].Lines) || before[i].Absent != after[i].Absent {
				t.Errorf("%s: section %s follows the setting", p.scope, before[i].Name)
			}
		}
	}
}

func TestNetconfStatements(t *testing.T) {
	for _, tc := range []struct {
		conn, rate int
		want       []string
	}{
		{0, 0, []string{"set system services netconf ssh"}},
		{5, 0, []string{"set system services netconf ssh connection-limit 5"}},
		{0, 10, []string{"set system services netconf ssh rate-limit 10"}},
		{5, 10, []string{"set system services netconf ssh connection-limit 5", "set system services netconf ssh rate-limit 10"}},
	} {
		if got := NetconfStatements(tc.conn, tc.rate); !slices.Equal(got, tc.want) {
			t.Errorf("NetconfStatements(%d, %d) = %q, want %q", tc.conn, tc.rate, got, tc.want)
		}
	}
}
