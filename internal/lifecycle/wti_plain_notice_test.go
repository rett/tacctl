package lifecycle

import (
	"slices"
	"strings"
	"testing"
)

// The notice names, per scope that has a registered WTI unit, the plain IPv4
// entries of the list that applies to it and the units, and says nothing
// when no such scope has one.
func TestWTIPlainNotice(t *testing.T) {
	units := func(pairs ...string) []WTIUnit {
		var out []WTIUnit
		for i := 0; i+1 < len(pairs); i += 2 {
			out = append(out, WTIUnit{Name: pairs[i], Scope: pairs[i+1]})
		}
		return out
	}
	many := units("u1", "lab", "u2", "lab", "u3", "lab", "u4", "lab", "u5", "lab", "u6", "lab", "u7", "lab")
	for _, tc := range []struct {
		name  string
		lists []ScopeACL
		units []WTIUnit
		want  []string // fragments, in order, of the scope lines; nil: no notice
	}{
		{"scope's own list", []ScopeACL{{Scope: "lab", Permits: []string{"10.0.0.0/8", "192.0.2.0/24:tcp/22"}}},
			units("u1", "lab"), []string{"scope lab: 10.0.0.0/8  (1 WTI device: u1)"}},
		{"the global list is the scope's", []ScopeACL{{Scope: "lab", Global: true, Permits: []string{"10.0.0.0/8"}}},
			units("u1", "lab", "u2", "lab"), []string{"scope lab: 10.0.0.0/8  (2 WTI devices: u1, u2; the global list)"}},
		{"entries with services only", []ScopeACL{{Scope: "lab", Permits: []string{"10.0.0.0/8:tcp/22", "192.0.2.0/24:tcp/22,udp/161", "198.51.100.0/24:icmp"}}},
			units("u1", "lab"), nil},
		{"ipv6 only", []ScopeACL{{Scope: "lab", Permits: []string{"2001:db8::/32", "2001:db8:1::/48:tcp/22"}}},
			units("u1", "lab"), nil},
		{"ipv6 is not named beside ipv4", []ScopeACL{{Scope: "lab", Permits: []string{"2001:db8::/32", "10.0.0.0/8"}}},
			units("u1", "lab"), []string{"scope lab: 10.0.0.0/8  (1 WTI device: u1)"}},
		{"a scope without a WTI unit", []ScopeACL{{Scope: "lab", Permits: []string{"10.0.0.0/8"}}, {Scope: "dmz", Permits: []string{"192.0.2.0/24"}}},
			units("u1", "dmz"), []string{"scope dmz: 192.0.2.0/24  (1 WTI device: u1)"}},
		{"a unit no scope answers", []ScopeACL{{Scope: "lab", Permits: []string{"10.0.0.0/8"}}},
			units("u1", ""), nil},
		{"no unit", []ScopeACL{{Scope: "lab", Permits: []string{"10.0.0.0/8"}}}, nil, nil},
		{"an empty list", []ScopeACL{{Scope: "lab"}}, units("u1", "lab"), nil},
		{"more than five units", []ScopeACL{{Scope: "lab", Permits: []string{"10.0.0.0/8"}}}, many,
			[]string{"scope lab: 10.0.0.0/8  (7 WTI devices: u1, u2, u3, u4, u5 and 2 more)"}},
		{"scopes in name order, entries once, the canonical net", []ScopeACL{
			{Scope: "prod", Permits: []string{"10.1.2.3/8", "10.0.0.0/8", "192.0.2.7/32"}}, {Scope: "lab", Permits: []string{"172.16.0.0/12"}}},
			units("b", "prod", "a", "lab"),
			[]string{"scope lab: 172.16.0.0/12  (1 WTI device: a)", "scope prod: 10.0.0.0/8, 192.0.2.7/32  (1 WTI device: b)"}},
		{"an entry that is no CIDR is skipped", []ScopeACL{{Scope: "lab", Permits: []string{"not-a-net", "", "10.0.0.0/8"}}},
			units("u1", "lab"), []string{"scope lab: 10.0.0.0/8  (1 WTI device: u1)"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := WTIPlainNotice(tc.lists, tc.units)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("a notice where none is due:\n%s", strings.Join(got, "\n"))
				}
				return
			}
			if len(got) == 0 || got[0] != "Management ACL: plain entries now permit every protocol and port on WTI units." {
				t.Fatalf("head: %q", got)
			}
			var scopes []string
			for _, l := range got {
				if s := strings.TrimPrefix(l, "  "); strings.HasPrefix(s, "scope ") {
					scopes = append(scopes, s)
				}
			}
			if !slices.Equal(scopes, tc.want) {
				t.Errorf("scope lines:\n got %q\nwant %q", scopes, tc.want)
			}
			text := strings.Join(got, "\n")
			for _, w := range []string{"'iptables -A INPUT -s <cidr> -j ACCEPT'", "(0.2.6 rendered ssh and ICMP)", "<cidr>:tcp/22", "tacctl scope mgmt-acl <scope> remove <cidr>"} {
				if !strings.Contains(text, w) {
					t.Errorf("the notice lacks %q:\n%s", w, text)
				}
			}
		})
	}
}
