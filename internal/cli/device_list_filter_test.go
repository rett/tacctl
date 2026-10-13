package cli

import (
	"testing"

	"github.com/rett/tacctl/internal/devreg"
)

func listEntry(name, addr, vendor, scope string) devreg.Entry {
	return devreg.Entry{Device: devreg.Device{Name: name, Address: addr, Vendor: vendor}, Scope: scope}
}

func TestDeviceListFilterMatch(t *testing.T) {
	es := []devreg.Entry{
		listEntry("Sw1.lab.example.net", "10.20.0.5", "juniper", "lab"),
		listEntry("rtr2.lab.example.net", "10.20.1.9", "cisco", "lab"),
		listEntry("wti1.site.example.net", "192.0.2.14", "wti", "prod"),
		listEntry("fw1", "2001:db8::1", "other", ""),
	}
	cases := []struct {
		name string
		f    deviceListFilter
		want []string
	}{
		{"none", deviceListFilter{}, []string{"Sw1.lab.example.net", "rtr2.lab.example.net", "wti1.site.example.net", "fw1"}},
		{"name substring, any case", deviceListFilter{names: []string{"sw1"}}, []string{"Sw1.lab.example.net"}},
		{"name list", deviceListFilter{names: []string{"rtr", "fw"}}, []string{"rtr2.lab.example.net", "fw1"}},
		{"ip exact", deviceListFilter{addrs: []string{"192.0.2.14"}}, []string{"wti1.site.example.net"}},
		{"ip cidr", deviceListFilter{addrs: []string{"10.20.0.0/16"}}, []string{"Sw1.lab.example.net", "rtr2.lab.example.net"}},
		{"ip text prefix", deviceListFilter{addrs: []string{"10.20.1."}}, []string{"rtr2.lab.example.net"}},
		{"ip v6 cidr", deviceListFilter{addrs: []string{"2001:db8::/32"}}, []string{"fw1"}},
		{"vendor", deviceListFilter{vendors: []string{"cisco", "wti"}}, []string{"rtr2.lab.example.net", "wti1.site.example.net"}},
		{"scope", deviceListFilter{scopes: []string{"lab"}}, []string{"Sw1.lab.example.net", "rtr2.lab.example.net"}},
		{"and across options", deviceListFilter{scopes: []string{"lab"}, vendors: []string{"juniper"}}, []string{"Sw1.lab.example.net"}},
		{"word: scope", deviceListFilter{word: "prod"}, []string{"wti1.site.example.net"}},
		{"word: address text", deviceListFilter{word: "10.20.0"}, []string{"Sw1.lab.example.net"}},
		{"word: vendor", deviceListFilter{word: "cisco"}, []string{"rtr2.lab.example.net"}},
		{"nothing", deviceListFilter{names: []string{"zzz"}}, nil},
	}
	for _, c := range cases {
		var got []string
		for _, e := range es {
			if c.f.match(e) {
				got = append(got, e.Name)
			}
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestSortEntriesByName(t *testing.T) {
	es := []devreg.Entry{
		listEntry("b2", "10.0.0.2", "", ""), listEntry("A1", "10.0.0.9", "", ""), listEntry("a1", "10.0.0.1", "", ""), listEntry("c", "10.0.0.3", "", ""),
	}
	sortEntriesByName(es)
	got := es[0].Name + es[1].Name + es[2].Name + es[3].Name
	if got != "a1A1b2c" {
		t.Errorf("order %q", got)
	}
}
