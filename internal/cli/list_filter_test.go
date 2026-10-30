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
		f    listFilter
		want []string
	}{
		{"none", listFilter{}, []string{"Sw1.lab.example.net", "rtr2.lab.example.net", "wti1.site.example.net", "fw1"}},
		{"name substring, any case", listFilter{names: []string{"sw1"}}, []string{"Sw1.lab.example.net"}},
		{"name list", listFilter{names: []string{"rtr", "fw"}}, []string{"rtr2.lab.example.net", "fw1"}},
		{"ip exact", listFilter{addrs: []string{"192.0.2.14"}}, []string{"wti1.site.example.net"}},
		{"ip cidr", listFilter{addrs: []string{"10.20.0.0/16"}}, []string{"Sw1.lab.example.net", "rtr2.lab.example.net"}},
		{"ip text prefix", listFilter{addrs: []string{"10.20.1."}}, []string{"rtr2.lab.example.net"}},
		{"ip v6 cidr", listFilter{addrs: []string{"2001:db8::/32"}}, []string{"fw1"}},
		{"vendor", listFilter{vendors: []string{"cisco", "wti"}}, []string{"rtr2.lab.example.net", "wti1.site.example.net"}},
		{"scope", listFilter{scopes: []string{"lab"}}, []string{"Sw1.lab.example.net", "rtr2.lab.example.net"}},
		{"and across options", listFilter{scopes: []string{"lab"}, vendors: []string{"juniper"}}, []string{"Sw1.lab.example.net"}},
		{"word: scope", listFilter{word: "prod"}, []string{"wti1.site.example.net"}},
		{"word: address text", listFilter{word: "10.20.0"}, []string{"Sw1.lab.example.net"}},
		{"word: vendor", listFilter{word: "cisco"}, []string{"rtr2.lab.example.net"}},
		{"nothing", listFilter{names: []string{"zzz"}}, nil},
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
