package mgmtacl

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/cidr"
)

func TestParseEntryCanonical(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// plain: the CIDR, as the cidr package canonicalises it
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.3", "10.1.2.3/32"},
		{"10.0.0.0/255.0.0.0", "10.0.0.0/8"},
		{"10.9.9.9/8", "10.0.0.0/8"},
		{"2001:DB8::/32", "2001:db8::/32"},
		// one service
		{"172.16.100.0/23:tcp/22", "172.16.100.0/23:tcp/22"},
		{"172.16.100.0/23:udp/161", "172.16.100.0/23:udp/161"},
		{"172.16.100.0/23:icmp", "172.16.100.0/23:icmp"},
		{"172.16.100.0/23:tcp/*", "172.16.100.0/23:tcp/*"},
		{"172.16.100.0/23:udp/161-162", "172.16.100.0/23:udp/161-162"},
		// the order is tcp, udp, icmp, then ports ascending
		{"172.16.100.0/23:icmp,udp/162,udp/161,tcp/443,tcp/22", "172.16.100.0/23:tcp/22,tcp/443,udp/161,udp/162,icmp"},
		{"172.16.100.0/23:udp/161,tcp/22,udp/162", "172.16.100.0/23:tcp/22,udp/161,udp/162"},
		// lower case, blanks
		{"172.16.100.0/23:TCP/22,UDP/161, ICMP", "172.16.100.0/23:tcp/22,udp/161,icmp"},
		{" 172.16.100.0/23 : tcp/22", ""}, // a blank before the colon is no entry
		{" 10.0.0.0/8", ""},               // a blank around the entry is no CIDR, as it never was
		{"10.0.0.0/8:tcp/22 ", ""},
		// repeats go
		{"172.16.100.0/23:tcp/22,tcp/22,udp/161,udp/161", "172.16.100.0/23:tcp/22,udp/161"},
		// '*' of a protocol takes the rest of its entries
		{"172.16.100.0/23:tcp/22,tcp/*,tcp/80-90,udp/161", "172.16.100.0/23:tcp/*,udp/161"},
		{"172.16.100.0/23:tcp/*,udp/*", "172.16.100.0/23:tcp/*,udp/*"},
		// every protocol and port is the plain CIDR, whatever the spelling
		{"172.16.100.0/23:*", "172.16.100.0/23"},
		{"172.16.100.0/23:tcp/*,udp/*,icmp", "172.16.100.0/23"},
		{"172.16.100.0/23:icmp,udp/*,tcp/*", "172.16.100.0/23"},
		{"172.16.100.0/23:tcp/22,*", "172.16.100.0/23"},
		// IPv6 holds colons of its own
		{"2001:db8::/32:tcp/22", "2001:db8::/32:tcp/22"},
		{"2001:db8::/32:tcp/22,icmp", "2001:db8::/32:tcp/22,icmp"},
		{"::/0:udp/161", "::/0:udp/161"},
		{"fe80::1:icmp", "fe80::1/128:icmp"},
		{"2001:db8::/32:*", "2001:db8::/32"},
		// a single port may be written as a range of equal ends? no: low < high
		{"10.0.0.0/8:tcp/1-65535", "10.0.0.0/8:tcp/1-65535"},
		{"10.0.0.0/8:tcp/65535", "10.0.0.0/8:tcp/65535"},
	} {
		got, err := ParseEntry(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("%q: accepted as %q", c.in, got.String())
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("%q: %q, want %q", c.in, got.String(), c.want)
		}
		// canonical is a fixed point
		again, err := ParseEntry(got.String())
		if err != nil || again.String() != got.String() {
			t.Errorf("%q: not stable: %q, %v", c.in, again.String(), err)
		}
	}
}

func TestParseEntryRefused(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "Invalid CIDR"},
		{"garbage", "Invalid CIDR: 'garbage'"},
		{"10.0.0.0/33", "Invalid CIDR"},
		{"foo:tcp/22", "Invalid CIDR: 'foo'"},
		{"10.0.0.0/8:", "no service"},
		{"10.0.0.0/8:ssh", "'ssh' is not a service"},
		{"10.0.0.0/8:22", "'22' is not a service"},
		{"10.0.0.0/8:tcp", "'tcp' is not a service"},
		{"10.0.0.0/8:tcp/", "is not a port"},
		{"10.0.0.0/8:tcp/0", "is not a port"},
		{"10.0.0.0/8:tcp/65536", "is not a port"},
		{"10.0.0.0/8:tcp/-5", "is not a port"},
		{"10.0.0.0/8:tcp/22-", "is not a port"},
		{"10.0.0.0/8:tcp/22-21", "must be lower"},
		{"10.0.0.0/8:tcp/22-22", "must be lower"},
		{"10.0.0.0/8:tcp/x", "is not a port"},
		{"10.0.0.0/8:tcp/22,", "empty service"},
		{"10.0.0.0/8:tcp/22,,udp/161", "empty service"},
		{"10.0.0.0/8:icmp/8", "icmp takes no port"},
		{"10.0.0.0/8:icmpv6", "not a service"},
		{"10.0.0.0/8:sctp/22", "not a service"},
		{"10.0.0.0/8:tcp/22/23", "is not a port"},
		{"10.0.0.0/8:tcp/22-30-40", "is not a port"},
		{"10.0.0.0/8:tcp/1,tcp/2,tcp/3,tcp/4,tcp/5,tcp/6,tcp/7,tcp/8,tcp/9", "9 services"},
	} {
		_, err := ParseEntry(c.in)
		if err == nil {
			t.Errorf("%q: accepted", c.in)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %q, want it to say %q", c.in, err, c.want)
		}
		if Problem(c.in) == "" {
			t.Errorf("%q: Problem is empty", c.in)
		}
	}
}

func TestServicesLimit(t *testing.T) {
	eight := "10.0.0.0/8:tcp/1,tcp/2,tcp/3,tcp/4,tcp/5,tcp/6,tcp/7,tcp/8"
	if _, err := ParseEntry(eight); err != nil {
		t.Errorf("eight services: %v", err)
	}
	// the repeats and the covered ports do not count
	if _, err := ParseEntry(eight + ",tcp/8,tcp/8"); err != nil {
		t.Errorf("eight and repeats: %v", err)
	}
	if e, err := ParseEntry(eight + ",tcp/*,udp/1,icmp"); err != nil || e.String() != "10.0.0.0/8:tcp/*,udp/1,icmp" {
		t.Errorf("tcp/* takes the ports: %q %v", e.String(), err)
	}
	if _, err := ParseEntry(eight + ",udp/9"); err == nil {
		t.Error("nine services accepted")
	}
}

func TestErrorTypes(t *testing.T) {
	_, err := ParseEntry("nonsense")
	var inv *cidr.InvalidError
	if !errors.As(err, &inv) || inv.Value != "nonsense" {
		t.Errorf("a bad CIDR is a *cidr.InvalidError: %T %v", err, err)
	}
	_, err = ParseEntry("10.0.0.0/8:tcp/0")
	var se *Error
	if !errors.As(err, &se) {
		t.Errorf("a bad service is a *Error: %T %v", err, err)
	}
	if Problem("10.0.0.0/8") != "" || Problem("10.0.0.0/8:udp/161") != "" {
		t.Error("a good entry has a problem")
	}
	if Problem("garbage") != "is not a valid CIDR" {
		t.Errorf("Problem(garbage) = %q", Problem("garbage"))
	}
}

func TestPredicates(t *testing.T) {
	for _, c := range []struct {
		in        string
		ssh, icmp bool
		plain     bool
	}{
		{"10.0.0.0/8", true, true, true},
		{"10.0.0.0/8:tcp/22", true, false, false},
		{"10.0.0.0/8:tcp/*", true, false, false},
		{"10.0.0.0/8:tcp/20-30", true, false, false},
		{"10.0.0.0/8:tcp/23-30", false, false, false},
		{"10.0.0.0/8:udp/22", false, false, false},
		{"10.0.0.0/8:udp/*", false, false, false},
		{"10.0.0.0/8:udp/161,icmp", false, true, false},
		{"10.0.0.0/8:tcp/443", false, false, false},
	} {
		e, err := ParseEntry(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if e.AllowsSSH() != c.ssh || e.AllowsICMP() != c.icmp || e.Plain() != c.plain {
			t.Errorf("%s: ssh %v icmp %v plain %v", c.in, e.AllowsSSH(), e.AllowsICMP(), e.Plain())
		}
	}
	if !(Entry{Net: "10.0.0.0/8"}).Permits(UDP, 161) {
		t.Error("a plain entry permits udp/161")
	}
}

func TestServicePorts(t *testing.T) {
	for _, c := range []struct{ in, ports, text string }{
		{"10.0.0.0/8:tcp/22", "22", "tcp/22"},
		{"10.0.0.0/8:udp/161-162", "161:162", "udp/161-162"},
		{"10.0.0.0/8:tcp/*", "", "tcp/*"},
		{"10.0.0.0/8:icmp", "", "icmp"},
	} {
		e, err := ParseEntry(c.in)
		if err != nil || len(e.Services) != 1 {
			t.Fatalf("%s: %v", c.in, err)
		}
		if e.Services[0].Ports() != c.ports || e.Services[0].String() != c.text {
			t.Errorf("%s: ports %q text %q", c.in, e.Services[0].Ports(), e.Services[0].String())
		}
	}
}

func TestGroupAndParseList(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"10.0.0.0/8,192.0.2.0/24", []string{"10.0.0.0/8", "192.0.2.0/24"}},
		{"10.0.0.0/8:tcp/22,udp/161,192.0.2.0/24", []string{"10.0.0.0/8:tcp/22,udp/161", "192.0.2.0/24"}},
		{"a:tcp/22,udp/161,c", nil}, // a is no CIDR: below
		{"192.0.2.0/24, 10.0.0.0/8:udp/161 ,tcp/22 ,icmp", []string{"192.0.2.0/24", "10.0.0.0/8:tcp/22,udp/161,icmp"}},
		{"10.0.0.0/8:tcp/22,10.0.0.0/8:udp/161", []string{"10.0.0.0/8:tcp/22", "10.0.0.0/8:udp/161"}},
		{"10.0.0.0/8:tcp/22,10.0.0.0/8:tcp/22", []string{"10.0.0.0/8:tcp/22"}},
		{"10.0.0.0/8,10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"10.0.0.0/8:tcp/22,10.0.0.0/8:udp/161,10.0.0.0/8", []string{"10.0.0.0/8:tcp/22", "10.0.0.0/8:udp/161", "10.0.0.0/8"}},
		{"2001:db8::/32:tcp/22,udp/161,10.0.0.0/8:icmp", []string{"2001:db8::/32:tcp/22,udp/161", "10.0.0.0/8:icmp"}},
		{"10.0.0.0/8:*,192.0.2.0/24:tcp/*,udp/*,icmp", []string{"10.0.0.0/8", "192.0.2.0/24"}},
		{",,10.0.0.0/8,,", []string{"10.0.0.0/8"}},
	} {
		got, err := ParseList(c.in)
		if c.want == nil && c.in != "" {
			if err == nil {
				t.Errorf("%q: accepted as %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		var strs []string
		for _, e := range got {
			strs = append(strs, e.String())
		}
		if !reflect.DeepEqual(strs, c.want) {
			t.Errorf("%q: %q, want %q", c.in, strs, c.want)
		}
	}
	for _, in := range []string{"tcp/22", "tcp/22,10.0.0.0/8", "icmp,10.0.0.0/8:udp/161"} {
		if _, err := ParseList(in); err == nil || !strings.Contains(err.Error(), "after a CIDR") {
			t.Errorf("%q: a service before any CIDR: %v", in, err)
		}
	}
	// a service after a plain entry has no ':' to follow
	if _, err := ParseList("10.0.0.0/8,tcp/22"); err == nil || !strings.Contains(err.Error(), "after a ':'") {
		t.Errorf("a service after a plain CIDR: %v", err)
	}
	if _, err := ParseList("2001:db8::/32,udp/161"); err == nil {
		t.Error("a service after a plain IPv6 CIDR was accepted")
	}
	// the first bad entry is the error
	if _, err := ParseList("10.0.0.0/8,bad,10.0.0.0/33"); err == nil || !strings.Contains(err.Error(), "'bad'") {
		t.Errorf("first bad entry: %v", err)
	}
}

func TestSort(t *testing.T) {
	in := []string{
		"10.0.0.0/8", "192.0.2.0/24:udp/161", "192.0.2.0/24:tcp/22", "192.0.2.0/24", "2001:db8::/32:tcp/22",
		"10.1.0.0/16:icmp", "192.0.2.0/24:tcp/22,udp/161", "10.0.0.0/8", "garbage", "", "192.0.2.5/24:tcp/22", " 10.0.0.0/8 ",
	}
	want := []string{
		"10.1.0.0/16:icmp",
		"10.0.0.0/8",
		"192.0.2.0/24",
		"192.0.2.0/24:tcp/22",
		"192.0.2.0/24:tcp/22,udp/161",
		"192.0.2.0/24:udp/161",
		"2001:db8::/32:tcp/22",
	}
	if got := Sort(in); !reflect.DeepEqual(got, want) {
		t.Errorf("Sort:\n got %q\nwant %q", got, want)
	}
	// plain lists order as they did: cidr.SortBySpecificity
	plain := []string{"10.0.0.0/8", "192.0.2.5", "10.1.0.0/16", "2001:db8::/32", "0.0.0.0/0", "192.0.2.0/24"}
	var want2 []string
	for _, s := range cidr.SortBySpecificity(plain) {
		want2 = append(want2, cidr.Canonical(s))
	}
	if got := Sort(plain); !reflect.DeepEqual(got, want2) {
		t.Errorf("plain Sort:\n got %q\nwant %q", got, want2)
	}
}

func TestDisplay(t *testing.T) {
	a, _ := ParseEntry("172.16.100.0/23:tcp/22,udp/161,udp/162")
	b, _ := ParseEntry("10.0.0.0/8")
	if got := Display(a, 15); got != "172.16.100.0/23   tcp/22, udp/161, udp/162" {
		t.Errorf("%q", got)
	}
	if got := Display(a, 18); got != "172.16.100.0/23      tcp/22, udp/161, udp/162" {
		t.Errorf("padded: %q", got)
	}
	if got := Display(b, 15); got != "10.0.0.0/8" {
		t.Errorf("plain: %q", got)
	}
}
