package cidr

import (
	"reflect"
	"testing"
)

func TestClientProblem(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"192.0.2.0/24", ""},
		{"192.0.2.7/32", ""},
		{"10.0.0.0/8", ""},
		{"0.0.0.0/1", ""},
		{"0.0.0.0/0", "would allow every address: 0.0.0.0/0 is the restrict tacctl always renders last, and is never stored"},
		{"2001:db8::/32", "is an IPv6 network (the SNMP client list is IPv4 only)"},
		{"::/0", "is an IPv6 network (the SNMP client list is IPv4 only)"},
		{"192.0.2.7", "is not in its canonical form (192.0.2.7/32)"},
		{"192.0.2.5/24", "is not in its canonical form (192.0.2.0/24)"},
		{"nonsense", "is not a valid CIDR"},
		{"", "is not a valid CIDR"},
		{"192.0.2.0/33", "is not a valid CIDR"},
	} {
		if got := ClientProblem(c.in); got != c.want {
			t.Errorf("ClientProblem(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestContainsAndOverlaps(t *testing.T) {
	for _, c := range []struct {
		outer, inner  string
		contains, ovl bool
	}{
		{"10.0.0.0/8", "10.1.2.0/24", true, true},
		{"10.1.2.0/24", "10.0.0.0/8", false, true},
		{"10.0.0.0/8", "10.0.0.0/8", true, true},
		{"10.0.0.0/8", "11.0.0.0/8", false, false},
		{"192.0.2.0/24", "192.0.2.77/32", true, true},
		{"192.0.2.0/25", "192.0.2.128/25", false, false},
		{"0.0.0.0/0", "192.0.2.1/32", true, true},
		{"2001:db8::/32", "2001:db8::1/128", false, false},
		{"bad", "10.0.0.0/8", false, false},
	} {
		if got := ContainsNet(c.outer, c.inner); got != c.contains {
			t.Errorf("ContainsNet(%q, %q) = %v", c.outer, c.inner, got)
		}
		if got := Overlaps(c.outer, c.inner); got != c.ovl {
			t.Errorf("Overlaps(%q, %q) = %v", c.outer, c.inner, got)
		}
	}
}

func TestCiscoPermit(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"192.0.2.7/32", "host 192.0.2.7"},
		{"192.0.2.0/24", "192.0.2.0 0.0.0.255"},
		{"10.0.0.0/8", "10.0.0.0 0.255.255.255"},
		{"172.16.0.0/12", "172.16.0.0 0.15.255.255"},
		{"192.0.2.128/25", "192.0.2.128 0.0.0.127"},
		{"198.51.100.4/30", "198.51.100.4 0.0.0.3"},
		{"0.0.0.0/0", "0.0.0.0 255.255.255.255"},
		{"2001:db8::/32", ""},
		{"junk", ""},
	} {
		if got := CiscoPermit(c.in); got != c.want {
			t.Errorf("CiscoPermit(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHost32(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"10.0.0.42", "10.0.0.42/32"},
		{"10.0.0.42/32", ""},
		{"10.0.0.0/24", ""},
		{"<TACQUITO_SERVER_IP>", ""},
		{"::1", ""},
		{"", ""},
	} {
		if got := Host32(c.in); got != c.want {
			t.Errorf("Host32(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestOverlapWarnings(t *testing.T) {
	got := OverlapWarnings([]string{"10.0.0.0/8", "192.0.2.0/24", "10.1.0.0/16", "192.0.2.9/32"})
	want := []string{"10.0.0.0/8 already contains 10.1.0.0/16", "192.0.2.0/24 already contains 192.0.2.9/32"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if OverlapWarnings(nil) != nil {
		t.Error("nil list")
	}
}
