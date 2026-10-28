package conf

import "testing"

// server.addresses is a list of one server address in this release.
func TestServerAddressesProblem(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{[]any{"192.0.2.10"}, ""},
		{[]any{"2001:db8::10"}, ""},
		{[]any{"192.0.2.10", "198.51.100.20"}, "only one server address is supported yet"},
		{[]any{}, "must be a list of one IP address"},
		{"192.0.2.10", "must be a list of one IP address"},
		{[]any{"127.0.0.1"}, "element 0: '127.0.0.1' is a loopback address: give the address devices and hosts reach this server at"},
		{[]any{"authsrv.example.net"}, "element 0: 'authsrv.example.net' is not an IP address (a host name is not taken)"},
		{[]any{"0.0.0.0"}, "element 0: '0.0.0.0' is the unspecified address: give the address devices and hosts reach this server at"},
		{[]any{7}, "element 0: must be a string"},
	} {
		if got := ServerAddressesProblem(c.v); got != c.want {
			t.Errorf("%v: %q, want %q", c.v, got, c.want)
		}
	}
}
