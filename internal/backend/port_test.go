package backend

import (
	"strconv"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

func TestPortOf(t *testing.T) {
	for in, want := range map[string]string{":49": "49", "10.1.0.1:4949": "4949", "[::]:1812": "1812", "[fd00::1]:11813": "11813", "49": "", "": ""} {
		if got := PortOf(in); got != want {
			t.Errorf("PortOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// ServerPort is the port of the listener that serves clients: TACACS+'s
// default one, RADIUS's auth and acct ones; another listener of the backend
// is an extra one and is never the answer.
func TestServerPort(t *testing.T) {
	tac := []Listener{{Name: "default", Network: "tcp", Address: "10.1.0.1:4949"}, {Name: "mgmt", Network: "tcp", Address: "127.0.0.1:5050"}}
	rad := []Listener{{Name: "auth", Network: "udp", Address: ":11812"}, {Name: "acct", Network: "udp6", Address: "[::]:11813"},
		{Name: "guests", Network: "udp", Address: ":2812"}}
	for _, c := range []struct {
		name string
		ls   []Listener
		id   string
		role string
		want int
	}{
		{"tacacs moved", tac, TACACS, RoleDefault, 4949},
		{"tacacs extra listener first", []Listener{tac[1], tac[0]}, TACACS, RoleDefault, 4949},
		{"radius auth", rad, RADIUS, RoleAuth, 11812},
		{"radius acct", rad, RADIUS, RoleAcct, 11813},
		{"tacacs default", []Listener{{Name: "default", Address: ":49"}}, TACACS, RoleDefault, 49},
		{"tacacs none", nil, TACACS, RoleDefault, 49},
		{"tacacs only an extra one", tac[1:], TACACS, RoleDefault, 49},
		{"radius none", nil, RADIUS, RoleAuth, 1812},
		{"radius acct none", rad[:1], RADIUS, RoleAcct, 1813},
		{"no port", []Listener{{Name: "default", Address: "10.1.0.1"}}, TACACS, RoleDefault, 49},
		{"not a port", []Listener{{Name: "default", Address: ":x"}}, TACACS, RoleDefault, 49},
		{"port 0", []Listener{{Name: "default", Address: ":0"}}, TACACS, RoleDefault, 49},
		{"radius has no default listener", rad, RADIUS, RoleDefault, 0},
		{"tacacs has no auth listener", tac, TACACS, RoleAuth, 0},
		{"unknown backend", tac, "ldap", RoleDefault, 0},
	} {
		if got := ServerPort(c.ls, c.id, c.role); got != c.want {
			t.Errorf("%s: ServerPort = %d, want %d", c.name, got, c.want)
		}
	}
}

// The defaults here are the built-in listeners of internal/conf's listener
// model: the two never differ.
func TestDefaultPortsAreTheBuiltInListeners(t *testing.T) {
	for _, c := range []struct {
		id, name string
		want     int
	}{
		{TACACS, "default", DefaultTACACSPort}, {RADIUS, "auth", DefaultRADIUSAuthPort}, {RADIUS, "acct", DefaultRADIUSAcctPort},
	} {
		var got string
		for _, l := range conf.ListenersEffective(nil, c.id) {
			if l.Name == c.name {
				got = PortOf(l.Address)
			}
		}
		if got != strconv.Itoa(c.want) {
			t.Errorf("%s.%s: the listener model has port %q, the default here is %d", c.id, c.name, got, c.want)
		}
	}
}
