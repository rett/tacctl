package backend

import "strconv"

// The ports of the built-in listeners (the defaults of internal/conf's
// listener model, which a test pins). Code that needs the port a server
// answers on asks ServerPort; these are what it answers when the listener
// list has no usable entry.
const (
	DefaultTACACSPort      = 49
	DefaultRADIUSAuthPort  = 1812
	DefaultRADIUSAcctPort  = 1813
	tacacsDefaultListener  = "default"
	radiusAuthListenerName = "auth"
	radiusAcctListenerName = "acct"
)

// The roles of a listener a port is asked for.
const (
	// RoleDefault is the default listener of a backend that has one
	// (TACACS+: authentication, authorization and accounting together).
	RoleDefault = ""
	// RoleAuth is the RADIUS authentication listener.
	RoleAuth = "auth"
	// RoleAcct is the RADIUS accounting listener.
	RoleAcct = "acct"
)

// PortOf is the port of a listen address ('host:port', '[v6]:port' or
// ':port'): the text after the last colon, "" when there is none.
func PortOf(address string) string {
	for i := len(address) - 1; i >= 0; i-- {
		if address[i] == ':' {
			return address[i+1:]
		}
	}
	return ""
}

// ServerPort is the port the server answers on for a protocol: the port of
// the listener that serves the role, from the listeners in effect (the list
// a backend's Listeners().List() returns). It is the one place the clients'
// configurations (device walkthroughs and their compare, the host scripts)
// take the server's port from, so that every one follows 'tacctl config
// listen'.
//
// id is TACACS or RADIUS and role RoleDefault for TACACS+ (the listener
// named default), RoleAuth or RoleAcct for RADIUS (the built-in listeners
// auth and acct, which keep their roles and come first in the list). Any
// other listener of a backend is an extra one, for other clients, and is
// never the answer. When the list has no such listener, or its address has
// no port, the built-in default is returned.
func ServerPort(listeners []Listener, id, role string) int {
	name, def := "", 0
	switch {
	case id == TACACS && role == RoleDefault:
		name, def = tacacsDefaultListener, DefaultTACACSPort
	case id == RADIUS && role == RoleAuth:
		name, def = radiusAuthListenerName, DefaultRADIUSAuthPort
	case id == RADIUS && role == RoleAcct:
		name, def = radiusAcctListenerName, DefaultRADIUSAcctPort
	default:
		return 0
	}
	for _, l := range listeners {
		if l.Name != name {
			continue
		}
		if n, err := strconv.Atoi(PortOf(l.Address)); err == nil && n > 0 {
			return n
		}
	}
	return def
}
