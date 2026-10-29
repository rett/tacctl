package conf

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/py"
)

// ServerAddressesKey is the tacctl.yaml key of the addresses devices and
// hosts reach this server at (0.2.21). It is a list so that more than one
// can be held later without another migration; this release takes one.
const ServerAddressesKey = "server.addresses"

// ServerAddressProblem is "" when s can be the server address, else why
// not: an IP literal that is not unspecified, loopback, link-local,
// multicast, the broadcast address or an IPv4-mapped IPv6 address. An address that is not on this machine (behind NAT or a VPN)
// is accepted: it is where the others reach the server.
func ServerAddressProblem(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return "is not an IP address (a host name is not taken)"
	}
	switch {
	case a.Is4In6():
		// kept mapped it would make the prefix ::ffff:a.b.c.d/128, which no
		// IPv4 login matches
		return "is an IPv4-mapped IPv6 address: give the IPv4 address devices and hosts reach this server at"
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "is the broadcast address: give the address devices and hosts reach this server at"
	case a.IsUnspecified():
		return "is the unspecified address: give the address devices and hosts reach this server at"
	case a.IsLoopback():
		return "is a loopback address: give the address devices and hosts reach this server at"
	case a.IsLinkLocalUnicast() || a.IsMulticast():
		return "is a link-local or multicast address: give the address devices and hosts reach this server at"
	}
	return ""
}

// ServerAddressesProblem is the check of server.addresses: a list of one
// server address (ServerAddressProblem).
func ServerAddressesProblem(value any) string {
	items, isList := py.List(value)
	if !isList || len(items) == 0 {
		return "must be a list of one IP address"
	}
	if len(items) > 1 {
		return "only one server address is supported yet"
	}
	str, isStr := items[0].(string)
	if !isStr {
		return "element 0: must be a string"
	}
	if p := ServerAddressProblem(str); p != "" {
		return fmt.Sprintf("element 0: %s %s", py.ReprString(str), p)
	}
	return ""
}

// ServerAddress is element 0 of server.addresses, "" when it is not set or
// not a server address.
func (c *Config) ServerAddress() string {
	list := c.GetList(ServerAddressesKey)
	if len(list) == 0 || ServerAddressProblem(list[0]) != "" {
		return ""
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(list[0])); err == nil {
		return a.String()
	}
	return ""
}

// ServerNameKey is the tacctl.yaml key of the name of this server in the
// console prompt and its notices (0.2.22).
const ServerNameKey = "server.name"

// ServerName is server.name, "" when it is not set or not a server name.
func (c *Config) ServerName() string {
	v, _ := c.Get(ServerNameKey, "")
	if names.ServerNameProblem(v) != "" {
		return ""
	}
	return v
}
