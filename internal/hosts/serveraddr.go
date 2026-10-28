package hosts

// The address of this server that devices and other hosts reach it at, for
// 'host enroll --local' when --server is not given: the first IPv4 address of
// the interface that carries the default route; without a default route, the
// first global IPv4 address of any interface that is up, by interface index;
// IPv6 only when the machine has no IPv4 at all. Loopback and link-local
// addresses never count.

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/conf"
)

// Iface is one network interface as the detection sees it.
type Iface struct {
	Name  string
	Index int
	Up    bool
	Addrs []netip.Addr
}

// ErrNoServerAddress is the detection finding no address to use.
var ErrNoServerAddress = errors.New("no address of this machine can be the server address: give --server <address>")

// DetectServerAddress picks the server address from the routing table (the
// text of /proc/net/route) and the interfaces; iface is the interface the
// address is on.
func DetectServerAddress(route []byte, ifaces []Iface) (addr, iface string, err error) {
	usable := func(a netip.Addr) bool {
		return a.IsValid() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() && !a.IsMulticast()
	}
	byName := map[string]Iface{}
	for _, i := range ifaces {
		byName[i.Name] = i
	}
	if name := defaultRouteIface(route); name != "" {
		if i, ok := byName[name]; ok {
			for _, a := range i.Addrs {
				if a.Is4() && usable(a) {
					return a.String(), i.Name, nil
				}
			}
		}
	}
	sorted := append([]Iface(nil), ifaces...)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].Index < sorted[b].Index })
	for _, want4 := range []bool{true, false} {
		for _, i := range sorted {
			if !i.Up {
				continue
			}
			for _, a := range i.Addrs {
				if a.Is4() == want4 && usable(a) && (want4 || a.IsGlobalUnicast()) {
					return a.String(), i.Name, nil
				}
			}
		}
		if want4 && hasIPv4(sorted, usable) {
			break
		}
	}
	return "", "", ErrNoServerAddress
}

func hasIPv4(ifaces []Iface, usable func(netip.Addr) bool) bool {
	for _, i := range ifaces {
		for _, a := range i.Addrs {
			if a.Is4() && usable(a) {
				return true
			}
		}
	}
	return false
}

// defaultRouteIface is the interface of the default route in the text of
// /proc/net/route (destination and mask 00000000), "" for none.
func defaultRouteIface(route []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(route))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0]
		}
	}
	return ""
}

// LocalServerAddress is DetectServerAddress of this machine.
func LocalServerAddress() (addr, iface string, err error) {
	route, _ := os.ReadFile("/proc/net/route")
	list, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	var ifaces []Iface
	for _, i := range list {
		it := Iface{Name: i.Name, Index: i.Index, Up: i.Flags&net.FlagUp != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					it.Addrs = append(it.Addrs, ip.Unmap())
				}
			}
		}
		ifaces = append(ifaces, it)
	}
	return DetectServerAddress(route, ifaces)
}

// CheckServerAddress is the check of an explicit --server of 'host enroll
// --local' (conf.ServerAddressProblem).
func CheckServerAddress(s string) error {
	if p := conf.ServerAddressProblem(s); p != "" {
		return errors.New("--server '" + s + "' " + p)
	}
	return nil
}
