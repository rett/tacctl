// Package firewall owns tacctl's one nftables table, 'inet tacctl' (0.2.24):
// what the server does with the TCP connections of the addresses held for
// break-glass ('tacctl breakglass hold').
//
// A hold takes an address out of every scope's prefixes, so FreeRADIUS (UDP)
// ignores the device and it times out. tacquito listens on TCP: the kernel
// completes the handshake, tacquito accepts, finds no secret for the address
// and closes the connection. A device whose fallback to its local accounts
// needs the server to be unreachable (WTI "Fallback Local: On (Transport
// Failure)", Junos 'authentication-order [ tacplus password ]') sees a
// reachable server and never falls back. The table refuses the connection
// before tacquito sees it, with a TCP reset (reject) or silently (drop).
//
// The table is the only thing of the host's ruleset tacctl touches: two sets
// (the held IPv4 and IPv6 addresses) and one input-hook chain at priority -10
// whose rules match a source address in a set and a TCP destination port of a
// tacquito listener. There is no connection-state match, so a session that is
// open from the address is cut too. Applying it is 'nft -f <rules file>' of a
// file that replaces the whole table in one transaction (Spec.Render);
// nothing is ever read from, flushed or edited in the rest of the ruleset.
//
// Every program runs through the execx.Runner of the invocation, so a test
// scripts nft and no test runs the real one.
package firewall

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
)

// The settings of breakglass.firewall.
const (
	// Reject answers a TCP connection from a held address with a reset.
	Reject = "reject"
	// Drop discards its packets: the device times out.
	Drop = "drop"
	// Off leaves the connections to tacquito (the 0.2.23 behaviour) and has no
	// table.
	Off = "off"
	// Default is the setting when the key is not set.
	Default = Reject
)

// Modes are the settings, in the order the help lists them.
var Modes = []string{Reject, Drop, Off}

// The table, as nft names it.
const (
	Family = "inet"
	Table  = "tacctl"
	// Set4 and Set6 are the sets of held IPv4 and IPv6 addresses.
	Set4 = "held4"
	Set6 = "held6"
	// Chain is the input-hook chain, at Priority (before the filters of a
	// firewall that uses priority 0).
	Chain    = "input"
	Priority = -10
)

// ValidMode reports whether s is a setting.
func ValidMode(s string) bool { return slices.Contains(Modes, s) }

// Mode is the setting in tacctl.yaml: Default when the key is not set or
// holds something that is not a setting ('config validate' names that).
func Mode(c *conf.Config) string {
	if v, ok := c.Value(conf.BreakglassFirewallKey); ok {
		if s, isStr := v.(string); isStr && ValidMode(s) {
			return s
		}
	}
	return Default
}

// Ports are the TCP ports tacquito's listeners bind (all of them: a listener
// added with 'server listen --listener' counts), sorted, each once. None when
// the TACACS+ backend is not enabled.
func Ports(c *conf.Config) []int {
	if enabled := c.GetList("backends.enabled"); len(enabled) > 0 && !slices.Contains(enabled, "tacacs") {
		return nil
	}
	var out []int
	for _, l := range conf.ListenersEffective(c.Merged(), rtacacs.Protocol) {
		if !strings.HasPrefix(l.Network, "tcp") {
			continue
		}
		if _, port, ok := conf.SplitListenAddress(l.Address); ok && port > 0 && port <= 65535 && !slices.Contains(out, port) {
			out = append(out, port)
		}
	}
	slices.Sort(out)
	return out
}

// Spec is what the table is to say.
type Spec struct {
	// Mode is Reject, Drop or Off.
	Mode string
	// Held are the held addresses, in any order, repeats and mapped IPv4
	// addresses allowed: the sets hold each once.
	Held []netip.Addr
	// Ports are the TCP destination ports of tacquito's listeners.
	Ports []int
}

// SpecOf is the table the holds and the setting of c ask for.
func SpecOf(c *conf.Config) Spec {
	s := Spec{Mode: Mode(c), Ports: Ports(c)}
	for _, h := range c.Holds() {
		if a, err := netip.ParseAddr(h.Address); err == nil {
			s.Held = append(s.Held, a.Unmap())
		}
	}
	return s
}

// Addrs are the held addresses of the sets, canonical, sorted (IPv4 first)
// and each once.
func (s Spec) Addrs() []netip.Addr {
	var out []netip.Addr
	for _, a := range s.Held {
		a = a.Unmap().WithZone("")
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int {
		if a.Is4() != b.Is4() {
			if a.Is4() {
				return -1
			}
			return 1
		}
		return a.Compare(b)
	})
	return out
}

// Strings are the addresses as text.
func (s Spec) Strings() []string {
	var out []string
	for _, a := range s.Addrs() {
		out = append(out, a.String())
	}
	return out
}

// Enforces reports whether the table refuses anything: a mode that is not
// off, an address and a port.
func (s Spec) Enforces() bool { return s.Mode != Off && len(s.Held) > 0 && len(s.Ports) > 0 }

// Verdict is the nft statement of the mode.
func (s Spec) Verdict() string {
	if s.Mode == Drop {
		return "drop"
	}
	return "reject with tcp reset"
}

// PortList is the ports as 'tcp/49,4949'.
func PortList(ports []int) string {
	if len(ports) == 0 {
		return "no port"
	}
	p := make([]string, len(ports))
	for i, n := range ports {
		p[i] = strconv.Itoa(n)
	}
	return "tcp/" + strings.Join(p, ",")
}

// Render is the rules file: the whole table, which 'nft -f' replaces in one
// transaction ('table' makes it exist, 'delete table' removes whatever was
// there, the definition follows), so the file loads whether or not the table
// is already in the kernel, and loading it twice changes nothing. With the
// mode off the file holds the first two lines only: loading it removes the
// table. Empty sets are written without elements.
func (s Spec) Render() string {
	var b strings.Builder
	b.WriteString("# Written by tacctl (breakglass.firewall = " + s.Mode + "); do not edit.\n")
	b.WriteString("# This file is the whole of the table 'inet tacctl' and nothing else of the ruleset:\n")
	b.WriteString("# 'nft -f' replaces the table in one step, the boot unit loads the same file.\n")
	b.WriteString("table " + Family + " " + Table + "\n")
	b.WriteString("delete table " + Family + " " + Table + "\n")
	if s.Mode == Off {
		return b.String()
	}
	var v4, v6 []string
	for _, a := range s.Addrs() {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	set := func(name, typ string, elems []string) {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n", name, typ)
		if len(elems) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("table " + Family + " " + Table + " {\n")
	set(Set4, "ipv4_addr", v4)
	set(Set6, "ipv6_addr", v6)
	fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook input priority %d; policy accept;\n", Chain, Priority)
	if len(s.Ports) > 0 {
		ports := make([]string, len(s.Ports))
		for i, n := range s.Ports {
			ports[i] = strconv.Itoa(n)
		}
		list := strings.Join(ports, ", ")
		fmt.Fprintf(&b, "\t\tip saddr @%s tcp dport { %s } %s\n", Set4, list, s.Verdict())
		fmt.Fprintf(&b, "\t\tip6 saddr @%s tcp dport { %s } %s\n", Set6, list, s.Verdict())
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}
