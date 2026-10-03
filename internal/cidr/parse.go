package cidr

import (
	"math/bits"
	"strings"
)

// The parsers below are a line-by-line port of CPython 3.12's ipaddress
// module (IPv4Network, IPv6Network with strict=False), so that every string
// bash's 'ipaddress.ip_network(s, strict=False)' accepts is accepted here,
// with the same canonical form, and nothing else is. They report only
// whether the input parses; the messages tacctl prints do not carry
// Python's reasons.

// u128 is an address: IPv4 uses the low 32 bits.
type u128 struct{ hi, lo uint64 }

func (a u128) and(b u128) u128 { return u128{a.hi & b.hi, a.lo & b.lo} }
func (a u128) or(b u128) u128  { return u128{a.hi | b.hi, a.lo | b.lo} }
func (a u128) not() u128       { return u128{^a.hi, ^a.lo} }

// cmp orders a before b (-1), after (1) or equal (0).
func (a u128) cmp(b u128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

// ones returns a mask of the top prefix bits of a width-bit address.
func ones(width, prefix int) u128 {
	if width == 32 {
		if prefix == 0 {
			return u128{}
		}
		return u128{lo: uint64(^uint32(0) << (32 - prefix))}
	}
	switch {
	case prefix == 0:
		return u128{}
	case prefix <= 64:
		return u128{hi: ^uint64(0) << (64 - prefix)}
	default:
		return u128{hi: ^uint64(0), lo: ^uint64(0) << (128 - prefix)}
	}
}

// allOnes is the all-ones address of the given width.
func allOnes(width int) u128 { return ones(width, width) }

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// prefixFromString is _prefix_from_prefix_string: ASCII digits only, value
// 0..max (int() accepts leading zeros).
func prefixFromString(s string, max int) (int, bool) {
	if !isASCIIDigits(s) {
		return 0, false
	}
	s = strings.TrimLeft(s, "0")
	if len(s) > 3 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	if n > max {
		return 0, false
	}
	return n, true
}

// ip4 is IPv4Address(str)._ip.
func ip4(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	octets := strings.Split(s, ".")
	if len(octets) != 4 {
		return 0, false
	}
	var v uint32
	for _, o := range octets {
		if !isASCIIDigits(o) || len(o) > 3 {
			return 0, false
		}
		if o != "0" && o[0] == '0' {
			return 0, false // leading zeros are refused, as inet_pton does
		}
		n := 0
		for i := 0; i < len(o); i++ {
			n = n*10 + int(o[i]-'0')
		}
		if n > 255 {
			return 0, false
		}
		v = v<<8 | uint32(n)
	}
	return v, true
}

// prefixFromIntMask is _prefix_from_ip_int for a 32-bit mask.
func prefixFromIntMask(x uint32) (int, bool) {
	tz := bits.TrailingZeros32(x) // 32 for zero
	prefix := 32 - tz
	var leading uint64
	if tz < 32 {
		leading = uint64(x >> tz)
	}
	if leading != (uint64(1)<<prefix)-1 {
		return 0, false
	}
	return prefix, true
}

// prefixFromIPString is _prefix_from_ip_string: a dotted netmask, else a
// dotted hostmask (all-ones and all-zeroes count as netmasks).
func prefixFromIPString(s string) (int, bool) {
	x, ok := ip4(s)
	if !ok {
		return 0, false
	}
	if p, ok := prefixFromIntMask(x); ok {
		return p, true
	}
	return prefixFromIntMask(^x)
}

func parse4(addr, mask string, hasMask bool) (Network, bool) {
	ip, ok := ip4(addr)
	if !ok {
		return Network{}, false
	}
	prefix := 32
	if hasMask {
		p, ok := prefixFromString(mask, 32)
		if !ok {
			if p, ok = prefixFromIPString(mask); !ok {
				return Network{}, false
			}
		}
		prefix = p
	}
	return Network{ip: u128{lo: uint64(ip)}.and(ones(32, prefix)), prefix: prefix}, true
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// hextet is _parse_hextet; an empty string is not a number.
func hextet(s string) (uint64, bool) {
	if s == "" || !isHexString(s) || len(s) > 4 {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			n = n<<4 | uint64(c-'0')
		case c >= 'a' && c <= 'f':
			n = n<<4 | uint64(c-'a'+10)
		default:
			n = n<<4 | uint64(c-'A'+10)
		}
	}
	return n, true
}

// ip6 is IPv6Address(str): the address and its RFC 4007 scope id.
func ip6(s string) (u128, string, bool) {
	scope := ""
	if i := strings.IndexByte(s, '%'); i >= 0 {
		scope = s[i+1:]
		s = s[:i]
		if scope == "" || strings.Contains(scope, "%") {
			return u128{}, "", false
		}
	}
	if s == "" {
		return u128{}, "", false
	}
	parts := strings.Split(s, ":")
	if len(parts) < 3 {
		return u128{}, "", false
	}
	if strings.Contains(parts[len(parts)-1], ".") {
		v4, ok := ip4(parts[len(parts)-1])
		if !ok {
			return u128{}, "", false
		}
		parts = parts[:len(parts)-1]
		parts = append(parts, formatHex(uint64(v4>>16)&0xFFFF), formatHex(uint64(v4)&0xFFFF))
	}
	if len(parts) > 9 {
		return u128{}, "", false
	}
	skip := -1
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			if skip >= 0 {
				return u128{}, "", false // more than one '::'
			}
			skip = i
		}
	}
	var hi, lo, skipped int
	if skip >= 0 {
		hi = skip
		lo = len(parts) - skip - 1
		if parts[0] == "" {
			hi--
			if hi != 0 {
				return u128{}, "", false
			}
		}
		if parts[len(parts)-1] == "" {
			lo--
			if lo != 0 {
				return u128{}, "", false
			}
		}
		skipped = 8 - (hi + lo)
		if skipped < 1 {
			return u128{}, "", false
		}
	} else {
		if len(parts) != 8 || parts[0] == "" || parts[len(parts)-1] == "" {
			return u128{}, "", false
		}
		hi = len(parts)
	}
	var h [8]uint64
	idx := 0
	for i := 0; i < hi; i++ {
		v, ok := hextet(parts[i])
		if !ok {
			return u128{}, "", false
		}
		h[idx] = v
		idx++
	}
	idx += skipped
	for i := len(parts) - lo; i < len(parts); i++ {
		v, ok := hextet(parts[i])
		if !ok {
			return u128{}, "", false
		}
		h[idx] = v
		idx++
	}
	return u128{hi: h[0]<<48 | h[1]<<32 | h[2]<<16 | h[3], lo: h[4]<<48 | h[5]<<32 | h[6]<<16 | h[7]}, scope, true
}

func formatHex(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v&0xf]
		v >>= 4
	}
	return string(b[i:])
}

func parse6(addr, mask string, hasMask bool) (Network, bool) {
	ip, scope, ok := ip6(addr)
	if !ok {
		return Network{}, false
	}
	prefix := 128
	if hasMask {
		var ok bool
		if prefix, ok = prefixFromString(mask, 128); !ok {
			return Network{}, false
		}
	}
	m := ones(128, prefix)
	if ip.and(m) != ip {
		// Host bits set: the network address is a new address without the
		// scope id.
		ip = ip.and(m)
		scope = ""
	}
	return Network{v6: true, ip: ip, prefix: prefix, scope: scope}, true
}
