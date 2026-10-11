package cidr

// The subtraction of the break-glass hold (docs/plans/0.2.5-plan.md D123):
// a prefix minus an address is the set of prefixes that cover every address
// of the prefix but that one. Pure, for both address families.

// Contains reports whether n holds every address of o (equal networks
// contain each other; the families must agree).
func (n Network) Contains(o Network) bool {
	if n.v6 != o.v6 || n.prefix > o.prefix {
		return false
	}
	return o.ip.and(ones(n.width(), n.prefix)).cmp(n.ip) == 0
}

// ContainsAddr reports whether the network net holds the address or network
// addr (false for anything that does not parse).
func ContainsAddr(net, addr string) bool {
	n, err := Parse(net)
	if err != nil {
		return false
	}
	a, err := Parse(addr)
	if err != nil {
		return false
	}
	return n.Contains(a)
}

// width is the address length in bits.
func (n Network) width() int {
	if n.v6 {
		return 128
	}
	return 32
}

// flipBit returns a with the bit at position pos (0 is the first bit of
// the address) inverted.
func flipBit(a u128, width, pos int) u128 {
	l := width - 1 - pos // index from the least significant bit
	if l < 64 {
		a.lo ^= 1 << uint(l)
	} else {
		a.hi ^= 1 << uint(l-64)
	}
	return a
}

// Minus is n without the addresses of h, as the canonical prefixes that
// remain: n itself when h is not inside it, none when h holds all of n, and
// otherwise the siblings along the path from n down to h (a /24 minus a /32
// is eight prefixes, /25 to /32, the shortest prefix first).
func (n Network) Minus(h Network) []Network {
	switch {
	case n.v6 != h.v6 || (!n.Contains(h) && !h.Contains(n)):
		return []Network{n}
	case h.Contains(n):
		return nil
	}
	w := n.width()
	out := make([]Network, 0, h.prefix-n.prefix)
	for i := n.prefix + 1; i <= h.prefix; i++ {
		ip := flipBit(h.ip, w, i-1).and(ones(w, i))
		out = append(out, Network{v6: n.v6, ip: ip, prefix: i, scope: n.scope})
	}
	return out
}

// Subtract is every prefix of prefixes with every hole taken out: a prefix
// that holds none of the holes is returned as it was written (text and
// all), a prefix inside a hole vanishes, and one that holds a hole is
// replaced by the canonical prefixes that cover it without the hole (holes
// are taken out in turn). The order is the input's, a prefix's pieces
// where the prefix stood, shortest first. An entry or a hole that does not
// parse leaves the list as it is for that entry.
func Subtract(prefixes, holes []string) []string {
	var hs []Network
	for _, h := range holes {
		if n, err := Parse(h); err == nil {
			hs = append(hs, n)
		}
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		n, err := Parse(p)
		if err != nil {
			out = append(out, p)
			continue
		}
		touched := false
		for _, h := range hs {
			if n.Contains(h) || h.Contains(n) {
				touched = true
			}
		}
		if !touched {
			out = append(out, p)
			continue
		}
		pieces := []Network{n}
		for _, h := range hs {
			var next []Network
			for _, q := range pieces {
				next = append(next, q.Minus(h)...)
			}
			pieces = next
		}
		for _, q := range pieces {
			out = append(out, q.String())
		}
	}
	return out
}
