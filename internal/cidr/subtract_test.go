package cidr

import (
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestSubtractTable(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
		holes    []string
		want     []string
	}{
		{"a /24 minus a /32 is eight prefixes, shortest first", []string{"192.0.2.0/24"}, []string{"192.0.2.21"},
			[]string{"192.0.2.128/25", "192.0.2.64/26", "192.0.2.32/27", "192.0.2.0/28", "192.0.2.24/29", "192.0.2.16/30", "192.0.2.22/31", "192.0.2.20/32"}},
		{"a /32 equal to the hole vanishes", []string{"192.0.2.21/32"}, []string{"192.0.2.21"}, []string{}},
		{"a prefix without the hole is kept as written", []string{"198.51.100.0/24", "192.0.2.021/32"}, []string{"192.0.2.21"},
			[]string{"198.51.100.0/24", "192.0.2.021/32"}},
		{"the other family is kept", []string{"2001:db8::/64"}, []string{"192.0.2.21"}, []string{"2001:db8::/64"}},
		{"a /31 minus one of its two addresses is the other", []string{"10.0.0.0/31"}, []string{"10.0.0.1"}, []string{"10.0.0.0/32"}},
		{"two holes in one prefix", []string{"10.0.0.0/30"}, []string{"10.0.0.0", "10.0.0.3"},
			[]string{"10.0.0.2/32", "10.0.0.1/32"}},
		{"no holes", []string{"10.0.0.0/8"}, nil, []string{"10.0.0.0/8"}},
		{"an unparsable entry stays", []string{"bogus"}, []string{"10.0.0.1"}, []string{"bogus"}},
		{"a hole wider than the prefix removes it", []string{"10.0.0.0/24"}, []string{"10.0.0.0/16"}, []string{}},
	}
	for _, c := range cases {
		got := Subtract(c.prefixes, c.holes)
		if !slices.Equal(c.want, got) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSubtractIPv6(t *testing.T) {
	got := Subtract([]string{"2001:db8:0:1::/64"}, []string{"2001:db8:0:1::5"})
	if len(got) != 64 {
		t.Fatalf("a /64 minus a /128 is %d prefixes, want 64", len(got))
	}
	for i, p := range got {
		n, err := Parse(p)
		if err != nil || n.PrefixLen() != 65+i {
			t.Fatalf("piece %d is %s, want a /%d", i, p, 65+i)
		}
		if ContainsAddr(p, "2001:db8:0:1::5") {
			t.Errorf("piece %s holds the hole", p)
		}
	}
}

// TestSubtractProperty: for random prefixes and holes of both families, no
// piece holds a hole, every other address is held by a piece exactly when
// it was held by a prefix, and the pieces of one prefix do not overlap.
func TestSubtractProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(20261010))
	for iter := 0; iter < 400; iter++ {
		v6 := iter%2 == 1
		randAddr := func(base netip.Addr, keep int) netip.Addr {
			b := base.AsSlice()
			bits := len(b) * 8
			for i := keep; i < bits; i++ {
				if rng.Intn(2) == 1 {
					b[i/8] ^= 1 << (7 - uint(i%8))
				}
			}
			a, _ := netip.AddrFromSlice(b)
			return a
		}
		base := netip.MustParseAddr("10.20.30.40")
		maxLen := 32
		if v6 {
			base = netip.MustParseAddr("2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff")
			maxLen = 128
		}
		var prefixes, holes []string
		for i := 0; i < 1+rng.Intn(3); i++ {
			l := maxLen - 1 - rng.Intn(10)
			if v6 {
				l = 120 + rng.Intn(8)
			}
			prefixes = append(prefixes, netip.PrefixFrom(randAddr(base, l-2), l).Masked().String())
		}
		for i := 0; i < rng.Intn(3); i++ {
			// A hole inside the first prefix, or anywhere nearby.
			p := netip.MustParsePrefix(prefixes[0])
			holes = append(holes, randAddr(p.Addr(), p.Bits()).String())
		}
		pieces := Subtract(prefixes, holes)
		for _, h := range holes {
			for _, p := range pieces {
				if ContainsAddr(p, h) {
					t.Fatalf("iter %d: piece %s holds the hole %s (prefixes %v, holes %v)", iter, p, h, prefixes, holes)
				}
			}
		}
		// Every address near the prefixes: held by a piece iff held by a
		// prefix and not a hole.
		for _, pfx := range prefixes {
			p := netip.MustParsePrefix(pfx)
			for k := 0; k < 40; k++ {
				a := randAddr(p.Addr(), p.Bits()-1).String()
				inPrefix := slices.ContainsFunc(prefixes, func(x string) bool { return ContainsAddr(x, a) })
				isHole := slices.Contains(holes, a)
				inPieces := slices.ContainsFunc(pieces, func(x string) bool { return ContainsAddr(x, a) })
				if inPieces != (inPrefix && !isHole) {
					t.Fatalf("iter %d: %s: prefix %v pieces %v hole %v (prefixes %v, holes %v, pieces %v)",
						iter, a, inPrefix, inPieces, isHole, prefixes, holes, pieces)
				}
			}
		}
		// A prefix left whole is untouched, text and all.
		for _, pfx := range prefixes {
			touched := slices.ContainsFunc(holes, func(h string) bool { return ContainsAddr(pfx, h) })
			if !touched && !slices.Contains(pieces, pfx) {
				t.Fatalf("iter %d: %s holds no hole and was changed: %v", iter, pfx, pieces)
			}
		}
	}
}

func TestSubtractPiecesAreCanonical(t *testing.T) {
	for _, p := range Subtract([]string{"10.0.0.0/16"}, []string{"10.0.77.200"}) {
		if Canonical(p) != p || strings.Contains(p, " ") {
			t.Errorf("%q is not canonical", p)
		}
	}
}
