package model

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// loadFixture loads tests/fixtures/<name> with old replaced by repl.
func loadFixture(t *testing.T, name, old, repl string) *Model {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "store.yaml")
	if err := os.WriteFile(p, []byte(strings.Replace(string(data), old, repl, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, err := LoadStore(p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// LookupAddr is ScopeLookup as data: the same scope, prefix, tag and
// shadowed scopes for every address.
func TestLookupAddrAgreesWithScopeLookup(t *testing.T) {
	// A tag on a prod-inner address.
	m := loadFixture(t, "store.multiscope.yaml", "    secret: inner-secret-0123456789abcdef\n",
		"    secret: inner-secret-0123456789abcdef\n    devices: {10.10.99.5/32: cisco}\n")
	cases := []struct {
		addr string
		want AddrInfo
		ok   bool
	}{
		{"10.1.2.3", AddrInfo{Scope: "prod", Prefix: "10.0.0.0/8"}, true},
		{"10.10.99.7", AddrInfo{Scope: "prod-inner", Prefix: "10.10.99.0/24", Shadowed: []string{"prod"}}, true},
		{"10.10.99.5", AddrInfo{Scope: "prod-inner", Prefix: "10.10.99.0/24", Tag: "cisco", TagCIDR: "10.10.99.5/32", Shadowed: []string{"prod"}}, true},
		{"192.168.4.4", AddrInfo{Scope: "lab", Prefix: "192.168.0.0/16"}, true},
		{"8.8.8.8", AddrInfo{}, false},
		{"2001:db8::1", AddrInfo{}, false},
		{"not-an-address", AddrInfo{}, false},
	}
	for _, c := range cases {
		got, ok := m.LookupAddr(c.addr)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("LookupAddr(%s) = %+v, %v; want %+v, %v", c.addr, got, ok, c.want, c.ok)
		}
		lines, code := m.ScopeLookup(c.addr)
		text := strings.Join(lines, "\n")
		switch {
		case c.ok && (code != LookupFound || !strings.Contains(text, "scope '"+c.want.Scope+"'")):
			t.Errorf("ScopeLookup(%s) disagrees: %d %q", c.addr, code, text)
		case c.ok && c.want.Tag != "" && !strings.Contains(text, "Tagged "+c.want.Tag):
			t.Errorf("ScopeLookup(%s) lacks the tag: %q", c.addr, text)
		case c.ok && len(c.want.Shadowed) > 0 && !strings.Contains(text, "scope '"+c.want.Shadowed[0]+"'"):
			t.Errorf("ScopeLookup(%s) lacks the shadowed scope: %q", c.addr, text)
		case !c.ok && code == LookupFound:
			t.Errorf("ScopeLookup(%s) found a scope", c.addr)
		}
	}
}
