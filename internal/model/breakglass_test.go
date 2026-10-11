package model

import (
	"slices"
	"testing"
)

func holdModel() *Model {
	a := &Scope{Name: "a", Prefixes: []string{"10.0.0.0/24", "192.0.2.0/25"},
		Devices: []Device{{CIDR: "10.0.0.0/28", Vendor: "cisco"}, {CIDR: "10.0.0.5/32", Vendor: "juniper"}}}
	b := &Scope{Name: "b", Prefixes: []string{"10.0.0.5/32"}}
	m := &Model{Scopes: []*Scope{a, b}, scopes: map[string]*Scope{"a": a, "b": b}}
	return m
}

func TestWithoutAddresses(t *testing.T) {
	m := holdModel()
	c := m.WithoutAddresses([]string{"10.0.0.5"})
	if got := m.Scope("a").Prefixes; len(got) != 2 {
		t.Fatalf("the receiver was changed: %v", got)
	}
	a := c.Scope("a")
	if len(a.Prefixes) != 9 { // 8 pieces of the /24 and the untouched /25
		t.Fatalf("a has %d prefixes: %v", len(a.Prefixes), a.Prefixes)
	}
	if !slices.Contains(a.Prefixes, "192.0.2.0/25") {
		t.Error("a prefix with no hole in it was changed")
	}
	for i, p := range a.Prefixes {
		o := a.PrefixOrigin(i)
		if p == "192.0.2.0/25" && o != "192.0.2.0/25" || p != "192.0.2.0/25" && o != "10.0.0.0/24" {
			t.Errorf("piece %s has origin %s", p, o)
		}
	}
	// The tagged /28 is cut (4 pieces: /29 to /32), the tagged /32 is gone.
	if len(a.Devices) != 4 {
		t.Fatalf("devices: %v", a.Devices)
	}
	for i, d := range a.Devices {
		if d.Vendor != "cisco" || a.DeviceOrigin(i) != "10.0.0.0/28" {
			t.Errorf("device %+v from %s", d, a.DeviceOrigin(i))
		}
	}
	if b := c.Scope("b"); len(b.Prefixes) != 0 {
		t.Errorf("b's /32 equal to the hole is left: %v", b.Prefixes)
	}
	if c.Scope("a") == m.Scope("a") {
		t.Error("the carved scope is the original")
	}
	// A scope the hole touches nowhere is the same text.
	if m2 := m.WithoutAddresses([]string{"203.0.113.9"}); !slices.Equal(m2.Scope("a").Prefixes, m.Scope("a").Prefixes) || m2.Scope("a").PrefixOrigin(0) != "10.0.0.0/24" {
		t.Error("an address no prefix holds changed the model")
	}
	if m.WithoutAddresses(nil) != m {
		t.Error("no addresses must be the model itself")
	}
}

func TestCarvedFrom(t *testing.T) {
	m := holdModel()
	got := m.CarvedFrom("10.0.0.5", "", true)
	want := []Carve{{"a", "10.0.0.0/24", false}, {"a", "10.0.0.0/28", true}, {"a", "10.0.0.5/32", true}, {"b", "10.0.0.5/32", false}}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
	if got := m.CarvedFrom("10.0.0.5", "", false); len(got) != 2 {
		t.Errorf("without tags: %v", got)
	}
}
