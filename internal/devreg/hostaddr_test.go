package devreg

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/hosts"
)

// An enrolled host's record holds its address (with the previous one and
// when it changed) and acknowledgements beside the pinned keys; it is read
// and written back as it was, and a record must hold something valid.
func TestHostRecordAddress(t *testing.T) {
	ed := testKey(t, "ed25519")
	f := Empty()
	if prev := f.SetHostAddress("web1", "192.0.2.50", "2026-10-04 12:00"); prev != "" || f.HostAddressOf("WEB1") != "192.0.2.50" {
		t.Fatalf("first: %q %+v", prev, f.Hosts)
	}
	if prev := f.SetHostAddress("web1", "192.0.2.50", "2026-10-04 13:00"); prev != "" || f.Host("web1").PrevAddress != "" {
		t.Fatalf("same: %q %+v", prev, f.Hosts)
	}
	f.SetHostKeys("web1", []string{ed.String()})
	f.Host("web1").Ack = []string{NoticeAddressChanged}
	if prev := f.SetHostAddress("web1", "192.0.2.51", "2026-10-04 14:00"); prev != "192.0.2.50" {
		t.Fatalf("changed: %q", prev)
	}
	h := f.Host("web1")
	if h.Address != "192.0.2.51" || h.PrevAddress != "192.0.2.50" || h.Changed != "2026-10-04 14:00" || len(h.Ack) != 0 || len(h.Keys) != 1 {
		t.Fatalf("record %+v", h)
	}
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	back, err := parse(text)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if b := back.Host("web1"); b == nil || b.Address != "192.0.2.51" || b.PrevAddress != "192.0.2.50" || b.Changed != "2026-10-04 14:00" || len(b.Keys) != 1 {
		t.Errorf("read back %+v\n%s", b, text)
	}
	// Unpinning keeps the address; forgetting drops the record.
	back.SetHostKeys("web1", nil)
	if back.HostAddressOf("web1") != "192.0.2.51" {
		t.Error("unpinning dropped the address")
	}
	back.ForgetHost("web1")
	if back.Host("web1") != nil {
		t.Error("ForgetHost")
	}
	for name, text := range map[string]string{
		"empty":       "version: 1\nhosts:\n  web1: {}\n",
		"bad address": "version: 1\nhosts:\n  web1: {address: 192.0.2.500}\n",
		"unnormal":    "version: 1\nhosts:\n  web1: {address: '2001:DB8::1'}\n",
		"address int": "version: 1\nhosts:\n  web1: {address: 5}\n",
		"bad ack":     "version: 1\nhosts:\n  web1: {address: 192.0.2.1, ack: [generic-name]}\n",
	} {
		if _, err := parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parse([]byte("version: 1\nhosts:\n  web1: {address: 192.0.2.1, ack: [address-changed]}\n")); err != nil {
		t.Errorf("address only: %v", err)
	}
}

// The resolver takes an enrolled host's address from its record (the
// scope's /32 only when none is recorded): the host is found by it, holds
// it against 'device add', owns its sightings and is not 'unregistered';
// a changed address is the address-changed notice, with the prefix to add
// when the host's scope does not answer the new one.
func TestResolverHostAddress(t *testing.T) {
	f := Empty()
	f.SetHostAddress("web1", "203.0.113.60", "2026-10-04 12:00")
	f.SetHostAddress("web2", "203.0.113.61", "2026-10-04 12:00")
	f.SetHostAddress("web2", "192.0.2.66", "2026-10-04 13:00")
	r := NewResolver(f, nil, fixtureModel(t, "store.multiscope.yaml"))
	r.Hosts = []hosts.Entry{{Name: "web1", Target: "admin@web1.example.net", Scope: "dmz"}, {Name: "web2", Target: "web2", Scope: "dmz"}}
	r.Seen = NewSeen()
	r.Seen.Apply("tacacs", []backend.Sighting{
		sight(0, "203.0.113.60", backend.SightAccept, "alice", ""),
		sight(1, "203.0.113.70", backend.SightAccept, "bob", ""),
	})
	if e, ok := r.Lookup("203.0.113.60", ScopeFilter{}); !ok || e.Name != "web1" || e.Source != SourceHost {
		t.Errorf("lookup by address: %+v %v", e, ok)
	}
	if err := r.CheckAddress("203.0.113.60", ""); err == nil || !strings.Contains(err.Error(), "203.0.113.60 belongs to the enrolled host 'web1'.") {
		t.Errorf("CheckAddress: %v", err)
	}
	var un []string
	for _, u := range r.Unregistered(true) {
		un = append(un, u.Address)
	}
	if strings.Join(un, " ") != "203.0.113.70" {
		t.Errorf("unregistered %q", un)
	}
	e1, _ := r.Lookup("web1", ScopeFilter{})
	if ns := r.NoticesFor(e1); len(ns) != 0 {
		t.Errorf("web1 notices %+v", ns)
	}
	e2, _ := r.Lookup("web2", ScopeFilter{})
	ns := r.NoticesFor(e2)
	if len(ns) != 1 || ns[0].Kind != NoticeAddressChanged || ns[0].Acked ||
		ns[0].Text != "the address of 'web2' changed from 203.0.113.61 to 192.0.2.66 (2026-10-04 13:00, seen by host enroll or sync) — readdressed, or replaced? verify on the host; "+
			"scope 'dmz' does not answer 192.0.2.66: 'tacctl scope prefixes dmz add 192.0.2.66/32', then acknowledge it: 'tacctl device notice web2 ack address-changed'" {
		t.Errorf("web2 notices %+v", ns)
	}
	f.Host("web2").Ack = []string{NoticeAddressChanged}
	r = NewResolver(f, nil, fixtureModel(t, "store.multiscope.yaml"))
	r.Hosts = []hosts.Entry{{Name: "web2", Target: "web2", Scope: "dmz"}}
	e2, _ = r.Lookup("web2", ScopeFilter{})
	if ns := r.NoticesFor(e2); len(ns) != 1 || !ns[0].Acked {
		t.Errorf("acknowledged: %+v", ns)
	}
}
