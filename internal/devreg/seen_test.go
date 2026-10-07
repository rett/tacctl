package devreg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func sight(min int, addr, outcome, user, nas string) backend.Sighting {
	return backend.Sighting{Time: t0.Add(time.Duration(min) * time.Minute), Address: addr, Outcome: outcome, User: user, NASID: nas}
}

func TestSeenApplyAndMerge(t *testing.T) {
	s := NewSeen()
	if s.HasData() {
		t.Error("a new cache has no data")
	}
	un := s.Apply("tacacs", []backend.Sighting{
		sight(0, "192.0.2.1", backend.SightSeen, "", ""),
		sight(1, "192.0.2.1", backend.SightAccept, "alice", ""),
		sight(2, "192.0.2.1", backend.SightSeen, "", ""),
		sight(3, "", backend.SightNoScope, "", ""),
		sight(4, "198.51.100.9", backend.SightBadSecret, "", ""),
	})
	if un != 1 {
		t.Errorf("unattributed %d", un)
	}
	r := s.Addrs["192.0.2.1"]["tacacs"]
	// A debug line after the authentication keeps its user and outcome.
	if r.Count != 3 || r.LastUser != "alice" || r.LastOutcome != backend.SightAccept || !r.Last.Equal(t0.Add(2*time.Minute)) ||
		!r.First.Equal(t0) || !r.LastOK.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("record %+v", r)
	}
	if b := s.Addrs["198.51.100.9"]["tacacs"]; !b.LastOK.IsZero() || b.LastOutcome != backend.SightBadSecret {
		t.Errorf("bad secret %+v", b)
	}

	// RADIUS later: the merged record takes the last exchange of any
	// source, the NAS-Identifier of the latest that carried one.
	s.Apply("radius", []backend.Sighting{
		sight(10, "192.0.2.1", backend.SightReject, "bob", "core-sw1"),
		sight(11, "192.0.2.1", backend.SightAccept, "carol", "Router"),
		// An older line does not overwrite the last ones.
		sight(-60, "192.0.2.1", backend.SightAccept, "old", "older"),
	})
	x, ok := s.Of("192.0.2.1")
	if !ok || x.Count != 6 || x.Via != "radius" || x.LastUser != "carol" || x.LastNASID != "Router" || x.PrevNASID != "core-sw1" ||
		!x.NASChanged.Equal(t0.Add(11*time.Minute)) || !x.First.Equal(t0.Add(-60*time.Minute)) || x.Rejected() {
		t.Errorf("merged %+v", x)
	}
	if _, ok := s.Of("203.0.113.1"); ok {
		t.Error("an unseen address has no record")
	}
	var addrs []string
	for _, a := range s.All() {
		addrs = append(addrs, a.Address)
	}
	if strings.Join(addrs, ",") != "192.0.2.1,198.51.100.9" {
		t.Errorf("All %q", addrs)
	}
}

func TestSeenPruneAndReset(t *testing.T) {
	s := NewSeen()
	s.Apply("tacacs", []backend.Sighting{sight(0, "192.0.2.1", backend.SightAccept, "a", "")})
	s.Apply("radius", []backend.Sighting{sight(0, "192.0.2.2", backend.SightAccept, "a", ""),
		sight(0, "192.0.2.1", backend.SightAccept, "a", "")})
	s.Apply("tacacs", []backend.Sighting{{Time: t0.AddDate(0, 0, 50), Address: "192.0.2.3", Outcome: backend.SightAccept}})
	s.RecordKeyScan("Core-SW1", "192.0.2.1", 22, nil, t0)
	s.RecordKeyScan("gone", "192.0.2.9", 22, nil, t0)
	// 2 × 30 days after t0 + 61 days drops the records of t0, not the one of
	// t0 + 50 days, and an address no scope covers is not special.
	s.Prune(t0.AddDate(0, 0, 61), 30, []string{"core-sw1"})
	if len(s.Addrs) != 1 || s.Addrs["192.0.2.3"] == nil {
		t.Errorf("prune %v", s.Addrs)
	}
	if _, ok := s.KeyScanOf("CORE-SW1"); !ok || len(s.HostKeys) != 1 {
		t.Errorf("hostkeys %v", s.HostKeys)
	}
	s.Apply("radius", []backend.Sighting{sight(0, "192.0.2.3", backend.SightAccept, "a", "")})
	s.Sources["tacacs"] = &SourceState{Resume: "c"}
	s.ResetSource("tacacs")
	if s.Sources["tacacs"] != nil || s.Addrs["192.0.2.3"]["tacacs"] != nil || s.Addrs["192.0.2.3"]["radius"] == nil {
		t.Errorf("reset %v", s.Addrs)
	}
	s.ResetSource("radius")
	if len(s.Addrs) != 0 {
		t.Errorf("reset all %v", s.Addrs)
	}
}

func TestSeenSaveLoadAndLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var-lib")
	path := filepath.Join(dir, "devices-seen.json")
	s, err := LoadSeen(path)
	if err != nil || s.HasData() {
		t.Fatalf("absent: %v", err)
	}
	unlock, err := LockSeen(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Apply("tacacs", []backend.Sighting{sight(0, "2001:db8::5", backend.SightReject, "x", "")})
	s.Sources["tacacs"] = &SourceState{Resume: "s=1", Window: "journal", Scanned: t0}
	s.RecordKeyScan("sw", "2001:db8::5", 2222, []HostKey{testKey(t, "ed25519")}, t0)
	s.Updated = t0
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	unlock()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	if di, err := os.Stat(dir); err != nil || di.Mode().Perm() != 0o711 {
		t.Errorf("directory mode %v %v", di, err)
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{`"version": 1`, `"2001:db8::5"`, `"last_outcome": "reject"`, `"resume": "s=1"`, `"port": 2222`, `"offered": [`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("no %s in\n%s", want, data)
		}
	}
	back, err := LoadSeen(path)
	if err != nil || !back.HasData() || back.Sources["tacacs"].Resume != "s=1" {
		t.Fatalf("load: %v %+v", err, back)
	}
	if k, ok := back.KeyScanOf("SW"); !ok || k.Unreachable || len(k.Offered) != 1 || !k.LastGood.Equal(t0) {
		t.Errorf("keys %+v", k)
	}
	// Unreachable later keeps the last good scan; another address forgets it.
	back.RecordKeyScan("sw", "2001:db8::5", 2222, nil, t0.Add(time.Hour))
	if k, _ := back.KeyScanOf("sw"); !k.Unreachable || !k.LastGood.Equal(t0) || len(k.Offered) != 1 {
		t.Errorf("unreachable %+v", k)
	}
	back.RecordKeyScan("sw", "2001:db8::6", 22, nil, t0.Add(2*time.Hour))
	if k, _ := back.KeyScanOf("sw"); !k.LastGood.IsZero() || k.Offered != nil {
		t.Errorf("moved %+v", k)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadSeen(path); err == nil || s == nil || !strings.Contains(err.Error(), "device scan --full") {
		t.Errorf("corrupt: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"version": 7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSeen(path); err == nil {
		t.Error("another version is refused")
	}
	if err := os.WriteFile(path, []byte(`{"version": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadSeen(path); err != nil || s.Addrs == nil || s.Sources == nil || s.HostKeys == nil {
		t.Errorf("minimal: %v", err)
	}
}

func TestCompareAddr(t *testing.T) {
	in := []string{"2001:db8::1", "x", "198.51.100.1", "192.0.2.10", "192.0.2.9"}
	s := NewSeen()
	for _, a := range in {
		s.Addrs[a] = map[string]*SourceSeen{"t": {Last: t0}}
	}
	var got []string
	for _, x := range s.All() {
		got = append(got, x.Address)
	}
	if strings.Join(got, " ") != "192.0.2.9 192.0.2.10 198.51.100.1 2001:db8::1 x" {
		t.Errorf("%q", got)
	}
}
