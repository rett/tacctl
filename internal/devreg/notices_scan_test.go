package devreg

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/model"
)

// noticeKinds are the kinds of e's notices, acknowledged ones marked '+'.
func noticeKinds(r *Resolver, name string) []string {
	e, ok := r.Lookup(name, ScopeFilter{})
	if !ok {
		return []string{"<missing>"}
	}
	var out []string
	for _, n := range r.NoticesFor(e) {
		k := n.Kind
		if n.Acked {
			k += "+"
		}
		out = append(out, k)
	}
	return out
}

func noticeText(r *Resolver, name, kind string) string {
	e, _ := r.Lookup(name, ScopeFilter{})
	for _, n := range r.NoticesFor(e) {
		if n.Kind == kind {
			return n.Text
		}
	}
	return ""
}

// Each scan-time notice from a minimal registry and cache.
func TestScanNoticeTable(t *testing.T) {
	ed, rsa, ecdsa := testKey(t, "ed25519"), testKey(t, "rsa"), testKey(t, "ecdsa")
	for _, c := range []struct {
		name  string
		dev   []*Device
		hosts string
		seen  func(s *Seen)
		check string
		want  []string
		text  []string
	}{
		{name: "nothing seen: the registry's notices only",
			dev:   []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco"}},
			check: "sw1", want: []string{NoticeHostKeyUnpinned}},
		{name: "a matching NAS-Identifier raises nothing",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", HostKeys: []string{ed.String()}}},
			seen: func(s *Seen) {
				s.Apply("radius", []backend.Sighting{sight(0, "192.0.2.1", backend.SightAccept, "a", "SW1.example.net")})
			},
			check: "sw1", want: nil},
		{name: "hostname as NAS-Identifier",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", Hostname: "core1.example.net", HostKeys: []string{ed.String()}}},
			seen: func(s *Seen) {
				s.Apply("radius", []backend.Sighting{sight(0, "192.0.2.1", backend.SightAccept, "a", "core1")})
			},
			check: "sw1", want: nil},
		{name: "name-mismatch",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "juniper", HostKeys: []string{ed.String()}}},
			seen: func(s *Seen) {
				s.Apply("radius", []backend.Sighting{sight(0, "192.0.2.1", backend.SightAccept, "a", "edge-7")})
			},
			check: "sw1", want: []string{NoticeNameMismatch},
			text: []string{"192.0.2.1 identifies itself as 'edge-7', not 'sw1' (informational)", "'tacctl device rename sw1 edge-7'",
				"set system host-name", "'tacctl device notice sw1 ack name-mismatch'"}},
		{name: "generic-nas-id",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", HostKeys: []string{ed.String()}}},
			seen: func(s *Seen) {
				s.Apply("radius", []backend.Sighting{sight(0, "192.0.2.1", backend.SightAccept, "a", "Switch")})
			},
			check: "sw1", want: []string{NoticeGenericNASID},
			text: []string{"identifies itself as 'Switch' (NAS-Identifier), a generic name", "hostname <name>", "ack generic-nas-id'"}},
		{name: "identity-changed and ambiguous-nas-id",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", HostKeys: []string{ed.String()}, Ack: []string{NoticeNameMismatch}}},
			seen: func(s *Seen) {
				s.Apply("radius", []backend.Sighting{
					sight(0, "192.0.2.1", backend.SightAccept, "a", "sw1"),
					sight(5, "192.0.2.1", backend.SightAccept, "a", "edge-9"),
					sight(6, "198.51.100.4", backend.SightAccept, "a", "EDGE-9"),
				})
			},
			check: "sw1", want: []string{NoticeIdentityChanged, NoticeNameMismatch + "+", NoticeAmbiguousNASID},
			text: []string{"192.0.2.1 now identifies as 'edge-9' (was 'sw1', changed 2026-10-01 12:05) — replaced or reset?",
				"NAS-Identifier 'edge-9' is sent from 2 addresses (192.0.2.1, 198.51.100.4)"}},
		{name: "duplicate-address: an address identifying as another entry",
			dev: []*Device{
				{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", HostKeys: []string{ed.String()}},
				{Name: "sw2", Address: "192.0.2.2", Vendor: "cisco", HostKeys: []string{ed.String()}},
			},
			seen: func(s *Seen) {
				s.Apply("radius", []backend.Sighting{sight(0, "192.0.2.1", backend.SightAccept, "a", "sw2")})
			},
			check: "sw1", want: []string{NoticeDuplicateAddress},
			text: []string{"192.0.2.1 ('sw1') identifies itself as 'sw2', which is registered at 192.0.2.2"}},
		{name: "duplicate-address: a device at an enrolled host's address",
			dev:   []*Device{{Name: "sw1", Address: "203.0.113.5", Vendor: "cisco", HostKeys: []string{ed.String()}}},
			hosts: "web9|root@203.0.113.5||host9|192.0.2.1|\n",
			check: "sw1", want: []string{NoticeDuplicateAddress},
			text: []string{"203.0.113.5 is the address of both 'sw1' and 'web9'"}},
		{name: "hostkey-changed cannot be acknowledged",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "juniper", HostKeys: []string{ed.String()}, Ack: []string{NoticeHostKeyAdded}}},
			seen: func(s *Seen) {
				s.RecordKeyScan("sw1", "192.0.2.1", 22, []HostKey{testKeyWithBlob(t, ed, rsa)}, t0)
			},
			check: "sw1", want: []string{NoticeHostKeyChanged},
			text: []string{"the host key of 'sw1' changed (scan 2026-10-01 12:00): pinned ED25519 " + ed.Fingerprint(),
				"'tacctl ssh' refuses it until it is pinned again", "show system ssh host-key", "'tacctl device hostkey sw1 accept'"}},
		{name: "hostkey-added, acknowledged",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", HostKeys: []string{ed.String()}, Ack: []string{NoticeHostKeyAdded}}},
			seen: func(s *Seen) {
				s.RecordKeyScan("sw1", "192.0.2.1", 22, []HostKey{ed, ecdsa}, t0)
			},
			check: "sw1", want: []string{NoticeHostKeyAdded + "+"},
			text: []string{"'sw1' offers a new host key type (scan 2026-10-01 12:00): ECDSA " + ecdsa.Fingerprint()}},
		{name: "hostkey-unreachable with the last good scan",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", Port: 2222, HostKeys: []string{ed.String()}}},
			seen: func(s *Seen) {
				s.RecordKeyScan("sw1", "192.0.2.1", 2222, []HostKey{ed}, t0)
				s.RecordKeyScan("sw1", "192.0.2.1", 2222, nil, t0.Add(24*time.Hour))
			},
			check: "sw1", want: []string{NoticeHostKeyUnreach},
			text: []string{"no host key could be read from 'sw1' (192.0.2.1 port 2222) at 2026-10-02 12:00; last good scan 2026-10-01 12:00",
				"'tacctl device check sw1'", "ack hostkey-unreachable'"}},
		{name: "the same keys raise nothing; unpinned entries are not compared",
			dev: []*Device{
				{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", HostKeys: []string{ed.String()}},
				{Name: "sw2", Address: "192.0.2.2", Vendor: "cisco", Ack: []string{NoticeHostKeyUnpinned}},
			},
			seen: func(s *Seen) {
				s.RecordKeyScan("sw1", "192.0.2.1", 22, []HostKey{ed}, t0)
				s.RecordKeyScan("sw2", "192.0.2.2", 22, nil, t0)
			},
			check: "sw2", want: []string{NoticeHostKeyUnpinned + "+"}},
		{name: "a re-scan of the old port says nothing",
			dev: []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco", Port: 2222, HostKeys: []string{ed.String()}}},
			seen: func(s *Seen) {
				s.RecordKeyScan("sw1", "192.0.2.1", 22, nil, t0)
			},
			check: "sw1", want: nil},
		{name: "an enrolled host: no acknowledgement offered",
			hosts: "web9|root@203.0.113.5||host9|192.0.2.1|\n",
			seen: func(s *Seen) {
				s.Apply("radius", []backend.Sighting{sight(0, "203.0.113.5", backend.SightAccept, "a", "ubuntu")})
			},
			check: "web9", want: []string{NoticeGenericNASID}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := Empty()
			f.Devices = c.dev
			var r *Resolver
			if c.hosts != "" {
				r = NewResolver(f, hostRegistry(t, c.hosts), host9Model(t))
			} else {
				r = NewResolver(f, nil, fixtureModel(t, "store.multiscope.yaml"))
			}
			r.Seen = NewSeen()
			if c.seen != nil {
				c.seen(r.Seen)
			}
			if got := noticeKinds(r, c.check); !slices.Equal(got, c.want) {
				t.Errorf("kinds %q, want %q", got, c.want)
			}
			for _, want := range c.text {
				found := false
				for _, k := range c.want {
					if strings.Contains(noticeText(r, c.check, strings.TrimSuffix(k, "+")), want) {
						found = true
					}
				}
				if !found {
					t.Errorf("no notice text has %q", want)
				}
			}
			if c.hosts != "" && c.check == "web9" {
				if txt := noticeText(r, "web9", NoticeGenericNASID); strings.Contains(txt, "acknowledge") {
					t.Errorf("a host's notice offers an acknowledgement: %q", txt)
				}
			}
		})
	}
}

// host9Model is the multiscope store with a scope 'host9' of the single
// address 203.0.113.5 (an enrolled host's scope).
func host9Model(t *testing.T) *model.Model {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "store.multiscope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(data), "scopes:\n", "scopes:\n  host9:\n    prefixes: [203.0.113.5/32]\n    secret: host9-secret-0123456789abcdef\n", 1)
	p := filepath.Join(t.TempDir(), "store.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, err := model.LoadStore(p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A resolver without a cache raises the registry's notices only.
func TestScanNoticesWithoutCache(t *testing.T) {
	f := Empty()
	f.Devices = []*Device{{Name: "sw1", Address: "192.0.2.1", Vendor: "cisco"}}
	r := NewResolver(f, nil, nil)
	if got := noticeKinds(r, "sw1"); !slices.Equal(got, []string{NoticeHostKeyUnpinned}) {
		t.Errorf("%q", got)
	}
}
