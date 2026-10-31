package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
)

// The test of the AAA source addresses (D315) with the host-key read faked:
// what each address reads as, what is left out and why, the cap, and that
// nothing but the reads happens.

// srcReader scripts the keys per address and records the addresses read.
type srcReader struct {
	keys map[string][]devreg.HostKey
	read []string
}

func (r *srcReader) fn(addr string) ([]devreg.HostKey, error) {
	r.read = append(r.read, addr)
	k, ok := r.keys[addr]
	if !ok {
		return nil, devreg.ErrNoAnswer
	}
	return k, nil
}

func srcAddrs(as ...string) devconf.SourceAddresses {
	var s devconf.SourceAddresses
	for _, a := range as {
		s.Addrs = append(s.Addrs, devconf.SourceAddr{Address: a})
	}
	return s
}

func sourceAt(r sourceReport, addr string) sourceResult {
	for _, x := range r.Results {
		if x.Address == addr {
			return x
		}
	}
	return sourceResult{}
}

func TestTestSourcesResults(t *testing.T) {
	ed, other := hkKey(t, "ed25519"), otherEd25519(t)
	rsa := hkKey(t, "rsa")
	pin := []string{ed.String()}
	rd := &srcReader{keys: map[string][]devreg.HostKey{
		"192.0.2.1": {ed},
		"192.0.2.2": {other},
		"192.0.2.3": {rsa, ed}, // shares the pinned key among others
		"192.0.2.5": {rsa},     // a type that is not pinned: not compared
	}}
	r := testSources(context.Background(), "sw1", "192.0.2.254", pin, srcAddrs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"), rd.fn)
	want := map[string]string{"192.0.2.1": sourceOK, "192.0.2.2": sourceMismatch, "192.0.2.3": sourceOK,
		"192.0.2.4": sourceUnreachable, "192.0.2.5": sourceSkipped}
	for a, w := range want {
		if got := sourceAt(r, a).Result; got != w {
			t.Errorf("%s: %q, want %q", a, got, w)
		}
	}
	m := sourceAt(r, "192.0.2.2")
	if m.Fingerprint != other.Fingerprint() || m.Pinned != ed.Fingerprint() {
		t.Errorf("mismatch fingerprints %q / %q", m.Fingerprint, m.Pinned)
	}
	if r.tested() != 4 || r.count(sourceUnreachable) != 1 || r.count(sourceMismatch) != 1 {
		t.Errorf("counts: %+v", r)
	}
}

func TestTestSourcesSkipsAndLimits(t *testing.T) {
	ed := hkKey(t, "ed25519")
	pin := []string{ed.String()}
	all := map[string][]devreg.HostKey{}
	var list []string
	for i := 1; i <= 11; i++ {
		a := fmt.Sprintf("192.0.2.%d", i)
		all[a] = []devreg.HostKey{ed}
		list = append(list, a)
	}
	rd := &srcReader{keys: all}
	srcs := srcAddrs(list...)
	srcs.Skipped = []devconf.SourceSkip{{Source: "source-interface gi0/2", Reason: devconf.SkipDynamic},
		{Source: "source-interface lo9", Reason: devconf.SkipNotRecorded}}
	// the registered address is among them, written another way
	r := testSources(context.Background(), "sw1", "192.0.2.3", pin, srcs, rd.fn)
	if slices.Contains(rd.read, "192.0.2.3") {
		t.Error("the registered address was read")
	}
	if !r.Registered {
		t.Error("the registered address is not noted")
	}
	if len(rd.read) != sourcesMax || r.tested() != sourcesMax || r.Over != 10-sourcesMax {
		t.Errorf("read %d, tested %d, over %d", len(rd.read), r.tested(), r.Over)
	}
	left := 0
	for _, x := range r.Results {
		if x.Result == sourceSkipped && x.Address != "" {
			left++
			if !strings.Contains(x.Reason, "not tested") || slices.Contains(rd.read, x.Address) {
				t.Errorf("left-out %+v", x)
			}
		}
	}
	if left != r.Over {
		t.Errorf("%d left out, over %d", left, r.Over)
	}
	var reasons []string
	for _, x := range r.Results {
		if x.Source != "" {
			reasons = append(reasons, x.Source+": "+x.Reason)
		}
	}
	if want := []string{"source-interface gi0/2: " + devconf.SkipDynamic, "source-interface lo9: " + devconf.SkipNotRecorded}; !slices.Equal(reasons, want) {
		t.Errorf("skips %v", reasons)
	}
	// an IPv6 registered address compares in canonical form
	rd = &srcReader{keys: map[string][]devreg.HostKey{"2001:db8::1": {ed}}}
	r = testSources(context.Background(), "sw1", "2001:0db8:0:0:0:0:0:1", pin, srcAddrs("2001:db8::1"), rd.fn)
	if len(rd.read) != 0 || !r.Registered {
		t.Errorf("v6 registered address: read %v", rd.read)
	}
}

func TestTestSourcesNothingToCompare(t *testing.T) {
	ed := hkKey(t, "ed25519")
	rd := &srcReader{}
	r := testSources(context.Background(), "sw1", "192.0.2.254", nil, srcAddrs("192.0.2.1"), rd.fn)
	if r.Note != "not compared: no host key is pinned for sw1" || len(rd.read) != 0 || len(r.Results) != 0 {
		t.Errorf("unpinned: %+v read %v", r, rd.read)
	}
	r = testSources(context.Background(), "sw1", "192.0.2.254", []string{ed.String()}, devconf.SourceAddresses{}, rd.fn)
	if r.Note != noteNoSource || len(rd.read) != 0 {
		t.Errorf("no source: %+v", r)
	}
}

func TestTestSourcesReadErrorAndCancel(t *testing.T) {
	ed := hkKey(t, "ed25519")
	pin := []string{ed.String()}
	boom := func(string) ([]devreg.HostKey, error) { return nil, errors.New("ssh-keyscan: not found\nmore") }
	r := testSources(context.Background(), "sw1", "192.0.2.254", pin, srcAddrs("192.0.2.1"), boom)
	if x := r.Results[0]; x.Result != sourceUnreachable || x.Reason != "ssh-keyscan: not found" {
		t.Errorf("read error: %+v", x)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	stop := func(string) ([]devreg.HostKey, error) {
		n++
		cancel()
		return nil, ctx.Err()
	}
	r = testSources(ctx, "sw1", "192.0.2.254", pin, srcAddrs("192.0.2.1", "192.0.2.2", "192.0.2.3"), stop)
	if n != 1 || r.tested() != 0 || r.count(sourceSkipped) != 3 {
		t.Errorf("Ctrl-C: %d reads, %+v", n, r)
	}
}

// A device that presents only a key type that is not pinned is not compared:
// no key of it is wrong.
func TestTestSourcesNoKeyTypeInCommon(t *testing.T) {
	ed, rsa := hkKey(t, "ed25519"), hkKey(t, "rsa")
	rd := &srcReader{keys: map[string][]devreg.HostKey{"192.0.2.1": {rsa}, "192.0.2.2": {rsa, ed}}}
	r := testSources(context.Background(), "sw1", "192.0.2.254", []string{ed.String()}, srcAddrs("192.0.2.1", "192.0.2.2"), rd.fn)
	x := sourceAt(r, "192.0.2.1")
	if x.Result != sourceSkipped || x.Reason != "not compared: presented only rsa, pinned ed25519" || r.tested() != 1 {
		t.Errorf("%+v", r)
	}
	if sourceAt(r, "192.0.2.2").Result != sourceOK {
		t.Errorf("a shared type that matches: %+v", r)
	}
}
