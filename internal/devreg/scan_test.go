package devreg

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

func TestScanSourcesResumeFullSinceAndErrors(t *testing.T) {
	now := t0.AddDate(0, 0, 10)
	tac := faketest.New("tacacs", "", t.TempDir())
	tac.Sights = []backend.Sighting{
		{Time: t0.AddDate(0, 0, -40), Address: "192.0.2.1", Outcome: backend.SightAccept, User: "old"},
		{Time: t0, Address: "192.0.2.1", Outcome: backend.SightAccept, User: "alice"},
		{Time: t0, Outcome: backend.SightNoScope},
	}
	broken := faketest.New("radius", "", t.TempDir())
	broken.SightErr = errors.New("cannot open tacctl-auth.log")
	srcs := []ScanSource{{ID: "tacacs", Sighter: tac}, {ID: "radius", Sighter: broken}, {ID: "fake"}}
	s := NewSeen()

	// The first scan reads the last stale_days days.
	reps := ScanSources(t.Context(), s, srcs, ScanOptions{Now: now, StaleDays: 30})
	if len(reps) != 3 || reps[0].Sightings != 2 || reps[0].Addresses != 1 || reps[0].Unattributed != 1 ||
		!strings.HasPrefix(reps[0].Window, "fake log ") || reps[1].Err == nil || !reps[2].NoLog {
		t.Fatalf("%+v", reps)
	}
	if x, _ := s.Of("192.0.2.1"); x.Count != 1 || x.LastUser != "alice" || !s.Updated.Equal(now) {
		t.Errorf("%+v", x)
	}
	if st := s.Sources["tacacs"]; st.Resume != "n=3" || st.Unattributed != 1 || !st.Scanned.Equal(now) {
		t.Errorf("state %+v", st)
	}
	if s.Sources["radius"] != nil {
		t.Error("a source that failed keeps no state")
	}

	// The next one resumes: only what is new.
	tac.Sights = append(tac.Sights, backend.Sighting{Time: t0.Add(time.Hour), Address: "192.0.2.1", Outcome: backend.SightReject, User: "bob"})
	ScanSources(t.Context(), s, srcs[:1], ScanOptions{Now: now, StaleDays: 30})
	if x, _ := s.Of("192.0.2.1"); x.Count != 2 || x.LastUser != "bob" || !tac.Called("sightings n=3") {
		t.Errorf("resume %+v %q", x, tac.Calls())
	}

	// --full re-reads everything, replacing the source's records.
	ScanSources(t.Context(), s, srcs[:1], ScanOptions{Now: now, StaleDays: 30, Full: true})
	if x, _ := s.Of("192.0.2.1"); x.Count != 3 || !x.First.Equal(t0.AddDate(0, 0, -40)) {
		t.Errorf("full %+v", x)
	}
	// --since: that stretch only.
	ScanSources(t.Context(), s, srcs[:1], ScanOptions{Now: now, StaleDays: 30, Since: 11 * 24 * time.Hour})
	if x, _ := s.Of("192.0.2.1"); x.Count != 2 {
		t.Errorf("since %+v", x)
	}
	// A failed full scan keeps what was there.
	tac.SightErr = errors.New("journal gone")
	ScanSources(t.Context(), s, srcs[:1], ScanOptions{Now: now, Full: true})
	if x, ok := s.Of("192.0.2.1"); !ok || x.Count != 2 {
		t.Errorf("failed full %+v", x)
	}
}

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "12h": 12 * time.Hour, "30m": 30 * time.Minute, "1h30m": 90 * time.Minute,
	} {
		if d, err := ParseSince(in); err != nil || d != want {
			t.Errorf("%s: %v %v", in, d, err)
		}
	}
	for _, in := range []string{"", "0d", "-1h", "7", "seven days", "1y"} {
		if _, err := ParseSince(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestRescanKeysAndRecord(t *testing.T) {
	ed := testKey(t, "ed25519")
	r := &fake.Runner{}
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh-keyscan" }, func(c execx.Cmd) (execx.Result, error) {
		switch c.Args[len(c.Args)-1] {
		case "192.0.2.1":
			return execx.Result{Stdout: []byte("192.0.2.1 " + ed.String() + "\n")}, nil
		case "192.0.2.3":
			return execx.Result{Code: 127}, errors.New("exec: ssh-keyscan: not found")
		}
		return execx.Result{}, nil
	})
	res := RescanKeys(t.Context(), r, []KeyTarget{
		{Name: "a", Address: "192.0.2.1", Port: 22},
		{Name: "b", Address: "192.0.2.2", Port: 2222, Legacy: true},
		{Name: "c", Address: "192.0.2.3", Port: 22},
	}, nil)
	if len(res) != 3 || len(res[0].Keys) != 1 || !errors.Is(res[1].Err, ErrNoAnswer) || res[2].Err == nil {
		t.Fatalf("%+v", res)
	}
	if !r.Called("ssh-keyscan", "-T", "5", "-p", "2222", "-t", "ed25519,ecdsa,rsa,ssh-rsa", "192.0.2.2") {
		t.Errorf("%q", r.Argvs())
	}
	s := NewSeen()
	if err := s.RecordKeyResults(res, t0); err == nil || !strings.Contains(err.Error(), "ssh-keyscan could not be run") {
		t.Errorf("err %v", err)
	}
	if k, _ := s.KeyScanOf("a"); k == nil || k.Unreachable {
		t.Errorf("a %+v", k)
	}
	if k, _ := s.KeyScanOf("b"); k == nil || !k.Unreachable || k.Port != 2222 {
		t.Errorf("b %+v", k)
	}
	if _, ok := s.KeyScanOf("c"); ok {
		t.Error("a scan that did not run is not recorded")
	}
}

func TestUnregistered(t *testing.T) {
	f := Empty()
	f.Devices = []*Device{{Name: "core-sw1", Address: "203.0.113.1", Vendor: "cisco"}}
	r := NewResolver(f, nil, fixtureModel(t, "store.multiscope.yaml"))
	r.Seen = NewSeen()
	r.Seen.Apply("radius", []backend.Sighting{
		sight(0, "203.0.113.1", backend.SightAccept, "a", "core-sw1"),
		sight(1, "203.0.113.50", backend.SightAccept, "carol", "edge-sw5"),
		sight(2, "203.0.113.51", backend.SightAccept, "carol", "Switch"),
		sight(3, "203.0.113.52", backend.SightAccept, "carol", "core-sw1"),
		sight(4, "192.0.2.66", backend.SightReject, "x", ""),
		sight(5, "198.51.100.1", backend.SightAccept, "y", "dup"),
		sight(6, "198.51.100.2", backend.SightAccept, "y", "dup"),
	})
	var got []string
	for _, u := range r.Unregistered(false) {
		got = append(got, u.Address+"/"+u.Suggest+"/"+u.Scope)
	}
	want := "198.51.100.1/<name>/ 198.51.100.2/<name>/ 203.0.113.50/edge-sw5/dmz 203.0.113.51/<name>/dmz 203.0.113.52/<name>/dmz"
	if strings.Join(got, " ") != want {
		t.Errorf("got  %q\nwant %q", strings.Join(got, " "), want)
	}
	if n := len(r.Unregistered(true)); n != 6 {
		t.Errorf("--all: %d", n)
	}
}

func TestProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	// A port that was just open and is closed now refuses.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln2.Addr().(*net.TCPAddr).Port
	_ = ln2.Close()
	got := Probe(t.Context(), []ProbeTarget{{Host: "127.0.0.1", Port: open}, {Host: "127.0.0.1", Port: closed}})
	if got[0] != ProbeOpen || got[1] != ProbeClosed {
		t.Errorf("%q", got)
	}

	// Timeouts and other failures, through a dialer that never leaves the
	// machine.
	ProbeDial = func(ctx context.Context, _, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "[2001:db8::1]") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	defer func() { ProbeDial = nil }()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	got = Probe(ctx, []ProbeTarget{{Host: "2001:db8::1", Port: 22}, {Host: "sw.example.net", Port: 22}})
	if got[0] != ProbeTimedOut || got[1] != ProbeUnreachable {
		t.Errorf("%q", got)
	}
	if (ProbeTarget{Host: "2001:db8::1", Port: 22}).Addr() != "[2001:db8::1]:22" {
		t.Error("Addr")
	}
}
