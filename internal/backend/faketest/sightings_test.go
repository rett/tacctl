package faketest

import (
	"errors"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
)

func TestFakeSightings(t *testing.T) {
	b := New("", "", t.TempDir())
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	b.Sights = []backend.Sighting{
		{Time: t0, Address: "192.0.2.1", Outcome: backend.SightAccept, User: "alice"},
		{Time: t0.Add(48 * time.Hour), Address: "192.0.2.2", Outcome: backend.SightReject, User: "bob"},
	}
	ss, next, window, err := b.Sightings(ctx, t0.Add(time.Hour), "")
	if err != nil || len(ss) != 1 || ss[0].User != "bob" || next != "n=2" || window != "fake log 2026-10-03 00:00:00 to 2026-10-03 00:00:00 (1 entry)" {
		t.Fatalf("%v %q %q %v", ss, next, window, err)
	}
	b.Sights = append(b.Sights, backend.Sighting{Time: t0.Add(72 * time.Hour), Address: "192.0.2.3", Outcome: backend.SightSeen})
	if ss, next, _, _ = b.Sightings(ctx, time.Time{}, next); len(ss) != 1 || ss[0].Address != "192.0.2.3" || next != "n=3" {
		t.Errorf("resume: %v %q", ss, next)
	}
	b.SightErr = errors.New("no log")
	if _, _, _, err := b.Sightings(ctx, time.Time{}, ""); err == nil || !b.Called("sightings n=2") {
		t.Errorf("%v %q", err, b.Calls())
	}
}
