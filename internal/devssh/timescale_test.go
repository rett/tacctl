package devssh_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devssh"
)

// A scale multiplies every timing of a host-key read, and 1 is the defaults
// byte for byte.
func TestScanTimingScaled(t *testing.T) {
	d := devssh.DefaultScanTiming()
	if got := (devssh.ScanTiming{}).Scaled(1); got != d {
		t.Errorf("scale 1 = %+v, want the defaults %+v", got, d)
	}
	got := (devssh.ScanTiming{}).Scaled(3)
	want := devssh.ScanTiming{Keyscan: 15 * time.Second, KeyscanRetry: 9 * time.Second, Connect: 9 * time.Second,
		Handshake: 30 * time.Second, Attempt: 15 * time.Second}
	if got != want {
		t.Errorf("scale 3 = %+v, want %+v", got, want)
	}
	// a field that is set is scaled as it is, not replaced by the default
	if got := (devssh.ScanTiming{Attempt: time.Second}).Scaled(4); got.Attempt != 4*time.Second || got.Handshake != 40*time.Second {
		t.Errorf("a set field: %+v", got)
	}
}

// A scale outside the bounds never shrinks a timeout nor makes it absurd.
func TestScaleDurationBounds(t *testing.T) {
	for scale, want := range map[int]time.Duration{-5: 10 * time.Second, 0: 10 * time.Second, 1: 10 * time.Second,
		2: 20 * time.Second, 10: 100 * time.Second, 11: 100 * time.Second, 1000: 100 * time.Second} {
		if got := devssh.ConnectTimeoutFor(scale); got != want {
			t.Errorf("ConnectTimeoutFor(%d) = %v, want %v", scale, got, want)
		}
	}
	if !devssh.ValidTimeoutScale(1) || !devssh.ValidTimeoutScale(10) || devssh.ValidTimeoutScale(0) || devssh.ValidTimeoutScale(11) {
		t.Error("ValidTimeoutScale is not 1 to 10")
	}
	if devssh.ConnectTimeoutFor(1) != devssh.DefaultConnectTimeout {
		t.Error("scale 1 is not DefaultConnectTimeout")
	}
}

// A device that connects after 1.5 units and greets 4 units later (a link
// with a long round trip and a slow CPU) is read with the timing of scale 3
// and not with that of scale 1. The unit is 100 ms, and the base timing is
// the default's shape at that unit (a handshake of 5 units, as the default
// attempt is), so that the test runs in under three seconds.
func TestScanHostKeysAtScale(t *testing.T) {
	t.Parallel()
	unit := 100 * time.Millisecond
	base := devssh.ScanTiming{Keyscan: 5 * unit, KeyscanRetry: 3 * unit, Connect: 3 * unit, Handshake: 5 * unit, Attempt: 5 * unit}
	srv := serve(t, transcript(t, nil))
	host, port := scanArgs(t, srv)
	slow := func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case <-time.After(15 * unit / 10):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &lateConn{Conn: c, delay: 4 * unit}, nil
	}
	for _, quick := range []bool{false, true} {
		_, err := devssh.ScanHostKeysTiming(bg(), host, port, base.Scaled(1), quick, slow)
		if !errors.Is(err, devssh.ErrTimeout) {
			t.Errorf("quick=%v, scale 1: err = %v, want a timeout", quick, err)
		}
		keys, err := devssh.ScanHostKeysTiming(bg(), host, port, base.Scaled(3), quick, slow)
		if err != nil || len(keys) == 0 {
			t.Errorf("quick=%v, scale 3: keys %q, err %v", quick, keys, err)
		}
	}
}
