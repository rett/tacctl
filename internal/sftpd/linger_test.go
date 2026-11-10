package sftpd

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A rate-limited session ends as soon as the client leaves. The requests
// that are past the point where they take their bytes from the bucket are
// asleep for the debt (here a rate of one byte per second, so each of them
// owes hours), the client drops the stream without waiting for a reply, and
// Serve must return at once: the sleeps end with the stream, the requests
// that were queued behind them take no sleep of their own, and nothing else
// holds the session.
//
// This test uses the real sleep of the session (the default one, that is
// the code under test) and so waits on a real timer, but only if the code is
// wrong: the debt is hours long and the end of the stream is what must end
// it, so a session that lingers fails the test after a deadline instead of
// hanging. Serve is expected to return in microseconds; the deadline is
// generous for a loaded machine.
func TestRateLimitedSessionEndsWhenTheClientLeaves(t *testing.T) {
	const chunk = 32768
	data := bytesOf(chunk)
	tests := []struct {
		name     string
		upload   bool
		requests int // more than the library's workers when it is 20
	}{
		{"upload, one request", true, 1},
		{"upload, more requests than workers", true, 20},
		{"download, one request", false, 1},
		{"download, more requests than workers", false, 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			if err := os.Mkdir(home, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, "d"), []byte(bytesOf(chunk*tc.requests)), 0o600); err != nil {
				t.Fatal(err)
			}
			asleep := make(chan struct{}, tc.requests)
			r := newRawConnCfg(t, Config{Home: home, Rate: 1}, seams{sleeping: func() { asleep <- struct{}{} }})
			var h string
			if tc.upload {
				h, _ = r.open("u", rawFlagWrite|rawFlagCreat, 0, nil)
			} else {
				h, _ = r.open("d", rawFlagRead, 0, nil)
			}
			if h == "" {
				t.Fatal("open refused")
			}
			for i := 0; i < tc.requests; i++ {
				r.id++
				b := str(binary.BigEndian.AppendUint32(nil, r.id), h)
				b = binary.BigEndian.AppendUint64(b, uint64(i)*chunk)
				if tc.upload {
					r.send(rawWrite, str(b, data))
				} else {
					r.send(rawRead, binary.BigEndian.AppendUint32(b, chunk))
				}
			}
			// Requests are asleep: as many as the library has workers for,
			// at most; the answers are not read, as a client that is gone.
			for i := 0; i < min(tc.requests, 8); i++ {
				select {
				case <-asleep:
				case <-time.After(10 * time.Second):
					t.Fatalf("only %d requests reached the sleep", i)
				}
			}
			_ = r.c.Close()
			r.c = nil
			select {
			case <-r.done:
			case <-time.After(10 * time.Second):
				t.Fatal("the session is still running 10 s after the client left")
			}
		})
	}
}
