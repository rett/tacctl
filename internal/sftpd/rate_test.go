package sftpd

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

var _ io.ReadWriteCloser = (*endNotifier)(nil)

// 5. The rate. No test here sleeps for the rate: the clock and the sleep
// are fakes.

// sleeps records the sleeps asked of the bucket and does not sleep.
type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
}

func (s *sleeps) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.d)
}

func (s *sleeps) longest() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m time.Duration
	for _, d := range s.d {
		m = max(m, d)
	}
	return m
}

func TestBucketBurstThenRate(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	b := newBucket(1000, clk.now, sl.sleep)
	b.take(1000) // the burst: one second of bytes
	if sl.count() != 0 {
		t.Fatalf("the burst slept: %v", sl.d)
	}
	b.take(500) // 500 bytes in debt: half a second
	if sl.count() != 1 || sl.d[0] != 500*time.Millisecond {
		t.Fatalf("sleeps = %v, want [500ms]", sl.d)
	}
	b.take(1000) // 1500 bytes in debt
	if len(sl.d) != 2 || sl.d[1] != 1500*time.Millisecond {
		t.Fatalf("sleeps = %v, want [500ms 1.5s]", sl.d)
	}
	// Time passes (the sleeps are not real, the clock is moved): the debt
	// is paid after 1.5 s, and an idle second fills the bucket again.
	clk.advance(1500 * time.Millisecond)
	b.take(0)
	clk.advance(10 * time.Second) // idle: the bucket holds one second at most
	before := sl.count()
	b.take(1000)
	if sl.count() != before {
		t.Errorf("a full bucket slept after an idle time: %v", sl.d)
	}
	b.take(1)
	if sl.count() != before+1 || sl.d[before] != time.Millisecond {
		t.Errorf("one byte over the burst: %v, want 1ms", sl.d[before:])
	}
}

func TestBucketRefillsWithTime(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	b := newBucket(1000, clk.now, sl.sleep)
	b.take(1000)
	clk.advance(250 * time.Millisecond) // 250 bytes back
	b.take(250)
	if sl.count() != 0 {
		t.Errorf("took what had refilled and slept: %v", sl.d)
	}
	clk.advance(250 * time.Millisecond)
	b.take(300) // 250 there, 50 short: 50 ms
	if sl.count() != 1 || sl.d[0] != 50*time.Millisecond {
		t.Errorf("sleeps = %v, want [50ms]", sl.d)
	}
}

func TestBucketBiggerThanTheBurst(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	b := newBucket(1000, clk.now, sl.sleep)
	b.take(5000) // 4000 over the burst: 4 s
	if sl.count() != 1 || sl.d[0] != 4*time.Second {
		t.Errorf("sleeps = %v, want [4s]", sl.d)
	}
}

func TestBucketClockGoingBack(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	b := newBucket(1000, clk.now, sl.sleep)
	b.take(1000)
	clk.advance(-time.Hour)
	b.take(1) // no refill from a step back, no panic
	if sl.count() != 1 || sl.d[0] != time.Millisecond {
		t.Errorf("sleeps = %v, want [1ms]", sl.d)
	}
	clk.advance(time.Hour + time.Second) // forward again: one second after the last refill
	b.take(999)                          // 1000 back, less the 1 owed
	if sl.count() != 1 {
		t.Errorf("sleeps = %v", sl.d)
	}
}

func TestBucketRateZeroCostsNothing(t *testing.T) {
	for _, r := range []int64{0, -5} {
		calls := 0
		b := newBucket(r, func() time.Time { calls++; return time.Time{} }, func(time.Duration) { calls++ })
		if b != nil {
			t.Errorf("rate %d gave a bucket", r)
		}
		b.take(1 << 30) // on nil: a no-op
		if calls != 0 {
			t.Errorf("rate %d used the clock or slept", r)
		}
	}
}

func TestBucketConcurrentTakers(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	b := newBucket(1000, clk.now, sl.sleep)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.take(100)
		}()
	}
	wg.Wait()
	// 5000 bytes from a bucket of 1000 on a frozen clock: the last taker
	// waits for the 4000 that are over.
	if got := sl.longest(); got != 4*time.Second {
		t.Errorf("longest sleep %v, want 4s", got)
	}
}

// Through a session.

func rateEnv(t *testing.T, rate int64, clk *clock, sl *sleeps) *env {
	return newEnvSeams(t, func(c *Config) { c.Rate = rate }, seams{now: clk.now, sleep: sl.sleep})
}

func TestRateLimitsUploadAndDownloadTogether(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	e := rateEnv(t, 10_000, clk, sl)
	e.put("a", bytesOf(25_000)) // 15 000 over the burst: 1.5 s
	if got := sl.longest(); got != 1500*time.Millisecond {
		t.Errorf("after the upload the longest sleep is %v, want 1.5s", got)
	}
	got, err := e.get("a") // another 25 000: 4 s over in all
	if err != nil || len(got) != 25_000 {
		t.Fatalf("download: %d bytes, %v", len(got), err)
	}
	if want := 4 * time.Second; sl.longest() != want {
		t.Errorf("after the download the longest sleep is %v, want %v", sl.longest(), want)
	}
	clk.advance(time.Hour)
	before := sl.count()
	e.put("b", bytesOf(10_000))
	if sl.count() != before {
		t.Errorf("a full bucket slept: %v", sl.d[before:])
	}
}

func TestRateLimitsOnlyTransfers(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	e := rateEnv(t, 100, clk, sl)
	e.write("d/f", "x")
	for i := 0; i < 20; i++ {
		_, _ = e.client.Stat("d/f")
		_, _ = e.client.ReadDir("d")
		_ = e.client.Mkdir("m")
		_ = e.client.Chmod("d/f", 0o600)
	}
	if sl.count() != 0 {
		t.Errorf("requests that move no file bytes slept: %v", sl.d)
	}
}

func TestRateZeroNeverSleeps(t *testing.T) {
	sl := &sleeps{}
	e := newEnvSeams(t, nil, seams{sleep: sl.sleep})
	e.put("a", bytesOf(1<<20))
	if _, err := e.get("a"); err != nil {
		t.Fatal(err)
	}
	if sl.count() != 0 {
		t.Errorf("Rate 0 slept: %v", sl.d)
	}
}

func TestRateWithQuota(t *testing.T) {
	clk, sl := newClock(), &sleeps{}
	e := newEnvSeams(t, func(c *Config) { c.Rate = 1000; c.Quota = 2000 }, seams{now: clk.now, sleep: sl.sleep})
	e.put("a", bytesOf(2000))
	wantQuotaRefusal(t, "over the quota", putFile(e.client, "b", "x"))
	if sl.longest() != time.Second {
		t.Errorf("longest sleep %v, want 1s (2000 bytes at 1000 per second after the burst)", sl.longest())
	}
}

// The real sleep ends with the session. This test waits on a real timer
// only if the code under test is wrong: the sleeps are an hour long and the
// stream ending is what must end them, so the test fails after a deadline
// instead of hanging.
func TestSleepEndsWhenTheStreamEnds(t *testing.T) {
	a, b := net.Pipe()
	n := newEndNotifier(a)
	slept := make(chan struct{})
	go func() {
		sleepUntil(n.done, time.Hour)
		close(slept)
	}()
	_ = b.Close() // the peer goes away: Read fails
	_, err := n.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read of a closed pipe succeeded")
	}
	select {
	case <-slept:
	case <-time.After(10 * time.Second):
		t.Fatal("the sleep did not end with the stream")
	}
	_ = n.Close()
	_ = n.Close() // twice is fine
}

func TestSleepEndsOnClose(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	n := newEndNotifier(a)
	slept := make(chan struct{})
	go func() {
		sleepUntil(n.done, time.Hour)
		close(slept)
	}()
	_ = n.Close()
	select {
	case <-slept:
	case <-time.After(10 * time.Second):
		t.Fatal("the sleep did not end with Close")
	}
}

func TestSleepUntilTimerFires(t *testing.T) {
	done := make(chan struct{})
	start := time.Now()
	sleepUntil(done, 5*time.Millisecond) // a real 5 ms: the timer path
	if time.Since(start) < 5*time.Millisecond {
		t.Error("sleepUntil returned early")
	}
}
