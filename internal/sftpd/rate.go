package sftpd

import (
	"io"
	"sync"
	"time"
)

// bucket is a token bucket for the bytes a session moves, reads and writes
// together: it holds up to one second of bytes (the burst), refills at rate
// bytes per second, and a caller that takes more than is there goes into
// debt and sleeps for the time the debt takes to refill. Callers that
// arrive together therefore wait one behind the other, and over time the
// session moves rate bytes per second.
//
// A nil *bucket takes nothing, costs nothing and never sleeps: it is what a
// rate of 0 gives.
type bucket struct {
	rate  float64 // bytes per second
	burst float64
	now   func() time.Time
	sleep func(time.Duration)

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// newBucket is a full bucket, or nil when rate is 0 or less.
func newBucket(rate int64, now func() time.Time, sleep func(time.Duration)) *bucket {
	if rate <= 0 {
		return nil
	}
	return &bucket{
		rate:   float64(rate),
		burst:  float64(rate),
		now:    now,
		sleep:  sleep,
		tokens: float64(rate),
		last:   now(),
	}
}

// take accounts for n bytes and sleeps, outside the lock, for as long as
// the bucket is in debt.
func (b *bucket) take(n int64) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	t := b.now()
	if el := t.Sub(b.last).Seconds(); el > 0 { // a clock that steps back refills nothing
		b.tokens = min(b.burst, b.tokens+el*b.rate)
		b.last = t
	}
	b.tokens -= float64(n)
	var wait time.Duration
	if b.tokens < 0 {
		wait = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()
	if wait > 0 {
		b.sleep(wait)
	}
}

// sleepUntil sleeps for d, or until done is closed.
func sleepUntil(done <-chan struct{}, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-done:
	}
}

// endNotifier closes done the first time the stream ends or fails to read,
// so that a request that is sleeping for the rate limit does not hold the
// session open after the client has gone: the library waits for its workers
// before Serve returns.
type endNotifier struct {
	io.ReadWriteCloser
	once sync.Once
	done chan struct{}
}

func newEndNotifier(rw io.ReadWriteCloser) *endNotifier {
	return &endNotifier{ReadWriteCloser: rw, done: make(chan struct{})}
}

func (e *endNotifier) end() { e.once.Do(func() { close(e.done) }) }

func (e *endNotifier) Read(p []byte) (int, error) {
	n, err := e.ReadWriteCloser.Read(p)
	if err != nil {
		e.end()
	}
	return n, err
}

func (e *endNotifier) Close() error {
	e.end()
	return e.ReadWriteCloser.Close()
}
