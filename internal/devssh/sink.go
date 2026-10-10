package devssh

import (
	"context"
	"sync"
)

// sink collects what a channel writes (stdout and stderr of one session) so
// a reader can wait for it with a context. It never blocks the writer: a
// device that sends more than MaxOutput has the excess dropped and the
// overflow reported, so the ssh window keeps draining.
type sink struct {
	mu       sync.Mutex
	buf      []byte
	closed   bool
	err      error
	overflow bool
	// notify has one pending wakeup at most: set by every write and by the
	// close, taken by wait.
	notify chan struct{}
}

func newSink() *sink { return &sink{notify: make(chan struct{}, 1)} }

// Write is the io.Writer the session copies into.
func (s *sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	switch {
	case s.overflow:
	case len(s.buf)+len(p) > MaxOutput:
		s.overflow = true
		s.buf = nil
	default:
		s.buf = append(s.buf, p...)
	}
	s.mu.Unlock()
	s.wake()
	return len(p), nil
}

// close marks the channel finished, with how it ended.
func (s *sink) close(err error) {
	s.mu.Lock()
	if !s.closed {
		s.closed, s.err = true, err
	}
	s.mu.Unlock()
	s.wake()
}

func (s *sink) wake() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// chunk is what take returns.
type chunk struct {
	data     []byte
	closed   bool
	err      error // how the channel ended, when closed
	overflow bool
}

// take moves what has arrived out of the sink.
func (s *sink) take() chunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := chunk{data: s.buf, closed: s.closed, err: s.err, overflow: s.overflow}
	s.buf = nil
	return c
}

// wait blocks until something is written or the sink is closed (the
// context's error when it ends first).
func (s *sink) wait(ctx context.Context) error {
	select {
	case <-s.notify:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
