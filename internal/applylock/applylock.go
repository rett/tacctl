// Package applylock is the apply lock: one flock on
// <StateDir>/.store-apply.lock that serialises every tacctl command that puts
// whole files back (StoreApply, ApplyForced, the outer transactions) with
// every single write of tacctl.yaml.
//
// The lock is reentrant and one per process: a transaction that holds it and
// calls StoreApply or Conf.Set does not wait for itself. The depth is counted
// here, so a nested Acquire never touches the file; the flock is taken at
// depth 0 and given up when the count returns to 0. It is reentrant per
// process, not per goroutine: a second goroutine of the process that holds
// it re-enters too, so no code that writes the configuration may run on
// concurrent goroutines (none does).
//
// A context that is over does not refuse a lock that is free; it only ends a
// wait (a command that outlives its Ctrl-C, an editor's save, still writes).
package applylock

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// FileName is the lock file, in the state directory beside .store.lock.
const FileName = ".store-apply.lock"

// poll is how often a waiter tries the lock again. A blocking flock would
// not return when the invocation is interrupted (Go's signal handlers restart
// it), so the wait is a poll that watches the context.
const poll = 100 * time.Millisecond

// ErrCancelled is a wait that ended because its context did: nothing was
// locked. Test with errors.Is.
var ErrCancelled = errors.New("cancelled while waiting for the apply lock")

// Lock is the apply lock of one process (one per invocation: the App makes
// it). Make it with New. A nil *Lock is a lock that is never contended:
// Acquire returns at once.
type Lock struct {
	path string

	// Touch, when set, is called at the start of every Acquire, before the
	// lock is waited for: the audit writer's mark that the command is about
	// to change something (audit.Writer.Touch). Set it before the lock is
	// used.
	Touch func()

	mu        sync.Mutex
	depth     int
	f         *os.File
	announced bool
}

// New is the lock on <stateDir>/.store-apply.lock. Nothing is opened or
// created until Acquire.
func New(stateDir string) *Lock {
	return &Lock{path: filepath.Join(stateDir, FileName)}
}

// Path is the lock file.
func (l *Lock) Path() string { return l.path }

// Held is the depth: 0 when this process does not hold the lock.
func (l *Lock) Held() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.depth
}

// Acquire takes the lock, or counts one more level when this process holds
// it already. At depth 0 it opens the file (0600; the directory is never
// created: a missing state directory is an error) and tries the exclusive
// flock without blocking. While another process holds it, onWait is called
// (it may be nil; at most once over the Lock's life, so a command that waits
// twice says so once) and the flock is tried again every 100 ms until it is
// free or ctx ends (ErrCancelled, the file closed, nothing held). A call from
// another goroutine of the process waits behind the one that is waiting.
//
// release gives one level back, once however often it is called; the flock
// is dropped, and the file closed, when the depth returns to 0. The file is
// opened with os.OpenFile, so it is close-on-exec: the image 'upgrade' execs
// does not inherit a lock it cannot release.
func (l *Lock) Acquire(ctx context.Context, onWait func()) (release func(), err error) {
	if l == nil {
		return func() {}, nil
	}
	if l.Touch != nil {
		l.Touch()
	}
	l.mu.Lock()
	if l.depth == 0 {
		f, err := l.flock(ctx, onWait)
		if err != nil {
			l.mu.Unlock()
			return nil, err
		}
		l.f = f
	}
	l.depth++
	l.mu.Unlock()
	var once sync.Once
	return func() { once.Do(l.release) }, nil
}

func (l *Lock) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.depth--
	if l.depth == 0 && l.f != nil {
		_ = l.f.Close() // closing the descriptor drops the flock
		l.f = nil
	}
}

// Busy reports whether another process holds the lock in dir right now (a
// file that does not exist, or cannot be opened, is not busy). It takes and
// gives back the lock for the probe only.
func Busy(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.Is(err, unix.EWOULDBLOCK)
	}
	return false
}

// flock opens the file and waits for the exclusive lock on it. The caller
// holds l.mu.
//
// A context that is already over does not refuse a lock that is free: a
// command that outlives its Ctrl-C (an editor's save) must still write. It
// only ends a wait.
func (l *Lock) flock(ctx context.Context, onWait func()) (*os.File, error) {
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("cannot open %s: %w", l.path, err)
	}
	fd := int(f.Fd())
	var tick *time.Ticker
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return f, nil
		case errors.Is(err, unix.EINTR):
			continue
		case !errors.Is(err, unix.EWOULDBLOCK):
			_ = f.Close()
			return nil, fmt.Errorf("cannot lock %s: %w", l.path, err)
		}
		if ctx.Err() != nil {
			_ = f.Close()
			return nil, fmt.Errorf("%w: %v", ErrCancelled, ctx.Err())
		}
		if tick == nil {
			if onWait != nil && !l.announced {
				onWait()
			}
			l.announced = true
			tick = time.NewTicker(poll)
			defer tick.Stop()
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("%w: %v", ErrCancelled, ctx.Err())
		case <-tick.C:
		}
	}
}
