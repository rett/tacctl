package applylock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var bg = context.Background()

func acquire(t *testing.T, l *Lock) func() {
	t.Helper()
	rel, err := l.Acquire(bg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// contended reports whether another descriptor on the file cannot take it.
func contended(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	return errors.Is(err, unix.EWOULDBLOCK)
}

func TestReentrantDepthIsCountedAndTheFileClosedAtZero(t *testing.T) {
	l := New(t.TempDir())
	r1 := acquire(t, l)
	r2 := acquire(t, l) // would block forever if it took the flock again
	r3 := acquire(t, l)
	if l.Held() != 3 || !contended(t, l.Path()) {
		t.Fatalf("depth %d", l.Held())
	}
	r3()
	r3() // a second call counts nothing
	r2()
	if l.Held() != 1 || !contended(t, l.Path()) {
		t.Fatalf("depth %d after two releases", l.Held())
	}
	r1()
	if l.Held() != 0 || contended(t, l.Path()) {
		t.Fatalf("depth %d, still locked", l.Held())
	}
	// It can be taken again.
	acquire(t, l)()
}

func TestTwoInstancesSerialise(t *testing.T) {
	dir := t.TempDir()
	a, b := New(dir), New(dir)
	relA := acquire(t, a)

	var waited atomic.Int32
	waiting := make(chan struct{}, 1)
	got := make(chan func(), 1)
	go func() {
		rel, err := b.Acquire(bg, func() { waited.Add(1); waiting <- struct{}{} })
		if err != nil {
			t.Error(err)
			got <- func() {}
			return
		}
		got <- rel
	}()
	select {
	case <-waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("the second instance never announced its wait")
	}
	select {
	case <-got:
		t.Fatal("the second instance took the lock while the first held it")
	case <-time.After(150 * time.Millisecond):
	}
	if waited.Load() != 1 {
		t.Fatalf("waiting line %d times", waited.Load())
	}
	relA()
	select {
	case rel := <-got:
		if b.Held() != 1 || !contended(t, b.Path()) {
			t.Fatal("not held")
		}
		rel()
	case <-time.After(5 * time.Second):
		t.Fatal("the second instance never got the lock")
	}
	if waited.Load() != 1 {
		t.Fatalf("waiting line %d times", waited.Load())
	}
}

func TestTheWaitingLineIsNotRepeatedForAnotherWait(t *testing.T) {
	dir := t.TempDir()
	a, b := New(dir), New(dir)
	var n atomic.Int32
	for range 2 {
		relA := acquire(t, a)
		go func() {
			time.Sleep(300 * time.Millisecond)
			relA()
		}()
		rel, err := b.Acquire(bg, func() { n.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	if n.Load() > 1 {
		t.Fatalf("called %d times", n.Load())
	}
}

func TestACancelledWaitReturnsHoldsNothingAndLeavesTheHolder(t *testing.T) {
	dir := t.TempDir()
	a, b := New(dir), New(dir)
	relA := acquire(t, a)
	defer relA()

	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() {
		_, err := b.Acquire(ctx, nil)
		done <- err
	}()
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not end with its context")
	}
	if b.Held() != 0 {
		t.Fatalf("depth %d", b.Held())
	}
	// A is still the holder, and B can have the lock once A is done.
	if !contended(t, a.Path()) {
		t.Fatal("the holder lost the lock")
	}
	relA()
	acquire(t, b)()

	// A context that is over before the call does not wait for a lock that
	// is held, and does not refuse one that is free (a save after a Ctrl-C
	// in an editor must still be written).
	relA = acquire(t, a)
	if _, err := b.Acquire(ctx, nil); !errors.Is(err, ErrCancelled) || b.Held() != 0 {
		t.Fatalf("got %v, depth %d", err, b.Held())
	}
	relA()
	rel, err := b.Acquire(ctx, nil)
	if err != nil || b.Held() != 1 {
		t.Fatalf("a free lock refused to a cancelled context: %v, depth %d", err, b.Held())
	}
	rel()
}

func TestTheFileIs0600AndStaleOnesDoNotBlock(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)
	acquire(t, l)()
	st, err := os.Stat(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if filepath.Base(l.Path()) != ".store-apply.lock" || filepath.Dir(l.Path()) != dir {
		t.Fatalf("path %s", l.Path())
	}
	// The file a process left behind holds no lock.
	acquire(t, New(dir))()
}

func TestNoStateDirIsAnErrorAndNothingIsCreated(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	l := New(dir)
	rel, err := l.Acquire(bg, nil)
	if err == nil {
		rel()
		t.Fatal("no error")
	}
	if errors.Is(err, ErrCancelled) || l.Held() != 0 {
		t.Fatalf("got %v, depth %d", err, l.Held())
	}
	if ents, _ := os.ReadDir(parent); len(ents) != 0 {
		t.Fatalf("created %v", ents)
	}
}

func TestTheDescriptorIsCloseOnExec(t *testing.T) {
	l := New(t.TempDir())
	rel := acquire(t, l)
	defer rel()
	l.mu.Lock()
	fd := l.f.Fd()
	l.mu.Unlock()
	flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("descriptor flags %#x: not close-on-exec", flags)
	}
}

func TestANilLockIsNeverContended(t *testing.T) {
	var l *Lock
	rel, err := l.Acquire(bg, func() { t.Fatal("waited") })
	if err != nil {
		t.Fatal(err)
	}
	rel()
	if l.Held() != 0 {
		t.Fatal("held")
	}
}

func TestBusyProbesWithoutKeepingTheLock(t *testing.T) {
	dir := t.TempDir()
	if Busy(dir) {
		t.Fatal("busy with no lock file")
	}
	a := New(dir)
	rel := acquire(t, a)
	if !Busy(dir) {
		t.Fatal("not busy while held")
	}
	rel()
	if Busy(dir) {
		t.Fatal("busy after release")
	}
	// The probe gave the lock back.
	acquire(t, New(dir))()
}

// Touch is called by every Acquire, a nested one and one that waits included,
// before the lock is waited for (the audit writer's mark that the command is
// about to change something).
func TestAcquireTouches(t *testing.T) {
	l := New(t.TempDir())
	n := 0
	l.Touch = func() { n++ }
	rel1 := acquire(t, l)
	rel2 := acquire(t, l)
	rel2()
	rel1()
	if n != 2 {
		t.Errorf("Touch called %d times, want 2", n)
	}
}
