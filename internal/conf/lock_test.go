package conf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
)

// The apply lock hook (Config.Lock): every write of tacctl.yaml takes it
// before the directory flock and gives it back after the write.

func lockedConfig(t *testing.T, dir string) (*Config, *applylock.Lock) {
	t.Helper()
	l := applylock.New(dir)
	c := Load(filepath.Join(dir, "tacctl.yaml"), DefaultBackends)
	c.Owner = nil
	c.Lock = func() (func(), error) { return l.Acquire(context.Background(), nil) }
	return c, l
}

// writes is every kind of write: write (Set, Unset), edit (SetValuesIf) and
// UnsetMany.
func writes() map[string]func(c *Config) error {
	return map[string]func(c *Config) error{
		"Set":         func(c *Config) error { return c.Set("bcrypt.cost", "13") },
		"Unset":       func(c *Config) error { return c.Unset("bcrypt.cost") },
		"SetValuesIf": func(c *Config) error { return c.SetValuesIf([]PathValue{{Path: "bcrypt.cost", Value: 13}}, nil) },
		"UnsetMany":   func(c *Config) error { return c.UnsetMany([]string{"bcrypt.cost"}) },
	}
}

func TestLockHookEveryWriteTakesTheLockOnceAndGivesItBack(t *testing.T) {
	for name, op := range writes() {
		t.Run(name, func(t *testing.T) {
			c, _ := lockedConfig(t, t.TempDir())
			taken, given := 0, 0
			c.Lock = func() (func(), error) {
				taken++
				return func() { given++ }, nil
			}
			if err := op(c); err != nil || taken != 1 || given != 1 {
				t.Fatalf("%v: taken %d, given back %d", err, taken, given)
			}
		})
	}
}

// A hook that fails is the write's error, and nothing is written.
func TestLockHookErrorIsTheWritesAndNothingIsWritten(t *testing.T) {
	boom := errors.New("cannot lock")
	for name, op := range writes() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			c, _ := lockedConfig(t, dir)
			if err := c.Set("bcrypt.cost", "11"); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(c.Path)
			c.Lock = func() (func(), error) { return nil, boom }
			if err := op(c); !errors.Is(err, boom) {
				t.Fatalf("got %v", err)
			}
			after, err := os.ReadFile(c.Path)
			if err != nil || string(after) != string(before) {
				t.Fatalf("file changed: %v %q", err, after)
			}
		})
	}
}

// A Config with no hook does not lock: it writes while another holder has
// the apply lock (snapshot views and tests).
func TestLockHookNilIsNoLock(t *testing.T) {
	dir := t.TempDir()
	holder := applylock.New(dir)
	rel, err := holder.Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	c := Load(filepath.Join(dir, "tacctl.yaml"), DefaultBackends)
	c.Owner = nil
	done := make(chan error, 1)
	go func() { done <- c.Set("bcrypt.cost", "13") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a Config without a hook waited")
	}
}

// With the real lock: a write on a second Config and a second lock object
// blocks while the first holds the lock, and happens after it is given back
// (what a second process does).
func TestLockHookWriteBlocksWhileAnotherInstanceHoldsTheLock(t *testing.T) {
	for name, op := range writes() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			holder := applylock.New(dir)
			c, _ := lockedConfig(t, dir)
			// A key to remove, for the unsetting writes.
			if err := c.Set("bcrypt.cost", "11"); err != nil {
				t.Fatal(err)
			}
			start, _ := os.ReadFile(c.Path)
			rel, err := holder.Acquire(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- op(c) }()
			select {
			case err := <-done:
				t.Fatalf("returned while the lock was held: %v", err)
			case <-time.After(400 * time.Millisecond):
			}
			if now, _ := os.ReadFile(c.Path); string(now) != string(start) {
				t.Fatal("written while the lock was held")
			}
			rel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("still waiting after the lock was given back")
			}
		})
	}
}

// A write inside a transaction of the same process (the lock held, depth 1)
// re-enters instead of deadlocking, and leaves the transaction's level.
func TestLockHookWriteInsideAHeldLockReenters(t *testing.T) {
	dir := t.TempDir()
	c, l := lockedConfig(t, dir)
	rel, err := l.Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		err := c.Set("bcrypt.cost", "13")
		if err == nil {
			err = c.UnsetMany([]string{"bcrypt.cost"})
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("deadlocked on its own transaction's lock")
	}
	if l.Held() != 1 {
		t.Fatalf("depth %d", l.Held())
	}
	rel()
}

// The apply lock is taken before the directory is locked, so a holder of
// the directory flock cannot hold off the apply lock's holder (the order is
// apply, then directory): a write blocked on the directory flock holds the
// apply lock, and a second one waits for that.
func TestLockHookIsOutsideTheDirectoryLock(t *testing.T) {
	dir := t.TempDir()
	c, l := lockedConfig(t, dir)
	unlock, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Set("bcrypt.cost", "13") }()
	deadline := time.Now().Add(10 * time.Second)
	for l.Held() != 1 {
		if time.Now().After(deadline) {
			unlock()
			t.Fatal("the write did not take the apply lock first")
		}
		time.Sleep(5 * time.Millisecond)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if l.Held() != 0 {
		t.Fatalf("depth %d", l.Held())
	}
}
