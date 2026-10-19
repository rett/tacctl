package hosts

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// UIDs.Numbers is what 'backup restore' compares two ledgers with: the
// entries in file order, the first line of a name winning, comments left out;
// a missing file has none.
func TestUIDsNumbers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "linux-uids")
	got, err := UIDs{Path: p}.Numbers()
	if err != nil || got != nil {
		t.Fatalf("missing file: %v %v", got, err)
	}
	writeFile(t, p, "# range 80000-89999\nalice:80000\nbob:80001\nalice:80007\n\n")
	got, err = UIDs{Path: p}.Numbers()
	want := [][2]string{{"alice", "80000"}, {"bob", "80001"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%v %v, want %v", got, err, want)
	}
}

// Registry.WithLock holds the lock the registry's writes take: a write made
// inside it (a second flock on another descriptor) waits and fails, and the
// lock is free again afterwards.
func TestRegistryWithLockHoldsTheWriteLock(t *testing.T) {
	old := registryLockWait
	registryLockWait = 100 * time.Millisecond
	defer func() { registryLockWait = old }()
	r := &Registry{Path: filepath.Join(t.TempDir(), "linux-hosts")}
	ran := false
	err := r.WithLock(func() error {
		ran = true
		other := &Registry{Path: r.Path}
		if err := other.Remember(Entry{Name: "web1", Target: "web1", Scope: "lab", Server: "192.0.2.1"}); !errors.Is(err, ErrRegistryBusy) {
			t.Errorf("a write inside the lock: %v", err)
		}
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("WithLock: %v ran %v", err, ran)
	}
	if err := r.Remember(Entry{Name: "web1", Target: "web1", Scope: "lab", Server: "192.0.2.1"}); err != nil {
		t.Errorf("the lock was not released: %v", err)
	}
	sentinel := errors.New("x")
	if err := r.WithLock(func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("fn's error: %v", err)
	}
}
