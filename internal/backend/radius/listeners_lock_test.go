package radius_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
)

// The apply lock around listenerApply (D154): it keeps tacctl.yaml before
// its first apply and puts it back through a second one after the restart.
// Another tacctl process is a second apply lock and a second Conf on the
// tree.

const lockWait = 20 * time.Second

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(lockWait)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// While another command holds the lock a listener change waits (one line)
// and touches nothing; a wait the context ends is "Nothing was changed.".
func TestListenerApplyWaitsForTheApplyLock(t *testing.T) {
	r := newEnv(t)
	r.up()
	before := r.state()
	r.reset()
	hold, err := applylock.New(r.p.StateDir).Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.m.Listeners().Set(ctx, "auth", "udp", "192.0.2.99:1812") }()
	waitUntil(t, "the waiting line", func() bool { return strings.Contains(r.out(), backend.WaitingMsg) })
	time.Sleep(300 * time.Millisecond)
	if r.state() != before || len(r.calls()) != 0 {
		t.Fatalf("ran while the lock was held: %v", r.calls())
	}
	cancel()
	select {
	case err := <-done:
		wantCode(t, err, 1)
	case <-time.After(lockWait):
		t.Fatal("the wait did not end with the context")
	}
	contains(t, r.stderr.String(), "Nothing was changed.")
	if r.state() != before || len(r.calls()) != 0 {
		t.Fatal("a cancelled change changed something")
	}
	if n := strings.Count(r.out(), backend.WaitingMsg); n != 1 {
		t.Fatalf("waiting line %d times", n)
	}
}

// The defect: a daemon that did not stay up got the whole tacctl.yaml put
// back, and with it a key another command wrote while the unit restarted.
// That command now waits at the lock, writes after the restore, and keeps
// its change.
func TestFailedListenerApplyKeepsAConcurrentConfWrite(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.setFailStart(true)

	otherLock := applylock.New(r.p.StateDir)
	otherOut := &safeBuf{}
	other := conf.Load(r.p.Overrides, r.reg.IDs())
	other.Owner = nil
	other.Lock = func() (func(), error) {
		return otherLock.Acquire(context.Background(), func() { _, _ = otherOut.Write([]byte(backend.WaitingMsg)) })
	}
	var once sync.Once
	otherDone := make(chan error, 1)
	r.m.Sleep = func(context.Context, time.Duration) {
		once.Do(func() {
			// The other command starts while this one's unit has been
			// restarted, and is held at the lock until this one is done.
			go func() { otherDone <- other.Set("bcrypt.cost", "13") }()
			waitUntil(t, "the other command's waiting line", func() bool {
				return strings.Contains(otherOut.String(), backend.WaitingMsg)
			})
		})
	}

	wantCode(t, r.m.Listeners().Set(context.Background(), "auth", "udp", "192.0.2.99:1812"), 1)
	contains(t, r.out(), "did not stay up with the new listener; putting the previous one back.")
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(lockWait):
		t.Fatal("the other command did not finish")
	}
	got := r.read(r.p.Overrides)
	contains(t, got, "cost: 13")
	if strings.Contains(got, "192.0.2.99") {
		t.Fatalf("this command's listener was not put back:\n%s", got)
	}
}
