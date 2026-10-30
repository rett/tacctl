package tacacs

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/store"
)

// The apply lock around settingsApply (D154): 'server listen|metrics' and
// 'config loglevel' copy tacctl.yaml and rendered.json, restart the unit and put
// the copies back when it does not stay up. Another tacctl process is a
// second tenv on the tree, with its own lock object.

// lockTestHash is a password hash the store accepts (bcrypt text, hex).
const lockTestHash = "24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"

// lockWait bounds every wait of these tests.
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

// otherHolds is another process holding the apply lock of e's tree.
func otherHolds(t *testing.T, e *tenv) (release func()) {
	t.Helper()
	rel, err := applylock.New(e.p.StateDir).Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

func hasSystemctl(e *tenv) bool {
	for _, a := range e.run.Argvs() {
		if strings.HasPrefix(a, "systemctl") {
			return true
		}
	}
	return false
}

// While another command holds the lock, a settings change waits (one line),
// touches nothing, and runs, its tacctl.yaml write included, when the lock
// is free: the write inside settingsApply re-enters the lock instead of
// waiting for it, which a deadline proves.
func TestSettingsApplyWaitsForTheApplyLock(t *testing.T) {
	e := newTenv(t).withStore("store.minimal.yaml")
	e.render(false)
	before := state(e.p.Overrides, e.p.Rendered, e.dropIn("default"))
	release := otherHolds(t, e)
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	done := make(chan error, 1)
	go func() { done <- e.b.LogLevel(context.Background(), "debug") }()
	waitUntil(t, "the waiting line", func() bool { return strings.Contains(e.stdout.String(), backend.WaitingMsg) })
	time.Sleep(300 * time.Millisecond)
	if hasSystemctl(e) || state(e.p.Overrides, e.p.Rendered, e.dropIn("default")) != before {
		t.Fatalf("ran while the lock was held: %v", e.run.Argvs())
	}
	// Not even the copies: they are taken under the lock.
	if m, _ := filepath.Glob(filepath.Join(e.p.StateDir, ".units.*")); len(m) != 0 {
		t.Fatalf("copied before the lock: %v", m)
	}
	release()
	released = true
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%v\n%s", err, e.stderr)
		}
	case <-time.After(lockWait):
		t.Fatal("the change did not finish (a write inside it waited for its own lock?)")
	}
	if n := strings.Count(e.stdout.String(), backend.WaitingMsg); n != 1 {
		t.Fatalf("waiting line %d times", n)
	}
	mustContain(t, readFile(t, e.p.Overrides), "level: 30")
	mustLine(t, readFile(t, e.dropIn("default")), `Environment="TACQUITO_LEVEL=30"`)
}

// A wait that the invocation's context ends changes nothing and says so.
func TestSettingsApplyCancelledWhileWaitingChangesNothing(t *testing.T) {
	e := newTenv(t).withStore("store.minimal.yaml")
	e.render(false)
	before := state(e.p.Overrides, e.p.Rendered, e.dropIn("default"))
	release := otherHolds(t, e)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.b.LogLevel(ctx, "debug") }()
	waitUntil(t, "the waiting line", func() bool { return strings.Contains(e.stdout.String(), backend.WaitingMsg) })
	cancel()
	select {
	case err := <-done:
		wantCode(t, err, 1)
	case <-time.After(lockWait):
		t.Fatal("the wait did not end with the context")
	}
	mustContain(t, e.stderr.String(), "Nothing was changed.")
	if hasSystemctl(e) || state(e.p.Overrides, e.p.Rendered, e.dropIn("default")) != before {
		t.Fatal("changed")
	}
	e.noKeep()
}

// The defect: a settings change whose unit does not come up put back the
// whole tacctl.yaml and rendered.json, and with them what another command
// wrote while the unit was restarting; that command's rendered file then
// looked hand-edited and the next gate refused it. The other command now
// waits at the lock, runs after the restore, and keeps its change.
func TestFailedSettingsApplyKeepsAConcurrentStoreChange(t *testing.T) {
	e := newTenv(t).withStore("store.minimal.yaml")
	e.render(false)
	peer := newTenvAt(t, e.w)
	peer.b.Chown = func(string) {}
	addUser := func(name string) func() error {
		return func() error {
			_, err := store.Mutate(peer.p.StoreFile, peer.env.MutateOptions(), func(s *store.Store) error {
				return s.UserSet(name, "group=operator", "hash="+lockTestHash)
			})
			return err
		}
	}

	e.failActive(`tacquito$`)
	var once sync.Once
	peerDone := make(chan error, 1)
	e.run.OnFunc([]string{"systemctl", "restart"}, func(execx.Cmd) (execx.Result, error) {
		once.Do(func() {
			// The other command starts while this one's unit restarts and
			// is held at its gate until this one has restored.
			go func() {
				_, err := peer.set.StoreApply(context.Background(), backend.ApplyOptions{}, addUser("zulub"))
				peerDone <- err
			}()
			waitUntil(t, "the other command's waiting line", func() bool {
				return strings.Contains(peer.stdout.String(), backend.WaitingMsg)
			})
		})
		return execx.Result{}, nil
	})

	wantCode(t, e.b.LogLevel(context.Background(), "debug"), 1)
	mustContain(t, e.stderr.String(), "failed to start. Restoring previous override.")
	select {
	case err := <-peerDone:
		if err != nil {
			t.Fatalf("the other command: %v\n%s", err, peer.stderr)
		}
	case <-time.After(lockWait):
		t.Fatal("the other command did not finish")
	}
	if !strings.Contains(readFile(t, e.p.StoreFile), "zulub") {
		t.Fatal("the other command's user is not in the store")
	}
	if !strings.Contains(readFile(t, e.p.Config), "zulub") {
		t.Fatal("the other command's user is not rendered")
	}
	if exists(e.p.Overrides) && strings.Contains(readFile(t, e.p.Overrides), "level") {
		t.Fatal("this command's change was not put back: " + readFile(t, e.p.Overrides))
	}
	// Its records survived the restore: the next gate is not refused.
	if _, err := peer.set.StoreApply(context.Background(), backend.ApplyOptions{}, addUser("zulud")); err != nil {
		if errors.Is(err, backend.ErrRefused) {
			t.Fatalf("the next gate refused: %s", peer.stderr)
		}
		t.Fatalf("%v\n%s", err, peer.stderr)
	}
}
