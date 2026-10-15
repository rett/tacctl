package backend_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/store"
)

// The apply lock (D152-D158): StoreApply, ApplyForced and ConfigRender hold
// one flock from before their first read to after their last restart, and
// every write of tacctl.yaml takes it too. Two tenvs on one tree are two
// processes: each has its own apply lock object, and flock conflicts between
// two descriptors of one process.

// deadline bounds every wait of these tests.
const deadline = 20 * time.Second

// waitFor polls cond until it holds, or fails the test.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(deadline):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// peer is another tacctl process on e's tree.
func (e *tenv) peer() *tenv { return newTenvAt(e.t, e.w) }

// waiting is whether the invocation has printed the waiting line.
func (e *tenv) waiting() bool { return strings.Contains(e.stdout.String(), backend.WaitingMsg) }

// ran is whether the invocation got as far as a gate, a render or a restart.
func (e *tenv) ran() bool {
	return len(e.tac.callList()) != 0 || len(e.fake.Calls()) != 0
}

// holding takes e's apply lock by hand, as a command that is changing the
// configuration does; the returned function gives it back.
func (e *tenv) holding() func() {
	e.t.Helper()
	rel, err := e.lock.Acquire(context.Background(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return rel
}

// settle is a pause in which a command that is going to run does.
func settle() { time.Sleep(300 * time.Millisecond) }

func users(t *testing.T, e *tenv) string { return readFile(t, e.p.StoreFile) }

// TestApplyLockAFailedCommandDoesNotUndoTheOneThatWaited is the defect: B's
// change, written between A's copy and A's rollback, was put back with A's.
// B now waits at the gate, runs after A's rollback, and keeps its change.
func TestApplyLockAFailedCommandDoesNotUndoTheOneThatWaited(t *testing.T) {
	for _, how := range []string{"render", "writer"} {
		t.Run(how, func(t *testing.T) {
			a := newTenv(t)
			a.withStore("tacacs, fake")
			b := a.peer()
			boom := errors.New("writer failed")
			before := a.state()

			entered, proceed := make(chan struct{}), make(chan struct{})
			aDone := make(chan error, 1)
			if how == "render" {
				a.faults[backend.FaultCommit+":fake"] = true
			}
			go func() {
				_, err := a.apply(func() error {
					if err := a.userSet("zulua", "group=operator", "hash="+testHash, "scopes=lab")(); err != nil {
						return err
					}
					close(entered)
					<-proceed
					if how == "writer" {
						return boom
					}
					return nil
				})
				aDone <- err
			}()
			recv(t, entered, "A's writer")

			bDone := make(chan error, 1)
			go func() {
				_, err := b.apply(b.userSet("zulub", "group=operator", "hash="+testHash, "scopes=lab"))
				bDone <- err
			}()
			waitFor(t, "B's waiting line", b.waiting)
			settle()
			// B waits at the gate: it has not looked at anything.
			if b.ran() {
				t.Fatalf("B ran while A held the lock: %v %v", b.tac.callList(), b.fake.Calls())
			}
			if strings.Contains(users(t, a), "zulub") {
				t.Fatal("B wrote while A held the lock")
			}
			close(proceed)

			aErr := recv(t, aDone, "A")
			if how == "writer" && aErr != boom || how == "render" && !errors.Is(aErr, backend.ErrFailed) {
				t.Fatalf("A: %v", aErr)
			}
			if err := recv(t, bDone, "B"); err != nil {
				t.Fatalf("B: %v: %s", err, b.stderr)
			}
			st := users(t, a)
			if !strings.Contains(st, "zulub") || strings.Contains(st, "zulua") {
				t.Fatalf("B's change present %v, A's change absent %v", strings.Contains(st, "zulub"), !strings.Contains(st, "zulua"))
			}
			if !strings.Contains(readFile(t, a.fakeConf), "zulub") {
				t.Fatal("B's change was not rendered")
			}
			if n := strings.Count(b.stdout.String(), backend.WaitingMsg); n != 1 {
				t.Fatalf("the waiting line %d times", n)
			}
			if a.waiting() {
				t.Fatal("A waited")
			}
			// What B rendered is what B recorded: the next gate is open.
			if _, err := a.set.Gate(ctx, nil); err != nil {
				t.Fatalf("gate after: %v: %s", err, a.stderr)
			}
			if a.state() == before {
				t.Fatal("nothing changed")
			}
			a.noLeftovers()
			b.noLeftovers()
		})
	}
}

// Two commands that both succeed run one after the other, and the second
// one's snapshot holds the first one's change.
func TestApplyLockSerialisedCommandsTakeInOrderedSnapshots(t *testing.T) {
	a := newTenv(t)
	a.withStore("")
	b := a.peer()
	entered, proceed := make(chan struct{}), make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		_, err := a.apply(func() error {
			if err := a.userSet("zulua", "group=operator", "hash="+testHash, "scopes=lab")(); err != nil {
				return err
			}
			close(entered)
			<-proceed
			return nil
		})
		aDone <- err
	}()
	recv(t, entered, "A's writer")
	bDone := make(chan error, 1)
	go func() {
		_, err := b.apply(b.userSet("zulub", "group=operator", "hash="+testHash, "scopes=lab"))
		bDone <- err
	}()
	waitFor(t, "B's waiting line", b.waiting)
	close(proceed)
	if err := recv(t, aDone, "A"); err != nil {
		t.Fatal(err)
	}
	if err := recv(t, bDone, "B"); err != nil {
		t.Fatalf("%v: %s", err, b.stderr)
	}
	ids := a.snapshots() // newest first
	if len(ids) != 2 {
		t.Fatalf("snapshots %v", ids)
	}
	newest := readFile(t, filepath.Join(a.p.BackupDir, ids[0], "store.yaml"))
	oldest := readFile(t, filepath.Join(a.p.BackupDir, ids[1], "store.yaml"))
	if !strings.Contains(newest, "zulua") || strings.Contains(newest, "zulub") {
		t.Fatal("B's snapshot is not the state A left")
	}
	if strings.Contains(oldest, "zulua") {
		t.Fatal("A's snapshot holds A's change")
	}
}

// The lock is held through the restart: a command that waits does not start
// until the restart of the one before has ended, and its gate then sees what
// that command rendered.
func TestApplyLockIsHeldThroughTheRestart(t *testing.T) {
	a := newTenv(t)
	a.withStore("")
	b := a.peer()
	inRestart, proceed := make(chan struct{}), make(chan struct{})
	a.tac.onRestart = func() {
		close(inRestart)
		<-proceed
	}
	aDone := make(chan error, 1)
	go func() {
		_, err := a.apply(a.userSet("zulua", "group=operator", "hash="+testHash, "scopes=lab"))
		aDone <- err
	}()
	recv(t, inRestart, "A's restart")

	bDone := make(chan error, 1)
	go func() {
		_, err := b.apply(b.userSet("zulub", "group=operator", "hash="+testHash, "scopes=lab"))
		bDone <- err
	}()
	waitFor(t, "B's waiting line", b.waiting)
	settle()
	if b.ran() || strings.Contains(users(t, a), "zulub") {
		t.Fatal("B ran while A was restarting")
	}
	select {
	case err := <-bDone:
		t.Fatalf("B finished during A's restart: %v", err)
	default:
	}
	close(proceed)
	if err := recv(t, aDone, "A"); err != nil {
		t.Fatal(err)
	}
	if err := recv(t, bDone, "B"); err != nil {
		t.Fatalf("%v: %s", err, b.stderr)
	}
	if !b.tac.called("gate") {
		t.Fatal("B never gated")
	}
}

// A StoreApply, ApplyForced or ConfigRender started by a writer is an error,
// not a hang.
func TestApplyLockAChangeInsideAChangeIsAnErrorNotAHang(t *testing.T) {
	nested := map[string]func(e *tenv) error{
		"StoreApply": func(e *tenv) error {
			_, err := e.apply(func() error { return nil })
			return err
		},
		"ApplyForced": func(e *tenv) error {
			_, err := e.set.ApplyForced(ctx, func() error { return nil })
			return err
		},
		"ConfigRender": func(e *tenv) error { return e.set.ConfigRender(ctx, false) },
	}
	for name, inner := range nested {
		for _, outer := range []string{"StoreApply", "ApplyForced"} {
			t.Run(outer+"/"+name, func(t *testing.T) {
				e := newTenv(t)
				e.withStore("tacacs, fake")
				before := e.state()
				var innerErr error
				done := make(chan error, 1)
				go func() {
					writer := func() error {
						innerErr = inner(e)
						return innerErr
					}
					if outer == "StoreApply" {
						_, err := e.apply(writer)
						done <- err
						return
					}
					_, err := e.set.ApplyForced(ctx, writer)
					done <- err
				}()
				err := recv(t, done, "the outer change")
				var be *backend.Error
				if !errors.As(innerErr, &be) || be.Code != 1 || !strings.Contains(be.Reason, "a change inside a change") {
					t.Fatalf("inner: %v", innerErr)
				}
				if err == nil || e.state() != before {
					t.Fatalf("outer: %v", err)
				}
				if e.lock.Held() != 0 {
					t.Fatalf("lock depth %d", e.lock.Held())
				}
				// The flag does not outlive the writer.
				if _, err := e.apply(e.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab")); err != nil {
					t.Fatalf("%v: %s", err, e.stderr)
				}
				e.noLeftovers()
			})
		}
	}
}

// A change inside an outer transaction that holds the lock is legal: it
// re-enters, and a Conf write inside a writer does not wait for its own
// transaction.
func TestApplyLockNestingInsideAnOuterTransactionAndConfWritesInsideAWriter(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	rel := e.holding()
	done := make(chan error, 1)
	go func() {
		_, err := e.apply(func() error {
			if err := e.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab")(); err != nil {
				return err
			}
			return e.env.Conf.Set("bcrypt.cost", "13")
		})
		done <- err
	}()
	if err := recv(t, done, "the apply"); err != nil {
		t.Fatalf("%v: %s", err, e.stderr)
	}
	if e.lock.Held() != 1 {
		t.Fatalf("depth %d: the outer transaction's level was given back", e.lock.Held())
	}
	if e.waiting() || !e.env.Conf.HasOverride("bcrypt.cost") {
		t.Fatal("waited, or the Conf write is missing")
	}
	rel()
	if e.lock.Held() != 0 {
		t.Fatal("still held")
	}
}

// Another command holds the lock: every transaction waits (the waiting line,
// once), and nothing of it has run until the lock is free.
func TestApplyLockEveryTransactionWaitsForTheHolder(t *testing.T) {
	ops := map[string]func(b *tenv, wrote *bool) error{
		"StoreApply": func(b *tenv, wrote *bool) error {
			_, err := b.apply(func() error {
				*wrote = true
				return b.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab")()
			})
			return err
		},
		"ApplyForced": func(b *tenv, wrote *bool) error {
			_, err := b.set.ApplyForced(ctx, func() error { *wrote = true; return nil })
			return err
		},
		"ConfigRender": func(b *tenv, _ *bool) error { return b.set.ConfigRender(ctx, false) },
		"ConfSet":      func(b *tenv, wrote *bool) error { *wrote = true; return b.env.Conf.Set("bcrypt.cost", "13") },
		"ConfUnsetMany": func(b *tenv, wrote *bool) error {
			*wrote = true
			return b.env.Conf.UnsetMany([]string{"bcrypt.cost"})
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			a := newTenv(t)
			a.withStore("tacacs, fake")
			b := a.peer()
			rel := a.holding()
			var wrote bool
			done := make(chan error, 1)
			go func() { done <- op(b, &wrote) }()
			waitFor(t, "the waiting line", b.waiting)
			settle()
			if b.ran() {
				t.Fatalf("ran while the lock was held: %v %v", b.tac.callList(), b.fake.Calls())
			}
			select {
			case err := <-done:
				t.Fatalf("returned while the lock was held: %v", err)
			default:
			}
			rel()
			if err := recv(t, done, name); err != nil {
				t.Fatalf("%v: %s", err, b.stderr)
			}
			if n := strings.Count(b.stdout.String(), backend.WaitingMsg); n != 1 {
				t.Fatalf("the waiting line %d times", n)
			}
			if b.lock.Held() != 0 {
				t.Fatalf("depth %d after", b.lock.Held())
			}
			b.noLeftovers()
		})
	}
}

// A cancelled wait changes nothing: no file, no snapshot, no backend call,
// the holder untouched, and the holder's own lock is not affected.
func TestApplyLockACancelledWaitChangesNothing(t *testing.T) {
	ops := map[string]func(b *tenv, ctx context.Context) error{
		"StoreApply": func(b *tenv, ctx context.Context) error {
			_, err := b.set.StoreApply(ctx, backend.ApplyOptions{}, b.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab"))
			return err
		},
		"ApplyForced": func(b *tenv, ctx context.Context) error {
			_, err := b.set.ApplyForced(ctx, func() error { return os.Remove(b.p.StoreFile) })
			return err
		},
		"ConfigRender": func(b *tenv, ctx context.Context) error { return b.set.ConfigRender(ctx, true) },
		"ConfSet": func(b *tenv, ctx context.Context) error {
			b.lockCtx = ctx
			return b.env.Conf.Set("bcrypt.cost", "13")
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			a := newTenv(t)
			a.withStore("tacacs, fake")
			b := a.peer()
			before := a.state()
			snaps := a.snapshots()
			rel := a.holding()
			defer rel()
			cctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- op(b, cctx) }()
			waitFor(t, "the waiting line", b.waiting)
			cancel()
			err := recv(t, done, "the cancelled command")
			if name == "ConfSet" {
				if !errors.Is(err, applylock.ErrCancelled) {
					t.Fatalf("got %v", err)
				}
			} else {
				wantCode(t, err, 1)
				if !strings.HasSuffix(b.stderr.String(), "Nothing was changed.\n") {
					t.Fatalf("stderr %q", b.stderr)
				}
			}
			if a.state() != before || !slices.Equal(a.snapshots(), snaps) || b.ran() {
				t.Fatal("something changed")
			}
			if b.lock.Held() != 0 || a.lock.Held() != 1 {
				t.Fatalf("depths %d %d", b.lock.Held(), a.lock.Held())
			}
			b.noLeftovers()
		})
	}
}

// A lock file and a .apply.* directory left by a killed command block nobody.
func TestApplyLockStaleFilesDoNotBlock(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	stale := filepath.Join(e.p.StateDir, ".apply.stale")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "store.yaml"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.p.StateDir, applylock.FileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.apply(e.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab"))
		done <- err
	}()
	if err := recv(t, done, "the apply"); err != nil {
		t.Fatalf("%v: %s", err, e.stderr)
	}
	if e.waiting() {
		t.Fatal("waited for a stale lock file")
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("the stale directory was touched")
	}
	_ = os.RemoveAll(stale)
	e.noLeftovers()
	st, err := os.Stat(filepath.Join(e.p.StateDir, applylock.FileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v %v", st, err)
	}
}

// Require comes before the lock: with no state directory nothing is created
// and the message is the store's.
func TestApplyLockNoStateDirIsTheStoreMessageAndCreatesNothing(t *testing.T) {
	e := newTenv(t)
	if err := os.RemoveAll(e.p.StateDir); err != nil {
		t.Fatal(err)
	}
	_, err := e.apply(func() error { t.Fatal("ran"); return nil })
	wantCode(t, err, 1)
	wantCode(t, e.set.ConfigRender(ctx, false), 1)
	want := "\033[0;31m[ERROR]\033[0m " + store.NotInitialisedMsg + "\n"
	if e.stderr.String() != want+want {
		t.Fatalf("stderr %q", e.stderr)
	}
	if _, err := os.Stat(e.p.StateDir); err == nil {
		t.Fatal("the state directory was created")
	}
}

// The lock is outermost: a store lock held by someone else blocks the writer
// (inside the apply), never the apply lock itself.
func TestApplyLockIsTakenBeforeTheStoreLock(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	unlock, err := store.Lock(e.p.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	b := e.peer()
	done := make(chan error, 1)
	go func() {
		_, err := e.apply(e.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab"))
		done <- err
	}()
	// A is in flight, holding the apply lock, blocked on the store lock.
	waitFor(t, "A to hold the apply lock", func() bool { return e.lock.Held() == 1 })
	settle()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("finished with the store lock held: %v", err)
	default:
	}
	// A third command is held off by the apply lock, not by the store lock.
	cctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_, err = b.set.StoreApply(cctx, backend.ApplyOptions{}, func() error { return nil })
	if !b.waiting() || !errors.Is(err, backend.ErrNotStarted) {
		t.Fatalf("waiting %v, err %v", b.waiting(), err)
	}
	unlock()
	if err := recv(t, done, "A"); err != nil {
		t.Fatalf("%v: %s", err, e.stderr)
	}
}

// --- the guard (D157) ------------------------------------------------------

// A rollback of files the writer did not touch renames nothing: the inode
// and the times are those of the original.
func TestApplyGuardNothingWrittenNothingRenamed(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	e.faults[backend.FaultCommit+":fake"] = true
	before := e.state()
	st0, err := os.Stat(e.p.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.apply(func() error { return nil })
	wantCode(t, err, 1)
	st1, err := os.Stat(e.p.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(st0, st1) || !st0.ModTime().Equal(st1.ModTime()) || e.state() != before {
		t.Fatal("store.yaml was replaced by its copy")
	}
	if strings.Contains(e.stdout.String(), "overwritten") || len(overwritten(t, e)) != 0 {
		t.Fatalf("a warning or a saved copy without a hand edit: %q", e.stdout)
	}
	e.noLeftovers()
}

func overwritten(t *testing.T, e *tenv) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(e.p.StateDir, "*.overwritten-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A file that is not what the writer left (a hand edit while the command ran)
// is saved, named, and then put back like the other.
func TestApplyGuardAHandEditIsSavedNamedAndThenRestored(t *testing.T) {
	for _, file := range []string{"store.yaml", "tacctl.yaml"} {
		for _, via := range []string{"StoreApply", "ApplyForced"} {
			t.Run(file+"/"+via, func(t *testing.T) {
				e := newTenv(t)
				e.withStore("tacacs, fake")
				live := e.p.StoreFile
				if file == "tacctl.yaml" {
					live = e.p.Overrides
				}
				before := e.state()
				orig := readFile(t, live)
				hand := "\n# edited by hand\n"
				// The edit lands after the writer, during the render.
				e.env.Fault = func(point string) error {
					if point == backend.FaultStage+":tacacs" {
						appendFile(t, live, hand)
						return errors.New("injected fault " + point)
					}
					return nil
				}
				writer := func() error {
					if err := e.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab")(); err != nil {
						return err
					}
					return e.env.Conf.Set("bcrypt.cost", "13")
				}
				var err error
				if via == "StoreApply" {
					_, err = e.apply(writer)
				} else {
					_, err = e.set.ApplyForced(ctx, writer)
				}
				wantCode(t, err, 1)
				if e.state() != before || readFile(t, live) != orig {
					t.Fatal("the file was not put back")
				}
				saved := overwritten(t, e)
				if len(saved) != 1 || !strings.HasPrefix(filepath.Base(saved[0]), file+".overwritten-") {
					t.Fatalf("saved %v", saved)
				}
				st, err := os.Stat(saved[0])
				if err != nil || st.Mode().Perm() != 0o600 {
					t.Fatalf("saved copy: %v %v", st, err)
				}
				data := readFile(t, saved[0])
				if !strings.HasSuffix(data, hand) || data == orig+hand {
					t.Fatalf("the saved copy is not the version found: %q", data)
				}
				out := e.stdout.String()
				if !strings.Contains(out, "[WARN]") || !strings.Contains(out, live+" was changed while this command ran") ||
					!strings.Contains(out, saved[0]) {
					t.Fatalf("stdout %q", out)
				}
				e.noLeftovers()
			})
		}
	}
}

// ApplyForced's own rollback: a store that did not exist is removed, the
// guard does not keep it.
func TestApplyGuardApplyForcedStillRemovesAStoreThatDidNotExist(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	_ = os.Remove(e.p.StoreFile)
	_, err := e.set.ApplyForced(ctx, func() error {
		if err := os.WriteFile(e.p.StoreFile, []byte("version: 1\n"), 0o600); err != nil {
			return err
		}
		return errors.New("boom")
	})
	wantCode(t, err, 1)
	if _, err := os.Stat(e.p.StoreFile); err == nil {
		t.Fatal("store.yaml left")
	}
	if len(overwritten(t, e)) != 0 {
		t.Fatal("a copy was saved")
	}
}

// --- a tacctl.yaml write against a failing transaction (test 10) -----------

// B's Conf write is made while A, which wrote tacctl.yaml itself, is between
// its writer and its render. It waits, lands after A's rollback, and A's own
// write is gone.
func TestApplyLockAConfWriteWaitsForAFailingTransactionAndSurvivesItsRollback(t *testing.T) {
	a := newTenv(t)
	a.withStore("tacacs, fake")
	a.faults[backend.FaultCommit+":fake"] = true
	b := a.peer()
	entered, proceed := make(chan struct{}), make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		_, err := a.apply(func() error {
			// Inside the transaction: re-enters, does not wait for itself.
			if err := a.env.Conf.Set("password.min_length", "20"); err != nil {
				return err
			}
			close(entered)
			<-proceed
			return nil
		})
		aDone <- err
	}()
	recv(t, entered, "A's writer")

	bDone := make(chan error, 1)
	go func() { bDone <- b.env.Conf.Set("bcrypt.cost", "13") }()
	waitFor(t, "B's waiting line", b.waiting)
	settle()
	if b.env.Conf.HasOverride("bcrypt.cost") || strings.Contains(readFile(t, a.p.Overrides), "bcrypt") {
		t.Fatal("B wrote while A held the lock")
	}
	close(proceed)
	wantCode(t, recv(t, aDone, "A"), 1)
	if err := recv(t, bDone, "B"); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, a.p.Overrides)
	if !strings.Contains(got, "cost: 13") || strings.Contains(got, "min_length") {
		t.Fatalf("tacctl.yaml:\n%s", got)
	}
	if !strings.Contains(got, "enabled") {
		t.Fatalf("A's rollback lost the start state:\n%s", got)
	}
}

// --- the lock file ---------------------------------------------------------

func TestApplyLockFileIsLeftBehindWith0600AndSnapshotsDoNotTakeIt(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := e.apply(e.userSet("zulud", "group=operator", "hash="+testHash, "scopes=lab")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(e.p.StateDir, applylock.FileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	for _, id := range e.snapshots() {
		if _, err := os.Stat(filepath.Join(e.p.BackupDir, id, applylock.FileName)); err == nil {
			t.Fatal("the snapshot holds the lock file")
		}
	}
	e.noLeftovers()
}
