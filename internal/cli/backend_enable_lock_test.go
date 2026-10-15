package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// The apply lock around backend enable and disable (D154): the copies of
// tacctl.yaml, the artifacts and rendered.json, the StoreApply and the undo
// that puts them back are one span. Another tacctl process is a second apply
// lock (and a second backend set) on the tree.

const enableLockWait = 20 * time.Second

// enableLockHash is a password hash the store accepts (bcrypt text, hex).
const enableLockHash = "24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(enableLockWait)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// switcherCtx is run's switcher with the context of the invocation.
func (e *swEnv) switcherCtx(ctx context.Context, stdin string) *switcher {
	return &switcher{ctx: ctx, set: e.set, out: e.env.Out,
		prompt: ui.NewPrompter(strings.NewReader(stdin), e.env.Out), tree: testTree, wait: func(time.Duration) {}}
}

// peerSet is another tacctl process on e's tree: its own registry of
// stand-ins over the same files, Env, Conf and apply lock. The returned
// output is where it prints.
func (e *swEnv) peerSet() (*backend.Set, *backend.Env, *lockedBuf) {
	e.t.Helper()
	reg := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	tac := faketest.New(backend.TACACS, e.p.Config, filepath.Join(e.w, "tac"))
	fake := faketest.New("fake", e.fakeConf, filepath.Join(e.w, "fake"))
	for _, b := range []*faketest.Backend{tac, fake} {
		if err := reg.Add(b.ID(), faketest.Factory(b)); err != nil {
			e.t.Fatal(err)
		}
	}
	buf := &lockedBuf{}
	out := ui.Output{Stdout: buf, Stderr: buf}
	lock := applylock.New(e.p.StateDir)
	cfg := conf.Load(e.p.Overrides, reg.IDs())
	cfg.Owner = nil
	cfg.Lock = func() (func(), error) {
		return lock.Acquire(context.Background(), func() { out.Info(backend.WaitingMsg) })
	}
	env := &backend.Env{Paths: e.p, Conf: cfg, Out: out, Now: time.Now, ApplyLock: lock}
	return backend.NewSet(reg, env), env, buf
}

// While another command holds the lock, enable waits (one line) before it
// copies anything, and finishes when the lock is free; a wait that the
// context ends changes nothing and says so.
func TestBackendEnableWaitsForTheApplyLock(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "released"
		if cancelled {
			name = "cancelled"
		}
		t.Run(name, func(t *testing.T) {
			e := newSwEnv(t)
			e.fake.SetInstalled(true)
			before := e.state()
			hold, err := applylock.New(e.p.StateDir).Acquire(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			released := false
			defer func() {
				if !released {
					hold()
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.switcherCtx(ctx, "").enable([]string{"fake", "-y"}) }()
			waitFor(t, "the waiting line", func() bool { return strings.Contains(e.out(), backend.WaitingMsg) })
			time.Sleep(300 * time.Millisecond)
			if e.state() != before || len(e.fake.Calls()) != 0 || len(e.tac.Calls()) != 0 {
				t.Fatalf("ran while the lock was held: %q %q", e.fake.Calls(), e.tac.Calls())
			}
			// Not even the copies: they are taken under the lock.
			if m, _ := filepath.Glob(filepath.Join(e.p.StateDir, ".enable.*")); len(m) != 0 {
				t.Fatalf("copied before the lock: %v", m)
			}
			if cancelled {
				cancel()
			} else {
				hold()
				released = true
			}
			var err2 error
			select {
			case err2 = <-done:
			case <-time.After(enableLockWait):
				t.Fatal("enable did not finish")
			}
			code := exitCode(err2, e.env.Out)
			if n := strings.Count(e.out(), backend.WaitingMsg); n != 1 {
				t.Errorf("waiting line %d times", n)
			}
			if cancelled {
				e.want(code, 1)
				e.has("[ERROR] Nothing was changed.\n")
				if e.state() != before || len(e.fake.Calls()) != 0 {
					t.Error("a cancelled enable changed something")
				}
				e.noLeftovers()
				return
			}
			e.want(code, 0)
			if e.enabledNow() != "tacacs fake" {
				t.Errorf("enabled: %s", e.enabledNow())
			}
		})
	}
}

// The defect: an enable whose backend did not come up put back tacctl.yaml,
// every artifact and rendered.json from its copies, and with them what
// another command rendered while the backend started. That command now waits
// at the lock, renders after the undo, and keeps its change; its records
// stand, so the next gate is not refused.
func TestFailedEnableKeepsAConcurrentStoreChange(t *testing.T) {
	e := newSwEnv(t)
	e.fake.SetInstalled(true)
	e.fake.StartFails = true
	peer, penv, pout := e.peerSet()

	peerDone := make(chan error, 1)
	started := false
	e.fake.OnService = func(backend.ServiceAction) {
		if started {
			return
		}
		started = true
		// The other command starts while the backend is being brought up
		// and is held at its gate until the undo is done.
		go func() {
			_, err := peer.StoreApply(context.Background(), backend.ApplyOptions{}, func() error {
				_, err := store.Mutate(penv.Paths.StoreFile, penv.MutateOptions(), func(s *store.Store) error {
					return s.UserSet("zulub", "group=operator", "scopes=lab", "hash="+enableLockHash)
				})
				return err
			})
			peerDone <- err
		}()
		waitFor(t, "the other command's waiting line", func() bool { return strings.Contains(pout.String(), backend.WaitingMsg) })
	}

	e.want(e.run("", "enable", "fake", "-y"), 1)
	e.has("did not come up")
	select {
	case err := <-peerDone:
		if err != nil {
			t.Fatalf("the other command: %v\n%s", err, pout)
		}
	case <-time.After(enableLockWait):
		t.Fatal("the other command did not finish")
	}
	if e.enabledNow() != "tacacs" {
		t.Errorf("enabled: %s", e.enabledNow())
	}
	if data := readText(t, e.p.StoreFile); !strings.Contains(data, "zulub") {
		t.Error("the other command's user is not in the store")
	}
	if data := readText(t, e.p.Config); !strings.Contains(data, "zulub") {
		t.Errorf("the other command's user is not rendered: %q", data)
	}
	if w, _ := rendered.Check(e.p.Rendered, e.p.Config); w != rendered.OK {
		t.Errorf("record of tacquito.yaml: %s", w)
	}
}

// The legacy-mode disable (tacctl.yaml alone, put back from a copy) waits
// for the lock too, and copies only after it.
func TestBackendDisableLegacyWaitsForTheApplyLock(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	if err := os.Remove(e.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	hold, err := applylock.New(e.p.StateDir).Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(800 * time.Millisecond)
		hold()
	}()
	start := time.Now()
	e.want(e.run("", "disable", "fake", "-y"), 0)
	if took := time.Since(start); took < 700*time.Millisecond {
		t.Errorf("took %v: did not wait", took)
	}
	if n := strings.Count(e.out(), backend.WaitingMsg); n != 1 {
		t.Errorf("waiting line %d times", n)
	}
	if e.enabledNow() != "tacacs" {
		t.Error("not disabled")
	}
	e.noLeftovers()
}
