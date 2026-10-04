package backend_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
)

// StoreApply's own steps: store_require, the snapshot (backup.bats
// "snapshot: a mutation that cannot be snapshotted is refused" and "one
// command with several store writes takes one snapshot"), the writer's
// failure, --gate and --defer-restart.

func TestStoreApplyNeedsTheStore(t *testing.T) {
	e := newTenv(t)
	called := false
	_, err := e.apply(func() error { called = true; return nil })
	wantCode(t, err, 1)
	if called || e.stderr.String() != "\033[0;31m[ERROR]\033[0m "+store.NotInitialisedMsg+"\n" {
		t.Fatalf("called %v, stderr %q", called, e.stderr)
	}
	if err := e.set.Require(); !errors.Is(err, backend.ErrFailed) {
		t.Fatal(err)
	}
}

func TestStoreApplyTakesOneSnapshotForSeveralStoreWrites(t *testing.T) {
	e := newTenv(t)
	e.withStore("")
	twoWrites := func() error {
		if err := e.userSet("dave", "group=operator", "hash="+testHash, "scopes=lab")(); err != nil {
			return err
		}
		return e.userSet("erin", "group=operator", "hash="+testHash, "scopes=lab")()
	}
	if _, err := e.apply(twoWrites); err != nil {
		t.Fatalf("%v: %s", err, e.stderr)
	}
	ids := e.snapshots()
	if len(ids) != 1 {
		t.Fatalf("snapshots %v", ids)
	}
	// It holds the state before either write.
	snap := readFile(t, filepath.Join(e.p.BackupDir, ids[0], "store.yaml"))
	if strings.Contains(snap, "dave") || strings.Contains(snap, "erin") {
		t.Fatal("snapshot taken after a write")
	}
	live := readFile(t, e.p.StoreFile)
	if !strings.Contains(live, "dave") || !strings.Contains(live, "erin") {
		t.Fatal("writes missing")
	}
	if !strings.Contains(e.stdout.String(), "Config snapshot saved to "+filepath.Join(e.p.BackupDir, ids[0])) {
		t.Fatalf("stdout %q", e.stdout)
	}
	// Outside StoreApply the hook snapshots again.
	if _, err := store.Mutate(e.p.StoreFile, e.env.MutateOptions(), func(s *store.Store) error {
		return s.UserSet("dave", "disabled=true")
	}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.snapshots()); n != 2 {
		t.Fatalf("%d snapshots", n)
	}
}

func TestStoreApplyAMutationThatCannotBeSnapshottedIsRefusedNothingWritten(t *testing.T) {
	e := newTenv(t)
	e.withStore("")
	e.faults[snapshot.FaultTake] = true
	e.env.Snapshots.Fault = e.fault
	before := e.state()
	called := false
	_, err := e.apply(func() error { called = true; return nil })
	wantCode(t, err, 1)
	want := "\033[0;31m[ERROR]\033[0m Cannot write a snapshot in " + e.p.BackupDir + ".\n" +
		"\033[0;31m[ERROR]\033[0m Nothing was changed: the pre-change snapshot could not be made.\n"
	if called || e.stderr.String() != want {
		t.Fatalf("called %v, stderr %q", called, e.stderr)
	}
	if e.state() != before {
		t.Fatal("state changed")
	}
	if m, _ := filepath.Glob(filepath.Join(e.p.BackupDir, ".snap.*")); len(m) != 0 {
		t.Fatalf("left %v", m)
	}
	e.noLeftovers()
}

func TestStoreApplyAFailingWriterPutsBothFilesBackAndReturnsItsError(t *testing.T) {
	e := newTenv(t)
	e.withStore("")
	before := e.state()
	boom := errors.New("writer failed")
	_, err := e.apply(func() error {
		if err := e.userSet("bob", "disabled=true")(); err != nil {
			return err
		}
		if err := e.env.Conf.Set("bcrypt.cost", "13"); err != nil {
			return err
		}
		return boom
	})
	if err != boom {
		t.Fatalf("got %v", err)
	}
	if e.state() != before || e.env.Conf.HasOverride("bcrypt.cost") {
		t.Fatal("not rolled back")
	}
	if e.stderr.Len() != 0 {
		t.Fatalf("printed %q", e.stderr)
	}
	if e.tac.called("stage") {
		t.Fatal("rendered after a failed writer")
	}
	// A store refusal is the store's error, for the caller to report.
	_, err = e.apply(e.userSet("bob", "group=nosuchgroup"))
	var se *store.Error
	if !errors.As(err, &se) || e.state() != before {
		t.Fatalf("got %v", err)
	}
	e.noLeftovers()
}

func TestStoreApplyGatesTheGivenBackendsAndDefersARestart(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs")
	// The writer enables fake: --gate names the set that will be rendered.
	res, err := e.set.StoreApply(ctx, backend.ApplyOptions{Gate: []string{"tacacs", "fake"}, DeferRestart: []string{"fake"}},
		func() error { return e.env.Conf.SetList("backends.enabled", []string{"tacacs", "fake"}) })
	if err != nil {
		t.Fatalf("%v: %s", err, e.stderr)
	}
	if !e.fake.Called("gate") || !slices.Equal(res.Changed, []string{"fake"}) {
		t.Fatalf("calls %v, changed %v", e.fake.Calls(), res.Changed)
	}
	if e.fake.Called("service restart") {
		t.Fatal("deferred restart was run")
	}
	// An unknown id in --gate is backend_call's error (2), before anything.
	e.reset()
	before := e.state()
	_, err = e.set.StoreApply(ctx, backend.ApplyOptions{Gate: []string{"ldap"}}, func() error { return nil })
	wantCode(t, err, 2)
	if e.stderr.String() != "\033[0;31m[ERROR]\033[0m Unknown backend 'ldap'.\n" || e.state() != before {
		t.Fatalf("stderr %q", e.stderr)
	}
}

func TestStoreApplyAGateThatFailsIs1AndAnUnreadableEnabledListToo(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	e.fake.Gate = backend.GateFailed
	_, err := e.apply(func() error { return nil })
	wantCode(t, err, 1)
	e.enable("tacacs, gone")
	e.reset()
	_, err = e.apply(func() error { return nil })
	wantCode(t, err, 1)
	if !strings.Contains(e.stderr.String(), "backends.enabled names 'gone'") {
		t.Fatalf("stderr %q", e.stderr)
	}
}

func TestRenderAllARefusedStageIs3AndStoreApplyMakesIt1(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	appendFile(t, e.p.Config, "# hand edit\n")
	_, err := e.set.RenderAll(ctx, backend.RenderOptions{})
	wantCode(t, err, 3)
	if !strings.Contains(e.stderr.String(), "was edited since tacctl rendered it") {
		t.Fatalf("stderr %q", e.stderr)
	}
	// Past an open gate, a refusing stage fails the apply (store_apply
	// returns 1 whatever the render returned) and rolls the store back.
	e = newTenv(t)
	e.withStore("fake")
	e.fake.Fail = "refuse"
	before := e.state()
	_, err = e.apply(e.userSet("bob", "disabled=true"))
	wantCode(t, err, 1)
	if e.state() != before {
		t.Fatal("state changed")
	}
}

func TestRestartAllRestartsEveryEnabledBackend(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if err := e.set.RestartAll(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.tac.restarted() || !e.fake.Called("service restart") {
		t.Fatal("not restarted")
	}
	e.enable("gone")
	if err := e.set.RestartAll(ctx); backend.ExitCode(err) != 1 {
		t.Fatal(err)
	}
}

func TestApplyForcedRendersWithForceAndKeepsNothingOnSuccess(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	changed, err := e.set.ApplyForced(ctx, func() error {
		return e.env.Conf.Set("bcrypt.cost", "13")
	})
	if err != nil || !slices.Equal(changed, []string{"fake"}) {
		t.Fatalf("%v %v: %s", changed, err, e.stderr)
	}
	if !e.fake.Called("stage --force") || !e.env.Conf.HasOverride("bcrypt.cost") {
		t.Fatal("not forced or not written")
	}
	if len(e.snapshots()) != 0 {
		t.Fatal("ApplyForced took a snapshot of its own")
	}
	e.noLeftovers()
	// A tacctl.yaml the writer puts in place by hand is the one rendered
	// (here: fake is no longer enabled, so it is not staged).
	e.fake.ResetCalls()
	if _, err := e.set.ApplyForced(ctx, func() error {
		return os.WriteFile(e.p.Overrides, []byte("backends:\n  enabled: [tacacs]\n"), 0o640)
	}); err != nil {
		t.Fatal(err)
	}
	if e.fake.Called("stage --force") || e.set.IsEnabled("fake") {
		t.Fatalf("calls %v", e.fake.Calls())
	}
	// A writer that fails: both files back, a store that did not exist is
	// removed again.
	_ = os.Remove(e.p.StoreFile)
	_, err = e.set.ApplyForced(ctx, func() error {
		if err := os.WriteFile(e.p.StoreFile, []byte("version: 1\n"), 0o600); err != nil {
			return err
		}
		return errors.New("boom")
	})
	wantCode(t, err, 1)
	if _, err := os.Stat(e.p.StoreFile); err == nil {
		t.Fatal("store.yaml left")
	}
	e.noLeftovers()
}

func TestKeepAndRestorePutEveryArtifactBack(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if err := os.Chmod(e.p.Config, 0o640); err != nil {
		t.Fatal(err)
	}
	before := e.state()
	stBefore, _ := os.Stat(e.p.Config)
	k, err := e.set.Keep(filepath.Join(e.w, "keep"), []string{"tacacs", "fake"})
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(e.p.Config, []byte("damaged\n"), 0o600)
	_ = os.WriteFile(e.fakeConf, []byte("created\n"), 0o600)
	_ = os.WriteFile(e.p.Rendered, []byte("{}\n"), 0o600)
	k.Restore()
	if e.state() != before {
		t.Fatal("not restored")
	}
	if _, err := os.Stat(e.fakeConf); err == nil {
		t.Fatal("an artifact that did not exist was not removed")
	}
	st, _ := os.Stat(e.p.Config)
	if st.Mode() != stBefore.Mode() || !st.ModTime().Equal(stBefore.ModTime()) {
		t.Fatalf("mode %v time %v, want %v %v", st.Mode(), st.ModTime(), stBefore.Mode(), stBefore.ModTime())
	}
	// A file that cannot be put back is warned about, on stderr.
	if _, err := e.set.Keep(filepath.Join(e.w, "keep2"), []string{"ldap"}); err == nil {
		t.Fatal("kept an unknown backend")
	}
	k2, err := e.set.Keep(filepath.Join(e.w, "keep3"), []string{"tacacs"})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(e.p.Config)
	_ = os.Chmod(dir, 0o500)
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if os.Geteuid() != 0 {
		k2.Restore()
		if !strings.Contains(e.stderr.String(), "[WARN]\033[0m Could not put "+e.p.Config+" back; 'tacctl config render' rewrites it from the store.") {
			t.Fatalf("stderr %q", e.stderr)
		}
	}
}
