package backend_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/rendered"
)

// Ported from tests/integration/backend_mutation.bats (15 tests): the
// mutation path with more than one backend. A stand-in backend 'fake'
// (internal/backend/faketest) is registered next to tacacs (the real
// TACACS+ render steps behind a test module) and enabled in tacctl.yaml.
// It renders one artifact (the user names, one per line) and can be told
// to refuse at its gate, to fail while staging, or to fail in its commit
// after damaging its artifact.
//
// What must hold whichever backend fails, and wherever:
//   - every rendered artifact and rendered.json are as they were;
//   - store.yaml and tacctl.yaml are as they were;
//   - no daemon was restarted.

var ctx = context.Background()

// testHash is the hex bcrypt hash of the fixtures' users.
const testHash = "24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"

func TestTwoBackendsAMutationRendersBothRecordsBothRestartsBoth(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	res, err := e.apply(e.userSet("bob", "disabled=true"))
	if err != nil {
		t.Fatalf("%v: %s", err, e.stderr)
	}
	if !slices.Equal(res.Changed, []string{"tacacs", "fake"}) {
		t.Fatalf("changed %v", res.Changed)
	}
	if !slices.Contains(strings.Split(readFile(t, e.fakeConf), "\n"), "bob") {
		t.Fatal("bob not rendered")
	}
	if e.check(e.fakeConf) != "ok" || e.check(e.p.Config) != "ok" {
		t.Fatal("not recorded")
	}
	if !e.tac.restarted() || !e.fake.Called("service restart") {
		t.Fatalf("restarts: %v %v", e.tac.calls, e.fake.Calls())
	}
	e.noLeftovers()
}

func TestTwoBackendsEveryBackendIsGatedAndStagedBeforeAnyIsCommitted(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	// tacacs is listed first, so it commits first -- but only after fake
	// staged.
	before := readFile(t, e.p.Config)
	var untouched bool
	e.fake.OnStage = func(string) { untouched = readFile(t, e.p.Config) == before }
	if _, err := e.apply(e.userSet("bob", "disabled=true")); err != nil {
		t.Fatal(err)
	}
	if readFile(t, e.p.Config) == before {
		t.Fatal("tacquito.yaml not rendered")
	}
	if !untouched {
		t.Fatal("tacquito.yaml was replaced before fake staged")
	}
	if got := e.fake.Calls(); !slices.Equal(got[:3], []string{"gate", "stage", "commit"}) {
		t.Fatalf("calls %v", got)
	}
	if got := e.tac.calls; !slices.Equal(got[:3], []string{"gate", "stage", "commit"}) {
		t.Fatalf("tacacs calls %v", got)
	}
}

func TestTwoBackendsOnlyTheBackendWhoseArtifactChangedIsRestarted(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := e.apply(e.userSet("bob", "disabled=true")); err != nil {
		t.Fatal(err)
	}
	e.reset()
	// The fake artifact holds names only: a group change leaves it as it is.
	res, err := e.apply(e.userSet("bob", "group=readonly"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Changed, []string{"tacacs"}) {
		t.Fatalf("changed %v", res.Changed)
	}
	if !e.tac.restarted() || e.fake.Called("service restart") {
		t.Fatalf("restarts: %v %v", e.tac.calls, e.fake.Calls())
	}
}

func TestTwoBackendsAChangeThatAltersNoArtifactRestartsNothing(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := e.apply(e.userSet("bob", "disabled=true")); err != nil {
		t.Fatal(err)
	}
	e.reset()
	res, err := e.apply(e.userSet("bob", "password_changed=2026-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changed) != 0 || e.tac.restarted() || e.fake.Called("service restart") {
		t.Fatalf("changed %v, calls %v %v", res.Changed, e.tac.calls, e.fake.Calls())
	}
}

func TestTwoBackendsOneGateRefusingRefusesTheCommandBeforeAnythingIsWritten(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	e.fake.Gate = backend.GateRefused
	before := e.state()
	_, err := e.apply(e.userSet("bob", "disabled=true"))
	wantCode(t, err, 3)
	if !errors.Is(err, backend.ErrRefused) || e.state() != before {
		t.Fatalf("%v; state changed", err)
	}
	if !slices.Equal(e.fake.Calls(), []string{"gate"}) || e.tac.restarted() {
		t.Fatalf("calls %v %v", e.fake.Calls(), e.tac.calls)
	}
	if len(e.snapshots()) != 0 {
		t.Fatalf("snapshots %v", e.snapshots())
	}
	e.noLeftovers()
}

func TestTwoBackendsAGateAnsweringAdoptForcesThatBackendOnly(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	e.fake.Gate = backend.GateAdopt
	res, err := e.apply(e.userSet("bob", "disabled=true"))
	if err != nil {
		t.Fatal(err)
	}
	if !e.fake.Called("stage --force") || !slices.Equal(res.Adopted, []string{"fake"}) {
		t.Fatalf("calls %v, adopted %v", e.fake.Calls(), res.Adopted)
	}
	// tacacs was not forced: a hand edit of its file would have refused.
	e.fake.Gate = backend.GateOK
	appendFile(t, e.p.Config, "# hand edit\n")
	_, err = e.apply(e.userSet("bob", "disabled=false"))
	wantCode(t, err, 3)
	if !strings.Contains(e.stderr.String(), "was edited since tacctl rendered it") {
		t.Fatalf("stderr %q", e.stderr)
	}
}

func TestTwoBackendsABackendThatCannotStageLeavesTheOthersArtifactAndTheStoreUntouched(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	e.fake.Fail = "stage"
	before := e.state()
	_, err := e.apply(e.userSet("bob", "disabled=true"))
	wantCode(t, err, 1)
	stderr := e.stderr.String()
	if !strings.Contains(stderr, "fake: cannot express this model") {
		t.Fatalf("stderr %q", stderr)
	}
	want := "The change was not applied: " + e.p.Config + ", " + e.dropIn() + ", " + e.fakeConf +
		" could not be rendered. Store and tacctl.yaml are as they were."
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr %q\nwant %q", stderr, want)
	}
	if e.state() != before {
		t.Fatal("state changed")
	}
	// tacacs staged, and was never committed.
	if e.fake.Called("commit") || slices.Contains(e.tac.calls, "commit") {
		t.Fatalf("committed: %v %v", e.fake.Calls(), e.tac.calls)
	}
	if e.check(e.p.Config) != "ok" || e.tac.restarted() {
		t.Fatal("tacquito.yaml record or restart")
	}
	e.noLeftovers()
}

func TestTwoBackendsACommitFailingAfterTheOthersSucceededPutsEveryArtifactTheRecordsAndTheStoreBack(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	// First a good render, so the fake artifact exists and is recorded.
	if _, err := e.apply(e.userSet("bob", "disabled=true")); err != nil {
		t.Fatal(err)
	}
	e.reset()
	e.fake.Fail = "commit"
	before := e.state()
	_, err := e.apply(e.userSet("bob", "disabled=false"))
	wantCode(t, err, 1)
	if !strings.Contains(e.stderr.String(), "could not be rendered") {
		t.Fatalf("stderr %q", e.stderr)
	}
	// tacacs had committed: tacquito.yaml was the new render and recorded.
	if !slices.Contains(e.tac.calls, "commit") || !e.fake.Called("commit") {
		t.Fatalf("calls %v %v", e.tac.calls, e.fake.Calls())
	}
	if e.state() != before {
		t.Fatal("state changed")
	}
	if e.check(e.p.Config) != "ok" || e.check(e.fakeConf) != "ok" {
		t.Fatal("records")
	}
	if e.tac.restarted() || e.fake.Called("service restart") {
		t.Fatal("restarted")
	}
	e.noLeftovers()
	// And nothing is stuck: the same change goes through once the fault is
	// gone.
	e.fake.Fail = ""
	if _, err := e.apply(e.userSet("bob", "disabled=false")); err != nil {
		t.Fatal(err)
	}
}

func TestTwoBackendsAFailedFirstCommitRemovesAnArtifactThatDidNotExistBefore(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := os.Stat(e.fakeConf); err == nil {
		t.Fatal("fake.conf exists")
	}
	e.fake.Fail = "commit"
	before := e.state()
	_, err := e.set.RenderAll(ctx, backend.RenderOptions{})
	wantCode(t, err, 1)
	if _, err := os.Stat(e.fakeConf); err == nil {
		t.Fatal("fake.conf left")
	}
	if e.state() != before {
		t.Fatal("state changed")
	}
}

func TestOneBackendACommitThatFailsAfterReplacingTacquitoYAMLPutsItAndItsRecordBack(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs")
	e.faults[backend.FaultCommit+":tacacs"] = true
	before := e.state()
	_, err := e.apply(e.userSet("bob", "disabled=true"))
	wantCode(t, err, 1)
	if !slices.Contains(e.tac.calls, "commit") {
		t.Fatal("not committed")
	}
	if e.state() != before {
		t.Fatal("state changed")
	}
	if e.check(e.p.Config) != "ok" {
		t.Fatal("record")
	}
	e.noLeftovers()
}

func TestRenderAllForceReachesEveryBackendForceIDOne(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := e.set.RenderAll(ctx, backend.RenderOptions{ForceAll: true}); err != nil {
		t.Fatal(err)
	}
	if !e.fake.Called("stage --force") {
		t.Fatalf("calls %v", e.fake.Calls())
	}
	e.fake.ResetCalls()
	if _, err := e.set.RenderAll(ctx, backend.RenderOptions{Force: []string{"tacacs"}}); err != nil {
		t.Fatal(err)
	}
	if !e.fake.Called("stage") || e.fake.Called("stage --force") {
		t.Fatalf("calls %v", e.fake.Calls())
	}
	// The bash function's '--bogus' usage error has no Go form: the options
	// are a struct.
}

func TestRenderAllNeedsTheStoreAndAnEnabledListItCanResolve(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, gone")
	before := e.state()
	_, err := e.set.RenderAll(ctx, backend.RenderOptions{})
	wantCode(t, err, 1)
	if !strings.Contains(e.stderr.String(), "backends.enabled names 'gone'") || e.state() != before {
		t.Fatalf("stderr %q", e.stderr)
	}
	_ = os.Remove(e.p.StoreFile)
	e.stderr.Reset()
	_, err = e.set.RenderAll(ctx, backend.RenderOptions{})
	wantCode(t, err, 1)
	if !strings.Contains(e.stderr.String(), "store not initialised") {
		t.Fatalf("stderr %q", e.stderr)
	}
}

func TestConfigRenderReportsEachBackendRestartsTheOnesItChanged(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if err := e.set.ConfigRender(ctx, false); err != nil {
		t.Fatal(err)
	}
	out := e.stdout.String()
	if !strings.Contains(out, e.p.Config+", "+e.dropIn()+" is already up to date.\n") ||
		!strings.Contains(out, "Rendered "+e.fakeConf+".\n") {
		t.Fatalf("stdout %q", out)
	}
	if e.tac.restarted() || !e.fake.Called("service restart") {
		t.Fatalf("calls %v %v", e.tac.calls, e.fake.Calls())
	}
}

func TestDriftAnEditedArtifactOfAnyBackendIsReported(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := e.set.RenderAll(ctx, backend.RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	appendFile(t, e.fakeConf, "intruder\n")
	got := e.set.CheckDrift(backend.DriftAll)
	if len(got) != 1 || got[0].Line() != "drift\t"+e.fakeConf {
		t.Fatalf("drift %v", got)
	}
	lines := strings.Join(e.set.DriftLines(backend.DriftAll), "")
	if !strings.Contains(lines, e.fakeConf+" — edited since tacctl rendered it") {
		t.Fatalf("lines %q", lines)
	}
}

func TestBackupRestoreABackendThatCannotStageLeavesAllFilesAsTheyWere(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := e.apply(e.userSet("bob", "disabled=true")); err != nil {
		t.Fatal(err)
	}
	snaps := e.snapshots()
	snap := filepath.Join(e.p.BackupDir, snaps[len(snaps)-1])
	before := e.state()
	e.fake.Fail = "stage"
	// _backup_install_snapshot: the snapshot's store.yaml and tacctl.yaml
	// become the live ones.
	_, err := e.set.ApplyForced(ctx, func() error {
		if err := os.WriteFile(e.p.StoreFile, []byte(readFile(t, filepath.Join(snap, "store.yaml"))), 0o600); err != nil {
			return err
		}
		ov, err := os.ReadFile(filepath.Join(snap, "tacctl.yaml"))
		if err != nil {
			return os.Remove(e.p.Overrides)
		}
		return os.WriteFile(e.p.Overrides, ov, 0o640)
	})
	wantCode(t, err, 1)
	if !e.fake.Called("stage --force") {
		t.Fatalf("not a stage failure: %v", e.fake.Calls())
	}
	if e.state() != before {
		t.Fatal("state changed")
	}
	e.noLeftovers()
}

// --- Acceptance (docs/plans/go-rewrite.md WP2.1) -------------------------

// All artifacts replaced or none: three backends, each failing in turn at
// its stage and at its commit; after a failure every artifact and
// rendered.json are byte for byte as before, after success all are new.
func TestAcceptanceAllArtifactsReplacedOrNone(t *testing.T) {
	for _, step := range []string{"stage", "commit"} {
		for _, failing := range []string{"tacacs", "fake", "fake2"} {
			t.Run(step+"/"+failing, func(t *testing.T) {
				e := newTenv(t)
				fake2 := e.addFake("fake2")
				e.withStore("tacacs, fake, fake2")
				if _, err := e.apply(e.userSet("bob", "disabled=true")); err != nil {
					t.Fatalf("%v: %s", err, e.stderr)
				}
				e.reset()
				fake2.ResetCalls()
				before := e.state() + readFile(t, fake2.Conf)
				switch failing {
				case "tacacs":
					if step == "stage" {
						e.faults[backend.FaultStage+":tacacs"] = true
					} else {
						e.faults[backend.FaultCommit+":tacacs"] = true
					}
				case "fake":
					e.fake.Fail = step
				case "fake2":
					fake2.Fail = step
				}
				// A change every artifact renders differently.
				_, err := e.apply(func() error {
					if err := e.userSet("dave", "group=operator", "scopes=lab", "hash="+testHash)(); err != nil {
						return err
					}
					return e.env.Conf.Set("bcrypt.cost", "11")
				})
				wantCode(t, err, 1)
				if !strings.Contains(e.stderr.String(), "could not be rendered") {
					t.Fatalf("not a render failure: %v: %s", err, e.stderr)
				}
				if after := e.state() + readFile(t, fake2.Conf); after != before {
					t.Fatalf("artifacts changed:\n%s\n%s", before, after)
				}
				for _, p := range []string{e.p.Config, e.dropIn(), e.fakeConf, fake2.Conf} {
					if w := e.check(p); w != rendered.OK {
						t.Fatalf("%s: %s", p, w)
					}
				}
				if e.tac.restarted() || e.fake.Called("service restart") || fake2.Called("service restart") {
					t.Fatal("restarted")
				}
				e.noLeftovers()
				// Without the fault, all of them are replaced.
				clear(e.faults)
				e.fake.Fail, fake2.Fail = "", ""
				res, err := e.apply(e.userSet("dave", "group=operator", "scopes=lab", "hash="+testHash))
				if err != nil {
					t.Fatalf("%v: %s", err, e.stderr)
				}
				if !slices.Equal(res.Changed, []string{"tacacs", "fake", "fake2"}) {
					t.Fatalf("changed %v", res.Changed)
				}
			})
		}
	}
}

// Store and tacctl.yaml are put back when a render fails: the writer
// changes both (and creates tacctl.yaml where there was none), the render
// fails, and both files are byte for byte (and by mode) as before, with
// the invocation's view of tacctl.yaml reloaded.
func TestAcceptanceStoreAndTacctlYAMLPutBackWhenARenderFails(t *testing.T) {
	for _, hadOverrides := range []bool{true, false} {
		name := "without tacctl.yaml"
		if hadOverrides {
			name = "with tacctl.yaml"
		}
		t.Run(name, func(t *testing.T) {
			e := newTenv(t)
			e.withStore("")
			if hadOverrides {
				if err := e.env.Conf.Set("password.max_age_days", "30"); err != nil {
					t.Fatal(err)
				}
			}
			e.reset()
			storeBefore := readFile(t, e.p.StoreFile)
			stBefore, _ := os.Stat(e.p.StoreFile)
			var ovBefore string
			if hadOverrides {
				ovBefore = readFile(t, e.p.Overrides)
			}
			e.faults[backend.FaultCommit+":tacacs"] = true
			_, err := e.apply(func() error {
				if err := e.userSet("bob", "disabled=true")(); err != nil {
					return err
				}
				return e.env.Conf.Set("bcrypt.cost", "13")
			})
			wantCode(t, err, 1)
			if readFile(t, e.p.StoreFile) != storeBefore {
				t.Fatal("store.yaml not put back")
			}
			if st, _ := os.Stat(e.p.StoreFile); st.Mode() != stBefore.Mode() {
				t.Fatalf("store.yaml mode %v", st.Mode())
			}
			if hadOverrides {
				if readFile(t, e.p.Overrides) != ovBefore {
					t.Fatal("tacctl.yaml not put back")
				}
			} else if _, err := os.Stat(e.p.Overrides); err == nil {
				t.Fatal("tacctl.yaml left behind")
			}
			if e.env.Conf.HasOverride("bcrypt.cost") {
				t.Fatal("Conf not reloaded")
			}
			if !strings.Contains(e.stderr.String(), "Store and tacctl.yaml are as they were.") {
				t.Fatalf("stderr %q", e.stderr)
			}
			e.noLeftovers()
		})
	}
}
