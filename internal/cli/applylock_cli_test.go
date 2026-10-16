package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
)

// The commands that change the configuration outside StoreApply take the
// apply lock for their whole span (D154): store import with its tier pins,
// store rollback and backup restore wait for a command that holds it, say so
// once, and then run.

// lockHold is how long another command holds the lock in these tests.
const lockHold = 800 * time.Millisecond

// holdFor holds the sandbox tree's apply lock, as another tacctl process
// does, and gives it back after d.
func holdFor(t *testing.T, sb *sandbox, d time.Duration) {
	t.Helper()
	rel, err := applylock.New(sb.path("state")).Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(d)
		rel()
	}()
}

// waited runs the command and reports how long it took and whether it said
// that it waited (once).
func (sb *sandbox) waited(t *testing.T, stdin string, args ...string) (time.Duration, bool) {
	t.Helper()
	start := time.Now()
	sb.run(stdin, args)
	took := time.Since(start)
	return took, strings.Count(plain(sb.out.String()), backend.WaitingMsg) == 1
}

func TestStoreImportWaitsForTheApplyLockAndCheckDoesNot(t *testing.T) {
	sb := newSandbox(t, false)
	sandboxRADIUS(sb)
	sb.write("etc/tacquito.yaml", fixture(t, "legacy.fresh-install.yaml"), 0o640)

	// A check writes nothing: it does not wait (it would say so).
	holdFor(t, sb, lockHold)
	sb.run("", []string{"store", "import", "--check"})
	if strings.Contains(sb.out.String(), backend.WaitingMsg) {
		t.Fatal("--check waited")
	}

	holdFor(t, sb, lockHold)
	took, said := sb.waited(t, "", "store", "import")
	sb.expect(0, "Store written to", "")
	if took < lockHold-100*time.Millisecond || !said {
		t.Fatalf("took %v, waiting line once: %v", took, said)
	}
}

func TestStoreRollbackWaitsForTheApplyLock(t *testing.T) {
	sb, original := flippedSandbox(t)
	holdFor(t, sb, lockHold)
	took, said := sb.waited(t, "y\n", "store", "rollback")
	sb.expect(0, "Rolled back", "")
	if took < lockHold-100*time.Millisecond || !said {
		t.Fatalf("took %v, waiting line once: %v", took, said)
	}
	if fileSHA(t, sb.path("etc", "tacquito.yaml")) != original {
		t.Error("tacquito.yaml is not the pre-store file")
	}
}

func TestBackupRestoreWaitsForTheApplyLock(t *testing.T) {
	sb := renderedSandbox(t)
	sb.mkSnapshot("20200101_000000_001", fixture(t, "store.minimal.yaml"), "")
	holdFor(t, sb, lockHold)
	took, said := sb.waited(t, "y\n", "backup", "restore", "20200101_000000_001")
	sb.expect(0, "Restored snapshot 20200101_000000_001", "")
	if took < lockHold-100*time.Millisecond || !said {
		t.Fatalf("took %v, waiting line once: %v", took, said)
	}
}
