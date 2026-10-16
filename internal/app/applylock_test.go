package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// lockedBuf is a buffer the test reads while a goroutine writes.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The App's one apply lock is the Env's and the Conf's: a tacctl.yaml write
// inside a transaction re-enters it, one from another process waits for it,
// says so once and ends with the invocation's context.
func TestApplyLockIsOneObjectAndTheConfWaitsWithTheInvocationContext(t *testing.T) {
	w := t.TempDir()
	if err := os.MkdirAll(filepath.Join(w, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, errb := &lockedBuf{}, &lockedBuf{}
	a := New(nil, paths.NewEnv([]string{"TACCTL_ETC=" + w + "/etc", "TACCTL_STATE_DIR=" + w + "/state"}),
		"", 0, Stdio{Stdin: strings.NewReader(""), Stdout: out, Stderr: errb}, &fake.Runner{})
	first := a.ApplyLock()
	if a.ApplyLock() != first || a.BackendEnv().ApplyLock != first || a.Conf().Lock == nil {
		t.Fatal("the lock is not shared")
	}
	if a.ApplyLock().Path() != filepath.Join(a.Paths.StateDir, applylock.FileName) {
		t.Fatalf("lock file %s", a.ApplyLock().Path())
	}
	// Inside a transaction: re-enters.
	rel, err := a.ApplyLock().Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Conf().Set("bcrypt.cost", "13"); err != nil {
		t.Fatal(err)
	}
	if a.ApplyLock().Held() != 1 {
		t.Fatalf("depth %d", a.ApplyLock().Held())
	}
	rel()

	// Another process holds it: the write waits, and Ctrl-C ends the wait.
	hold, err := applylock.New(a.Paths.StateDir).Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	ctx, cancel := context.WithCancel(context.Background())
	a.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Conf().Set("bcrypt.cost", "14") }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), backend.WaitingMsg) {
		if time.Now().After(deadline) {
			t.Fatal("no waiting line")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	err = <-done
	if err == nil || err.Error() != "Nothing was changed." {
		t.Fatalf("got %v", err)
	}
	if a.Tunables().BcryptCost != 13 {
		t.Fatal("the cancelled write changed something")
	}
	if strings.Count(out.String(), backend.WaitingMsg) != 1 || errb.String() != "" {
		t.Fatalf("stdout %q stderr %q", out, errb)
	}
}

// A write after a Ctrl-C (an editor's save in 'blocks edit') still goes
// through when nobody holds the lock: the context only ends a wait.
func TestAConfWriteWithACancelledContextProceedsWhenTheLockIsFree(t *testing.T) {
	w := t.TempDir()
	if err := os.MkdirAll(filepath.Join(w, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	a := New(nil, paths.NewEnv([]string{"TACCTL_ETC=" + w + "/etc", "TACCTL_STATE_DIR=" + w + "/state"}),
		"", 0, Stdio{Stdin: strings.NewReader(""), Stdout: &lockedBuf{}, Stderr: &lockedBuf{}}, &fake.Runner{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.SetContext(ctx)
	if err := a.Conf().Set("bcrypt.cost", "13"); err != nil {
		t.Fatalf("a free lock refused to a cancelled context: %v", err)
	}
}
