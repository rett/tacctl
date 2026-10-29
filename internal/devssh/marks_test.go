package devssh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// marked runs do as the one job of a batch with a clock of one second per
// reading and returns the steps the job's marks made, in order.
func marked(t *testing.T, do func(ctx context.Context) batch.Result) []string {
	t.Helper()
	clock := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	s := batch.Run(context.Background(), batch.Options{Concurrency: 1, Clock: func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}}, []batch.Job{{Name: "sw1", Do: do}}, nil)
	var steps []string
	for _, m := range s.Entries[0].Marks {
		steps = append(steps, m.Step)
	}
	return steps
}

func sameSteps(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("steps %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("steps %v, want %v", got, want)
		}
	}
}

// Dial marks the end of the connection (the TCP connect and the ssh key
// exchange up to the host key) and then the end of the login: the two apart,
// in that order, and the session each opens after them.
func TestDialMarksConnectThenLogin(t *testing.T) {
	srv := serve(t, transcript(t, map[string]string{"prompt": "rtr1#", "show version.out": "Cisco IOS Software\n"}))
	got := marked(t, func(ctx context.Context) batch.Result {
		c, err := devssh.Dial(ctx, target(t, srv, nil))
		if err != nil {
			return batch.Result{Status: batch.StatusFailed, Err: err}
		}
		defer func() { _ = c.Close() }()
		s, err := c.CLI(devssh.VendorCisco)
		if err != nil {
			return batch.Result{Status: batch.StatusFailed, Err: err}
		}
		_ = s.Close()
		return batch.Result{}
	})
	sameSteps(t, got, "connect", "login", "session")
}

func TestNetconfMarksTheSession(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	got := marked(t, func(ctx context.Context) batch.Result {
		c, err := devssh.Dial(ctx, target(t, srv, nil))
		if err != nil {
			return batch.Result{Status: batch.StatusFailed, Err: err}
		}
		defer func() { _ = c.Close() }()
		n, err := c.NETCONF()
		if err != nil {
			return batch.Result{Status: batch.StatusFailed, Err: err}
		}
		_ = n.Close()
		return batch.Result{}
	})
	sameSteps(t, got, "connect", "login", "session")
}

// A login that the device refuses has reached the connection and not the
// login.
func TestRefusedLoginMarksOnlyTheConnect(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	got := marked(t, func(ctx context.Context) batch.Result {
		tg := target(t, srv, nil)
		tg.Password = func() (string, error) { return "not-the-password-0123", nil }
		_, err := devssh.Dial(ctx, tg)
		if !errors.Is(err, devssh.ErrAuth) {
			t.Errorf("err = %v, want ErrAuth", err)
		}
		return batch.Result{Status: batch.StatusAuthFailed, Err: err}
	})
	sameSteps(t, got, "connect")
}

// A host key that is not pinned stops the connection before either mark.
func TestUnpinnedKeyMarksNothing(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	other := serve(t, transcript(t, nil), fakedev.WithRandomHostKey())
	got := marked(t, func(ctx context.Context) batch.Result {
		tg := target(t, srv, nil)
		tg.HostKeys = []string{other.HostKey()}
		_, err := devssh.Dial(ctx, tg)
		return batch.Result{Status: batch.StatusFailed, Err: err}
	})
	sameSteps(t, got)
}
