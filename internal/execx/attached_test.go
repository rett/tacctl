package execx

import (
	"context"
	"io"
	"testing"
	"time"
)

// A program run with EndOnDeadline ends when the deadline passes; without it
// the program is left to finish, and a cancellation that is no deadline
// (Ctrl-C) never ends it.
func TestAttachedEndOnDeadline(t *testing.T) {
	run := func(ctx context.Context) (int, time.Duration) {
		start := time.Now()
		code, _, _ := Attached(ctx, Real{}, Cmd{Name: "sh", Args: []string{"-c", "exec sleep 2"}}, nil, io.Discard, io.Discard)
		return code, time.Since(start)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if code, d := run(EndOnDeadline(ctx)); code == 0 || d > time.Second {
		t.Errorf("deadline: code %d after %v", code, d)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if code, d := run(ctx2); code != 0 || d < time.Second {
		t.Errorf("no EndOnDeadline: code %d after %v", code, d)
	}
	ctx3, cancel3 := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel3)
	if code, d := run(EndOnDeadline(ctx3)); code != 0 || d < time.Second {
		t.Errorf("a cancel is not a deadline: code %d after %v", code, d)
	}
}

// A program run with EndOnCancel ends when ctx is cancelled, by any cause.
func TestAttachedEndOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	code, interrupted, _ := Attached(EndOnCancel(ctx), Real{}, Cmd{Name: "sh", Args: []string{"-c", "exec sleep 2"}}, nil, io.Discard, io.Discard)
	if d := time.Since(start); code == 0 || !interrupted || d > time.Second {
		t.Errorf("cancel: code %d interrupted %v after %v", code, interrupted, d)
	}
}
