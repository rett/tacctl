package devreg

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// OpenSSH's ssh-keyscan (9.6, -T 2, without -v) prints nothing on standard
// error for a refused connection, for a filtered address and for a listener
// that never greets; only a name that does not resolve prints
// "getaddrinfo <host>: Name or service not known". A device it reads
// nothing from and prints nothing about is therefore not known to be down
// (plain ssh waits longer than -T 5, and may well reach a slow server):
// ScanWith tries the built-in client once, with a short connect budget (the
// quick flag of the fallback). Only an unresolvable name costs one
// ssh-keyscan and nothing else.

// downText is the one failure text ssh-keyscan was observed to print.
const downText = "getaddrinfo sw1.example.net: Name or service not known\n"

// recordingFallback is a KeyFallback that records its calls.
type recordingFallback struct {
	mu    sync.Mutex
	calls []string
	quick []bool
	keys  []HostKey
	err   error
}

func (f *recordingFallback) fn() KeyFallback {
	return func(_ context.Context, address string, port int, quick bool) ([]HostKey, error) {
		f.mu.Lock()
		f.calls = append(f.calls, address+" "+strconv.Itoa(port))
		f.quick = append(f.quick, quick)
		f.mu.Unlock()
		return f.keys, f.err
	}
}

func keyscanSaying(stderr string) *fake.Runner {
	r := &fake.Runner{Strict: true}
	r.On([]string{"ssh-keyscan"}, execx.Result{Stderr: []byte(stderr)})
	return r
}

// Nothing on stderr and no key: the built-in client is tried once, and its
// keys are returned in type order.
func TestScanWithSilentDeviceFallsBack(t *testing.T) {
	ed, rsa := testKey(t, "ed25519"), testKey(t, "rsa")
	r := keyscanSaying("")
	fb := &recordingFallback{keys: []HostKey{rsa, ed}}
	keys, err := ScanWith(context.Background(), r, "192.0.2.7", 22, false, fb.fn())
	if err != nil || !reflect.DeepEqual(keys, []HostKey{ed, rsa}) {
		t.Fatalf("keys %v, err %v", keys, err)
	}
	if !reflect.DeepEqual(fb.calls, []string{"192.0.2.7 22"}) || !reflect.DeepEqual(fb.quick, []bool{true}) {
		t.Errorf("fallback calls %q, quick %v (the short connect budget is for a silent device)", fb.calls, fb.quick)
	}
	if n := r.Count("ssh-keyscan"); n != 1 {
		t.Errorf("%d ssh-keyscan runs, want 1 (a silent device is not asked one type at a time)", n)
	}
}

// The built-in client fails too: a NoAnswerError that says it was tried,
// still ErrNoAnswer for every caller.
func TestScanWithSilentDeviceFallbackFails(t *testing.T) {
	for name, fb := range map[string]*recordingFallback{
		"error": {err: errors.New("handshake failed")},
		"empty": {},
	} {
		fb := fb
		_, err := ScanWith(context.Background(), keyscanSaying(""), "192.0.2.7", 22, false, fb.fn())
		var na *NoAnswerError
		if !errors.Is(err, ErrNoAnswer) || !errors.As(err, &na) || !na.Builtin || len(na.OneByOne) != 0 {
			t.Errorf("%s: %#v", name, err)
		}
		if len(fb.calls) != 1 {
			t.Errorf("%s: fallback calls %q", name, fb.calls)
		}
	}
}

// A name that does not resolve: one ssh-keyscan, no fallback, the plain
// ErrNoAnswer.
func TestScanWithUnresolvableNameIsNotRetried(t *testing.T) {
	for _, stderr := range []string{
		downText,
		"getaddrinfo sw1.example.net: Temporary failure in name resolution\n",
	} {
		r := keyscanSaying(stderr)
		fb := &recordingFallback{keys: []HostKey{testKey(t, "ed25519")}}
		_, err := ScanWith(context.Background(), r, "sw1.example.net", 22, false, fb.fn())
		if err != ErrNoAnswer || len(fb.calls) != 0 || r.Count("ssh-keyscan") != 1 {
			t.Errorf("%q: err %v, fallback calls %q, %d ssh-keyscan runs", stderr, err, fb.calls, r.Count("ssh-keyscan"))
		}
	}
}

// A reached device (banner, no key) behaves as before: the one-type retry,
// then the built-in client.
func TestScanWithReachedDeviceUnchanged(t *testing.T) {
	r := keyscanSaying(banner)
	fb := &recordingFallback{err: errors.New("handshake failed")}
	_, err := ScanWith(context.Background(), r, "192.0.2.7", 22, false, fb.fn())
	var na *NoAnswerError
	if !errors.As(err, &na) || !na.Builtin || !reflect.DeepEqual(na.OneByOne, []string{"ed25519", "ecdsa", "rsa"}) {
		t.Errorf("err %#v", err)
	}
	if len(fb.calls) != 1 || fb.quick[0] || r.Count("ssh-keyscan") != 4 {
		t.Errorf("fallback calls %q quick %v, %d ssh-keyscan runs", fb.calls, fb.quick, r.Count("ssh-keyscan"))
	}
}

// A legacy device keeps its path: the fallback is tried whatever stderr
// shows (not quick), and no one-type retry for a device that was not reached;
// when it fails too the error says the built-in client was tried, as it
// always did, with no Silent and no retry types, also for an unresolvable
// name.
func TestScanWithLegacyDeviceUnchanged(t *testing.T) {
	ed := testKey(t, "ed25519")
	for _, stderr := range []string{"", downText} {
		r := keyscanSaying(stderr)
		fb := &recordingFallback{keys: []HostKey{ed}}
		keys, err := ScanWith(context.Background(), r, "192.0.2.7", 22, true, fb.fn())
		if err != nil || !reflect.DeepEqual(keys, []HostKey{ed}) || len(fb.calls) != 1 || fb.quick[0] || r.Count("ssh-keyscan") != 1 {
			t.Errorf("%q: keys %v err %v calls %q quick %v runs %d", stderr, keys, err, fb.calls, fb.quick, r.Count("ssh-keyscan"))
		}

		r = keyscanSaying(stderr)
		fb = &recordingFallback{err: errors.New("handshake failed")}
		_, err = ScanWith(context.Background(), r, "192.0.2.7", 22, true, fb.fn())
		var na *NoAnswerError
		if !errors.As(err, &na) || !na.Builtin || na.Silent || len(na.OneByOne) != 0 || r.Count("ssh-keyscan") != 1 {
			t.Errorf("%q, fallback fails: %#v, %d runs", stderr, err, r.Count("ssh-keyscan"))
		}
	}
}

// A cancelled context is the context's error, and the built-in client is not
// asked for a silent device (the runner honours the context, as the real one
// does).
func TestScanWithSilentDeviceCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &fake.Runner{}
	r.OnFunc([]string{"ssh-keyscan"}, func(execx.Cmd) (execx.Result, error) { return execx.Result{}, ctx.Err() })
	fb := &recordingFallback{keys: []HostKey{testKey(t, "ed25519")}}
	keys, err := ScanWith(ctx, r, "192.0.2.7", 22, false, fb.fn())
	if !errors.Is(err, context.Canceled) || len(keys) != 0 || len(fb.calls) != 0 {
		t.Errorf("keys %v, err %v, fallback calls %q", keys, err, fb.calls)
	}
}

// The context ends while the built-in client runs: its error is the
// context's, not a NoAnswerError.
func TestScanWithSilentDeviceCancelledInFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fb := func(ctx context.Context, _ string, _ int, _ bool) ([]HostKey, error) {
		cancel()
		return nil, ctx.Err()
	}
	_, err := ScanWith(ctx, keyscanSaying(""), "192.0.2.7", 22, false, fb)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

// Down knows the failure ssh-keyscan was observed to print, and nothing
// else: silence (a refused connection, a filtered address, a server that
// never greets), a banner and a dropped session are not Down.
func TestKeyscanDownPatterns(t *testing.T) {
	for _, c := range []struct {
		stderr string
		down   bool
	}{
		{downText, true},
		{"getaddrinfo nosuchhost.invalid: Name or service not known\n", true},
		// Another resolver text in the same getaddrinfo message.
		{"getaddrinfo sw1.example.net: Temporary failure in name resolution\n", true},
		{banner + downText, true},
		{"", false},
		{banner, false},
		{"192.0.2.7: Connection closed by remote host\n", false},
		{"read (192.0.2.7): Connection reset by peer\n", false},
		{"192.0.2.7: kex_exchange_identification: read: Connection reset by peer\n", false},
		{"a getaddrinfo sw1.example.net: Name or service not known\n", false},
	} {
		if got := Down([]byte(c.stderr)); got != c.down {
			t.Errorf("%q: Down %v, want %v", c.stderr, got, c.down)
		}
	}
}

// ScanWithAnswered is ScanWith without the read of a silent device: the
// diagnosis after a failed ssh waits no longer than ssh-keyscan and a device
// that answered.
func TestScanWithAnsweredSkipsTheSilentRead(t *testing.T) {
	ctx := context.Background()
	ed := testKey(t, "ed25519")

	r := keyscanSaying("")
	fb := &recordingFallback{keys: []HostKey{ed}}
	_, err := ScanWithAnswered(ctx, r, "192.0.2.7", 22, false, fb.fn(), devssh.ScanTiming{})
	if err != ErrNoAnswer || len(fb.calls) != 0 || r.Count("ssh-keyscan") != 1 {
		t.Errorf("silent: err %v, calls %q, %d runs", err, fb.calls, r.Count("ssh-keyscan"))
	}

	// A device that answered, and a legacy one, still have the fallback.
	r = keyscanSaying(banner)
	fb = &recordingFallback{keys: []HostKey{ed}}
	if keys, err := ScanWithAnswered(ctx, r, "192.0.2.7", 22, false, fb.fn(), devssh.ScanTiming{}); err != nil || len(keys) != 1 || len(fb.calls) != 1 {
		t.Errorf("reached: %v %v calls %q", keys, err, fb.calls)
	}
	r = keyscanSaying("")
	fb = &recordingFallback{keys: []HostKey{ed}}
	if keys, err := ScanWithAnswered(ctx, r, "192.0.2.7", 22, true, fb.fn(), devssh.ScanTiming{}); err != nil || len(keys) != 1 || len(fb.calls) != 1 || fb.quick[0] {
		t.Errorf("legacy: %v %v calls %q quick %v", keys, err, fb.calls, fb.quick)
	}
}

// A banner next to a failure still counts as reached: the combined scan opens
// several connections, and some may fail where others greeted.
func TestKeyscanReachedWinsOverDown(t *testing.T) {
	ed := testKey(t, "ed25519")
	stderr := banner + downText
	r := keyscanSaying(stderr)
	fb := &recordingFallback{keys: []HostKey{ed}}
	keys, err := ScanWith(context.Background(), r, "192.0.2.7", 22, false, fb.fn())
	if err != nil || len(keys) != 1 || len(fb.calls) != 1 || r.Count("ssh-keyscan") != 4 {
		t.Errorf("keys %v err %v calls %q runs %d", keys, err, fb.calls, r.Count("ssh-keyscan"))
	}
}

// The error of a silent device says so (Silent), and only that: a reached
// device carries the retry, a legacy one is as it was.
func TestScanWithSilentFlag(t *testing.T) {
	fail := func(legacy bool, stderr string) *NoAnswerError {
		fb := &recordingFallback{}
		_, err := ScanWith(context.Background(), keyscanSaying(stderr), "192.0.2.7", 22, legacy, fb.fn())
		var na *NoAnswerError
		if !errors.As(err, &na) {
			t.Fatalf("legacy=%v %q: %v", legacy, stderr, err)
		}
		return na
	}
	if na := fail(false, ""); !na.Silent || !na.Builtin || len(na.OneByOne) != 0 {
		t.Errorf("silent: %+v", na)
	}
	if na := fail(false, banner); na.Silent || !na.Builtin || len(na.OneByOne) == 0 {
		t.Errorf("reached: %+v", na)
	}
	if na := fail(true, ""); na.Silent || !na.Builtin {
		t.Errorf("legacy: %+v", na)
	}
}

// The timing of a read is one value: ssh-keyscan's two -T come from it (the
// defaults are 5 and 3 seconds, whole seconds, at least 1), and a zero field
// is the default.
func TestScanWithTimingSetsTheKeyscanTimeouts(t *testing.T) {
	ctx := context.Background()
	run := func(tm devssh.ScanTiming) *fake.Runner {
		r := keyscanSaying(banner)
		_, _ = ScanWithTiming(ctx, r, "192.0.2.7", 22, false, nil, tm)
		return r
	}
	r := run(devssh.ScanTiming{})
	if !r.Called("ssh-keyscan", "-T", "5", "-p", "22", "-t", "ed25519,ecdsa,rsa", "192.0.2.7") || !r.Called("ssh-keyscan", "-T", "3", "-p", "22", "-t", "ed25519", "192.0.2.7") {
		t.Errorf("defaults: %q", r.Argvs())
	}
	r = run(devssh.ScanTiming{Keyscan: 12 * time.Second, KeyscanRetry: 6500 * time.Millisecond})
	if !r.Called("ssh-keyscan", "-T", "12", "-p", "22", "-t", "ed25519,ecdsa,rsa", "192.0.2.7") || !r.Called("ssh-keyscan", "-T", "7", "-p", "22", "-t", "ed25519", "192.0.2.7") {
		t.Errorf("scaled: %q", r.Argvs())
	}
	if seconds(0) != 1 || seconds(time.Millisecond) != 1 || seconds(2*time.Second) != 2 {
		t.Errorf("seconds: %d %d %d", seconds(0), seconds(time.Millisecond), seconds(2*time.Second))
	}
}
