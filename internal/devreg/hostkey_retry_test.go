package devreg

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// A device that answers a single connection but not the several
// simultaneous ones of ssh-keyscan's combined '-t ed25519,ecdsa,rsa' (a
// connection limit, or a long algorithm offer it drops): the combined scan
// prints a banner and no key, and a scan of one type prints the key.

const banner = "# 192.0.2.7:22 SSH-2.0-OpenSSH_7.5\n"

// pickyDevice scripts ssh-keyscan against a device that holds keys: the
// combined scan (a -t with several types) reads nothing, a scan of one
// type reads that type's key if the device holds one. calls records the -t
// and -T of every run.
func pickyDevice(calls *[]string, stderr string, held ...HostKey) *fake.Runner {
	r := &fake.Runner{Strict: true}
	var mu sync.Mutex
	r.OnFunc([]string{"ssh-keyscan"}, func(c execx.Cmd) (execx.Result, error) {
		a := c.Args
		typ := a[slices.Index(a, "-t")+1]
		mu.Lock()
		*calls = append(*calls, "-T "+a[slices.Index(a, "-T")+1]+" -t "+typ)
		mu.Unlock()
		res := execx.Result{Stderr: []byte(stderr)}
		if strings.Contains(typ, ",") {
			return res, nil
		}
		for _, k := range held {
			if strings.HasPrefix(k.Type, map[string]string{"ed25519": "ssh-ed25519", "ecdsa": "ecdsa-", "rsa": "ssh-rsa", "ssh-rsa": "ssh-rsa"}[typ]) {
				res.Stdout = append(res.Stdout, []byte("192.0.2.7 "+k.String()+"\n")...)
			}
		}
		return res, nil
	})
	return r
}

func TestScanRetriesOneTypeAtATime(t *testing.T) {
	ed, ec, rsa := testKey(t, "ed25519"), testKey(t, "ecdsa"), testKey(t, "rsa")
	ctx := context.Background()

	// Reproduction: the combined scan reads nothing, the keys come one type
	// at a time, ed25519 first.
	var calls []string
	keys, err := Scan(ctx, pickyDevice(&calls, banner, ed), "192.0.2.7", 22, false)
	if err != nil || !reflect.DeepEqual(keys, []HostKey{ed}) {
		t.Fatalf("one key: %v %v", keys, err)
	}
	want := []string{"-T 5 -t ed25519,ecdsa,rsa", "-T 3 -t ed25519", "-T 3 -t ecdsa", "-T 3 -t rsa"}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls %q, want %q", calls, want)
	}

	// Every type the device holds is collected, in type order; a type that
	// fails does not fail the scan (the pinned set is complete).
	calls = nil
	keys, err = Scan(ctx, pickyDevice(&calls, banner, rsa, ec, ed), "192.0.2.7", 22, false)
	if err != nil || !reflect.DeepEqual(keys, []HostKey{ed, ec, rsa}) {
		t.Errorf("three keys: %v %v", keys, err)
	}
	calls = nil
	keys, err = Scan(ctx, pickyDevice(&calls, banner, rsa), "192.0.2.7", 22, false)
	if err != nil || !reflect.DeepEqual(keys, []HostKey{rsa}) || len(calls) != 4 {
		t.Errorf("rsa only: %v %v %q", keys, err, calls)
	}

	// A legacy-ssh device is asked for ssh-rsa by its algorithm name last.
	calls = nil
	if _, err = Scan(ctx, pickyDevice(&calls, banner, ed), "192.0.2.7", 22, true); err != nil {
		t.Fatal(err)
	}
	want = []string{"-T 5 -t ed25519,ecdsa,rsa,ssh-rsa", "-T 3 -t ed25519", "-T 3 -t ecdsa", "-T 3 -t rsa", "-T 3 -t ssh-rsa"}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("legacy calls %q, want %q", calls, want)
	}

	// The retry uses the device's port.
	r := pickyDevice(&calls, banner, ed)
	if _, err = Scan(ctx, r, "192.0.2.7", 830, false); err != nil || !r.Called("ssh-keyscan", "-T", "3", "-p", "830", "-t", "ed25519", "192.0.2.7") {
		t.Errorf("port: %v %q", err, r.Argvs())
	}

	// ssh-keyscan answering at once is not retried.
	r = &fake.Runner{Strict: true}
	r.On([]string{"ssh-keyscan"}, execx.Result{Stdout: []byte("192.0.2.7 " + ed.String() + "\n"), Stderr: []byte(banner)})
	if _, err = Scan(ctx, r, "192.0.2.7", 22, false); err != nil || r.Count("ssh-keyscan") != 1 {
		t.Errorf("answered: %v %q", err, r.Argvs())
	}
}

// Nothing read from a device that was reached ends in a NoAnswerError that
// names the retry (it is ErrNoAnswer for every caller); a device that was
// not reached is the plain ErrNoAnswer after one ssh-keyscan. ssh-keyscan's
// messages on stderr tell them apart: its exit status says nothing.
func TestScanTellsAnUnreachableDeviceFromAnSilentOne(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		stderr  string
		reached bool
	}{
		{banner, true},
		{"192.0.2.7: Connection closed by remote host\n", true},
		{"read (192.0.2.7): Connection reset by peer\n", true},
		{"192.0.2.7: kex_exchange_identification: read: Connection reset by peer\n", true},
		{"192.0.2.7: Connection refused\n", false},
		{"connect (`192.0.2.7'): Connection refused\n", false},
		{"192.0.2.7: Connection timed out\n", false},
		{"connect (`192.0.2.7'): No route to host\n", false},
		{"connect (`192.0.2.7'): Network is unreachable\n", false},
		{"getaddrinfo example.net: Name or service not known\n", false},
		{"", false},
	} {
		for _, code := range []int{0, 1} {
			r := &fake.Runner{Strict: true}
			r.On([]string{"ssh-keyscan"}, execx.Result{Code: code, Stderr: []byte(c.stderr)})
			_, err := Scan(ctx, r, "192.0.2.7", 22, false)
			var na *NoAnswerError
			isNA := errors.As(err, &na)
			if !errors.Is(err, ErrNoAnswer) || isNA != c.reached {
				t.Errorf("%q exit %d: err %v, NoAnswerError %v", c.stderr, code, err, isNA)
				continue
			}
			wantRuns := 1
			if c.reached {
				wantRuns = 4
				if !reflect.DeepEqual(na.OneByOne, []string{"ed25519", "ecdsa", "rsa"}) || na.Builtin {
					t.Errorf("%q: tried %+v", c.stderr, na)
				}
			}
			if n := r.Count("ssh-keyscan"); n != wantRuns {
				t.Errorf("%q exit %d: %d ssh-keyscan runs, want %d", c.stderr, code, n, wantRuns)
			}
		}
	}

	// ssh-keyscan that cannot be run is not retried.
	r := &fake.Runner{}
	r.Missing("ssh-keyscan")
	if _, err := Scan(ctx, r, "192.0.2.7", 22, false); err == nil || errors.Is(err, ErrNoAnswer) || r.Count("ssh-keyscan") != 1 {
		t.Errorf("missing: %v", err)
	}
}

// One type that cannot be run or whose scan errors does not end the series,
// and a cancelled context does.
func TestScanRetryEnds(t *testing.T) {
	ed := testKey(t, "ed25519")
	var runs int
	r := &fake.Runner{Strict: true}
	r.OnFunc([]string{"ssh-keyscan"}, func(c execx.Cmd) (execx.Result, error) {
		runs++
		typ := c.Args[slices.Index(c.Args, "-t")+1]
		switch typ {
		case "ed25519":
			return execx.Result{}, errors.New("exec: killed")
		case "rsa":
			return execx.Result{Stdout: []byte("192.0.2.7 " + ed.String() + "\n")}, nil
		}
		return execx.Result{Stderr: []byte(banner)}, nil
	})
	keys, err := Scan(context.Background(), r, "192.0.2.7", 22, false)
	if err != nil || len(keys) != 1 || runs != 4 {
		t.Errorf("%v %v runs %d", keys, err, runs)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runs = 0
	r = &fake.Runner{Strict: true}
	r.OnFunc([]string{"ssh-keyscan"}, func(execx.Cmd) (execx.Result, error) {
		runs++
		if runs == 2 {
			cancel()
		}
		return execx.Result{Stderr: []byte(banner)}, nil
	})
	if _, err = Scan(ctx, r, "192.0.2.7", 22, false); !errors.Is(err, context.Canceled) || runs != 2 {
		t.Errorf("cancelled: %v after %d runs", err, runs)
	}
}

// 'device hostkey rescan --all' keeps its parallelism (KeyscanParallel) with
// the retry, and an unreachable device costs one ssh-keyscan each, only a
// silent one the series.
func TestRescanKeysRetryStaysBounded(t *testing.T) {
	ed := testKey(t, "ed25519")
	var running, peak, total atomic.Int32
	r := &fake.Runner{Strict: true}
	r.OnFunc([]string{"ssh-keyscan"}, func(c execx.Cmd) (execx.Result, error) {
		n := running.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		total.Add(1)
		time.Sleep(2 * time.Millisecond)
		running.Add(-1)
		addr := c.Args[len(c.Args)-1]
		typ := c.Args[slices.Index(c.Args, "-t")+1]
		switch {
		case strings.HasPrefix(addr, "198.51.100."): // unreachable
			return execx.Result{Stderr: []byte(addr + ": Connection timed out\n")}, nil
		case typ == "ed25519" && strings.HasPrefix(addr, "192.0.2."): // answers one type
			return execx.Result{Stdout: []byte(addr + " " + ed.String() + "\n"), Stderr: []byte(banner)}, nil
		}
		return execx.Result{Stderr: []byte(banner)}, nil
	})
	var targets []KeyTarget
	for i := 1; i <= 20; i++ {
		targets = append(targets, KeyTarget{Name: "up" + string(rune('a'+i)), Address: "192.0.2." + string(rune('0'+i%10)), Port: 22})
		targets = append(targets, KeyTarget{Name: "down" + string(rune('a'+i)), Address: "198.51.100." + string(rune('0'+i%10)), Port: 22})
	}
	res := RescanKeys(context.Background(), r, targets, nil)
	up, down := 0, 0
	for _, x := range res {
		switch {
		case x.Err == nil && len(x.Keys) == 1:
			up++
		case errors.Is(x.Err, ErrNoAnswer):
			down++
		}
	}
	if up != 20 || down != 20 {
		t.Errorf("up %d, down %d", up, down)
	}
	// 20 reachable: combined + ed25519 + ecdsa + rsa; 20 unreachable: one.
	if got := total.Load(); got != 20*4+20 {
		t.Errorf("%d ssh-keyscan runs, want %d", got, 20*4+20)
	}
	if p := peak.Load(); p > KeyscanParallel {
		t.Errorf("%d at once, more than %d", p, KeyscanParallel)
	}
}
