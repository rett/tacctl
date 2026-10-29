package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'host sync' and 'host check' with --concurrency: the hosts run side by
// side, each host's output is held and printed in the order typed, the
// questions are not asked, and what the hosts write on this server (the
// records, the registry of devices, the UID ledger) is written one host at
// a time.

// hostGate lets the run step of each host through only when n hosts are in
// it at once, so a test that finishes proves the hosts overlapped; a run
// that does not overlap fails the step after a timeout.
type hostGate struct {
	mu      sync.Mutex
	n       int
	arrived int
	open    chan struct{}
	maxIn   int
	in      int
}

func newHostGate(n int) *hostGate { return &hostGate{n: n, open: make(chan struct{})} }

// pass is called by a host's step; it returns false when the gate did not
// open in time.
func (g *hostGate) pass() bool {
	g.mu.Lock()
	g.arrived++
	g.in++
	g.maxIn = max(g.maxIn, g.in)
	if g.arrived == g.n {
		close(g.open)
	}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.in--
		g.mu.Unlock()
	}()
	select {
	case <-g.open:
		return true
	case <-time.After(10 * time.Second):
		return false
	}
}

// concRunner is the runner of a concurrent run over hosts web1..web3: every
// host resolves to its own address, and its client script reports
// "Accounts: <n>" with n the number of its name (web2: 2), after the gate
// when there is one; the hosts in fails fail on the host. It never touches
// the sandbox's fields, which the sandbox's own ssh rule writes without a
// lock.
func (hs *hostSandbox) concRunner(gate *hostGate, delay map[string]time.Duration, fails ...string) *fake.Runner {
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool { return c.Name == "getent" && len(c.Args) == 2 && c.Args[0] == "ahostsv4" },
		func(c execx.Cmd) (execx.Result, error) {
			n := strings.TrimPrefix(strings.SplitN(c.Args[1], ".", 2)[0], "web")
			return execx.Result{Stdout: []byte("192.0.2.1" + n + " STREAM " + c.Args[1] + "\n")}, nil
		})
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" }, func(c execx.Cmd) (execx.Result, error) {
		j := strings.Join(c.Args, " ")
		host := ""
		for _, n := range []string{"web1", "web2", "web3", "web4"} {
			if strings.Contains(j, n+".example.net") {
				host = n
			}
		}
		switch {
		case strings.Contains(j, "mktemp"):
			return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
		case strings.Contains(j, "rm -f"):
			if gate != nil && !gate.pass() {
				return execx.Result{Code: 1}, errors.New("the hosts did not overlap")
			}
			time.Sleep(delay[host])
			for _, f := range fails {
				if f == host {
					return execx.Result{Code: 1}, nil
				}
			}
			return execx.Result{Stdout: []byte("[INFO] Accounts: " + strings.TrimPrefix(host, "web") + " managed by tacctl here.\n")}, nil
		}
		return execx.Result{}, nil
	})
	return r
}

// concHosts enrols web1..web3 in scope lab (the address 192.0.2.0/24).
func (hs *hostSandbox) concHosts() {
	hs.t.Helper()
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n"+
		"web2|admin@web2.example.net||lab|192.0.2.1|\n"+
		"web3|admin@web3.example.net||lab|192.0.2.1|\n", 0o600)
}

// runSteps are the ssh calls of r that ran the client script, in call order.
func runSteps(r *fake.Runner) []string {
	var out []string
	for _, a := range r.Argvs() {
		if strings.HasPrefix(a, "ssh ") && strings.Contains(a, "rm -f") {
			out = append(out, a)
		}
	}
	return out
}

// Three hosts at once: all run together, the lines come in the order typed
// whichever host ends first, each host's record and recorded address are
// there (no write of one host loses another's), and the hosts were reached
// without a terminal.
func TestHostSyncConcurrent(t *testing.T) {
	hs := newHostSandbox(t)
	hs.concHosts()
	hs.tty = func() bool { return true }
	gate := newHostGate(3)
	// web1 ends last, web3 first.
	r := hs.concRunner(gate, map[string]time.Duration{"web1": 150 * time.Millisecond, "web2": 60 * time.Millisecond})
	got := plain(hs.run(r, "host", "sync", "web1", "web2", "web3", "--concurrency", "3"))
	if hs.code != 0 {
		t.Fatalf("exit %d\n%s%s", hs.code, got, hs.err.String())
	}
	i1, i2, i3 := strings.Index(got, "web1: synced (1 user)."), strings.Index(got, "web2: synced (2 users)."), strings.Index(got, "web3: synced (3 users).")
	if i1 < 0 || i2 < i1 || i3 < i2 {
		t.Errorf("not in the order typed:\n%s", got)
	}
	if gate.maxIn != 3 {
		t.Errorf("%d hosts at once, want 3", gate.maxIn)
	}
	steps := runSteps(r)
	if len(steps) != 3 {
		t.Fatalf("%d runs: %q", len(steps), steps)
	}
	for _, s := range steps {
		if !strings.Contains(s, "BatchMode=yes") || strings.Contains(s, " -t ") {
			t.Errorf("a host was reached with a terminal: %s", s)
		}
	}
	dev := hs.devices()
	for _, n := range []string{"web1", "web2", "web3"} {
		if _, err := os.Stat(hs.path("state", "hosts", n+".json")); err != nil {
			t.Errorf("no record of %s: %v", n, err)
		}
		if rec := hs.read("state/hosts/" + n + ".json"); !strings.Contains(rec, `"ok": true`) {
			t.Errorf("record of %s:\n%s", n, rec)
		}
	}
	for _, a := range []string{"192.0.2.11", "192.0.2.12", "192.0.2.13"} {
		if !strings.Contains(dev, a) {
			t.Errorf("address %s is not recorded (a lost update?):\n%s", a, dev)
		}
	}
	// The sequential run of the same hosts prints the same lines.
	hs2 := newHostSandbox(t)
	hs2.concHosts()
	want := plain(hs2.run(hs2.concRunner(nil, nil), "host", "sync", "web1", "web2", "web3"))
	if got != want {
		t.Errorf("--concurrency 3:\n%s\nsequential:\n%s", got, want)
	}
}

// One host that fails does not stop the others; its lines are in its place
// and the exit status is 1.
func TestHostSyncConcurrentOneFails(t *testing.T) {
	hs := newHostSandbox(t)
	hs.concHosts()
	r := hs.concRunner(newHostGate(3), nil, "web2")
	got := plain(hs.run(r, "host", "sync", "web1", "web2", "web3", "--concurrency", "3"))
	errText := plain(hs.err.String())
	if hs.code != 1 {
		t.Errorf("exit %d\n%s%s", hs.code, got, errText)
	}
	if !strings.Contains(got, "web1: synced") || !strings.Contains(got, "web3: synced") || strings.Contains(got, "web2: synced") {
		t.Errorf("stdout:\n%s", got)
	}
	if !strings.Contains(errText, "web2: sync failed") || strings.Contains(errText, "web1: sync failed") {
		t.Errorf("stderr:\n%s", errText)
	}
	if len(runSteps(r)) != 3 {
		t.Errorf("runs: %q", runSteps(r))
	}
	if rec := hs.read("state/hosts/web2.json"); !strings.Contains(rec, `"ok": false`) {
		t.Errorf("record of web2:\n%s", rec)
	}
	if rec := hs.read("state/hosts/web3.json"); !strings.Contains(rec, `"ok": true`) {
		t.Errorf("record of web3:\n%s", rec)
	}
}

// With several hosts at once the home-removal questions are not asked: the
// host is told of the removal and its homes are kept, with the way to delete
// them. --remove-home deletes them; one at a time nothing changes.
func TestHostSyncConcurrentAsksNothing(t *testing.T) {
	hs := newHostSandbox(t)
	hs.concHosts()
	hs.write("state/linux-uids", "# range 80000-89999\nzed:80050\n", 0o600)
	hs.tty = func() bool { return true }
	hs.stdin = "y\ny\ny\n"
	passwd := "zed:x:80050:80000:zed (TACACS+):/home/zed:/bin/bash\n"
	runner := func() *fake.Runner {
		r := hs.concRunner(nil, nil)
		r.Func(func(c execx.Cmd) bool {
			return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "getent passwd")
		},
			func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(passwd)}, nil })
		return r
	}
	// removeHomes is the TAC_REMOVE_HOMES line of each script pushed.
	removeHomes := func(r *fake.Runner) []string {
		var out []string
		for _, rec := range r.Records() {
			if strings.Contains(strings.Join(rec.Cmd.Args, " "), "mktemp") {
				for _, l := range strings.Split(string(rec.Stdin), "\n") {
					if strings.HasPrefix(l, "TAC_REMOVE_HOMES=") {
						out = append(out, l)
					}
				}
			}
		}
		return out
	}

	r := runner()
	got := plain(hs.run(r, "host", "sync", "web1", "web2", "--concurrency", "2"))
	if hs.code != 0 {
		t.Fatalf("exit %d\n%s%s", hs.code, got, hs.err.String())
	}
	for _, n := range []string{"web1", "web2"} {
		for _, w := range []string{
			n + ": removed users with an account there (deleted by this run): zed",
			n + ": the home directories of removed users are kept, as no questions are asked with --concurrency above 1: " +
				"add --remove-home to delete them, or sync " + n + " alone to be asked.",
		} {
			if !strings.Contains(got, w) {
				t.Errorf("no %q in:\n%s", w, got)
			}
		}
	}
	if strings.Contains(got, "Delete /home/zed") {
		t.Errorf("a question was asked:\n%s", got)
	}
	if h := removeHomes(r); len(h) != 2 || h[0] != "TAC_REMOVE_HOMES=''" || h[1] != "TAC_REMOVE_HOMES=''" {
		t.Errorf("a home is to be deleted: %q", h)
	}

	// --remove-home needs no answer and is not refused.
	r = runner()
	got = plain(hs.run(r, "host", "sync", "web1", "web2", "--concurrency", "2", "--remove-home"))
	if hs.code != 0 || strings.Contains(got, "no questions are asked") || strings.Contains(got, "Delete /home/zed") {
		t.Errorf("--remove-home: exit %d\n%s", hs.code, got)
	}
	if h := removeHomes(r); len(h) != 2 || h[0] != "TAC_REMOVE_HOMES=\\*" {
		t.Errorf("--remove-home: %q", h)
	}

	// One at a time, as before: the host's accounts are not even read when
	// there is no terminal, and nothing is said of questions.
	r = runner()
	got = plain(hs.run(r, "host", "sync", "web1", "web2", "--concurrency", "1"))
	if hs.code != 0 || strings.Contains(got, "no questions are asked") || strings.Contains(got, "removed users with an account") || r.ArgvContains("getent passwd") {
		t.Errorf("--concurrency 1: exit %d\n%s", hs.code, got)
	}
}

// --concurrency takes a whole number of hosts, 1 or more, and no host is
// reached when it is wrong.
func TestHostSyncConcurrencyArgument(t *testing.T) {
	hs := newHostSandbox(t)
	hs.concHosts()
	for _, v := range []string{"0", "-1", "two", "", "1.5"} {
		r := hs.concRunner(nil, nil)
		hs.run(r, "host", "sync", "web1", "--concurrency", v)
		hs.expect(1, "", fmt.Sprintf("--concurrency takes a number of hosts, 1 or more: '%s'", v))
		if n := r.Count("ssh"); n != 0 {
			t.Errorf("%q: %d ssh calls", v, n)
		}
	}
	hs.run(nil, "host", "sync", "web1", "--concurrency")
	hs.expect(1, "", "Usage: tacctl host sync <name>... | --all  [--allow-uid-mismatch] [--remove-home] [--concurrency <n>]")
	// The = form, and a pool wider than the hosts.
	r := hs.concRunner(nil, nil)
	hs.run(r, "host", "sync", "web1", "web2", "--concurrency=50")
	hs.expect(0, "web2: synced", "")
	if len(runSteps(r)) != 2 {
		t.Errorf("runs: %q", runSteps(r))
	}
}

// A ledger entry for a new user is made once however many hosts run at once:
// the hosts get the same number.
func TestHostSyncConcurrentSameUIDs(t *testing.T) {
	hs := newHostSandbox(t)
	hs.concHosts()
	r := hs.concRunner(newHostGate(3), nil)
	hs.run(r, "host", "sync", "--all", "--concurrency", "3")
	if hs.code != 0 {
		t.Fatalf("exit %d\n%s%s", hs.code, hs.out.String(), hs.err.String())
	}
	ledger := hs.read("state/linux-uids")
	for _, u := range []string{"alice", "bob", "carol"} {
		if n := strings.Count(ledger, "\n"+u+":"); n != 1 {
			t.Errorf("%s has %d entries in the ledger:\n%s", u, n, ledger)
		}
	}
	var uids []string
	for _, rec := range r.Records() {
		if strings.Contains(strings.Join(rec.Cmd.Args, " "), "mktemp") {
			uids = append(uids, scriptUsersLine(string(rec.Stdin)))
		}
	}
	if len(uids) != 3 || uids[0] != uids[1] || uids[1] != uids[2] || uids[0] == "" {
		t.Errorf("the scripts carry different users:\n%q", uids)
	}
}

// scriptUsersLine is the TAC_USERS block of a client script.
func scriptUsersLine(script string) string {
	_, rest, ok := strings.Cut(script, "TAC_USERS=")
	if !ok {
		return ""
	}
	line, _, _ := strings.Cut(rest, "\n")
	return line
}

// runStepRule is the match of the ssh call that runs the client script.
func runStepRule(c execx.Cmd) bool {
	return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "rm -f")
}

// signalledByCancel makes r run its calls in the background and answers the
// call for which match is true as a program that waits to be signalled: it
// holds until n signals have reached programs (the hosts are in it together
// first), cancels the run once with cancel, and then ends with status 255 as
// ssh does when it is killed. A run that does not signal them fails the call
// after a timeout.
func signalledByCancel(r *fake.Runner, match func(execx.Cmd) bool, n int, cancel func()) {
	gate := newHostGate(n)
	var once sync.Once
	r.Async = true
	r.Func(match, func(execx.Cmd) (execx.Result, error) {
		if !gate.pass() {
			return execx.Result{Code: 1}, errors.New("the hosts did not overlap")
		}
		once.Do(cancel)
		deadline := time.Now().Add(10 * time.Second)
		for len(r.Signals()) < n {
			if time.Now().After(deadline) {
				return execx.Result{Code: 1}, errors.New("the hosts were not signalled")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return execx.Result{Code: 255}, nil
	})
}

// A SIGINT (the context of the command is cancelled) ends the whole run as it
// ends a run one host after the other: the hosts under way are signalled and
// reported (record, audit) as interrupted, not as script failures, the
// others are named as not started, the status is 130, and nothing else
// (a cancelled context in a step) replaces it.
func TestHostSyncConcurrentInterrupt(t *testing.T) {
	hs := newHostSandbox(t)
	hs.concHosts()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hs.ctx = ctx
	r := hs.concRunner(nil, nil)
	signalledByCancel(r, runStepRule, 2, cancel)
	got := plain(hs.run(r, "host", "sync", "web1", "web2", "web3", "--concurrency", "2"))
	errText := plain(hs.err.String())
	if hs.code != 130 {
		t.Errorf("exit %d\n%s%s", hs.code, got, errText)
	}
	if !strings.Contains(got, "web3: not started (interrupted).") || strings.Contains(got+errText, "synced") ||
		strings.Contains(got+errText, "client script failed") || strings.Contains(got+errText, "sync failed") || strings.Contains(got+errText, "canceled") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", got, errText)
	}
	if n := len(runSteps(r)); n != 2 {
		t.Errorf("runs: %q", runSteps(r))
	}
	for _, n := range []string{"web1", "web2"} {
		rec := hs.read("state/hosts/" + n + ".json")
		if !strings.Contains(rec, `"ok": false`) || !strings.Contains(rec, `"reason": "interrupted"`) {
			t.Errorf("record of %s:\n%s", n, rec)
		}
	}
	if _, err := os.Stat(hs.path("state", "hosts", "web3.json")); err == nil {
		t.Error("a host that was not started has a record")
	}
}

// A panic in the job of one host fails that host, with the text, and no other:
// the others are synced and printed, and the command ends normally.
func TestHostSyncConcurrentPanic(t *testing.T) {
	hs := newHostSandbox(t)
	hs.concHosts()
	r := hs.concRunner(nil, nil)
	r.Func(func(c execx.Cmd) bool {
		return runStepRule(c) && strings.Contains(strings.Join(c.Args, " "), "web2.example.net")
	},
		func(execx.Cmd) (execx.Result, error) { panic("boom") })
	got := plain(hs.run(r, "host", "sync", "web1", "web2", "web3", "--concurrency", "3"))
	errText := plain(hs.err.String())
	if hs.code != 1 || !strings.Contains(got, "web1: synced") || !strings.Contains(got, "web3: synced") ||
		!strings.Contains(errText, "web2: stopped by an internal error: boom") {
		t.Errorf("exit %d\n%s%s", hs.code, got, errText)
	}
}

// Two registrations of one ssh target share ssh's connection socket, so they
// run one after the other; a host of another target runs beside them.
func TestHostSyncConcurrentSameTarget(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n"+
		"web2|admin@web1.example.net||lab|192.0.2.1|\n"+
		"web3|admin@web3.example.net||lab|192.0.2.1|\n", 0o600)
	r := hs.concRunner(nil, nil)
	var mu sync.Mutex
	in := map[string]int{}
	maxIn := map[string]int{}
	all, maxAll := 0, 0
	r.Func(runStepRule, func(c execx.Cmd) (execx.Result, error) {
		target := "web3"
		if strings.Contains(strings.Join(c.Args, " "), "web1.example.net") {
			target = "web1"
		}
		mu.Lock()
		in[target]++
		all++
		maxIn[target] = max(maxIn[target], in[target])
		maxAll = max(maxAll, all)
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		mu.Lock()
		in[target]--
		all--
		mu.Unlock()
		return execx.Result{Stdout: []byte("[INFO] Accounts: 1 managed by tacctl here.\n")}, nil
	})
	got := plain(hs.run(r, "host", "sync", "web1", "web2", "web3", "--concurrency", "3"))
	if hs.code != 0 || strings.Count(got, ": synced") != 3 {
		t.Fatalf("exit %d\n%s%s", hs.code, got, hs.err.String())
	}
	if maxIn["web1"] != 1 {
		t.Errorf("two hosts of one target ran at once")
	}
	if maxAll < 2 {
		t.Errorf("the other target did not run beside them")
	}
}
