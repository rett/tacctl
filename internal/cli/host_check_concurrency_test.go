package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// sinceRe is the time a hold was made, which differs between two sandboxes.
var sinceRe = regexp.MustCompile(`"since": "[^"]*"|since [0-9][^ ]* [0-9:]+`)

// checkLabFour is the lab of TestHostCheckAllStates: web1 as it should be,
// web2 with two differences, web3 held, web4 not reachable.
func checkLabFour(t *testing.T) (*hostSandbox, map[string]string) {
	t.Helper()
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	ed := hkKey(t, "ed25519")
	hs.checkLab(ed, "web1|admin@web1.example.net||lab|192.0.2.1|\n"+
		"web2|admin@web2.example.net||lab|192.0.2.1|\n"+
		"web3|admin@web3.example.net||lab|192.0.2.1|\n"+
		"web4|admin@web4.example.net||lab|192.0.2.1|\n",
		map[string]string{"web3": "192.0.2.33"})
	holdHost(t, hs.sandbox, "web3", "locked out of sudo")
	bad := strings.Replace(strings.Replace(checkGood(ed), "tacctl-check account alice 80000 80000 700 /home/alice\n", "", 1),
		"tacctl-check pam tacctl-auth aaa\n", "tacctl-check pam tacctl-auth zzz\n", 1)
	return hs, map[string]string{"web1": "Welcome to web1\n" + checkGood(ed), "web2": bad}
}

// gatedCheckRunner is checkRunner whose read-only runs pass a gate, with the
// first host slowest.
func (hs *hostSandbox) gatedCheckRunner(out map[string]string, gate *hostGate) *fake.Runner {
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "tacctl-check")
	}, func(c execx.Cmd) (execx.Result, error) {
		if !gate.pass() {
			return execx.Result{Code: 1}, errors.New("the hosts did not overlap")
		}
		j := strings.Join(c.Args, " ")
		if strings.Contains(j, "@web1.example.net") {
			time.Sleep(150 * time.Millisecond)
		}
		for host, text := range out {
			if strings.Contains(j, "@"+host+".example.net") {
				return execx.Result{Stdout: []byte(text)}, nil
			}
		}
		return execx.Result{Code: 1}, nil
	})
	return r
}

// 'host check --concurrency': the hosts are read side by side, the report,
// the lines on standard error, the summary and the status are those of a
// sequential run (hosts in the order typed, a held host in its place), and
// the hosts are reached without a terminal.
func TestHostCheckConcurrent(t *testing.T) {
	for _, js := range []bool{false, true} {
		args := []string{"host", "check", "web1", "web2", "web3", "web4"}
		if js {
			args = append(args, "--json")
		}
		seq, out := checkLabFour(t)
		wantOut := sinceRe.ReplaceAllString(plain(seq.run(seq.checkRunner(out), args...)), "since T")
		wantErr, wantCode := plain(seq.err.String()), seq.code

		hs, out := checkLabFour(t)
		hs.tty = func() bool { return true }
		gate := newHostGate(3)
		r := hs.gatedCheckRunner(out, gate)
		got := sinceRe.ReplaceAllString(plain(hs.run(r, append(args, "--concurrency", "4")...)), "since T")
		if hs.code != wantCode || hs.code != 1 {
			t.Errorf("json=%v: exit %d, sequential %d\n%s%s", js, hs.code, wantCode, got, hs.err.String())
		}
		if got != wantOut {
			t.Errorf("json=%v: stdout\n%s\nsequential\n%s", js, got, wantOut)
		}
		if e := plain(hs.err.String()); e != wantErr {
			t.Errorf("json=%v: stderr\n%s\nsequential\n%s", js, e, wantErr)
		}
		if gate.maxIn != 3 {
			t.Errorf("json=%v: %d hosts at once, want 3", js, gate.maxIn)
		}
		calls := checkCalls(r)
		if len(calls) != 3 {
			t.Fatalf("json=%v: checks %q", js, calls)
		}
		for _, c := range calls {
			if !strings.Contains(c, "BatchMode=yes") || strings.Contains(c, " -t ") {
				t.Errorf("json=%v: a host was reached with a terminal: %s", js, c)
			}
		}
	}
}

// --concurrency takes a whole number of hosts, 1 or more, and no host is
// reached when it is wrong; a pool wider than the hosts is fine.
func TestHostCheckConcurrencyArgument(t *testing.T) {
	hs, out := checkLabFour(t)
	for _, v := range []string{"0", "-3", "many", ""} {
		r := hs.checkRunner(out)
		hs.run(r, "host", "check", "web1", "--concurrency", v)
		hs.expect(1, "", fmt.Sprintf("--concurrency takes a number of hosts, 1 or more: '%s'", v))
		if n := len(checkCalls(r)); n != 0 {
			t.Errorf("%q: %d checks", v, n)
		}
	}
	hs.run(nil, "host", "check", "web1", "--concurrency")
	hs.expect(1, "", "Usage: tacctl host check <name>... | --all [--json] [--concurrency <n>]")
	r := hs.checkRunner(out)
	got := plain(hs.run(r, "host", "check", "web1", "web2", "--concurrency=50"))
	if hs.code != 1 || !strings.Contains(got, "web1: as tacctl would make it.") || !strings.Contains(got, "web2: 2 differences:") || len(checkCalls(r)) != 2 {
		t.Errorf("exit %d\n%s", hs.code, got)
	}
}
