package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// 'host check <name>... | --all [--json]' (0.2.15 plan D216-D218).

// checkGood is what a host that is as tacctl would make it prints (accounts
// alice, bob and carol of the multiscope store; no UID in the ledger yet).
func checkGood(key devreg.HostKey) string {
	return "tacctl-check group tac-users 80000\ntacctl-check group tac-superuser 80002\ntacctl-check group tac-engineer 80005\n" +
		"tacctl-check account alice 80000 80000 700 /home/alice\ntacctl-check account bob 80001 80000 700 /home/bob\n" +
		"tacctl-check account carol 80002 80000 700 /home/carol\n" +
		"tacctl-check pam tacctl-auth aaa\ntacctl-check pam tacctl-account bbb\ntacctl-check pam tacctl-session ccc\n" +
		"tacctl-check pam-written tacctl-auth aaa\ntacctl-check pam-written tacctl-account bbb\ntacctl-check pam-written tacctl-session ccc\n" +
		"tacctl-check protocol " + hosts.ScriptProtocol + "\ntacctl-check key " + key.String() + " root@web\n"
}

// checkLab registers the hosts of lines and pins key for each remote one,
// with the address recorded for it (the address a hold on it carves out).
func (hs *hostSandbox) checkLab(key devreg.HostKey, lines string, addrs map[string]string) {
	hs.t.Helper()
	hs.write("state/linux-hosts", lines, 0o600)
	f, err := devreg.Load(hs.path("state", "devices.yaml"))
	if err != nil {
		hs.t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(lines), "\n") {
		name, rest, _ := strings.Cut(l, "|")
		if strings.HasPrefix(rest, "local|") {
			continue
		}
		f.SetHostKeys(name, []string{key.String()})
		if a := addrs[name]; a != "" {
			f.SetHostAddress(name, a, "2026-10-04 12:00")
		}
	}
	text, err := f.Text()
	if err != nil {
		hs.t.Fatal(err)
	}
	hs.write("state/devices.yaml", string(text), 0o600)
}

// checkRunner answers the read-only run of each host with out[host name
// (as it appears in the ssh target)]; a host not in out fails the run.
func (hs *hostSandbox) checkRunner(out map[string]string) *fake.Runner {
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "tacctl-check")
	}, func(c execx.Cmd) (execx.Result, error) {
		j := strings.Join(c.Args, " ")
		for host, text := range out {
			if strings.Contains(j, "@"+host+".example.net") {
				return execx.Result{Stdout: []byte(text)}, nil
			}
		}
		return execx.Result{Code: 1}, nil
	})
	return r
}

// checkCalls are the ssh calls of r that ran a read-only check.
func checkCalls(r *fake.Runner) []string {
	var out []string
	for _, a := range r.Argvs() {
		if strings.HasPrefix(a, "ssh ") && strings.Contains(a, "tacctl-check") {
			out = append(out, a)
		}
	}
	return out
}

// Every state in one run: as tacctl would make it, differences, a host that
// could not be checked and a held host (skipped, not a failure of its own);
// the report, the summary and exit 1. Nothing is written here.
func TestHostCheckAllStates(t *testing.T) {
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
	out := map[string]string{"web1": "Welcome to web1\n" + checkGood(ed), "web2": bad}
	before := hs.read("state/linux-hosts") + hs.devices()
	r := hs.checkRunner(out)
	got := plain(hs.run(r, "host", "check", "web1", "web2", "web3", "web4"))
	if hs.code != 1 {
		t.Errorf("exit %d, want 1\n%s%s", hs.code, got, hs.err.String())
	}
	want := "web1: as tacctl would make it.\n" +
		"web2: 2 differences:\n" +
		"  - alice has no account. Fix: tacctl host sync web2\n" +
		"  - /etc/pam.d/tacctl-auth is not the text tacctl wrote there. Fix: tacctl host enroll admin@web2.example.net --name web2\n"
	if !strings.HasPrefix(got, want) {
		t.Errorf("report:\n%s\nwant it to start with:\n%s", got, want)
	}
	for _, w := range []string{
		"web3: skipped: break-glass is held on it since ", ": locked out of sudo (tacctl breakglass release web3)\n",
		"web4: could not be checked: the read-only run as root on admin@web4.example.net failed (see above); nothing was compared.\n",
		"4 hosts: 1 as tacctl would make it, 1 with differences, 1 not checked, 1 skipped (held).\n",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("report lacks %q:\n%s", w, got)
		}
	}
	// The banner of a host goes to standard error, not into the report.
	if strings.Contains(got, "Welcome to web1") || !strings.Contains(hs.err.String(), "Welcome to web1") ||
		!strings.Contains(hs.err.String(), "Checking web1 at admin@web1.example.net (read-only)...") {
		t.Errorf("stdout %q\nstderr %q", got, hs.err.String())
	}
	if calls := checkCalls(r); len(calls) != 3 || strings.Contains(strings.Join(r.Argvs(), "\n"), "web3.example.net") {
		t.Errorf("checks %q, argvs %q", calls, r.Argvs())
	}
	if after := hs.read("state/linux-hosts") + hs.devices(); after != before {
		t.Error("the check changed the registry")
	}
	if _, err := os.Stat(hs.path("state", "hosts", "web1.json")); err == nil {
		t.Error("the check wrote a record")
	}
}

// All hosts as they should be: exit 0, the summary only with several hosts.
func TestHostCheckAllOK(t *testing.T) {
	hs := newHostSandbox(t)
	ed := hkKey(t, "ed25519")
	hs.checkLab(ed, "web1|admin@web1.example.net||lab|192.0.2.1|\nweb2|admin@web2.example.net||lab|192.0.2.1|\n", nil)
	good := checkGood(ed)
	// An older host has no record of the PAM text: a note, not a difference.
	old := strings.NewReplacer("tacctl-check pam-written tacctl-auth aaa\n", "", "tacctl-check pam-written tacctl-account bbb\n", "",
		"tacctl-check pam-written tacctl-session ccc\n", "").Replace(good)
	r := hs.checkRunner(map[string]string{"web1": good, "web2": old})
	got := plain(hs.run(r, "host", "check", "--all"))
	if hs.code != 0 || !strings.HasPrefix(got, "web1: as tacctl would make it.\nweb2: as tacctl would make it.\n  The PAM files are there; the host has no record of the text tacctl wrote") ||
		!strings.HasSuffix(got, "2 hosts: 2 as tacctl would make it.\n") {
		t.Errorf("--all: %d\n%s%s", hs.code, got, hs.err.String())
	}
	// One name: its line alone; a name given twice is checked once.
	r = hs.checkRunner(map[string]string{"web1": good})
	got = plain(hs.run(r, "host", "check", "web1", "web1"))
	if hs.code != 0 || got != "web1: as tacctl would make it.\n" || len(checkCalls(r)) != 1 {
		t.Errorf("one name: %d %q (%d checks)", hs.code, got, len(checkCalls(r)))
	}
}

// --json: an array on standard output and nothing else there, one object
// per host in the order given, the exit status of the text report.
func TestHostCheckAllJSON(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	ed := hkKey(t, "ed25519")
	hs.checkLab(ed, "web1|admin@web1.example.net||lab|192.0.2.1|\n"+
		"web2|admin@web2.example.net||lab|192.0.2.1|\n"+
		"web3|admin@web3.example.net||lab|192.0.2.1|\n"+
		"web4|admin@web4.example.net||lab|192.0.2.1|\n",
		map[string]string{"web3": "192.0.2.33"})
	holdHost(t, hs.sandbox, "web3", "locked out of sudo")
	bad := strings.Replace(checkGood(ed), "tacctl-check account bob 80001 80000 700 /home/bob\n", "", 1)
	js := hs.run(hs.checkRunner(map[string]string{"web1": "Welcome to web1\n" + checkGood(ed), "web2": bad}), "host", "check", "--all", "--json")
	if hs.code != 1 {
		t.Errorf("exit %d", hs.code)
	}
	var v []struct {
		Name, Target, State, Error string
		Differences                []struct{ Text, Fix string }
		Notes                      []string
		Breakglass                 *struct {
			Held   bool
			Reason string
		}
	}
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatalf("stdout is not the array alone: %v\n%s", err, js)
	}
	if len(v) != 4 {
		t.Fatalf("%d hosts:\n%s", len(v), js)
	}
	for i, w := range []struct{ name, state string }{{"web1", "ok"}, {"web2", "differences"}, {"web3", "held"}, {"web4", "failed"}} {
		if v[i].Name != w.name || v[i].State != w.state || v[i].Target != "admin@"+w.name+".example.net" {
			t.Errorf("host %d: %+v, want %s %s", i, v[i], w.name, w.state)
		}
	}
	if d := v[1].Differences; len(d) != 1 || d[0].Text != "bob has no account" || d[0].Fix != "tacctl host sync web2" {
		t.Errorf("differences %+v", d)
	}
	if b := v[2].Breakglass; b == nil || !b.Held || b.Reason != "locked out of sudo" || v[0].Breakglass != nil {
		t.Errorf("breakglass %+v", v[2].Breakglass)
	}
	if !strings.Contains(v[3].Error, "the read-only run as root on admin@web4.example.net failed") || v[0].Error != "" || len(v[0].Differences) != 0 {
		t.Errorf("error %q", v[3].Error)
	}
	// The arrays are never null.
	for _, k := range []string{`"differences": null`, `"notes": null`} {
		if strings.Contains(js, k) {
			t.Errorf("json has %s:\n%s", k, js)
		}
	}
	if !strings.Contains(hs.err.String(), "Welcome to web1") {
		t.Errorf("stderr %q", hs.err.String())
	}

	// No host: an empty array (text: the usual line).
	hs.write("state/linux-hosts", "", 0o600)
	if js := hs.run(nil, "host", "check", "--all", "--json"); hs.code != 0 || strings.TrimSpace(js) != "[]" {
		t.Errorf("no host: %d %q", hs.code, js)
	}
	hs.run(nil, "host", "check", "--all")
	hs.expect(0, "No hosts enrolled.", "")
}

// This server's own host is checked without ssh.
func TestHostCheckAllLocal(t *testing.T) {
	hs := newHostSandbox(t)
	ed := hkKey(t, "ed25519")
	hs.checkLab(ed, "authsrv|local||lab|127.0.0.1|\n", nil)
	local := strings.Join([]string{
		"tacctl-check group tac-users 80000", "tacctl-check group tac-console 80001", "tacctl-check group tac-superuser 80002",
		"tacctl-check group tac-operator 80003", "tacctl-check group tac-readonly 80004", "tacctl-check group tac-engineer 80005",
		"tacctl-check account alice 80000 80000 700 /home/alice", "tacctl-check account bob 80001 80000 700 /home/bob",
		"tacctl-check account carol 80002 80000 700 /home/carol",
		"tacctl-check pam tacctl-auth aaa", "tacctl-check pam tacctl-account bbb", "tacctl-check pam tacctl-session ccc",
		"tacctl-check pam-written tacctl-auth aaa", "tacctl-check pam-written tacctl-account bbb", "tacctl-check pam-written tacctl-session ccc",
		"tacctl-check protocol " + hosts.ScriptProtocol, ""}, "\n")
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "bash" && len(c.Args) == 2 && strings.Contains(c.Args[1], "tacctl-check")
	},
		func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(local)}, nil })
	got := plain(hs.run(r, "host", "check", "authsrv"))
	if hs.code != 0 || got != "authsrv: as tacctl would make it.\n" {
		t.Errorf("local: %d %q %q", hs.code, got, hs.err.String())
	}
	if n := r.Count("ssh") + r.Count("ssh-keyscan"); n != 0 || !r.Called("bash") {
		t.Errorf("ssh calls %d, bash called %v: %q", n, r.Called("bash"), r.Argvs())
	}
}

// Names are checked first; names and --all do not go together; a host that
// is not enrolled, or an option that is not one, is a usage error with no
// ssh call.
func TestHostCheckAllUsage(t *testing.T) {
	hs := newHostSandbox(t)
	ed := hkKey(t, "ed25519")
	hs.checkLab(ed, "web1|admin@web1.example.net||lab|192.0.2.1|\n", nil)
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"web1", "ghost"}, "No enrolled host named 'ghost'. See 'tacctl host list'."},
		{[]string{"ghost", "web1"}, "No enrolled host named 'ghost'. See 'tacctl host list'."},
		{[]string{"web1", "--all"}, "Give names or --all, not both."},
		{[]string{"--all", "web1"}, "Give names or --all, not both."},
		{[]string{}, "Usage: tacctl host check <name>... | --all [--json]"},
		{[]string{"--json"}, "Usage: tacctl host check <name>... | --all [--json]"},
		{[]string{"web1", "--bogus"}, "Unknown option: '--bogus'"},
	} {
		r := hs.checkRunner(map[string]string{"web1": checkGood(ed)})
		hs.run(r, append([]string{"host", "check"}, c.args...)...)
		hs.expect(1, "", c.err)
		if n := r.Count("ssh") + r.Count("ssh-keyscan"); n != 0 {
			t.Errorf("%v: %d ssh calls: %q", c.args, n, r.Argvs())
		}
	}
}

// 'host check' logs in to each host as the invoker: the engineer tier has no
// row for it, so the gate refuses it before the verb runs.
func TestHostCheckAllEngineerRefused(t *testing.T) {
	sb := engineerSandbox(t)
	for _, args := range [][]string{{"host", "check", "web1"}, {"host", "check", "--all"}, {"host", "check", "--all", "--json"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
		if n := sb.sshCalls(); n != 0 || sb.out.String() != "" {
			t.Errorf("%v: %d ssh calls, printed %q", args, n, sb.out.String())
		}
	}
}
