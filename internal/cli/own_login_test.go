package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/lifecycle"
)

// ownLogin runs the setup of this machine's own login that install and
// upgrade make (lifecycle.Host.OwnLogin) on r (a scripted runner when nil),
// in the invocation of 'tacctl install'.
func (hs *hostSandbox) ownLogin(r *fake.Runner, o lifecycle.OwnLoginOptions) *fake.Runner {
	hs.t.Helper()
	if r == nil {
		r = hs.runner()
	}
	args := []string{"upgrade"}
	if o.Install {
		args = []string{"install"}
	}
	a := hs.newApp(r, args)
	ctx := context.Background()
	a.SetContext(ctx)
	inv := &invocation{ctx: ctx, app: a, build: BuildInfo{Version: "0.2.0-test"}, hooks: hs.hooks}
	inv.root = newRoot(inv)
	hs.code = exitCode(inv.dispatch(func() error {
		if err := inv.prelude(noPreflight); err != nil {
			return err
		}
		inv.ownLogin(ctx, o)
		return nil
	}), a.Out)
	return r
}

// pam puts the PAM files the client script writes where the sandbox looks.
func (hs *hostSandbox) pam(present bool) {
	hs.t.Helper()
	dir := hs.path("pam.d")
	_ = os.RemoveAll(dir)
	if !present {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		hs.t.Fatal(err)
	}
	for _, f := range hosts.PAMFiles {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("# written\n"), 0o644); err != nil {
			hs.t.Fatal(err)
		}
	}
}

// scriptRan reports whether the client script ran on this machine.
func scriptRan(r *fake.Runner) bool { return r.Called("bash") }

const ownLoginCmd = "tacctl host enroll --local"

// out is everything the run printed, without colour.
func (hs *hostSandbox) out2() string { return plain(hs.out.String() + hs.err.String()) }

// A fresh install with --yes sets this machine's own login up with the
// machinery of 'host enroll --local': the managed scope, the registry entry,
// the recorded address and the client script, after a snapshot; the detected
// address is said.
func TestOwnLoginFreshInstall(t *testing.T) {
	hs := newHostSandbox(t)
	snaps := hs.snapshots()
	r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true, Yes: true})
	out := hs.out2()
	if hs.code != 0 || !scriptRan(r) {
		t.Fatalf("exit %d, ran %v\n%s", hs.code, scriptRan(r), out)
	}
	for _, want := range []string{"Using 192.0.2.10 as the server address (the address of eth0); pass --server to use another.", "enrolled"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "was not set up") || strings.Contains(out, "[y/N]") {
		t.Errorf("a skip line or a question:\n%s", out)
	}
	if !strings.Contains(hs.registry(), "|local||tacctl|192.0.2.10|\n") || !strings.Contains(hs.read("state/tacctl.yaml"), "- 192.0.2.10\n") {
		t.Errorf("registry %q\n%s", hs.registry(), hs.read("state/tacctl.yaml"))
	}
	if !strings.Contains(hs.store(), "tacctl:\n    prefixes: [127.0.0.1/32, 192.0.2.10/32]") {
		t.Errorf("store:\n%s", hs.store())
	}
	if hs.snapshots() <= snaps {
		t.Error("no snapshot was taken before the change")
	}
}

// --server is the address given to install, and wins over the detection,
// which is then not asked.
func TestOwnLoginInstallServerFlag(t *testing.T) {
	hs := newHostSandbox(t)
	hs.serverAddress = func() (string, string, error) { return "", "", os.ErrInvalid }
	hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true, Yes: true, Server: "203.0.113.9"})
	if hs.code != 0 || strings.Contains(hs.out2(), "Using ") || !strings.Contains(hs.registry(), "|local||tacctl|203.0.113.9|\n") {
		t.Errorf("exit %d registry %q\n%s", hs.code, hs.registry(), hs.out2())
	}
	if !strings.Contains(hs.read("state/tacctl.yaml"), "- 203.0.113.9\n") {
		t.Errorf("tacctl.yaml:\n%s", hs.read("state/tacctl.yaml"))
	}
}

// An install without --yes asks once, with the address in the question, and
// reads the answer from standard input as its other prompts do; anything
// but y leaves the server as it was and says the command in one line.
func TestOwnLoginInstallAsks(t *testing.T) {
	for _, c := range []struct {
		name, stdin string
		done        bool
	}{{"yes", "y\n", true}, {"no", "n\n", false}, {"closed stdin", "", false}} {
		t.Run(c.name, func(t *testing.T) {
			hs := newHostSandbox(t)
			hs.stdin = c.stdin
			hs.tty = func() bool { return true }
			r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true})
			out := hs.out2()
			if hs.code != 0 || scriptRan(r) != c.done || (hs.registry() != "") != c.done {
				t.Fatalf("exit %d, ran %v, registry %q\n%s", hs.code, scriptRan(r), hs.registry(), out)
			}
			if !c.done && !strings.Contains(out, "This machine's own login was not set up (not asked for); to set it up: "+ownLoginCmd+"\n") {
				t.Errorf("no skip line:\n%s", out)
			}
			if c.done && strings.Contains(out, "was not set up") {
				t.Errorf("skip line:\n%s", out)
			}
			if strings.Count(out, "Set up this machine's own login now, with 192.0.2.10 as the server address? [y/N]") > 1 {
				t.Errorf("asked twice:\n%s", out)
			}
		})
	}
}

// An upgrade of a server with no entry asks on a terminal only; without one
// it prints the one line and changes nothing (the address is not detected,
// since nothing would use it).
func TestOwnLoginUpgradeNoEntry(t *testing.T) {
	hs := newHostSandbox(t)
	r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{})
	if hs.code != 0 || scriptRan(r) || hs.registry() != "" {
		t.Fatalf("exit %d, ran %v, registry %q\n%s", hs.code, scriptRan(r), hs.registry(), hs.out2())
	}
	if want := "[INFO] This machine's own login was not set up (an upgrade does not ask without a terminal); to set it up: " + ownLoginCmd + "\n"; hs.out2() != want {
		t.Errorf("got %q, want %q", hs.out2(), want)
	}
	// on a terminal it asks
	hs.stdin = "y\n"
	hs.tty = func() bool { return true }
	r = hs.ownLogin(nil, lifecycle.OwnLoginOptions{})
	if hs.code != 0 || !scriptRan(r) || !strings.Contains(hs.registry(), "|local||tacctl|192.0.2.10|\n") {
		t.Fatalf("exit %d, ran %v, registry %q\n%s", hs.code, scriptRan(r), hs.registry(), hs.out2())
	}
	// and a no leaves it
	hs2 := newHostSandbox(t)
	hs2.stdin = "n\n"
	hs2.tty = func() bool { return true }
	r = hs2.ownLogin(nil, lifecycle.OwnLoginOptions{})
	if scriptRan(r) || hs2.registry() != "" || !strings.Contains(hs2.out2(), "not asked for); to set it up: "+ownLoginCmd) {
		t.Errorf("ran %v, registry %q\n%s", scriptRan(r), hs2.registry(), hs2.out2())
	}
}

// A healthy setup does nothing and prints nothing: no question, no script,
// no write, install or upgrade.
func TestOwnLoginHealthyPrintsNothing(t *testing.T) {
	hs := newHostSandbox(t)
	hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true, Yes: true})
	hs.pam(true)
	state := hs.registry() + hs.store() + hs.read("state/tacctl.yaml")
	snaps := hs.snapshots()
	hs.serverAddress = func() (string, string, error) { return "", "", os.ErrInvalid } // not asked: the address is recorded
	for _, o := range []lifecycle.OwnLoginOptions{{}, {Install: true, Yes: true}, {Install: true}} {
		r := hs.ownLogin(nil, o)
		if hs.code != 0 || hs.out2() != "" || scriptRan(r) || r.Called("systemctl") {
			t.Errorf("%+v: exit %d, ran %v\n%q", o, hs.code, scriptRan(r), hs.out2())
		}
	}
	if state != hs.registry()+hs.store()+hs.read("state/tacctl.yaml") || hs.snapshots() != snaps {
		t.Error("a healthy setup was written")
	}
}

// A managed scope whose prefixes drifted is repaired, with the line the sync
// of the server has, and nothing is run on the server.
func TestOwnLoginRepairsADriftingScope(t *testing.T) {
	hs := newHostSandbox(t)
	hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true, Yes: true})
	hs.pam(true)
	hs.write("state/store.yaml", strings.Replace(hs.store(), "prefixes: [127.0.0.1/32, 192.0.2.10/32]", "prefixes: [127.0.0.1/32]", 1), 0o600)
	r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{})
	if hs.code != 0 || !strings.HasSuffix(hs.out2(), "[INFO] Repaired the managed server login.\n") || scriptRan(r) {
		t.Fatalf("exit %d, ran %v\n%q", hs.code, scriptRan(r), hs.out2())
	}
	if !strings.Contains(hs.store(), "prefixes: [127.0.0.1/32, 192.0.2.10/32]") {
		t.Errorf("store:\n%s", hs.store())
	}
	r = hs.ownLogin(nil, lifecycle.OwnLoginOptions{})
	if hs.out2() != "" || scriptRan(r) {
		t.Errorf("not healthy afterwards: %q", hs.out2())
	}
}

// An entry from before the setting existed (the address is in the entry
// only) is recorded, in one line, and nothing is run.
func TestOwnLoginRecordsTheAddress(t *testing.T) {
	hs := newHostSandbox(t)
	hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true, Yes: true})
	hs.pam(true)
	hs.write("state/tacctl.yaml", "", 0o600)
	hs.serverAddress = func() (string, string, error) { return "", "", os.ErrInvalid }
	r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{})
	if hs.code != 0 || hs.out2() != "[INFO] The server address 192.0.2.10 is recorded in tacctl.yaml (server.addresses).\n" || scriptRan(r) {
		t.Fatalf("exit %d, ran %v\n%q", hs.code, scriptRan(r), hs.out2())
	}
	if got := hs.read("state/tacctl.yaml"); !strings.Contains(got, "- 192.0.2.10\n") {
		t.Errorf("tacctl.yaml:\n%s", got)
	}
}

// A rebuilt server has the entry but no PAM files: the enrolment sets them
// up again with no question, in an upgrade without a terminal too.
func TestOwnLoginRebuiltServer(t *testing.T) {
	hs := newHostSandbox(t)
	hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true, Yes: true})
	hs.pam(false)
	reg := hs.registry()
	r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{})
	out := hs.out2()
	if hs.code != 0 || !scriptRan(r) || !strings.Contains(out, "enrolled") || strings.Contains(out, "[y/N]") || strings.Contains(out, "was not set up") {
		t.Fatalf("exit %d, ran %v\n%s", hs.code, scriptRan(r), out)
	}
	if hs.registry() != reg {
		t.Errorf("registry %q, was %q", hs.registry(), reg)
	}
}

// A server registered in a scope of its own from before 0.2.21 is set up
// again by the enrolment, which makes the managed scope; no question.
func TestOwnLoginEntryInAnotherScope(t *testing.T) {
	hs := newHostSandbox(t)
	hs.loopback()
	hs.write("state/linux-hosts", "authsrv|local|22|lab|127.0.0.1|\n", 0o600)
	r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{})
	if hs.code != 0 || !scriptRan(r) || !strings.Contains(hs.registry(), "authsrv|local|22|tacctl|192.0.2.10|") && !strings.Contains(hs.registry(), "authsrv|local||tacctl|192.0.2.10|") {
		t.Fatalf("exit %d, ran %v, registry %q\n%s", hs.code, scriptRan(r), hs.registry(), hs.out2())
	}
	if strings.Contains(hs.out2(), "[y/N]") {
		t.Errorf("asked:\n%s", hs.out2())
	}
}

// A failure in the middle leaves the server as it was: the script failed, so
// the managed scope is taken out again and nothing is registered; the
// command that called it goes on (the exit status is the caller's) and one
// line says what was skipped and what to run.
func TestOwnLoginFailureInTheMiddle(t *testing.T) {
	hs := newHostSandbox(t)
	before := hs.store()
	r := hs.runner()
	r.On([]string{"bash"}, execx.Result{Code: 1})
	hs.ownLogin(r, lifecycle.OwnLoginOptions{Install: true, Yes: true})
	out := hs.out2()
	if hs.code != 0 || !strings.Contains(out, "This machine's own login was not set up (the enrolment stopped, see above; nothing is half applied); to set it up: "+ownLoginCmd+"\n") {
		t.Fatalf("exit %d\n%s", hs.code, out)
	}
	if hs.registry() != "" || strings.Contains(hs.store(), "tacctl:") || hs.store() != before {
		t.Errorf("half applied: registry %q\nstore:\n%s", hs.registry(), hs.store())
	}
	if data, err := os.ReadFile(hs.path("state", "tacctl.yaml")); err == nil && strings.Contains(string(data), "192.0.2.10") {
		t.Errorf("the address was recorded:\n%s", data)
	}
	// the same with an address given: the line says so
	hs.serverAddress = nil
	hs.ownLogin(r, lifecycle.OwnLoginOptions{Install: true, Yes: true, Server: "203.0.113.9"})
	if !strings.Contains(hs.out2(), "to set it up: "+ownLoginCmd+" --server 203.0.113.9\n") {
		t.Errorf("no address in the command:\n%s", hs.out2())
	}
}

// No address to detect is a line, not a failure.
func TestOwnLoginNoAddress(t *testing.T) {
	hs := newHostSandbox(t)
	hs.serverAddress = func() (string, string, error) { return "", "", os.ErrInvalid }
	r := hs.ownLogin(nil, lifecycle.OwnLoginOptions{Install: true, Yes: true})
	if hs.code != 0 || scriptRan(r) || hs.registry() != "" ||
		!strings.Contains(hs.out2(), "This machine's own login was not set up (No address of this machine can be the server address: give --server <address>.); to set it up: "+ownLoginCmd) {
		t.Errorf("exit %d\n%s", hs.code, hs.out2())
	}
}
