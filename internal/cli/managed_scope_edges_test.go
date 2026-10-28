package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// The states a release before 0.2.21, an interrupted command or a rollback
// leaves, and the edges of the managed server scope around them.

// renderedBlock is the rendered tacquito.yaml text of one user: from its
// "- name:" line to the next one.
func renderedBlock(t *testing.T, hs *hostSandbox, user string) string {
	t.Helper()
	r := hs.read("etc/tacquito.yaml")
	i := strings.Index(r, "- name: "+user+"\n")
	if i < 0 {
		t.Fatalf("%s is not in the rendered file:\n%s", user, r)
	}
	rest := r[i+1:]
	if j := strings.Index(rest, "- name: "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// withScope adds a scope to the store of the sandbox, as 0.2.20 would hold
// it, and puts alice in it when member is true.
func withScope(hs *hostSandbox, name, prefixes string, member bool) {
	hs.t.Helper()
	st := strings.Replace(hs.store(), "  dmz:\n", "  "+name+":\n    prefixes: ["+prefixes+"]\n    secret: "+name+"-secret-0123456789abcdef\n  dmz:\n", 1)
	if member {
		st = strings.Replace(st, "    scopes: [prod, lab]\n", "    scopes: [prod, lab, "+name+"]\n", 1)
	}
	hs.write("state/store.yaml", st, 0o600)
}

// clashSandbox is a 0.2.20 install whose scope called tacctl is the
// operator's: it answers 198.51.100.0/24 as well as this server, and alice is
// in it. The server is registered in registered.
func clashSandbox(t *testing.T, registered string) *hostSandbox {
	t.Helper()
	hs := newHostSandbox(t)
	withScope(hs, "tacctl", "127.0.0.1/32, 198.51.100.0/24", true)
	hs.write("state/linux-hosts", "authsrv|local|22|"+registered+"|127.0.0.1|\n", 0o600)
	return hs
}

const clashLine = "Scope 'tacctl' is reserved. Rename the scope of that name first: tacctl scope rename tacctl <new-name>. Nothing was changed."

// An operator's scope called tacctl that the server was enrolled in with
// 0.2.20 is not the managed scope: no user is made a member of it (the
// rendered file gives bob his own scopes only), it is listed and can be
// renamed, the sync of the server refuses in one line and takes no prefix out
// of it, and 'config validate' says what to do. After the rename the server
// is taken over as a shared scope is.
func TestManagedScopeClashRegisteredInIt(t *testing.T) {
	hs := clashSandbox(t, "tacctl")
	hs.run(nil, "scope", "add", "extra", "--prefixes", "192.0.2.128/25")
	hs.expect(0, "Scope 'extra' added", "")
	for _, u := range []string{"bob", "carol"} {
		if b := renderedBlock(t, hs, u); strings.Contains(b, `"tacctl"`) {
			t.Errorf("%s is a member of the operator's scope tacctl:\n%s", u, b)
		}
	}
	if !strings.Contains(renderedBlock(t, hs, "alice"), `"tacctl"`) {
		t.Error("alice, its member, lost it")
	}
	hs.run(nil, "scope", "list")
	hs.expect(0, "tacctl", "")
	hs.run(nil, "scope", "lookup", "198.51.100.7")
	hs.expect(0, "scope 'tacctl'", "")
	hs.run(nil, "host", "list")
	if out := plain(hs.out.String()); !strings.Contains(out, "authsrv  local:22  -        tacctl  ") {
		t.Errorf("host list hides the scope of the server:\n%s", out)
	}
	before, reg := hs.store(), hs.registry()
	hs.run(nil, "host", "sync", "authsrv")
	hs.expect(1, "", "authsrv: "+clashLine)
	if strings.Contains(hs.all(), "Repaired") || hs.store() != before || hs.registry() != reg {
		t.Errorf("the sync changed the scope or the registration:\n%s", hs.all())
	}
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
	hs.expect(1, "", clashLine)
	if hs.store() != before || hs.registry() != reg {
		t.Error("the enrolment changed something")
	}
	hs.run(nil, "config", "validate")
	if out := hs.all(); !strings.Contains(out, "a scope of the operator's has the name 'tacctl'") || !strings.Contains(out, "tacctl scope rename tacctl <new-name>") {
		t.Errorf("config validate:\n%s", out)
	}
	// the fix is the one it names
	hs.run(nil, "scope", "rename", "tacctl", "ops")
	hs.expect(0, "Scope renamed: tacctl -> ops", "")
	if !strings.HasPrefix(hs.registry(), "authsrv|local|22|ops|") {
		t.Errorf("registry %q", hs.registry())
	}
	hs.run(nil, "host", "sync", "authsrv")
	hs.expect(0, "authsrv: to set up this server's own login for every user: tacctl host enroll --local", "")
	enrolLocal(t, hs)
	if st := hs.store(); !strings.Contains(st, "ops:\n    prefixes: [198.51.100.0/24]") || !strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32, 192.0.2.10/32]") {
		t.Errorf("store:\n%s", st)
	}
}

// The server registered in a scope of its own and an ordinary scope called
// tacctl that is none of the server's: the sync of everything goes on with
// the other hosts after it reports the server.
func TestManagedScopeClashDoesNotStopTheSyncOfTheOtherHosts(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "add", "srv", "--prefixes", "127.0.0.1/32", "--secret", "srv-secret-0123456789abcdef")
	hs.run(nil, "user", "scope", "bob", "add", "srv")
	withScope(hs, "tacctl", "198.51.100.0/24", true)
	hs.write("state/linux-hosts", "authsrv|local|22|srv|127.0.0.1|\nweb1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	hs.run(nil, "host", "sync", "--all")
	hs.expect(1, "web1: synced", "authsrv: "+clashLine)
	if !strings.Contains(hs.pushed, "TAC_SCOPE=lab") && !strings.Contains(hs.pushed, "scope 'lab'") {
		t.Errorf("web1 was not synced:\n%s", hs.pushed)
	}
	// the tier-lowering sync of the server reports the same and exits
	hs.run(nil, "group", "edit", "operator", "tier", "readonly")
	if out := hs.all(); !strings.Contains(out, clashLine) {
		t.Errorf("the sync after a lowered tier:\n%s", out)
	}
}

// Forgetting or unenrolling a server registered in an operator's scope called
// tacctl leaves the scope: it is no scope of the server's to take away.
func TestManagedScopeClashSurvivesForget(t *testing.T) {
	hs := clashSandbox(t, "tacctl")
	before := hs.store()
	hs.run(nil, "host", "forget", "authsrv", "--yes")
	hs.expect(0, "Host 'authsrv' forgotten.", "")
	if hs.store() != before {
		t.Errorf("the operator's scope went with the registration:\n%s", hs.store())
	}
}

// A rollback adds the managed scope to the users' own scopes only when it is
// the managed one: an operator's scope called tacctl gets no new member.
func TestRollbackLeavesAnOperatorsScopeCalledTacctl(t *testing.T) {
	hs := rollbackState(t)
	withScope(hs, "tacctl", "127.0.0.1/32, 198.51.100.0/24", true)
	hs.write("state/linux-hosts", "authsrv|local|22|tacctl|127.0.0.1|\n", 0o600)
	hs.run(hs.runner(), "rollback", "0.2.20")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	if out := hs.all(); strings.Contains(out, "add scope tacctl") || strings.Contains(out, "managed-scope") {
		t.Errorf("the plan adds users to the operator's scope:\n%s", out)
	}
}

// legacySharedSandbox is a 0.2.20 install whose server is registered in the
// scope lab, which serves devices too and has the server's address.
func legacySharedSandbox(t *testing.T) *hostSandbox {
	t.Helper()
	hs := newHostSandbox(t)
	hs.loopback()
	hs.write("state/linux-hosts", "authsrv|local|22|lab|127.0.0.1|\n", 0o600)
	return hs
}

// scriptFails is a runner whose local client script ends the way an
// interruption does: with an error, not an exit status.
func scriptFails(hs *hostSandbox, cancel func()) *fake.Runner {
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool { return c.Name == "bash" }, func(execx.Cmd) (execx.Result, error) {
		if cancel != nil {
			cancel()
		}
		return execx.Result{Code: 130}, errors.New("interrupted")
	})
	return r
}

// noHalfEnrolment checks that nothing of an enrolment that did not finish is
// left: the store and the registry are as they were, the server's logins
// are still answered by the scope the registry names, and the retry works.
func noHalfEnrolment(t *testing.T, hs *hostSandbox, store, registry string) {
	t.Helper()
	if hs.store() != store || hs.registry() != registry {
		t.Errorf("the failed enrolment left a change:\nstore\n%s\nregistry %q", hs.store(), hs.registry())
	}
	hs.run(nil, "scope", "lookup", "127.0.0.1")
	hs.expect(0, "scope 'lab'", "")
	if b := renderedBlock(t, hs, "bob"); !strings.Contains(b, `"lab"`) {
		t.Errorf("bob lost the scope the server answers him with:\n%s", b)
	}
	hs.run(nil, "host", "sync", "authsrv")
	if strings.Contains(hs.all(), "reserved") {
		t.Errorf("the sync meets a scope of the failed enrolment:\n%s", hs.all())
	}
	enrolLocal(t, hs)
	if hs.registry() != "authsrv|local||tacctl|192.0.2.10|\n" || strings.Count(hs.store(), "\n  tacctl:\n") != 1 {
		t.Errorf("the retry:\n%q\n%s", hs.registry(), hs.store())
	}
}

// An enrolment of a server registered in a shared scope that ends in an
// error (Ctrl-C during the client script, which a build on the host makes
// long) or before the script runs puts the prefixes back and removes the new
// scope, as a script that exits non-zero does; the retry is accepted.
func TestManagedEnrolmentThatEndsInAnErrorLeavesNothing(t *testing.T) {
	for name, fail := range map[string]func(*hostSandbox){
		"script error": func(hs *hostSandbox) {
			hs.run(scriptFails(hs, nil), "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
			hs.expect(1, "", "interrupted")
		},
		"script interrupted": func(hs *hostSandbox) {
			ctx, cancel := context.WithCancel(context.Background())
			hs.ctx = ctx
			hs.run(scriptFails(hs, cancel), "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
			hs.ctx = nil
			if hs.code == 0 {
				t.Error("exit 0")
			}
		},
		"no tarball": func(hs *hostSandbox) {
			if err := os.Remove(filepath.Join(hs.dir, "linux", "pam_tacplus-1.7.0.tar.gz")); err != nil {
				t.Fatal(err)
			}
			hs.run(nil, "host", "enroll", "--local", "--name", "authsrv")
			hs.expect(1, "", "pam_tacplus tarball not found")
			enrolTarball(t, hs)
		},
		"script exit status": func(hs *hostSandbox) {
			hs.runFails = false
			r := hs.runner()
			r.When(func(c execx.Cmd) bool { return c.Name == "bash" }, execx.Result{Code: 1}, nil)
			hs.run(r, "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
			hs.expect(1, "", "Enrollment of authsrv failed")
		},
	} {
		t.Run(name, func(t *testing.T) {
			hs := legacySharedSandbox(t)
			store, registry := hs.store(), hs.registry()
			fail(hs)
			noHalfEnrolment(t, hs, store, registry)
		})
	}
}

// enrolTarball puts back the stand-in tarball the test removed.
func enrolTarball(t *testing.T, hs *hostSandbox) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(hs.dir, "linux", "pam_tacplus-1.7.0.tar.gz"), []byte("not really a tarball\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A scope called tacctl that answers the login addresses only, has no member
// and serves no one else is what an enrolment that did not finish left (an
// earlier build did not take it out): the retry adopts it, with its secret,
// and the sync says what to run instead of calling it a clash.
func TestManagedEnrolmentAdoptsAnUnfinishedScope(t *testing.T) {
	hs := legacySharedSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "remove", "127.0.0.1/32")
	hs.expect(0, "", "")
	withScope(hs, "tacctl", "127.0.0.1/32", false)
	hs.run(nil, "host", "sync", "authsrv")
	hs.expect(0, "authsrv: to set up this server's own login for every user: tacctl host enroll --local", "")
	if strings.Contains(hs.all(), "reserved") {
		t.Errorf("the sync calls it a clash:\n%s", hs.all())
	}
	enrolLocal(t, hs)
	st := hs.store()
	if hs.registry() != "authsrv|local||tacctl|192.0.2.10|\n" || strings.Count(st, "\n  tacctl:\n") != 1 ||
		!strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32, 192.0.2.10/32]\n    secret: tacctl-secret-0123456789abcdef") {
		t.Errorf("registry %q\n%s", hs.registry(), st)
	}
	// both login addresses already in it: nothing to repair
	hs = legacySharedSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "remove", "127.0.0.1/32")
	withScope(hs, "tacctl", "127.0.0.1/32, 192.0.2.10/32", false)
	enrolLocal(t, hs)
	if st := hs.store(); strings.Count(st, "\n  tacctl:\n") != 1 || strings.Contains(hs.all(), "Repaired") ||
		!strings.Contains(st, "secret: tacctl-secret-0123456789abcdef") {
		t.Errorf("adoption:\n%s\n%s", hs.all(), st)
	}
	// with a member it is the operator's
	hs = newHostSandbox(t)
	withScope(hs, "tacctl", "127.0.0.1/32, 192.0.2.10/32", true)
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
	hs.expect(1, "", clashLine)
}

// capturedLocalScript is a runner that keeps the text of the client script
// the local bash is given.
func capturedLocalScript(hs *hostSandbox, text *string) *fake.Runner {
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool { return c.Name == "bash" }, func(c execx.Cmd) (execx.Result, error) {
		if b, err := os.ReadFile(c.Args[0]); err == nil {
			*text = string(b)
		}
		return execx.Result{}, nil
	})
	return r
}

// The server's own PAM client connects to 127.0.0.1, whatever the server
// address: behind NAT (203.0.113.9 is not on this machine) a connection to it
// would come from the gateway, or not arrive, and the server's own logins
// would not find the scope. The address devices and other hosts use is
// recorded (the registry, server.addresses, the scope's prefixes), and the
// scope keeps both login addresses.
func TestManagedServerPAMConnectsToLoopback(t *testing.T) {
	hs := newHostSandbox(t)
	var script string
	hs.run(capturedLocalScript(hs, &script), "host", "enroll", "--local", "--name", "authsrv", "--server", "203.0.113.9", "--build-on-host")
	hs.expect(0, "", "")
	if !strings.Contains(script, "TAC_SERVER=127.0.0.1\n") {
		t.Errorf("the enrolment script:\n%s", strings.SplitN(script, "# --- tacctl", 2)[0])
	}
	if got := hs.registry(); got != "authsrv|local||tacctl|203.0.113.9|\n" || !strings.Contains(hs.store(), "prefixes: [127.0.0.1/32, 203.0.113.9/32]") ||
		!strings.Contains(hs.read("state/tacctl.yaml"), "- 203.0.113.9\n") {
		t.Errorf("registry %q\n%s", got, hs.store())
	}
	script = ""
	hs.run(capturedLocalScript(hs, &script), "host", "sync", "authsrv")
	hs.expect(0, "", "")
	if !strings.Contains(script, "TAC_SERVER=127.0.0.1\n") {
		t.Errorf("the sync script:\n%s", strings.SplitN(script, "# --- tacctl", 2)[0])
	}
}
