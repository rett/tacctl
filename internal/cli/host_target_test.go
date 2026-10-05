package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// 'host target': shown; changed only after a test connection that logs
// in, finds root, reads keys matching the pin and the address reached;
// refused for a --local host, a tacctl user as the login, sudo that needs
// a password without a terminal, other keys, and a tier user.
func TestHostTarget(t *testing.T) {
	hs := newHostSandbox(t)
	ed, rsa := hkKey(t, "ed25519"), hkKey(t, "rsa")
	// session: the test connection answers root (or root), prints own as
	// the host's key files and conn as SSH_CONNECTION's host side.
	session := func(root string, own []devreg.HostKey, conn string) *fake.Runner {
		r := hs.factsRunner("ssh_connection=198.51.100.9 50022 " + conn + " 22\n")
		scan("web1.example.net", ed)(r)
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.ProbeCommand },
			func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(root + "\n")}, nil })
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.ReadKeysCommand },
			func(execx.Cmd) (execx.Result, error) {
				var b strings.Builder
				for _, k := range own {
					b.WriteString(k.String() + " root@web1\n")
				}
				return execx.Result{Stdout: []byte(b.String())}, nil
			})
		return r
	}
	hs.run(session("root", []devreg.HostKey{ed}, "192.0.2.50"), "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	before := hs.registry()

	out := plain(hs.run(nil, "host", "target", "web1"))
	for _, want := range []string{"Host web1", "Target:       admin@web1.example.net", "Port:         22", "Identity:     -",
		"Server:       192.0.2.1", "Address:      192.0.2.50", "Scope:        lab", "Method:       tacplus"} {
		if hs.code != 0 || !strings.Contains(out, want) {
			t.Errorf("show: %d, no %q\n%s", hs.code, want, out)
		}
	}
	snaps := func() int { m, _ := filepath.Glob(filepath.Join(hs.dir, "state", "backups", "2*")); return len(m) }
	n0 := snaps()

	// Refusals: nothing written.
	for _, c := range []struct {
		r    *fake.Runner
		args []string
		err  string
	}{
		{nil, []string{"nope", "root@x"}, "No enrolled host named 'nope'."},
		{nil, []string{"web1", "carol@web1.example.net"}, "The provisioning account 'carol' (the ssh login for carol@web1.example.net) is a tacctl user."},
		{nil, []string{"web1", "--identity", "/nonexistent/key"}, "Identity file '/nonexistent/key' not found."},
		{nil, []string{"web1", "--port", "x"}, "Invalid --port 'x'."},
		{session("sudo-password", []devreg.HostKey{ed}, "192.0.2.60"), []string{"web1", "admin@web1-new.example.net"},
			"sudo there needs a password (or the login may not sudo)"},
		{session("root", []devreg.HostKey{rsa}, "192.0.2.60"), []string{"web1", "admin@web1-new.example.net"},
			"The host reached is not 'web1' as pinned: its ssh keys differ; nothing was changed."},
		{session("root", nil, "192.0.2.60"), []string{"web1", "admin@web1-new.example.net"},
			"The host's ssh keys could not be read over the test connection"},
	} {
		hs.run(c.r, append([]string{"host", "target"}, c.args...)...)
		hs.expect(1, "", c.err)
		if hs.registry() != before || snaps() != n0 {
			t.Errorf("%v: changed something", c.args)
		}
	}
	// ssh fails: refused.
	r := session("root", []devreg.HostKey{ed}, "192.0.2.60")
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.ProbeCommand },
		func(execx.Cmd) (execx.Result, error) { return execx.Result{Code: 255}, nil })
	hs.run(r, "host", "target", "web1", "admin@web1-new.example.net")
	hs.expect(1, "", "Could not log in to admin@web1-new.example.net (ssh failed, see above); nothing was changed.")

	// The change: tested, snapshotted, written in place, logged, the new
	// address recorded.
	r = session("sudo", []devreg.HostKey{ed, rsa}, "192.0.2.60")
	r.On([]string{"getent"}, execx.Result{Stdout: []byte("192.0.2.60 STREAM web1-new\n")})
	hs.run(r, "host", "target", "web1", "admin@web1-new.example.net", "--port", "2222")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Host 'web1' is now reached at admin@web1-new.example.net port 2222 (scope, server and method unchanged).") ||
		!strings.Contains(all, "web1: its address changed from 192.0.2.50 to 192.0.2.60") {
		t.Errorf("change: %d\n%s", hs.code, all)
	}
	if !r.CalledRegexp(`^ssh .* -p 2222 -T admin@web1-new\.example\.net if \[`) || !r.CalledRegexp(`-O exit admin@web1-new\.example\.net$`) {
		t.Errorf("test connection %q", r.Argvs())
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "host target name=web1 target=admin@web1-new.example.net port=2222 by=root") {
		t.Errorf("not logged: %q", r.Argvs())
	}
	if got := hs.registry(); got != "web1|admin@web1-new.example.net|2222|lab|192.0.2.1|\n" || snaps() != n0+1 {
		t.Errorf("registry %q, snapshots %d", got, snaps()-n0)
	}
	// The same again: nothing to do.
	hs.run(nil, "host", "target", "web1", "admin@web1-new.example.net", "--port", "2222")
	hs.expect(0, "'web1' is already reached that way; nothing was changed.", "")

	// --local: no target.
	hs.loopback()
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--scope", "lab", "--build-on-host")
	hs.run(nil, "host", "target", "authsrv", "root@x")
	hs.expect(1, "", "'authsrv' is this server (enrolled with --local)")

	// A tier user: denied by the gate.
	hs.cfgRun("", []string{"host", "target", "web1", "root@x"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-operator\n")})
	}, "SUDO_USER=carol")
	if hs.code != 1 || !strings.Contains(hs.stderr(), "'tacctl host target' is not permitted for the") {
		t.Errorf("carol: %d %q", hs.code, hs.stderr())
	}
}
