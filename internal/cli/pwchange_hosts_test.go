package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// A user who must change the password has no login on an enrolled host but
// this server: the host's sync expires the account (TAC_INACTIVE, as for a
// disabled user, so an SSH key fails as the password does) and the sync after
// the change opens it again. The server's own sync keeps the account, since
// the password is changed there, and a superuser is held nowhere. The verb
// that flags or clears says the hosts follow at their next sync.
func TestHostSyncExpiresAFlaggedUserOnTheOtherHostsOnly(t *testing.T) {
	hs := newHostSandbox(t)
	hs.reroot = true
	hs.loopback()
	script := ""
	local := func() *fake.Runner {
		r := hs.runner()
		r.OnFunc([]string{"bash"}, func(c execx.Cmd) (execx.Result, error) {
			b, _ := os.ReadFile(c.Args[0])
			script = string(b)
			return execx.Result{}, nil
		})
		r.On([]string{"getent", "passwd"}, execx.Result{Stdout: []byte("root:x:0:0::/root:/bin/bash\n")})
		return r
	}
	hs.run(local(), "host", "enroll", "--local", "--name", "authsrv", "--scope", "lab", "--build-on-host")
	if hs.code != 0 {
		t.Fatalf("enroll --local: %d %s", hs.code, plain(hs.out.String()+hs.err.String()))
	}
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")

	all := plain(hs.run(nil, "user", "require-password-change", "--all") + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Flagged 2, skipped 1 (1 superuser)") ||
		!strings.Contains(all, "'bob', 'carol' can still log in to 1 enrolled host until each host's next sync, which expires the account there: tacctl host sync --all") {
		t.Fatalf("require: %d\n%s", hs.code, all)
	}
	hs.run(nil, "host", "sync", "web1")
	if hs.code != 0 || !strings.Contains(hs.pushed, "TAC_USERS=alice:superuser:80000\nTAC_INACTIVE=$'bob\\ncarol'\nTAC_INACTIVE_UIDS=$'bob:80001\\ncarol:80002'\n") {
		t.Errorf("web1 sync: %d\n%s", hs.code, head(hs.pushed))
	}
	hs.run(local(), "host", "sync", "authsrv")
	if hs.code != 0 || !strings.Contains(script, "TAC_USERS=$'alice:superuser:80000:/bin/bash\\nbob:operator:80001:/usr/sbin/nologin\\ncarol:readonly:80002:/usr/sbin/nologin'\nTAC_INACTIVE=''\n") {
		t.Errorf("the server's sync: %d\n%s", hs.code, head(script))
	}
	out := plain(hs.run(nil, "host", "show", "web1"))
	if !strings.Contains(out, "2 users (accounts expired, files kept; not listed)") {
		t.Errorf("host show web1:\n%s", out)
	}

	all = plain(hs.run(nil, "user", "require-password-change", "bob", "off") + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "'bob' can log in to 1 enrolled host again after each host's next sync: tacctl host sync --all") {
		t.Fatalf("clear: %d\n%s", hs.code, all)
	}
	hs.run(nil, "host", "sync", "web1")
	if hs.code != 0 || !strings.Contains(hs.pushed, "TAC_USERS=$'alice:superuser:80000\\nbob:operator:80001'\nTAC_INACTIVE=carol\n") {
		t.Errorf("web1 sync after the change: %d\n%s", hs.code, head(hs.pushed))
	}
	// 'config linux script' is for a host that is not this server
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "--output", hs.path("lab.sh"))
	if data, _ := os.ReadFile(hs.path("lab.sh")); hs.code != 0 || !strings.Contains(string(data), "\nTAC_INACTIVE=carol\n") {
		t.Errorf("config linux script: %d %s\n%s", hs.code, hs.err.String(), head(string(data)))
	}
}
