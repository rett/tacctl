package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// The UID file of a release that gave out 20000-29999 is renumbered once, by
// the first command that reads it: logged, the old file kept, the scripts
// carry the new numbers; a second command changes nothing. The sync's
// summary counts the accounts the host renumbered.
func TestUIDFileRenumberedOnce(t *testing.T) {
	hs := newHostSandbox(t)
	state := filepath.Join(hs.dir, "state")
	uids := filepath.Join(state, "linux-uids")
	if err := os.WriteFile(uids, []byte("alice:20000\nbob:20001\ngone:20002\nodd:1500\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := hs.runner()
	hs.run(r, "config", "linux", "uid")
	hs.expect(0, "Renumbered 3 entries of "+uids+" from 20000-29999 to 80000-89999 (the same offset; the old file is kept as "+uids+".pre-renumber-", "")
	if !strings.Contains(hs.out.String(), "  alice                    80000\n  bob                      80001\n  gone                     80002\n") {
		t.Errorf("listing %q", hs.out.String())
	}
	if data, _ := os.ReadFile(uids); string(data) != "alice:80000\nbob:80001\ngone:80002\nodd:1500\n" {
		t.Errorf("uid file %q", data)
	}
	backups, _ := filepath.Glob(uids + ".pre-renumber-*")
	if len(backups) != 1 {
		t.Fatalf("backups %q", backups)
	}
	if data, _ := os.ReadFile(backups[0]); string(data) != "alice:20000\nbob:20001\ngone:20002\nodd:1500\n" {
		t.Errorf("backup %q", data)
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "uid-map renumbered 3 entries from=20000-29999 to=80000-89999 backup="+backups[0]) {
		t.Errorf("not logged: %q", r.Argvs())
	}

	// Idempotent: nothing more to do, nothing said or logged.
	r = hs.runner()
	hs.run(r, "config", "linux", "uid", "bob")
	hs.expect(0, "80001\n", "")
	if strings.Contains(hs.out.String(), "Renumbered") || r.CalledRegexp(`uid-map`) {
		t.Errorf("second run: %q %q", hs.out.String(), r.Argvs())
	}

	// A sync whose host renumbered an account says so.
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	if !strings.Contains(hs.pushed, "TAC_USERS=$'alice:superuser:80000\\nbob:operator:80001\\ncarol:readonly:80003'\n") {
		t.Errorf("enroll header:\n%s", strings.SplitN(hs.pushed, "# --- tacctl", 2)[0])
	}
	r = hs.runner()
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "sudo -n bash")
	},
		func(execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: []byte("[INFO] 'bob': renumbered 20001 -> 80001 (home re-owned)\n[INFO] Accounts: 3 managed by tacctl here; 1 renumbered.\n")}, nil
		})
	hs.run(r, "host", "sync", "web1")
	hs.expect(0, "web1: synced (3 users; 1 renumbered).", "")
}

// A legacy number whose new one is another name's: 'host sync' (and every
// command that writes a script) refuses, nothing changed; 'config linux uid'
// warns and goes on, so the other name can be given another number.
func TestUIDFileRenumberCollision(t *testing.T) {
	hs := newHostSandbox(t)
	uids := filepath.Join(hs.dir, "state", "linux-uids")
	coll := "alice:20000\nbob:20001\ncarol:80001\n"
	if err := os.WriteFile(uids, []byte(coll), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "Cannot renumber " + uids + " from 20000-29999 to 80000-89999: 'bob' (20001) would become 80001, which is already assigned to 'carol'. Nothing was changed."
	out := filepath.Join(hs.dir, "x.sh")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", out)
	hs.expect(1, "", "[ERROR] "+want)
	if !strings.Contains(hs.err.String(), "Give 'carol' another number first: tacctl config linux uid carol <uid>") {
		t.Errorf("stderr %q", hs.err.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("a script was written")
	}
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	hs.run(nil, "host", "sync", "web1")
	hs.expect(1, "", want)
	if hs.pushed != "" {
		t.Error("a script was pushed")
	}
	if data, _ := os.ReadFile(uids); string(data) != coll {
		t.Errorf("uid file %q", data)
	}
	if b, _ := filepath.Glob(uids + ".pre-renumber-*"); len(b) != 0 {
		t.Errorf("backups %q", b)
	}

	// The way out: carol gets another number; the next command renumbers.
	hs.run(nil, "config", "linux", "uid", "carol", "85000")
	hs.expect(0, "'carol' is now assigned UID/GID 85000.", "")
	if !strings.Contains(plain(hs.out.String()), "[WARN] "+want) {
		t.Errorf("no warning: %q", hs.out.String())
	}
	hs.run(nil, "config", "linux", "uid")
	hs.expect(0, "Renumbered 2 entries of "+uids, "")
	if data, _ := os.ReadFile(uids); string(data) != "alice:80000\nbob:80001\ncarol:85000\n" {
		t.Errorf("uid file %q", data)
	}
}
