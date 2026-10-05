package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
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
	if !strings.Contains(hs.out.String(), "  alice     80000\n  bob       80001\n  gone      80002\n") {
		t.Errorf("listing %q", hs.out.String())
	}
	if data, _ := os.ReadFile(uids); string(data) != "# range 80000-89999\n# previous 20000-29999\nalice:80000\nbob:80001\ngone:80002\nodd:1500\n" {
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
	if data, _ := os.ReadFile(uids); string(data) != "# range 80000-89999\n# previous 20000-29999\nalice:80000\nbob:80001\ncarol:85000\n" {
		t.Errorf("uid file %q", data)
	}
}

// 'config linux uid-range': shown, refused with the reason, changed (the
// UID file renumbered by offset, the scripts carrying the new range and the
// ones before), and refused when the file cannot be renumbered.
func TestConfigLinuxUIDRange(t *testing.T) {
	hs := newHostSandbox(t)
	uids := filepath.Join(hs.dir, "state", "linux-uids")
	hs.run(nil, "config", "linux", "uid-range")
	hs.expect(0, "  Linux UID range: 80000-89999 (default; one range for all hosts)", "")
	for _, c := range []struct{ arg, err string }{
		{"999-5000", "Cannot use UID range 999-5000: it starts below 1000 (system accounts)."},
		{"90000-80000", "Cannot use UID range 90000-80000: uid_min must be below uid_max."},
		{"80000-80500", "Cannot use UID range 80000-80500: it holds 501 numbers; at least 1000 are needed (numbers are never reused)."},
		{"60000-61000", "Cannot use UID range 60000-61000: it overlaps 60001-60513, which systemd reserves."},
		{"64000-66000", "Cannot use UID range 64000-66000: it overlaps 61184-65519, which systemd reserves."},
		{"600000-700000", "Cannot use UID range 600000-700000: it reaches 524288 and up, where systemd gives out container UIDs."},
		{"80000", "Usage: tacctl config linux uid-range <min>-<max>"},
		{"x-y", "Usage: tacctl config linux uid-range <min>-<max>"},
	} {
		hs.run(nil, "config", "linux", "uid-range", c.arg)
		hs.expect(1, "", c.err)
	}
	if _, err := os.Stat(uids); !os.IsNotExist(err) {
		t.Error("a refused change made the UID file")
	}

	// Some users get numbers, then the range moves.
	out := filepath.Join(hs.dir, "x.sh")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", out)
	hs.expect(0, "", "")
	r := hs.runner()
	hs.run(r, "config", "linux", "uid-range", "100000-109999")
	hs.expect(0, "Linux UID range set to 100000-109999 (was 80000-89999). Hosts renumber the accounts tacctl created at their next enroll or sync.", "")
	if !strings.Contains(hs.out.String(), "Renumbered 3 entries of "+uids+" from 80000-89999 to 100000-109999") {
		t.Errorf("out %q", hs.out.String())
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "uid-range set from=80000-89999 to=100000-109999") {
		t.Errorf("not logged: %q", r.Argvs())
	}
	if data, _ := os.ReadFile(uids); string(data) != "# range 100000-109999\n# previous 80000-89999\nalice:100000\nbob:100001\ncarol:100002\n" {
		t.Errorf("uid file %q", data)
	}
	hs.run(nil, "config", "get", "linux.uid_min")
	hs.expect(0, "100000", "")
	hs.run(nil, "config", "linux", "uid-range")
	hs.expect(0, "  Linux UID range: 100000-109999 (tacctl.yaml; one range for all hosts)\n  "+uids+" is numbered for 100000-109999 (before: 80000-89999)", "")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "-o", out)
	script, _ := os.ReadFile(out)
	if !strings.Contains(string(script), "TAC_USERS=$'alice:superuser:100000\\nbob:operator:100001\\ncarol:readonly:100002'\n") ||
		!strings.Contains(string(script), "TAC_UID_FIRST=100000\nTAC_UID_LAST=109999\nTAC_UID_PREVIOUS=80000-89999\nTAC_PROTOCOL=4\n") {
		t.Errorf("script header:\n%s", strings.SplitN(string(script), "# --- tacctl", 2)[0])
	}
	hs.run(nil, "config", "linux", "uid", "bob", "85000")
	hs.expect(1, "", "UID must be a number from 100000 to 109999")

	// Refused, nothing changed: back into a range used before, too small.
	before, _ := os.ReadFile(uids)
	hs.run(nil, "config", "linux", "uid-range", "85000-95000")
	hs.expect(1, "", "[ERROR] Cannot renumber "+uids+" from 100000-109999 to 85000-95000: it overlaps 80000-89999, a range the file was numbered for (hosts may still have accounts there). Nothing was changed.")
	if err := os.WriteFile(uids, append(before, []byte("zed:105000\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	hs.run(nil, "config", "linux", "uid-range", "100000-100999")
	hs.expect(1, "", "[ERROR] Cannot renumber "+uids+" from 100000-109999 to 100000-100999: 'zed' (105000) would become 105000, past its end. Nothing was changed.")
	hs.run(nil, "config", "linux", "uid-range", "300000-300999")
	hs.expect(1, "", "'zed' (105000) would become 305000, past its end.")
	hs.run(nil, "config", "linux", "uid-range")
	hs.expect(0, "  Linux UID range: 100000-109999 (tacctl.yaml", "")
	// Grown at the same start: nothing moves.
	hs.run(nil, "config", "linux", "uid-range", "100000-119999")
	hs.expect(0, "Linux UID range set to 100000-119999 (was 100000-109999).", "")
	if strings.Contains(hs.out.String(), "Renumbered") {
		t.Errorf("a grown range renumbered: %q", hs.out.String())
	}

	hs.run(nil, "config", "get", "linux.uid_max")
	hs.expect(0, "119999", "")
}

// A host whose user namespace cannot hold the range: enroll refuses before
// anything changes, sync refuses that host (exit 1), --local checks this
// machine (TACCTL_TEST_PROC stands for /proc/self).
func TestHostIDMapRefusal(t *testing.T) {
	hs := newHostSandbox(t)
	container := "uid_map\n         0     100000      65536\ngid_map\n         0     100000      65536\n"
	idmap := func(out string) *fake.Runner {
		r := hs.runner()
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.IDMapCommand },
			func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(out)}, nil })
		return r
	}
	want := "'web1' cannot hold UIDs 80000-89999: its user namespace maps only 0-65535 (an unprivileged container). Give it an ID map that covers 80000-89999, run it privileged, or choose a range it can hold: tacctl config linux uid-range <min>-<max> (one range for all hosts)."
	r := idmap(container)
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--build-on-host")
	hs.expect(1, "", want)
	if !strings.Contains(hs.err.String(), "Enrollment of web1 refused; nothing was changed.") || hs.pushed != "" || hs.registry() != "" {
		t.Errorf("enroll went on: %q pushed %d", hs.err.String(), len(hs.pushed))
	}
	if out := hs.run(nil, "scope", "list"); strings.Contains(out, "linux-web1") {
		t.Error("a scope was created")
	}
	// A plain host passes; then it turns out to be a container at sync.
	hs.run(idmap("uid_map\n0 0 4294967295\ngid_map\n0 0 4294967295\n"), "host", "enroll", "admin@web1.example.net", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	hs.pushed = ""
	hs.run(idmap(container), "host", "sync", "web1")
	hs.expect(1, "", want)
	if hs.pushed != "" {
		t.Error("sync pushed a script")
	}
	// A range the container can hold.
	hs.run(nil, "config", "linux", "uid-range", "40000-49999")
	hs.expect(0, "Linux UID range set to 40000-49999", "")
	hs.run(idmap(container), "host", "sync", "web1")
	hs.expect(0, "web1: synced", "")
	if !strings.Contains(hs.pushed, "TAC_UID_FIRST=40000\nTAC_UID_LAST=49999\n") {
		t.Error("the range is not in the script")
	}

	// --local: this machine's maps (the knob is in testknobs builds only).
	if !app.TestKnobs {
		return
	}
	hs.run(nil, "config", "linux", "uid-range", "100000-109999")
	proc := filepath.Join(hs.dir, "proc")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"uid_map", "gid_map"} {
		if err := os.WriteFile(filepath.Join(proc, f), []byte("0 100000 65536\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := hs.env
	hs.env = append(append([]string(nil), env...), "TACCTL_TEST_PROC="+proc)
	hs.loopback()
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--scope", "lab", "--build-on-host")
	hs.expect(1, "", "'authsrv' cannot hold UIDs 100000-109999: its user namespace maps only 0-65535 (an unprivileged container).")
	hs.env = env
}

// A UID file that holds its range record and no entry lists as empty.
func TestConfigLinuxUIDRecordOnly(t *testing.T) {
	hs := newHostSandbox(t)
	if err := os.WriteFile(filepath.Join(hs.dir, "state", "linux-uids"), []byte("# range 80000-89999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hs.run(nil, "config", "linux", "uid")
	hs.expect(0, "  None yet. A UID is assigned the first time a user is sent to a host.", "")
}
