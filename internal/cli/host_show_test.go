package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// showRunner is the host sandbox's runner for a host that offers key
// (session and keyscan), whose facts read prints facts, whose client
// script prints script, and whose read-only check prints check (a
// non-zero checkCode after it).
func (hs *hostSandbox) showRunner(key devreg.HostKey, facts, script, check string, checkCode int) *fake.Runner {
	r := hs.runner()
	scan("web1.example.net", key)(r)
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.ReadKeysCommand },
		func(execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: []byte(key.String() + " root@web1\n")}, nil
		})
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.FactsCommand },
		func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(facts)}, nil })
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "bash /tmp/tacctl.AbCd1234")
	}, func(execx.Cmd) (execx.Result, error) {
		if hs.runFails {
			return execx.Result{Stdout: []byte(script), Code: 1}, nil
		}
		return execx.Result{Stdout: []byte(script)}, nil
	})
	r.Func(func(c execx.Cmd) bool {
		return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "tacctl-check")
	}, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte(check), Code: checkCode}, nil
	})
	return r
}

const showFacts = "ssh_connection=198.51.100.9 50022 192.0.2.50 22\nlogin_defs=present\nUID_MIN 1000\nUID_MAX 60000\n" +
	"os_NAME=\"Ubuntu\"\nos_VERSION_ID=\"24.04\"\nos_PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nsshd=OpenSSH_9.6p1\n" +
	"pam=pam_tacplus /lib/x86_64-linux-gnu/security/pam_tacplus.so 1.7.0\n"

// One enrolled host in full; the record of its last run (written by
// enroll and sync, a failure too, removed by unenroll); --json; --all.
func TestHostShow(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	hs.expect(0, "", "")
	ed := hkKey(t, "ed25519")
	enrollOut := "[INFO] '" + "alice': home /home/alice is now 0700 (its primary group is shared).\n" +
		"[INFO] Created account 'alice' (superuser).\n[INFO] Created account 'bob' (operator).\n" +
		"[INFO] Accounts: 3 managed by tacctl here.\n"
	hs.run(hs.showRunner(ed, showFacts, enrollOut, "", 0), "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled (3 users).", "")
	rec := filepath.Join(hs.dir, "state", "hosts", "web1.json")
	if st, err := os.Stat(rec); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("record: %v %v", st, err)
	}

	out := plain(hs.run(nil, "host", "show", "web1"))
	hs.expect(0, "", "")
	for _, w := range []string{
		"Host web1\n",
		"Connection\n  Target:       admin@web1.example.net\n  Port:         22\n  Identity:     -\n  Server:       192.0.2.1\n  Method:       tacplus (pam_tacplus)\n",
		"Scope\n  Registered:   lab\n  Answering:    lab (prefix 192.0.2.0/24) for 192.0.2.50\n  Staging:      none\n",
		"Address\n  Recorded:     192.0.2.50\n",
		"Host keys\n  Pinned:       ED25519  " + ed.Fingerprint() + "\n  On the host:  Linux: 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'",
		"Sightings\n  Last seen:    never",
		"Notices\n  Open:         none\n",
		"Accounts (what the next sync makes there)\n  alice  superuser  UID 80000  tac-users, tac-superuser\n  bob    operator   UID 80001  tac-users\n",
		"Last sync\n  When:         ",
		" by root (host enroll)\n  Result:       ok\n  Protocol:     " + hosts.ScriptProtocol + "\n  Created:      alice, bob\n  Updated:      none\n  Removed:      none\n",
		"Host facts\n  Read:         ",
		"  OS:           Ubuntu 24.04.1 LTS\n  sshd:         OpenSSH_9.6p1\n  PAM module:   pam_tacplus 1.7.0 (/lib/x86_64-linux-gnu/security/pam_tacplus.so)\n  useradd UIDs: 1000-60000 (/etc/login.defs UID_MIN/UID_MAX)\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("show lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "Check") {
		t.Errorf("no --check, but:\n%s", out)
	}

	// A failed sync is recorded too; the facts of the last good run stay.
	hs.runFails = true
	hs.run(hs.showRunner(ed, "", "[INFO] Deleted account 'carol': no longer a TACACS+ user here.\n", "", 0), "host", "sync", "web1")
	hs.expect(1, "", "web1: sync failed")
	hs.runFails = false
	out = plain(hs.run(nil, "host", "show", "web1"))
	if !strings.Contains(out, "(host sync)\n  Result:       failed: the client script failed on the host (exit status 1)\n") ||
		!strings.Contains(out, "  Removed:      carol\n") || !strings.Contains(out, "OS:           Ubuntu 24.04.1 LTS") {
		t.Errorf("after a failed sync:\n%s", out)
	}

	// --json: every field.
	js := hs.run(nil, "host", "show", "web1", "--json")
	var v map[string]any
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatalf("json: %v\n%s", err, js)
	}
	for _, k := range []string{"name", "connection", "scope", "address", "host_keys", "sightings", "notices", "accounts", "last_sync", "facts"} {
		if _, ok := v[k]; !ok {
			t.Errorf("json lacks %q:\n%s", k, js)
		}
	}
	if _, ok := v["check"]; ok {
		t.Errorf("json has check without --check:\n%s", js)
	}
	for _, w := range []string{`"answering": "lab"`, `"ok": false`, `"removed": [`, `"os_pretty_name": "Ubuntu 24.04.1 LTS"`, `"uid": "80000"`, `"fingerprint": "` + ed.Fingerprint() + `"`} {
		if !strings.Contains(js, w) {
			t.Errorf("json lacks %s:\n%s", w, js)
		}
	}

	// An acknowledged notice is counted, and listed with --all.
	hs.run(hs.factsRunner("ssh_connection=1 2 192.0.2.51 22\n"), "host", "sync", "web1")
	hs.run(nil, "device", "notice", "web1", "ack", "address-changed")
	out = plain(hs.run(nil, "host", "show", "web1"))
	if !strings.Contains(out, "  Open:         none; 1 acknowledged notice not shown: tacctl host show web1 --all\n") ||
		!strings.Contains(out, "  Previous:     192.0.2.50 (changed ") {
		t.Errorf("acknowledged:\n%s", out)
	}
	out = plain(hs.run(nil, "host", "show", "web1", "--all"))
	if !strings.Contains(out, "  Open:         address-changed (acknowledged): the address of 'web1' changed from 192.0.2.50 to 192.0.2.51") {
		t.Errorf("--all:\n%s", out)
	}

	// Unknown hosts and options.
	hs.run(nil, "host", "show", "ghost")
	hs.expect(1, "", "No enrolled host named 'ghost'. See 'tacctl host list'.")
	hs.run(nil, "host", "show", "web1", "--bogus")
	hs.expect(1, "", "Unknown option: '--bogus'")
	hs.run(nil, "host", "show")
	hs.expect(1, "", "Usage: tacctl host show <name> [--all] [--json] [--check]")

	// Unenroll removes the record.
	hs.run(nil, "host", "unenroll", "web1")
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Errorf("record after unenroll: %v", err)
	}
}

// A host enrolled before 0.2.2 has no record; this server shows as such.
func TestHostShowNotRecordedAndLocal(t *testing.T) {
	hs := newHostSandbox(t)
	if err := os.WriteFile(filepath.Join(hs.dir, "state", "linux-hosts"),
		[]byte("web1|admin@web1.example.net||lab|192.0.2.1|\nauthsrv|local||lab|127.0.0.1|\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := plain(hs.run(nil, "host", "show", "web1"))
	if hs.code != 0 || !strings.Contains(out, "Last sync\n  Recorded:     not recorded (before 0.2.2)\n") ||
		!strings.Contains(out, "Host facts\n  Recorded:     not recorded (before 0.2.2)\n") ||
		!strings.Contains(out, "  Pinned:       none (the next 'tacctl host sync web1' pins them)\n") ||
		!strings.Contains(out, "  Recorded:     none (the next enroll or sync records it)\n") {
		t.Errorf("not recorded: %d\n%s", hs.code, out)
	}
	out = plain(hs.run(nil, "host", "show", "authsrv"))
	if !strings.Contains(out, "  Target:       this server (enrolled --local)\n  Port:         -\n") ||
		!strings.Contains(out, "  alice  superuser  UID -      tac-users, tac-superuser, tac-console\n") ||
		!strings.Contains(out, "  UID -:        given at the next sync\n") ||
		// 127.0.0.1 is not covered by lab: the warning 'host sync' gives.
		!strings.Contains(out, "[WARN] authsrv: scope 'lab' does not cover 127.0.0.1") {
		t.Errorf("local: %d\n%s", hs.code, out)
	}
}

// --check: read-only, one line per difference with its fix, exit 1 when
// there is one; a run that fails says so.
func TestHostShowCheck(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	ed, rsa := hkKey(t, "ed25519"), hkKey(t, "rsa")
	hs.run(hs.showRunner(ed, showFacts, "", "", 0), "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")

	good := "tacctl-check group tac-users 80000\ntacctl-check group tac-superuser 80002\ntacctl-check group tac-engineer 80005\n" +
		"tacctl-check account alice 80000 80000 700 /home/alice\ntacctl-check account bob 80001 80000 700 /home/bob\n" +
		"tacctl-check account carol 80002 80000 700 /home/carol\n" +
		"tacctl-check pam tacctl-auth aaa\ntacctl-check pam tacctl-account bbb\ntacctl-check pam tacctl-session ccc\n" +
		"tacctl-check pam-written tacctl-auth aaa\ntacctl-check pam-written tacctl-account bbb\ntacctl-check pam-written tacctl-session ccc\n" +
		"tacctl-check protocol " + hosts.ScriptProtocol + "\ntacctl-check key " + ed.String() + " root@web1\n"
	r := hs.showRunner(ed, "", "", "Welcome to web1\n"+good, 0)
	out := plain(hs.run(r, "host", "show", "web1", "--check"))
	if hs.code != 0 || !strings.Contains(out, "Check (read on the host now)\n  web1 is as tacctl would make it.\n") ||
		!strings.Contains(out, "Welcome to web1") || strings.Contains(out, "tacctl-check") {
		t.Errorf("good: %d\n%s%s", hs.code, out, hs.err.String())
	}
	if !r.CalledRegexp(`(?s)^ssh .* -T admin@web1\.example\.net s='STATE_DIR=.*'; trap 'exit 130' HUP INT TERM; if .* sudo -n bash -c "\$s"; else`) ||
		!r.CalledRegexp(`^ssh .*-O exit admin@web1.example.net$`) || r.ArgvContains("mktemp") {
		t.Errorf("ssh calls %q", r.Argvs())
	}

	bad := "tacctl-check group tac-users 1001\n" +
		"tacctl-check account alice 80007 80000 755 /home/alice\n" +
		"tacctl-check pam tacctl-auth zzz\ntacctl-check pam tacctl-account bbb\ntacctl-check pam tacctl-session -\n" +
		"tacctl-check pam-written tacctl-auth aaa\ntacctl-check pam-written tacctl-account bbb\ntacctl-check pam-written tacctl-session ccc\n" +
		"tacctl-check protocol 4\ntacctl-check key " + ed.String() + " root@web1\ntacctl-check key " + rsa.String() + " root@web1\n"
	out = plain(hs.run(hs.showRunner(ed, "", "", bad, 0), "host", "show", "web1", "--check"))
	for _, w := range []string{
		"  - group tac-users has GID 1001, not 80000. Fix: tacctl host sync web1\n",
		"  - group tac-superuser is missing. Fix: tacctl host sync web1\n",
		"  - group tac-engineer is missing. Fix: tacctl host sync web1\n",
		"  - alice has UID 80007, not 80000. Fix: tacctl host sync web1\n",
		"  - alice's home /home/alice is 0755, open to others (tacctl makes it private: 0700). Fix: tacctl host sync web1\n",
		"  - bob has no account. Fix: tacctl host sync web1\n",
		"  - carol has no account. Fix: tacctl host sync web1\n",
		"  - /etc/pam.d/tacctl-auth is not the text tacctl wrote there. Fix: tacctl host enroll admin@web1.example.net --name web1\n",
		"  - /etc/pam.d/tacctl-session is missing. Fix: tacctl host enroll admin@web1.example.net --name web1\n",
		"  - the host ran client script protocol 4; this tacctl writes " + hosts.ScriptProtocol + ". Fix: tacctl host sync web1\n",
		"  - the host has keys of types not pinned: RSA " + rsa.Fingerprint() + ". Fix: check on the host",
		"  11 differences.\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("bad lacks %q:\n%s", w, out)
		}
	}
	if hs.code != 1 {
		t.Errorf("bad: exit %d", hs.code)
	}
	// --json carries the findings under check.
	js := hs.run(hs.showRunner(ed, "", "", bad, 0), "host", "show", "web1", "--check", "--json")
	if hs.code != 1 || !strings.Contains(js, `"check": {`) || !strings.Contains(js, `"fix": "tacctl host sync web1"`) || !json.Valid([]byte(js)) {
		t.Errorf("json: %d\n%s", hs.code, js)
	}
	js = hs.run(hs.showRunner(ed, "", "", "Welcome to web1\n"+good, 0), "host", "show", "web1", "--check", "--json")
	if hs.code != 0 || !json.Valid([]byte(js)) || !strings.Contains(hs.err.String(), "Welcome to web1") {
		t.Errorf("json, good: %d\n%s\nstderr %s", hs.code, js, hs.err.String())
	}

	// Before 0.2.2 there is no record of the PAM text or the protocol.
	old := strings.NewReplacer("tacctl-check pam-written tacctl-auth aaa\ntacctl-check pam-written tacctl-account bbb\ntacctl-check pam-written tacctl-session ccc\n", "",
		"tacctl-check protocol "+hosts.ScriptProtocol, "tacctl-check protocol ").Replace(good)
	out = plain(hs.run(hs.showRunner(ed, "", "", old, 0), "host", "show", "web1", "--check"))
	if hs.code != 1 || !strings.Contains(out, "  - the host has no record of the client script protocol it ran (last enrolled or synced before 0.2.2). Fix: tacctl host sync web1\n") ||
		!strings.Contains(out, "  The PAM files are there; the host has no record of the text tacctl wrote (enrolled before 0.2.2)") ||
		!strings.Contains(out, "  1 difference.\n") {
		t.Errorf("old: %d\n%s", hs.code, out)
	}

	// The run fails (no terminal for a sudo password): nothing compared.
	hs.run(hs.showRunner(ed, "", "", "", 1), "host", "show", "web1", "--check")
	hs.expect(1, "", "Could not check web1: the read-only run as root on admin@web1.example.net failed (see above); nothing was compared.")
	if strings.Contains(hs.out.String(), "Host web1") {
		t.Errorf("printed after a failed check:\n%s", hs.out.String())
	}
}

// The engineer tier on a host: an engineer's account is in tac-users and
// tac-engineer there (a superuser's in tac-superuser), every tier's group on
// this server; --check reads who is in the sudo groups and flags an engineer
// left in tac-superuser, which only a sync from before the tier leaves.
func TestHostShowEngineer(t *testing.T) {
	hs := newHostSandbox(t)
	hs.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	if err := os.WriteFile(filepath.Join(hs.dir, "state", "linux-hosts"),
		[]byte("web1|admin@web1.example.net||lab|192.0.2.1|\nauthsrv|local||lab|127.0.0.1|\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := plain(hs.run(nil, "host", "show", "web1"))
	if hs.code != 0 || !strings.Contains(out, "  alice  superuser  UID -      tac-users, tac-superuser\n  bob    engineer   UID -      tac-users, tac-engineer\n  carol  readonly   UID -      tac-users\n") {
		t.Errorf("remote: %d\n%s", hs.code, out)
	}
	out = plain(hs.run(nil, "host", "show", "authsrv"))
	if !strings.Contains(out, "  bob    engineer   UID -      tac-users, tac-engineer, tac-console\n") {
		t.Errorf("local: %d\n%s", hs.code, out)
	}

	ed := hkKey(t, "ed25519")
	hs.run(hs.showRunner(ed, "", "", "", 0), "host", "sync", "web1")
	base := "tacctl-check group tac-users 80000\ntacctl-check group tac-superuser 80002\ntacctl-check group tac-engineer 80005\n" +
		"tacctl-check account alice 80000 80000 700 /home/alice\ntacctl-check account bob 80001 80000 700 /home/bob\n" +
		"tacctl-check account carol 80002 80000 700 /home/carol\n" +
		"tacctl-check pam tacctl-auth aaa\ntacctl-check pam tacctl-account bbb\ntacctl-check pam tacctl-session ccc\n" +
		"tacctl-check pam-written tacctl-auth aaa\ntacctl-check pam-written tacctl-account bbb\ntacctl-check pam-written tacctl-session ccc\n" +
		"tacctl-check protocol " + hosts.ScriptProtocol + "\ntacctl-check key " + ed.String() + " root@web1\n"
	// Engineers in tac-engineer, alice alone in tac-superuser: as it should be.
	out = plain(hs.run(hs.showRunner(ed, "", "", "tacctl-check members tac-superuser alice\ntacctl-check members tac-engineer bob\n"+base, 0), "host", "show", "web1", "--check"))
	if hs.code != 0 || !strings.Contains(out, "  web1 is as tacctl would make it.\n") {
		t.Errorf("good: %d\n%s", hs.code, out)
	}
	// An engineer still in tac-superuser (a superuser in tac-engineer is not a finding).
	out = plain(hs.run(hs.showRunner(ed, "", "", "tacctl-check members tac-superuser alice,bob\ntacctl-check members tac-engineer alice\n"+base, 0), "host", "show", "web1", "--check"))
	if hs.code != 1 || !strings.Contains(out, "  - bob is an engineer but is still in tac-superuser (full sudo; the engineer tier gets tac-engineer). Fix: tacctl host sync web1\n") ||
		strings.Contains(out, "alice is") || !strings.Contains(out, "  1 difference.\n") {
		t.Errorf("engineer in tac-superuser: %d\n%s", hs.code, out)
	}
}
