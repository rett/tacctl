package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// The emergency lockdown on the enrolled hosts (0.2.23, D309-D311), in-process
// on the host sandbox: alice (superuser), bob (operator) and carol (readonly)
// are in scope lab, and web1 and web2 are enrolled in it.

func lockdownHostSandbox(t *testing.T) *hostSandbox {
	t.Helper()
	hs := newHostSandbox(t)
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\nweb2|admin@web2.example.net||lab|192.0.2.1|\n", 0o600)
	return hs
}

// lockdown runs 'emergency lockdown <args>' on r, typing typed on a terminal.
func (hs *hostSandbox) lockdown(t *testing.T, r *fake.Runner, typed string, args ...string) string {
	t.Helper()
	hs.sandbox.tty = nil
	if typed != "" {
		holdTTY(t, hs.sandbox, typed)
	}
	out := plain(hs.run(r, append([]string{"emergency", "lockdown"}, args...)...))
	hs.sandbox.tty = nil
	return out
}

func sshCalls(r *fake.Runner) bool { return r.CalledRegexp(`^ssh `) }

// header is the part of a pushed or written script that the client script's
// own text does not mention: its variables.
func header(script string) string { return strings.SplitN(script, "# --- tacctl", 2)[0] }

// 'enable' changes the devices, then names the hosts and the command and asks
// whether to sync them; the hosts wait on the record's list, a sync that
// succeeds takes a host off it, and the sync of a host that waits ends the
// live sessions (on-end) once.
func TestLockdownEnableOffersTheHostSync(t *testing.T) {
	hs := lockdownHostSandbox(t)
	// the prompt says what the hosts get before the name is asked for
	out := hs.lockdown(t, nil, "", "lab", "enable", "--dry-run")
	for _, want := range []string{"Hosts (2): web1, web2.", "refuses key logins and every forwarding, and the live sessions end, for every account that is not a superuser's:", "    bob, carol."} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "does not name every group") {
		t.Errorf("a lockdown of every group is called partial:\n%s", out)
	}
	// a partial lockdown says plainly that the hosts lock everyone
	out = hs.lockdown(t, nil, "", "lab", "enable", "operator", "--dry-run")
	if want := "does not name every group of the scope's users. A host knows tiers, not the store's groups, so on the hosts it locks EVERY account that is not a superuser's, including carol, whose groups are not locked."; !strings.Contains(out, want) {
		t.Errorf("the partial lockdown is not said:\n%s", out)
	}

	// no sync is asked for: the answer is no
	r := hs.runner()
	out = hs.lockdown(t, r, "lab\nn\n", "lab", "enable", "--reason", "drill")
	if hs.code != 0 {
		t.Fatalf("enable: %d %q %q", hs.code, out, hs.stderr())
	}
	all := out + hs.stderr()
	for _, want := range []string{"Rendered: tacacs rendered and restarted",
		"[WARN] The lockdown has not reached 2 enrolled hosts (ssh key logins, forwarding and open sessions of the accounts that are not superusers stay open there): tacctl host sync web1 web2"} {
		if !strings.Contains(all, want) {
			t.Errorf("enable lacks %q:\n%s", want, all)
		}
	}
	if sshCalls(r) {
		t.Errorf("a host was reached without a yes: %q", r.Argvs())
	}
	if o := hs.overrides(); !strings.Contains(o, "pending:\n      - web1\n      - web2\n") {
		t.Errorf("the hosts are not on the record:\n%s", o)
	}
	if !hasAuditMatch(r, "auth.notice", `emergency lockdown enable scope=lab groups=operator,readonly exempt=alice reason="drill" by=root locked=2 hosts=2 result=ok`) {
		t.Errorf("no audit line of the enable: %v", r.Argvs())
	}
	if !hasAudit(r, "auth.notice", "emergency lockdown hosts action=enable scopes=lab hosts=web1,web2 synced=no pending=web1,web2 by=root") {
		t.Errorf("no audit line of the host step: %v", r.Argvs())
	}

	// status names the hosts and the command, in JSON too
	st := plain(hs.run(nil, "emergency", "lockdown", "status"))
	if want := "Hosts not locked yet (2 of 2): web1, web2: ssh keys and forwarding stay open there until: tacctl host sync web1 web2"; !strings.Contains(st, want) {
		t.Errorf("status lacks %q:\n%s", want, st)
	}
	var js []lockdownJSON
	if err := json.Unmarshal([]byte(hs.run(nil, "emergency", "lockdown", "status", "--json")), &js); err != nil || len(js) != 1 ||
		strings.Join(js[0].Hosts, ",") != "web1,web2" || strings.Join(js[0].PendingHosts, ",") != "web1,web2" {
		t.Errorf("status --json: %v %+v", err, js)
	}
	if got := plain(hs.run(nil, "config", "validate")); !strings.Contains(got, "sshd's lockdown drop-in of scope lab has not reached 2 enrolled hosts (web1, web2)") {
		t.Errorf("config validate:\n%s", got)
	}

	// the sync of a host that waits: the drop-in and the end of the sessions
	hs.run(nil, "host", "sync", "web1")
	hs.expect(0, "web1: synced", "")
	if !strings.Contains(header(hs.pushed), "\nTAC_LOCKDOWN=on-end\nTAC_PROTOCOL=7\n") {
		t.Errorf("the first sync's header:\n%s", header(hs.pushed))
	}
	if o := hs.overrides(); strings.Contains(o, "- web1") || !strings.Contains(o, "pending:\n      - web2\n") {
		t.Errorf("web1 is still on the list:\n%s", o)
	}
	// a later sync only keeps the drop-in: no session is ended again
	hs.run(nil, "host", "sync", "web1")
	hs.expect(0, "web1: synced", "")
	if !strings.Contains(header(hs.pushed), "\nTAC_LOCKDOWN=on\nTAC_PROTOCOL=7\n") {
		t.Errorf("the second sync's header:\n%s", header(hs.pushed))
	}
	// the last host completes the lockdown
	hs.run(nil, "host", "sync", "web2")
	hs.expect(0, "web2: synced", "")
	if o := hs.overrides(); strings.Contains(o, "pending") {
		t.Errorf("a settled lockdown keeps a list:\n%s", o)
	}
	st = plain(hs.run(nil, "emergency", "lockdown", "status"))
	if want := "Hosts (2): the sshd lockdown is in force on web1, web2."; !strings.Contains(st, want) {
		t.Errorf("status lacks %q:\n%s", want, st)
	}
	if strings.Contains(plain(hs.run(nil, "config", "validate")), "sshd's lockdown drop-in") {
		t.Error("config validate names a lockdown that is settled")
	}

	// a host enrolled again during the lockdown gets the drop-in
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--allow-uid-mismatch", "--remove-home", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled", "")
	if !strings.Contains(header(hs.pushed), "\nTAC_LOCKDOWN=on\nTAC_PROTOCOL=7\n") {
		t.Errorf("the enrolment's header:\n%s", header(hs.pushed))
	}
	if o := hs.overrides(); strings.Contains(o, "pending") {
		t.Errorf("an enrolled host waits:\n%s", o)
	}
}

// 'disable' with --yes syncs the hosts at once; a host that fails stays on the
// list as a lifted lockdown that status shows, and the next sync completes it.
func TestLockdownDisableSyncsAndKeepsWhatFails(t *testing.T) {
	hs := lockdownHostSandbox(t)
	hs.lockdown(t, nil, "lab\nn\n", "lab", "enable")
	if hs.code != 0 {
		t.Fatalf("enable: %d %q", hs.code, hs.stderr())
	}
	// 'enable' again, with --yes (it needs no terminal: nothing is locked
	// anew) offers the hosts that wait and syncs both: the lockdown is settled
	out0 := hs.lockdown(t, nil, "", "lab", "enable", "--yes")
	if hs.code != 0 || !strings.Contains(out0, "Already locked: operator, readonly on 'lab'. Nothing was changed.") || !strings.Contains(out0+hs.stderr(), "The lockdown is in force on the hosts.") {
		t.Fatalf("enable --yes: %d %q %q", hs.code, out0, hs.stderr())
	}
	if o := hs.overrides(); strings.Contains(o, "pending") || !strings.Contains(o, "groups:") {
		t.Fatalf("after the sync:\n%s", o)
	}
	if !strings.Contains(hs.pushed, "\nTAC_LOCKDOWN=on-end\n") {
		t.Errorf("the hosts were not given the lockdown:\n%s", header(hs.pushed))
	}

	// no terminal and no --yes: the notice, and nothing is sent
	r := hs.runner()
	out := hs.lockdown(t, r, "", "lab", "disable")
	if hs.code != 0 || !strings.Contains(out+hs.stderr(), "[WARN] sshd's lockdown drop-in is still on 2 enrolled hosts: tacctl host sync web1 web2") {
		t.Fatalf("disable: %d %q %q", hs.code, out, hs.stderr())
	}
	if sshCalls(r) {
		t.Errorf("a host was reached with no terminal: %q", r.Argvs())
	}
	o := hs.overrides()
	if strings.Contains(o, "groups:") || !strings.Contains(o, "pending:\n      - web1\n      - web2\n") {
		t.Errorf("a lifted lockdown is not on the list:\n%s", o)
	}
	st := plain(hs.run(nil, "emergency", "lockdown", "status"))
	if want := "The lockdown of scope 'lab' is lifted, but sshd's lockdown drop-in is still on 2 enrolled hosts (web1, web2): tacctl host sync web1 web2"; !strings.Contains(st, want) || !strings.Contains(st, "No emergency lockdown stands.") {
		t.Errorf("status:\n%s", st)
	}
	// nothing locks on the devices any more: a rollback and the red line are
	// not about it, the validator is
	if strings.Contains(hs.stderr(), "EMERGENCY LOCKDOWN") {
		t.Errorf("a lifted lockdown is shown as standing: %q", hs.stderr())
	}
	if got := plain(hs.run(nil, "config", "validate")); !strings.Contains(got, "sshd's lockdown drop-in of scope lab is still on 2 enrolled hosts (web1, web2)") {
		t.Errorf("config validate:\n%s", got)
	}

	// --yes, and the hosts fail: they stay
	hs.runFails = true
	out = hs.lockdown(t, nil, "", "lab", "disable", "--yes")
	hs.runFails = false
	all := out + hs.stderr()
	if hs.code != 0 || !strings.Contains(all, "web1: sync failed") || !strings.Contains(all, "2 enrolled hosts not settled (web1, web2;") {
		t.Fatalf("disable --yes with failing hosts: %d\n%s", hs.code, all)
	}
	if o = hs.overrides(); !strings.Contains(o, "pending:\n      - web1\n      - web2\n") {
		t.Errorf("failed hosts left the list:\n%s", o)
	}
	// a later sync of one host takes it off; the lifted header has no variable
	hs.run(nil, "host", "sync", "web1")
	hs.expect(0, "web1: synced", "")
	if strings.Contains(header(hs.pushed), "TAC_LOCKDOWN") {
		t.Errorf("a lifted lockdown's header has the variable:\n%s", header(hs.pushed))
	}
	if o = hs.overrides(); strings.Contains(o, "- web1") || !strings.Contains(o, "- web2") {
		t.Errorf("after web1:\n%s", o)
	}
	// 'disable' again offers the host that is left, and the last one ends the record
	r = hs.runner()
	out = hs.lockdown(t, r, "", "lab", "disable", "--yes")
	if hs.code != 0 || !strings.Contains(out, "No lockdown stands on 'lab' for those groups. Nothing was changed.") || !strings.Contains(out+hs.stderr(), "The lockdown is lifted on the hosts.") {
		t.Fatalf("disable again: %d %q %q", hs.code, out, hs.stderr())
	}
	if o = hs.overrides(); strings.Contains(o, "emergency") {
		t.Errorf("a settled lift keeps its record:\n%s", o)
	}
	if !hasAudit(r, "auth.notice", "emergency lockdown hosts action=disable scopes=lab hosts=web2 synced=yes pending=- by=root") {
		t.Errorf("no audit line of the host step: %v", r.Argvs())
	}
}

// A host that is held is not logged in to: it is said, and stays waiting. A
// host forgotten or renamed leaves or follows the list.
func TestLockdownListFollowsHosts(t *testing.T) {
	hs := lockdownHostSandbox(t)
	hs.lockdown(t, nil, "lab\nn\n", "lab", "enable")
	if hs.code != 0 {
		t.Fatalf("enable: %d %q", hs.code, hs.stderr())
	}
	hs.run(nil, "host", "rename", "web2", "web9", "--yes")
	hs.expect(0, "renamed to 'web9'", "")
	if o := hs.overrides(); !strings.Contains(o, "- web1\n      - web9\n") || strings.Contains(o, "web2") {
		t.Errorf("rename:\n%s", o)
	}
	hs.run(nil, "host", "forget", "web1", "--yes")
	hs.expect(0, "forgotten", "")
	if o := hs.overrides(); strings.Contains(o, "web1") || !strings.Contains(o, "- web9") {
		t.Errorf("forget:\n%s", o)
	}
	hs.run(nil, "host", "forget", "web9", "--yes")
	if o := hs.overrides(); strings.Contains(o, "pending") || !strings.Contains(o, "groups:") {
		t.Errorf("the last host:\n%s", o)
	}
	// a host the lockdown had reached keeps the drop-in when it is forgotten, and the forget says so
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	hs.run(nil, "host", "sync", "web1")
	hs.run(nil, "host", "forget", "web1", "--yes")
	if !strings.Contains(hs.stderr()+hs.out.String(), "web1 keeps sshd's emergency-lockdown drop-in") {
		t.Errorf("forget says nothing of the drop-in: %d %q", hs.code, hs.stderr())
	}
}

// A script written by hand for a locked scope carries the state, and one for a
// scope that is not locked does not.
func TestLockdownStateInAHandWrittenScript(t *testing.T) {
	hs := lockdownHostSandbox(t)
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "--output", hs.path("lab.sh"))
	if hs.code != 0 || strings.Contains(header(hs.read("lab.sh")), "TAC_LOCKDOWN") {
		t.Fatalf("before: %d %q", hs.code, hs.stderr())
	}
	hs.lockdown(t, nil, "lab\nn\n", "lab", "enable")
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "--output", hs.path("lab2.sh"))
	if hs.code != 0 || !strings.Contains(header(hs.read("lab2.sh")), "\nTAC_LOCKDOWN=on\nTAC_PROTOCOL=7\n") {
		t.Errorf("a locked scope: %d %q", hs.code, hs.stderr())
	}
}

// A sync that ends clears its host only when its script was written for what
// the record says now: one that started before a 'disable' (sent on or on-end)
// must not clear the host the 'disable' listed, nor a lift's (sent "") a
// lockdown that came back meanwhile.
func TestLockdownImpliedState(t *testing.T) {
	standing := conf.Lockdown{Scope: "lab", Groups: []string{"operator"}, Pending: []string{"web1"}}
	lifted := conf.Lockdown{Scope: "lab", Pending: []string{"web1", "web2"}}
	for _, tc := range []struct {
		name string
		l    conf.Lockdown
		host string
		want string
	}{
		{"a host that waits for the start", standing, "web1", hosts.LockdownOnEnd},
		{"a host that has it", standing, "web2", hosts.LockdownOn},
		{"a script written by hand", standing, "", hosts.LockdownOn},
		{"a lifted lockdown, a host that waits to drop it", lifted, "web1", ""},
		{"a lifted lockdown, another host", lifted, "web9", ""},
	} {
		if got := lockdownImplied(tc.l, tc.host); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A full 'disable' lists every enrolled host of the scope, the ones that were
// waiting for the start too: a listed host may hold the file (a run that
// failed after the script wrote it), and a sync of a host without it removes
// nothing.
func TestLockdownDisableListsEveryHost(t *testing.T) {
	hs := lockdownHostSandbox(t)
	hs.lockdown(t, nil, "lab\nn\n", "lab", "enable")
	hs.run(nil, "host", "sync", "web1")
	hs.expect(0, "web1: synced", "")
	if o := hs.overrides(); strings.Contains(o, "- web1") || !strings.Contains(o, "- web2") {
		t.Fatalf("setup:\n%s", o)
	}
	hs.lockdown(t, nil, "", "lab", "disable")
	if hs.code != 0 {
		t.Fatalf("disable: %d %q", hs.code, hs.stderr())
	}
	if o := hs.overrides(); strings.Contains(o, "groups:") || !strings.Contains(o, "pending:\n      - web1\n      - web2\n") {
		t.Errorf("the lifted record does not list both hosts:\n%s", o)
	}
}

// A host moved into a scope that is locked down gets the step that ends the
// sessions; moved out of one, it leaves the list instead of blocking a rollback.
func TestLockdownHostMove(t *testing.T) {
	hs := lockdownHostSandbox(t)
	// one host at a time: the stand-in resolver gives every name one address
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	hs.lockdown(t, nil, "prod\nn\n", "prod", "enable")
	if hs.code != 0 {
		t.Fatalf("enable: %d %q", hs.code, hs.stderr())
	}
	hs.run(nil, "host", "move", "web1", "prod", "--yes")
	hs.expect(0, "Host 'web1' enrolled", "")
	if !strings.Contains(header(hs.pushed), "\nTAC_LOCKDOWN=on-end\nTAC_PROTOCOL=7\n") {
		t.Errorf("the move's header:\n%s", header(hs.pushed))
	}
	if o := hs.overrides(); strings.Contains(o, "- web1") {
		t.Errorf("the moved host waits in a list:\n%s", o)
	}
	// out of a locked scope into one that is not: no stale name, and the
	// script removes the file
	hs.lockdown(t, nil, "", "prod", "disable")
	hs.write("state/linux-hosts", "web2|admin@web2.example.net||lab|192.0.2.1|\n", 0o600)
	hs.lockdown(t, nil, "lab\nn\n", "lab", "enable")
	if o := hs.overrides(); !strings.Contains(o, "- web2") {
		t.Fatalf("lab:\n%s", o)
	}
	hs.run(nil, "host", "move", "web2", "dmz", "--yes")
	hs.expect(0, "Host 'web2' enrolled", "")
	if strings.Contains(header(hs.pushed), "TAC_LOCKDOWN") {
		t.Errorf("web2 moved out of locked lab into dmz:\n%s", header(hs.pushed))
	}
	if o := hs.overrides(); strings.Contains(o, "web2") {
		t.Errorf("web2 stays on a list:\n%s", o)
	}
}

// A restore of a snapshot taken before a lockdown, while the hosts hold the
// file, leaves a lifted record that lists them, so the next sync removes it.
func TestLockdownRestoreListsTheHosts(t *testing.T) {
	hs := lockdownHostSandbox(t)
	hs.lockdown(t, nil, "lab\nn\n", "lab", "enable")
	hs.run(nil, "host", "sync", "web1", "web2")
	hs.expect(0, "web2: synced", "")
	if o := hs.overrides(); strings.Contains(o, "pending") {
		t.Fatalf("setup:\n%s", o)
	}
	// the snapshot the enable took first has no lockdown
	var id string
	for _, d := range hs.snapshotDirs() {
		if !strings.Contains(readIn(t, d, "tacctl.yaml"), "emergency") {
			id = filepath.Base(d)
		}
	}
	if id == "" {
		t.Fatal("no snapshot without the lockdown")
	}
	hs.stdin = "y\n"
	out := plain(hs.run(nil, "backup", "restore", id))
	hs.stdin = ""
	if hs.code != 0 {
		t.Fatalf("restore: %d %q %q", hs.code, out, hs.stderr())
	}
	o := hs.overrides()
	if strings.Contains(o, "groups:") || !strings.Contains(o, "pending:\n      - web1\n      - web2\n") {
		t.Errorf("the restored state does not list the hosts that hold the file:\n%s", o)
	}
	if all := out + hs.stderr(); !strings.Contains(all, "sshd's lockdown drop-in on 2 enrolled hosts (web1, web2) follows the restored lockdown record only at their next sync: tacctl host sync web1 web2") {
		t.Errorf("the restore does not say so:\n%s", all)
	}
	// the sync removes the file's reason: the record goes with the last host
	hs.run(nil, "host", "sync", "web1", "web2")
	hs.expect(0, "web2: synced", "")
	if strings.Contains(hs.overrides(), "emergency") {
		t.Errorf("the lifted record stays:\n%s", hs.overrides())
	}
}

// 'host show --check' compares sshd's lockdown drop-in with the scope's state.
func TestHostCheckComparesTheLockdownDropIn(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	ed := hkKey(t, "ed25519")
	hs.run(hs.showRunner(ed, showFacts, "", "", 0), "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	base := "tacctl-check group tac-users 80000\ntacctl-check group tac-superuser 80002\ntacctl-check group tac-engineer 80005\n" +
		"tacctl-check account alice 80000 80000 700 /home/alice\ntacctl-check account bob 80001 80000 700 /home/bob\n" +
		"tacctl-check account carol 80002 80000 700 /home/carol\n" +
		"tacctl-check pam tacctl-auth aaa\ntacctl-check pam tacctl-account bbb\ntacctl-check pam tacctl-session ccc\n" +
		"tacctl-check pam-written tacctl-auth aaa\ntacctl-check pam-written tacctl-account bbb\ntacctl-check pam-written tacctl-session ccc\n" +
		"tacctl-check protocol " + hosts.ScriptProtocol + "\ntacctl-check key " + ed.String() + " root@web1\n"
	check := func(state string) string {
		return plain(hs.run(hs.showRunner(ed, "", "", base+state, 0), "host", "show", "web1", "--check"))
	}
	// not locked down: absent is right, present is a difference
	if out := check("tacctl-check lockdown absent\n"); !strings.Contains(out, "web1 is as tacctl would make it.") {
		t.Errorf("absent, not locked:\n%s", out)
	}
	if out := check("tacctl-check lockdown present\n"); !strings.Contains(out, "  - the host has sshd's lockdown drop-in, but scope lab is not locked down. Fix: tacctl host sync web1\n") {
		t.Errorf("present, not locked:\n%s", out)
	}
	if out := check("tacctl-check lockdown unreloaded\n"); !strings.Contains(out, "  - the host's lockdown drop-in was removed but sshd was not told to reload it, so it may still enforce the lockdown. Fix: tacctl host sync web1\n") {
		t.Errorf("unreloaded:\n%s", out)
	}
	hs.lockdown(t, nil, "lab\nn\n", "lab", "enable")
	if out := check("tacctl-check lockdown absent\n"); !strings.Contains(out, "  - scope lab is locked down, but the host has no lockdown drop-in (key logins and forwarding are open there). Fix: tacctl host sync web1\n") {
		t.Errorf("absent, locked:\n%s", out)
	}
	if out := check("tacctl-check lockdown present\n"); !strings.Contains(out, "web1 is as tacctl would make it.") {
		t.Errorf("present, locked:\n%s", out)
	}
	// a host a sync cannot lock down says why, not "sync"
	if out := check("tacctl-check lockdown noinclude\n"); !strings.Contains(out, "the host's sshd_config does not include sshd_config.d, so the lockdown cannot be applied (key logins and forwarding are open there). Fix: add the Include line (OpenSSH 8.2 or later) or close those logins another way, then: tacctl host sync web1\n") {
		t.Errorf("noinclude:\n%s", out)
	}
	if out := check("tacctl-check lockdown nosshd\n"); !strings.Contains(out, "web1 is as tacctl would make it.") || !strings.Contains(out, "web1 has no sshd, so there is no ssh login to close") {
		t.Errorf("nosshd:\n%s", out)
	}
	// provisioned through a tacctl user that is not a superuser: the sync refuses it
	hs.write("state/linux-hosts", "web1|bob@web1.example.net||lab|192.0.2.1|\n", 0o600)
	if out := check("tacctl-check lockdown absent\n"); !strings.Contains(out, "the host is provisioned through 'bob', a tacctl user that is not a superuser, so the sync refuses to lock it down (it would close its own key). Fix: enroll it through a local account: tacctl host enroll <account>@<host> --name web1\n") {
		t.Errorf("provisioner:\n%s", out)
	}
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	// a host that ran an earlier script says nothing: no comparison
	if out := check(""); !strings.Contains(out, "web1 is as tacctl would make it.") {
		t.Errorf("no word:\n%s", out)
	}
}
