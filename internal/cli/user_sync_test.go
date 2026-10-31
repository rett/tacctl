package cli

// The user verbs sync this server's own accounts at once (D313): the
// accounts-only script runs locally after the store write, once per verb,
// with one INFO line for the result; a server that is not enrolled prints
// nothing about it; a sync that fails is a WARN with the retry command and
// the verb exits 0; the verbs that change no account do not sync.

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// syncRunner is a runner whose local sync prints out; seen, when set, is
// called with the text of the store and the script each time the script runs.
func (hs *hostSandbox) syncRunner(out string, seen func(store, script string)) *fake.Runner {
	r := hs.runner()
	r.OnFunc([]string{"bash"}, func(c execx.Cmd) (execx.Result, error) {
		if seen != nil {
			script, _ := os.ReadFile(c.Args[0])
			seen(hs.read("state/store.yaml"), string(script))
		}
		return execx.Result{Stdout: []byte(out)}, nil
	})
	return r
}

// userSyncSandbox is the sandbox with this server enrolled in scope lab.
func userSyncSandbox(t *testing.T) *hostSandbox {
	t.Helper()
	return hostLowerSandbox(t)
}

const syncAccounts = "[INFO] Accounts: 3 managed by tacctl here.\n"

// Each verb that changes an account here runs the sync once, after the store
// is written, and says what it did in one line.
func TestUserVerbsSyncThisServer(t *testing.T) {
	h := hashOf(t, "CorrectHorse99")
	for _, c := range []struct {
		name  string
		setup func(*hostSandbox)
		args  []string
		stdin string
		out   string // what the script reports
		want  string // the INFO line
		store string // in the store when the script runs
		users string // in the script's user list
	}{
		{name: "add", args: []string{"user", "add", "dave", "operator", "--hash", h, "--scopes", "lab"},
			out: "[INFO] Created account 'dave' (UID 80000)\n" + syncAccounts, want: "This server's accounts were synced: 1 created (UID 80003).", store: "dave:", users: "dave:operator:"},
		{name: "rename", args: []string{"user", "rename", "bob", "robert"},
			out: "[INFO] 'bob' is now 'robert' (renamed; home kept)\n" + syncAccounts, want: "This server's accounts were synced: 1 renamed.", store: "robert:", users: "robert:operator:"},
		{name: "disable", args: []string{"user", "disable", "bob"},
			out: "[INFO] 'bob' has no tacctl login here now\n" + syncAccounts, want: "This server's accounts were synced: 1 updated.", store: "disabled: true", users: "TAC_INACTIVE=bob"},
		{name: "remove", args: []string{"user", "remove", "carol"}, stdin: "y\n",
			out: "[INFO] Deleted account 'carol'\n" + syncAccounts, want: "This server's accounts were synced: 1 removed."},
		{name: "move", args: []string{"user", "move", "bob", "readonly"},
			want: "This server's accounts were synced: no account changed.", out: syncAccounts, store: "group: readonly"},
		{name: "scope add", args: []string{"user", "scope", "bob", "add", "dmz"},
			want: "This server's accounts were synced: no account changed.", out: syncAccounts},
		{name: "scope remove --all", args: []string{"user", "scope", "bob", "remove", "--all"}, stdin: "y\n",
			want: "This server's accounts were synced: no account changed.", out: syncAccounts},
		{name: "require-password-change", args: []string{"user", "require-password-change", "bob"},
			want: "This server's accounts were synced: no account changed.", out: syncAccounts, store: "password_change_required: true"},
		{name: "enable", setup: func(hs *hostSandbox) { hs.run(hs.syncRunner(syncAccounts, nil), "user", "disable", "bob") },
			args: []string{"user", "enable", "bob"}, want: "This server's accounts were synced: no account changed.", out: syncAccounts},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := userSyncSandbox(t)
			if c.setup != nil {
				c.setup(hs)
			}
			hs.stdin = c.stdin
			stored, script := "", ""
			r := hs.syncRunner(c.out, func(s, sc string) { stored, script = s, sc })
			hs.run(r, c.args...)
			all := plain(hs.out.String() + hs.err.String())
			if hs.code != 0 || !strings.Contains(all, "[INFO] "+c.want) || r.Count("bash") != 1 {
				t.Fatalf("%d, %d scripts\n%s", hs.code, r.Count("bash"), all)
			}
			if c.store != "" && !strings.Contains(stored, c.store) {
				t.Errorf("the script ran before the store held %q:\n%s", c.store, stored)
			}
			if !strings.Contains(script, c.users) {
				t.Errorf("the script was built from a model before the change (want %q):\n%s", c.users, script)
			}
			// the script's own lines are held back
			if strings.Contains(all, "Accounts: 3 managed") || strings.Contains(all, "authsrv: synced") {
				t.Errorf("the sync's lines are shown:\n%s", all)
			}
			// the sync takes no snapshot of its own
			if n := strings.Count(all, "Config snapshot saved"); n > 1 {
				t.Errorf("%d snapshots:\n%s", n, all)
			}
		})
	}
}

// The sync comes after the INFO line of the change, and a reset syncs only
// when it enables a disabled user.
func TestUserPasswdSyncsOnlyAnEnabledAccount(t *testing.T) {
	h := hashOf(t, "CorrectHorse99")
	hs := userSyncSandbox(t)
	r := hs.syncRunner(syncAccounts, nil)
	hs.run(r, "user", "passwd", "bob", "--hash", h)
	if hs.code != 0 || r.Count("bash") != 0 || strings.Contains(plain(hs.out.String()+hs.err.String()), "synced") {
		t.Errorf("a reset of an enabled user: %d %d\n%s", hs.code, r.Count("bash"), hs.out.String())
	}
	hs.run(hs.syncRunner(syncAccounts, nil), "user", "disable", "bob")
	r = hs.syncRunner(syncAccounts, nil)
	hs.run(r, "user", "passwd", "bob", "--hash", h)
	if hs.code != 0 || r.Count("bash") != 1 || !strings.Contains(plain(hs.out.String()), "This server's accounts were synced") {
		t.Errorf("a reset of a disabled user: %d %d\n%s", hs.code, r.Count("bash"), hs.out.String())
	}
}

// The verbs that change no account, and the changes that write nothing, do
// not sync.
func TestUserVerbsThatChangeNoAccountDoNotSync(t *testing.T) {
	hs := userSyncSandbox(t)
	for _, args := range [][]string{
		{"user", "list"}, {"user", "show", "bob"}, {"user", "scope", "bob", "list"},
		{"user", "email", "bob", "bob@example.net"}, {"user", "move", "bob", "operator"},
		{"user", "remove", "carol"}, {"user", "scope", "bob", "remove", "--all"},
		{"user", "enable", "bob"}, {"user", "scope", "bob", "add", "lab"},
		{"user", "require-password-change", "bob", "off"},
	} {
		// a cancelled remove and a cancelled remove --all are answered no
		hs.stdin = "n\n"
		r := hs.syncRunner(syncAccounts, nil)
		hs.run(r, args...)
		if r.Count("bash") != 0 || strings.Contains(plain(hs.out.String()+hs.err.String()), "synced") {
			t.Errorf("%v synced:\n%s%s", args, hs.out.String(), hs.err.String())
		}
	}
	if st := hs.read("state/store.yaml"); !strings.Contains(st, "  carol:") {
		t.Errorf("the cancelled remove removed carol:\n%s", st)
	}
}

// A server that is not enrolled says nothing about a sync.
func TestUserVerbWithoutAnEnrolledServerSaysNothingOfASync(t *testing.T) {
	hs := userSyncSandbox(t)
	hs.write("state/linux-hosts", "", 0o600)
	r := hs.syncRunner(syncAccounts, nil)
	hs.run(r, "user", "disable", "bob")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || r.Count("bash") != 0 || strings.Contains(all, "sync") {
		t.Errorf("%d %d\n%s", hs.code, r.Count("bash"), all)
	}
}

// A sync that fails is one warning with the retry command; the store change
// stands and the verb exits 0. What the script printed on stderr is its
// detail, plain lines under the warning: no second level.
func TestUserVerbWarnsWhenTheSyncFails(t *testing.T) {
	hs := userSyncSandbox(t)
	r := hs.runner()
	r.OnFunc([]string{"bash"}, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Code: 1, Stderr: []byte("[ERROR] no free UID\n")}, nil
	})
	hs.run(r, "user", "disable", "bob")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "[WARN] This server's accounts were not synced; the change reaches them at the next sync: tacctl host sync authsrv\n") || !strings.Contains(all, "\n  no free UID\n") ||
		strings.Contains(all, "[INFO] This server's accounts were synced") || strings.Contains(all, "[ERROR]") {
		t.Errorf("%d\n%s", hs.code, all)
	}
	if !strings.Contains(hs.read("state/store.yaml"), "disabled: true") {
		t.Error("the store change was lost")
	}
}

// The script's warnings are shown after the line; its other lines are not.
func TestUserVerbShowsTheWarningsOfTheSync(t *testing.T) {
	hs := userSyncSandbox(t)
	r := hs.syncRunner("[INFO] busy work\n[WARN] a local account named 'bob' was not made by tacctl\n"+syncAccounts, nil)
	hs.run(r, "user", "disable", "bob")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "[WARN] a local account named 'bob' was not made by tacctl") || strings.Contains(all, "busy work") {
		t.Errorf("%d\n%s", hs.code, all)
	}
}

// One sync for a bulk verb.
func TestRequirePasswordChangeForAllSyncsOnce(t *testing.T) {
	hs := userSyncSandbox(t)
	r := hs.syncRunner(syncAccounts, nil)
	hs.run(r, "user", "require-password-change", "--all")
	if hs.code != 0 || r.Count("bash") != 1 {
		t.Errorf("%d, %d scripts\n%s", hs.code, r.Count("bash"), hs.out.String()+hs.err.String())
	}
}
