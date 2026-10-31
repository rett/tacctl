package cli

// The notices of a user change (D313): this server's accounts are synced at
// once, the other enrolled hosts the change reaches are named in one WARN
// with the command, a terminal is asked whether to sync them now (never
// answered by --yes), and a fact is said once.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/testpty"
)

// userHostsSandbox is the sandbox with this server enrolled in scope lab and
// web1 enrolled in it too.
func userHostsSandbox(t *testing.T) *hostSandbox {
	t.Helper()
	hs := hostLowerSandbox(t)
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	hs.pushed = ""
	return hs
}

// answerOn gives the sandbox a terminal and types line on it.
func (hs *hostSandbox) answerOn(line string) {
	hs.t.Helper()
	master, slave, err := testpty.Open()
	if err != nil {
		hs.t.Skip("no pty:", err)
	}
	hs.t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	hs.sandbox.tty = slave
	// What a fake command reads of the terminal (the runner's Run drains its
	// standard input) ends at an end-of-file character after the answer.
	if _, err := master.WriteString(line + strings.Repeat("\x04", 32)); err != nil {
		hs.t.Fatal(err)
	}
}

// localRunner is a runner whose local sync succeeds.
func (hs *hostSandbox) localRunner() *fake.Runner { return hs.lowerRunner() }

// Every verb that changes an account names the other hosts it reaches in one
// WARN with the command, and without a terminal asks nothing and syncs none.
func TestUserChangeNamesTheOtherHostsAndAsksNothingWithoutATerminal(t *testing.T) {
	h := hashOf(t, "CorrectHorse99")
	for _, c := range []struct {
		name  string
		setup []string
		args  []string
		stdin string
		want  string
	}{
		{name: "add", args: []string{"user", "add", "dave", "operator", "--hash", h, "--scopes", "lab"},
			want: "[WARN] 'dave' gets an account on 1 enrolled host at each host's next sync: tacctl host sync web1"},
		{name: "remove", args: []string{"user", "remove", "carol"}, stdin: "y\n",
			want: "[WARN] 'carol' keeps its account on 1 enrolled host until each host's next sync, which removes it: tacctl host sync web1"},
		{name: "rename", args: []string{"user", "rename", "bob", "robert"},
			want: ""},
		{name: "move", args: []string{"user", "move", "bob", "readonly"},
			want: "[WARN] The group of 'bob' changes on 1 enrolled host at each host's next sync: tacctl host sync web1"},
		{name: "disable", args: []string{"user", "disable", "bob"},
			want: "[WARN] 'bob' can still log in to 1 enrolled host until each host's next sync, which expires the account there: tacctl host sync web1"},
		{name: "enable", setup: []string{"user", "disable", "bob"}, args: []string{"user", "enable", "bob"},
			want: "[WARN] 'bob' can log in to 1 enrolled host again after each host's next sync: tacctl host sync web1"},
		{name: "scope", args: []string{"user", "scope", "bob", "replace", "prod"},
			want: "[WARN] The account of 'bob' on 1 enrolled host follows the new scopes at each host's next sync: tacctl host sync web1"},
		{name: "scope remove --all", args: []string{"user", "scope", "bob", "remove", "--all"}, stdin: "y\n",
			want: "[WARN] The account of 'bob' on 1 enrolled host follows the new scopes at each host's next sync: tacctl host sync web1"},
		{name: "require-password-change", args: []string{"user", "require-password-change", "bob"},
			want: "[WARN] 'bob' can still log in to 1 enrolled host until each host's next sync, which expires the account there: tacctl host sync web1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := userHostsSandbox(t)
			if c.setup != nil {
				hs.run(hs.localRunner(), c.setup...)
			}
			hs.stdin = c.stdin
			hs.run(hs.localRunner(), c.args...)
			all := plain(hs.out.String() + hs.err.String())
			if hs.code != 0 || strings.Count(all, "tacctl host sync web1") > 1 || strings.Contains(all, "Sync these hosts now") || hs.pushed != "" {
				t.Fatalf("exit %d, pushed %q\n%s", hs.code, hs.pushed, all)
			}
			if c.want != "" && !strings.Contains(all, c.want) {
				t.Errorf("no %q:\n%s", c.want, all)
			}
		})
	}
}

// A rename carries the UID in the ledger, so the hosts rename the account.
func TestUserRenameNamesTheOtherHostsThatRenameTheAccount(t *testing.T) {
	hs := userHostsSandbox(t)
	hs.run(hs.localRunner(), "user", "rename", "bob", "robert")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "[WARN] The account 'bob' is renamed to 'robert' on 1 enrolled host at each host's next sync, home kept where it is: tacctl host sync web1") {
		t.Errorf("rename: %d\n%s", hs.code, all)
	}
}

// A host outside the user's scopes is not named.
func TestUserChangeDoesNotNameAHostWithoutTheUser(t *testing.T) {
	hs := userHostsSandbox(t)
	hs.run(hs.localRunner(), "user", "add", "dave", "operator", "--hash", hashOf(t, "CorrectHorse99"), "--scopes", "dmz")
	if all := plain(hs.out.String() + hs.err.String()); hs.code != 0 || strings.Contains(all, "web1") {
		t.Errorf("%d\n%s", hs.code, all)
	}
}

// Many hosts: the command is --all.
func TestUserChangeNamesAllWhenManyHostsAreReached(t *testing.T) {
	hs := userHostsSandbox(t)
	reg := hs.registry()
	for i, n := range []string{"web2", "web3", "web4", "web5"} {
		reg += n + "|" + n + "||lab|192.0.2." + strconv.Itoa(i+2) + "|\n"
	}
	hs.write("state/linux-hosts", reg, 0o600)
	hs.run(hs.localRunner(), "user", "disable", "bob")
	if all := plain(hs.out.String() + hs.err.String()); hs.code != 0 || !strings.Contains(all, "until each host's next sync, which expires the account there: tacctl host sync --all") ||
		!strings.Contains(all, "5 enrolled hosts") {
		t.Errorf("%d\n%s", hs.code, all)
	}
}

// On a terminal the verb asks; no leaves the hosts as they were, yes syncs
// just those hosts and says so.
func TestUserChangeOffersToSyncTheOtherHostsOnATerminal(t *testing.T) {
	hs := userHostsSandbox(t)
	hs.answerOn("n\n")
	hs.run(hs.localRunner(), "user", "disable", "bob")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Sync these hosts now? [y/N]: ") || hs.pushed != "" || strings.Contains(all, "enrolled hosts were synced") || strings.Contains(all, "enrolled host was synced") {
		t.Fatalf("no: %d, pushed %q\n%s", hs.code, hs.pushed, all)
	}

	hs = userHostsSandbox(t)
	hs.run(hs.localRunner(), "user", "disable", "bob")
	hs.pushed = ""
	hs.answerOn("y\n")
	hs.run(hs.localRunner(), "user", "enable", "bob")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Sync these hosts now? [y/N]: ") || !strings.Contains(all, "[INFO] 1 enrolled host was synced.") ||
		!strings.Contains(hs.pushed, "TAC_USERS=") {
		t.Fatalf("yes: %d, pushed %q\n%s", hs.code, hs.pushed, all)
	}
	// the sync of this server came first, in its own line
	if i, j := strings.Index(all, "This server's accounts were synced"), strings.Index(all, "1 enrolled host was synced."); i < 0 || j < i {
		t.Errorf("order:\n%s", all)
	}
}

// The answer is never taken from --yes or any option: the terminal is asked,
// and without one nothing is asked.
func TestUserChangeNeverTakesTheAnswerFromYes(t *testing.T) {
	hs := userHostsSandbox(t)
	hs.answerOn("n\n")
	hs.run(hs.localRunner(), "user", "disable", "bob", "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Sync these hosts now? [y/N]: ") || hs.pushed != "" {
		t.Errorf("--yes on a terminal: %d, pushed %q\n%s", hs.code, hs.pushed, all)
	}
	hs = userHostsSandbox(t)
	hs.stdin = "y\n"
	hs.run(hs.localRunner(), "user", "disable", "bob", "--yes")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || strings.Contains(all, "Sync these hosts now") || hs.pushed != "" || !strings.Contains(all, "tacctl host sync web1") {
		t.Errorf("--yes without a terminal: %d, pushed %q\n%s", hs.code, hs.pushed, all)
	}
}

// A fact is said once: the password-change rule of a new user is one line,
// no line is repeated and the sync of this server is named only to retry it.
func TestUserVerbsSayAFactOnce(t *testing.T) {
	h := hashOf(t, "CorrectHorse99")
	for _, args := range [][]string{
		{"user", "add", "dave", "operator", "--hash", h, "--scopes", "lab"},
		{"user", "require-password-change", "--all"},
		{"user", "rename", "bob", "robert"},
		{"user", "passwd", "bob", "--hash", h},
		{"user", "disable", "bob"},
		{"user", "move", "bob", "readonly"},
	} {
		hs := userHostsSandbox(t)
		hs.run(hs.localRunner(), args...)
		all := plain(hs.out.String() + hs.err.String())
		seen := map[string]bool{}
		for _, l := range strings.Split(all, "\n") {
			if l = strings.TrimSpace(l); l == "" {
				continue
			}
			if seen[l] {
				t.Errorf("%v: the line is repeated: %s", args, l)
			}
			seen[l] = true
		}
		if n := strings.Count(all, "must change the password at the") + strings.Count(all, "must change it at the"); n > 1 {
			t.Errorf("%v: the password-change rule is said %d times:\n%s", args, n, all)
		}
		for _, l := range strings.Split(all, "\n") {
			if strings.Contains(l, "[INFO]") && strings.Contains(l, "next sync") || strings.Contains(l, "[WARN]") && strings.Contains(l, "cannot log in") {
				t.Errorf("%v: a notice at the wrong level or an old one: %s", args, l)
			}
		}
		if strings.Contains(all, "@") {
			t.Errorf("%v: an address in the messages:\n%s", args, all)
		}
	}
}

// A host is named only when its own account of the user changes: a flagged
// user's account is expired on the other hosts already, so disabling or
// enabling the user changes nothing there, and a reset of a disabled user
// that flags it leaves the expired account as it was.
func TestUserChangeNamesNoHostWhoseAccountStaysAsItWas(t *testing.T) {
	h := hashOf(t, "CorrectHorse99")
	for _, c := range []struct {
		name  string
		setup [][]string
		args  []string
	}{
		{"disable a flagged user", [][]string{{"user", "require-password-change", "bob"}}, []string{"user", "disable", "bob"}},
		{"enable a user who is still flagged", [][]string{{"user", "require-password-change", "bob"}, {"user", "disable", "bob"}}, []string{"user", "enable", "bob"}},
		{"reset a disabled user", [][]string{{"user", "disable", "bob"}}, []string{"user", "passwd", "bob", "--hash", h}},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := userHostsSandbox(t)
			for _, a := range c.setup {
				hs.run(hs.localRunner(), a...)
				if hs.code != 0 {
					t.Fatalf("%v: %d\n%s%s", a, hs.code, hs.out.String(), hs.err.String())
				}
			}
			// on a terminal a named host would be asked about
			hs.answerOn("n\n")
			hs.run(hs.localRunner(), c.args...)
			all := plain(hs.out.String() + hs.err.String())
			if hs.code != 0 || strings.Contains(all, "web1") || strings.Contains(all, "enrolled host") || strings.Contains(all, "Sync these hosts now") {
				t.Errorf("%d\n%s", hs.code, all)
			}
		})
	}
}

// A name that is no Linux account name has no account on any host.
func TestUserAddOfANameWithNoLinuxAccountNamesNoHost(t *testing.T) {
	hs := userHostsSandbox(t)
	hs.run(hs.localRunner(), "user", "add", "9dave", "operator", "--hash", hashOf(t, "CorrectHorse99"), "--scopes", "lab")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "User '9dave' added") || strings.Contains(all, "web1") || strings.Contains(all, "enrolled host") {
		t.Errorf("%d\n%s", hs.code, all)
	}
}

// A rename to a name that has a UID of its own: the hosts remove the old
// account and create the new one, and are named, with the command and the
// offer.
func TestUserRenameToANameWithItsOwnUIDNamesTheHosts(t *testing.T) {
	hs := userHostsSandbox(t)
	hs.write("state/linux-uids", hs.read("state/linux-uids")+"robert:80009\n", 0o600)
	hs.answerOn("n\n")
	hs.run(hs.localRunner(), "user", "rename", "bob", "robert")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "[WARN] 'robert' already has UID 80009 in linux-uids") ||
		!strings.Contains(all, "[WARN] The change reaches 1 enrolled host at each host's next sync: tacctl host sync web1") ||
		!strings.Contains(all, "Sync these hosts now? [y/N]: ") || hs.pushed != "" {
		t.Errorf("%d, pushed %q\n%s", hs.code, hs.pushed, all)
	}
}
