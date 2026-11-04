package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/tier"
)

// heldSandbox is pwSandbox with the console's link, an sshd_config that
// includes the drop-ins and the accounts bob and carol with the console as
// their shell (alice, a superuser, has none): the sshd the runner stands for
// accepts the drop-in and applies it. It returns the sandbox, the console's
// path and the drop-in's.
func heldSandbox(t *testing.T) (*sandbox, string, string) {
	t.Helper()
	sb := pwSandbox(t)
	link := sb.consoleCommand()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sb.path("usr", "local", "bin", "tacctl"), link); err != nil {
		t.Fatal(err)
	}
	sb.write("sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n", 0o644)
	sb.write("shells", "# /etc/shells\n/bin/sh\n/bin/bash\n", 0o644)
	base := sb.script
	// the list of accounts is asked with no name; the question for one is
	// answered as before (alice is UID 1001)
	list := func(r *fake.Runner) {
		text := "root:x:0:0:root:/root:/bin/bash\n"
		for _, u := range []string{"bob", "carol"} {
			text += u + ":x:80000:80000:" + u + " (TACACS+):/home/" + u + ":" + link + "\n"
		}
		r.Func(func(c execx.Cmd) bool { return slices.Equal(c.Argv(), []string{"getent", "passwd"}) },
			func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(text)}, nil })
	}
	sb.script = both(base, sshdOK(link), list)
	return sb, link, sb.path("sshd_config.d", "tacctl-console.conf")
}

// heldList is the user list of the drop-in's 'Match User' line ("" for none).
func heldList(t *testing.T, dropin string) string {
	t.Helper()
	data, err := os.ReadFile(dropin)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(l, "Match User "); ok {
			return rest
		}
	}
	return ""
}

// The users held to a password change are listed in the console's sshd
// drop-in, so a forwarding tier cannot let them forward ports: every verb
// that flags or unflags one rewrites the list (the sync of this server after
// the user verbs; the verbs no sync follows rewrite the drop-in themselves),
// 'console install' and the sync write it, and 'console check' reports the
// drop-in drifting from the users held now.
func TestConsoleDropInListsTheHeldUsers(t *testing.T) {
	sb, link, dropin := heldSandbox(t)
	h := hashOf(t, "CorrectHorse99")
	want := func(held ...string) string {
		return console.DropIn(link, false, false, []tier.Tier{tier.Superuser}, held)
	}
	read := func() string {
		data, err := os.ReadFile(dropin)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	// Nobody is held: no block.
	sb.run("", []string{"console", "install"})
	sb.expect(0, "Installed: sshd drop-in "+dropin, "")
	if read() != want() || heldList(t, dropin) != "" {
		t.Errorf("no user held:\n%s", read())
	}

	// A user verb flags bob, and its sync of this server lists him.
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	if heldList(t, dropin) != "bob" || read() != want("bob") {
		t.Errorf("bob flagged by require-password-change:\n%s", read())
	}

	// The check is green with the list current and red when a user is flagged
	// since (here directly in the store: no sync ran), and names the drift.
	out := plain(sb.run("", []string{"console", "check"}))
	if sb.code != 0 || !strings.Contains(out, "sshd drop-in "+dropin+": present, current") ||
		!strings.Contains(out, "sshd for bob:") {
		t.Errorf("check with the list current: %d\n%s", sb.code, out)
	}
	flagUser(t, sb, "carol")
	out = plain(sb.run("", []string{"console", "check"}))
	if sb.code != 1 || !strings.Contains(out, "present, differs from this release's") ||
		!strings.Contains(out, "users held to a password change, forwarding closed: drop-in bob, now bob,carol") ||
		!strings.Contains(out, "the users held to a password change in the drop-in (bob) are not the ones held now (bob,carol)") {
		t.Errorf("check with a user flagged since: %d\n%s", sb.code, out)
	}
	sb.run("", []string{"console", "install"})
	sb.expect(0, "Updated: sshd drop-in "+dropin, "")
	if heldList(t, dropin) != "bob,carol" {
		t.Errorf("after console install:\n%s", read())
	}

	// A superuser is never held, flagged or not.
	flagUser(t, sb, "alice")
	sb.run("", []string{"console", "install"})
	sb.expect(0, "Unchanged: sshd drop-in "+dropin, "")
	if heldList(t, dropin) != "bob,carol" {
		t.Errorf("a flagged superuser is listed:\n%s", read())
	}

	// An administrator's reset lifts and requires the change with no sync of
	// this server: it rewrites the list itself.
	sb.asAlice("", "user", "passwd", "bob", "--no-change-required", "--hash", h)
	sb.expect(0, "The password change required of 'bob' is lifted.", "")
	if heldList(t, dropin) != "carol" || !strings.Contains(plain(sb.out.String()), "Updated: sshd drop-in "+dropin+" (users held to a password change)") {
		t.Errorf("reset that lifts:\n%s\n%s", read(), sb.out.String())
	}
	sb.asAlice("", "user", "passwd", "bob", "--hash", h)
	sb.expect(0, "'bob' must change it at the next login", "")
	if heldList(t, dropin) != "bob,carol" {
		t.Errorf("reset that requires:\n%s", read())
	}

	// The user's own change lifts the flag and the drop-in follows at once.
	sb.run("CorrectHorse99\nNewHorse123456\nNewHorse123456\n", []string{"passwd"}, "SUDO_USER=bob")
	sb.expect(0, "The required password change is done.", "")
	if heldList(t, dropin) != "carol" {
		t.Errorf("after bob's own change:\n%s", read())
	}

	// A sshd that refuses the new list leaves the old one and one warning.
	before := read()
	sb.script = both(sb.script, func(r *fake.Runner) {
		r.Fail([]string{"sshd", "-t"}, 1, "sshd_config: bad configuration")
	})
	sb.asAlice("", "user", "passwd", "bob", "--hash", h)
	out = plain(sb.out.String() + sb.err.String())
	if sb.code != 0 || read() != before || !strings.Contains(out, "was not updated for the users held to a password change") ||
		!strings.Contains(out, "tacctl console install") {
		t.Errorf("sshd refuses: %d\n%s", sb.code, out)
	}
}

// With no drop-in (the console is not installed) the verbs that flag a user
// write none and say nothing about it.
func TestHeldForwardingWithoutTheDropIn(t *testing.T) {
	sb, _, dropin := heldSandbox(t)
	sb.asAlice("", "user", "passwd", "bob", "--hash", hashOf(t, "CorrectHorse99"))
	sb.expect(0, "'bob' must change it", "")
	if _, err := os.Stat(dropin); err == nil {
		t.Error("a drop-in was written")
	}
	if out := plain(sb.out.String() + sb.err.String()); strings.Contains(out, "held to a password change") {
		t.Errorf("said something: %s", out)
	}
}

// The check asks for no agent forwarding of a user held to a password
// change, whatever 'console agent-forwarding' says: a drop-in that lacks his
// block (a flag set since, no sync yet) leaves sshd answering yes for him, and
// that is a problem; the same answer for a user that is not held is not.
func TestConsoleCheckExpectsNoAgentForAHeldUser(t *testing.T) {
	sb, link, _ := heldSandbox(t)
	sb.run("", []string{"console", "agent-forwarding", "enable"})
	sb.expect(0, "", "")
	sb.run("", []string{"console", "install"})
	sb.expect(0, "", "")
	flagUser(t, sb, "bob")
	// sshd answers as for a user the drop-in does not close
	sb.script = both(sb.script, func(r *fake.Runner) {
		r.On([]string{"sshd", "-T"}, execx.Result{Stdout: []byte("allowtcpforwarding no\nallowagentforwarding yes\ndisableforwarding no\nforcecommand " + link + "\npubkeyauthentication no\n")})
	})
	for _, args := range [][]string{{"console", "check"}, {"console", "show"}} {
		out := plain(sb.run("", args))
		if !strings.Contains(out, "sshd for bob:") || strings.Count(out, "allowagentforwarding is 'yes'") != 1 {
			t.Errorf("%v: want the agent flagged for bob only, once:\n%s", args, out)
		}
	}
	// the list current: sshd answers closed for bob and nothing is flagged
	// (the install's own check still sees the old answer)
	sb.run("", []string{"console", "install"})
	sb.script = both(sb.script, func(r *fake.Runner) {
		r.On([]string{"sshd", "-T"}, execx.Result{Stdout: []byte("allowtcpforwarding no\nallowagentforwarding yes\ndisableforwarding yes\nforcecommand " + link + "\npubkeyauthentication no\n")})
	})
	out := plain(sb.run("", []string{"console", "check"}))
	if sb.code != 0 || strings.Contains(out, "allowagentforwarding is") {
		t.Errorf("the held user's agent under disableforwarding yes: %d\n%s", sb.code, out)
	}
}
