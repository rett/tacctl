package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

// Every verb that flags or unflags a user rewrites the console's sshd
// drop-in itself: the sync of this server it may run next reaches the drop-in
// only when the server is enrolled, the checks of the sync pass (the UID
// ledger, the scope) and a user of the scope gets the console, so a list
// that waited for it stayed as it was when the sync stopped early or never
// ran, and a user held since forwarded ports, or one released since did not.

// heldScenario prepares the sandbox after the drop-in lists the users flagged
// before the verb runs.
type heldScenario struct {
	name string
	// flags says the scenario has an enrolled server: with none, no user has
	// a login to change the password at, so no verb flags one, and a rename of
	// a held user is refused; the other verbs still unflag, remove and move.
	flags bool
	setup func(t *testing.T, sb *sandbox)
}

var heldScenarios = []heldScenario{
	{name: "server not enrolled", setup: func(t *testing.T, sb *sandbox) {
		sb.write("state/linux-hosts", "", 0o600)
	}},
	{name: "sync stops at the UID ledger", flags: true, setup: func(t *testing.T, sb *sandbox) {
		// 'bob' would be renumbered to a number 'carol' holds: the sync of
		// this server refuses before it writes anything
		sb.write("state/linux-uids", "alice:20000\nbob:20001\ncarol:80001\n", 0o600)
	}},
}

func TestHeldListFollowsEveryVerbWhateverTheSyncDoes(t *testing.T) {
	h := hashOf(t, "CorrectHorse99")
	for _, c := range []struct {
		name  string
		flags bool     // the verb needs an enrolled server (it flags a user, or is refused for a held one)
		held  []string // flagged before the verb, listed in the drop-in
		args  []string
		stdin string
		env   []string
		want  string // the list after
	}{
		// flag
		{name: "require-password-change", flags: true, args: []string{"user", "require-password-change", "bob"}, want: "bob"},
		{name: "require-password-change --all", flags: true, args: []string{"user", "require-password-change", "--all"}, want: "bob"},
		{name: "user add", flags: true, args: []string{"user", "add", "dave", "operator", "--hash", h, "--scopes", "srv"}, want: "dave"},
		{name: "user passwd", flags: true, args: []string{"user", "passwd", "bob", "--hash", h}, want: "bob"},
		// unflag
		{name: "require-password-change off", held: []string{"bob", "carol"}, args: []string{"user", "require-password-change", "bob", "off"}, want: "carol"},
		{name: "require-password-change --all off", held: []string{"bob", "carol"}, args: []string{"user", "require-password-change", "--all", "off"}, want: ""},
		{name: "user passwd --no-change-required", held: []string{"bob", "carol"}, args: []string{"user", "passwd", "bob", "--no-change-required", "--hash", h}, want: "carol"},
		{name: "passwd", held: []string{"bob", "carol"}, args: []string{"passwd"}, stdin: "CorrectHorse99\nNewHorse123456\nNewHorse123456\n", env: []string{"SUDO_USER=bob"}, want: "carol"},
		// the held user goes, changes name or tier
		{name: "user remove", held: []string{"bob", "carol"}, args: []string{"user", "remove", "bob"}, stdin: "y\n", want: "carol"},
		{name: "user rename", flags: true, held: []string{"bob", "carol"}, args: []string{"user", "rename", "bob", "robert"}, want: "carol,robert"},
		{name: "user move to a superuser group", held: []string{"bob", "carol"}, args: []string{"user", "move", "bob", "superuser"}, want: "carol"},
	} {
		for _, sc := range heldScenarios {
			if c.flags && !sc.flags {
				continue
			}
			t.Run(c.name+"/"+sc.name, func(t *testing.T) {
				sb, _, dropin := heldSandbox(t)
				for _, n := range c.held {
					flagUser(t, sb, n)
				}
				// bob knows his password (the user's own change asks for it)
				if _, err := store.Mutate(sb.path("state", "store.yaml"), store.MutateOptions{}, func(s *store.Store) error {
					return s.UserSet("bob", "hash="+h)
				}); err != nil {
					t.Fatal(err)
				}
				sb.run("", []string{"console", "install"})
				sb.expect(0, "sshd drop-in "+dropin, "")
				if got, want := heldList(t, dropin), strings.Join(c.held, ","); got != want {
					t.Fatalf("the control: the drop-in lists %q, want %q", got, want)
				}
				sc.setup(t, sb)
				env := c.env
				if env == nil {
					env = []string{"SUDO_USER=alice", "SUDO_UID=1001"}
				}
				sb.run(c.stdin, c.args, env...)
				if sb.code != 0 {
					t.Fatalf("exit %d\n%s%s", sb.code, sb.out.String(), sb.err.String())
				}
				if got := heldList(t, dropin); got != c.want {
					data, _ := os.ReadFile(dropin)
					t.Errorf("the drop-in lists %q, want %q\n%s\n%s%s", got, c.want, data, sb.out.String(), sb.err.String())
				}
			})
		}
	}
}

// A group verb that lowers a tier makes the flagged users of the group held
// (a superuser is never): the drop-in lists them whether or not the sync it
// runs gets to the console's pieces. Where no server is enrolled (a flag can
// still be in the store: flagUser writes it directly) the held user would
// have no login to change the password at, so the verb is refused and the
// drop-in is left as it was.
func TestHeldListFollowsALoweredTier(t *testing.T) {
	for _, sc := range heldScenarios {
		t.Run(sc.name, func(t *testing.T) {
			sb, _, dropin := heldSandbox(t)
			// alice, a superuser, carries a flag that binds nobody now
			flagUser(t, sb, "alice")
			sb.run("", []string{"console", "install"})
			sb.expect(0, "sshd drop-in "+dropin, "")
			if got := heldList(t, dropin); got != "" {
				t.Fatalf("the control: the drop-in lists %q", got)
			}
			sc.setup(t, sb)
			out := sb.asAlice("", "group", "edit", "superuser", "tier", "operator")
			if !sc.flags {
				if sb.code == 0 || !strings.Contains(plain(sb.err.String()), "without a login on this server") {
					t.Errorf("want the change refused: exit %d\n%s%s", sb.code, out, sb.err.String())
				}
				if got := heldList(t, dropin); got != "" {
					t.Errorf("the refused change left the drop-in listing %q, want none", got)
				}
				return
			}
			if got := heldList(t, dropin); got != "alice" {
				t.Errorf("the drop-in lists %q, want alice\n%s%s", got, sb.out.String(), sb.err.String())
			}
		})
	}
}
