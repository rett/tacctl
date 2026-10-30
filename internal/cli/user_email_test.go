package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
)

// emailOf is the address the store holds for a user ("" when none).
func emailOf(t *testing.T, sb *sandbox, user string) string {
	t.Helper()
	data, err := os.ReadFile(sb.path("state", "store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// the user's block runs to the next key of the users section
	_, rest, ok := strings.Cut(string(data), "\n  "+user+":\n")
	if !ok {
		t.Fatalf("no user %s in\n%s", user, data)
	}
	for _, l := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(l, "    ") {
			break
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "email: "); ok {
			return v
		}
	}
	return ""
}

// 'user email' shows, sets and clears the address; the address is stored as
// typed, shown by 'user show' and by the model JSON, and not listed.
func TestUserEmailShowSetClear(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "email", "bob")
	sb.expect(0, "User 'bob' has no email address.", "")
	sb.asAlice("", "user", "email", "bob", "Bob.Jones@Example.NET")
	sb.expect(0, "Email address of 'bob' set.", "")
	if got := emailOf(t, sb, "bob"); got != "Bob.Jones@Example.NET" {
		t.Errorf("stored %q", got)
	}
	if out := sb.asAlice("", "user", "email", "bob"); out != "Bob.Jones@Example.NET\n" {
		t.Errorf("the address: %q", out)
	}
	if out := sb.asAlice("", "user", "show", "bob"); !strings.Contains(out, "  Email:            Bob.Jones@Example.NET\n") {
		t.Errorf("user show lacks the address:\n%s", out)
	}
	if out := sb.asAlice("", "user", "show", "carol"); strings.Contains(out, "Email") {
		t.Errorf("user show of a user with none:\n%s", out)
	}
	if out := sb.asAlice("", "user", "list"); strings.Contains(out, "example.net") || strings.Contains(strings.ToLower(out), "email") {
		t.Errorf("user list shows the address:\n%s", out)
	}
	if out := sb.asAlice("", "store", "show", "--json"); !strings.Contains(out, `"email": "Bob.Jones@Example.NET"`) {
		t.Errorf("store show --json lacks the address:\n%s", out)
	}
	// the same address again: nothing to do
	sb.asAlice("", "user", "email", "bob", "Bob.Jones@Example.NET")
	sb.expect(0, "has that email address already", "")
	// a rename carries it
	sb.asAlice("", "user", "rename", "bob", "robert")
	sb.expect(0, "", "")
	if got := emailOf(t, sb, "robert"); got != "Bob.Jones@Example.NET" {
		t.Errorf("after the rename: %q", got)
	}
	sb.asAlice("", "user", "email", "robert", "clear")
	sb.expect(0, "Email address of 'robert' cleared.", "")
	if got := emailOf(t, sb, "robert"); got != "" {
		t.Errorf("after clear: %q", got)
	}
	if b, _ := os.ReadFile(sb.path("state", "store.yaml")); strings.Contains(string(b), "email") {
		t.Errorf("the key stays:\n%s", b)
	}
	sb.asAlice("", "user", "email", "robert", "clear")
	sb.expect(0, "nothing to clear", "")
}

// An address belongs to one user, compared without regard to case; a bad
// address, an unknown user, the sink and extra words are refused with
// nothing changed, and no message repeats the address.
func TestUserEmailRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "email", "alice", "alice@example.net")
	sb.expect(0, "", "")
	before, _ := os.ReadFile(sb.path("state", "store.yaml"))
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"user", "email", "bob", "ALICE@example.net"}, "That email address already belongs to user 'alice'"},
		{[]string{"user", "email", "bob", "alice@example.net"}, "That email address already belongs to user 'alice'"},
		{[]string{"user", "email", "bob", "bob@example"}, "Not a plain email address"},
		{[]string{"user", "email", "bob", "Bob Jones <bob@example.net>"}, "Not a plain email address"},
		{[]string{"user", "email", "bob", "bob@example.net", "extra@example.net"}, "Usage: tacctl user email <username> [<address>|clear]"},
		{[]string{"user", "email"}, "Usage: tacctl user email <username> [<address>|clear]"},
		// an option is no address, and is not stored as one
		{[]string{"user", "email", "bob", "--email=bob@example.net"}, "Usage: tacctl user email <username> [<address>|clear]"},
		{[]string{"user", "email", "bob", "--email", "bob@example.net"}, "Usage: tacctl user email <username> [<address>|clear]"},
		{[]string{"user", "email", "bob", "-bob@example.net"}, "Usage: tacctl user email <username> [<address>|clear]"},
		{[]string{"user", "email", "nobody@example.net"}, "Username must contain only"},
		{[]string{"user", "email", "nobody", "nobody@example.net"}, "User 'nobody' does not exist."},
	} {
		sb.asAlice("", c.args...)
		sb.expect(1, "", c.want)
		for _, w := range append(c.args[2:], "example.net") {
			if strings.Contains(w, "@") && strings.Contains(sb.stderr()+sb.out.String(), w) {
				t.Errorf("%q: the message repeats %q:\n%s", c.args, w, sb.stderr())
			}
		}
	}
	if after, _ := os.ReadFile(sb.path("state", "store.yaml")); string(after) != string(before) {
		t.Errorf("a refusal changed the store:\n%s", after)
	}
}

// 'user add --email' records the address with the user; a bad or held address
// refuses the add before anything is written.
func TestUserAddEmail(t *testing.T) {
	sb := newSandbox(t, true)
	h, err := hash.Generate("CorrectHorse99", 4)
	if err != nil {
		t.Fatal(err)
	}
	sb.asAlice("", "user", "email", "bob", "bob@example.net")
	sb.expect(0, "", "")
	before, _ := os.ReadFile(sb.path("state", "store.yaml"))
	for _, c := range []struct{ email, want string }{
		{"Bob@Example.net", "That email address already belongs to user 'bob'"},
		{"dave at example.net", "Not a plain email address"},
	} {
		sb.asAlice("", "user", "add", "dave", "operator", "--hash", h, "--scopes", "lab", "--email", c.email)
		sb.expect(1, "", c.want)
		if strings.Contains(sb.stderr(), c.email) {
			t.Errorf("the message repeats the address: %s", sb.stderr())
		}
	}
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", h, "--scopes", "lab", "--email")
	sb.expect(1, "", "Usage: tacctl user add <username> <group> --email <address>")
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", h, "--scopes", "lab", "dave@example.net")
	sb.expect(1, "", "An email address follows --email.")
	if strings.Contains(sb.stderr(), "dave@example.net") {
		t.Errorf("the message repeats the address: %s", sb.stderr())
	}
	if after, _ := os.ReadFile(sb.path("state", "store.yaml")); string(after) != string(before) {
		t.Errorf("a refusal changed the store:\n%s", after)
	}
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", h, "--scopes", "lab", "--email", "dave@example.net", "--no-change-required")
	sb.expect(0, "Email address recorded for 'dave'.", "")
	if got := emailOf(t, sb, "dave"); got != "dave@example.net" {
		t.Errorf("stored %q", got)
	}
	// the option may come before the others
	sb.asAlice("", "user", "add", "erin", "operator", "--email", "erin@example.net", "--hash", h, "--scopes", "lab", "--no-change-required")
	sb.expect(0, "", "")
	if got := emailOf(t, sb, "erin"); got != "erin@example.net" {
		t.Errorf("stored %q", got)
	}
}

// An address changes no rendered file: no backend is restarted.
func TestUserEmailRestartsNothing(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	sb.asAlice("", "user", "email", "bob", "bob@example.net")
	sb.expect(0, "", "")
	if n := sb.runner.Count("systemctl", "restart"); n != 0 {
		t.Errorf("an address restarted a backend %d times", n)
	}
}
