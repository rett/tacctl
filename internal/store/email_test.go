package store_test

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

// email (0.2.23) is an optional user key written only when set: a store
// that never used it is what 0.2.22 wrote, byte for byte, and the address is
// kept as typed.
func TestEmailRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	before := string(readFile(t, e.path))
	e.mustMutate(userSet("alice", "email=Alice.Smith@Example.NET"))
	if text := string(readFile(t, e.path)); strings.Count(text, "email: Alice.Smith@Example.NET") != 1 {
		t.Fatalf("the key is not written once, as typed:\n%s", text)
	}
	equal(t, e.mustGet("users", "alice", "email"), "Alice.Smith@Example.NET")
	if out, _ := e.get("users", "bob", "email"); out != "" {
		t.Errorf("bob has the key: %q", out)
	}
	s, err := store.Load(e.path)
	if err != nil {
		t.Fatal(err)
	}
	m := model.FromStore(s)
	if m.User("alice").Email != "Alice.Smith@Example.NET" || m.User("bob").Email != "" {
		t.Error("the model does not carry the address")
	}

	// null (or nothing) removes the key, and the file is the one it was
	e.mustMutate(userSet("alice", "email=null"))
	equal(t, string(readFile(t, e.path)), before)
	e.mustMutate(userSet("alice", "email=bob@example.net"))
	e.mustMutate(userSet("alice", "email="))
	equal(t, string(readFile(t, e.path)), before)

	// a user the key was never set on has no key at all
	e.mustMutate(userSet("bob", "email=null"))
	equal(t, string(readFile(t, e.path)), before)
}

func TestEmailFollowsARename(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("bob", "email=bob@example.net"))
	e.mustMutate(func(s *store.Store) error { return s.UserRename("bob", "robert") })
	equal(t, e.mustGet("users", "robert", "email"), "bob@example.net")
}

func TestEmailValidation(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	for _, bad := range []string{"nobody", "nobody@example", "nobody@@example.net", "a b@example.net", "<a@example.net>", "a@example.net.", "nobody\u200b@example.net", "nobody\u202e@example.net"} {
		out := e.mutate(userSet("alice", "email="+bad))
		contains(t, out, "user 'alice': email must be a plain address")
		if strings.Contains(out, bad) {
			t.Errorf("the refusal of %q echoes it: %s", bad, out)
		}
	}
	out, ok := e.validateYAML("version: 1\n" + builtins + `
users:
  alice: {group: readonly, scopes: [], hash: null, disabled: true, email: 7}
`)
	if ok {
		t.Fatal("a number is valid")
	}
	contains(t, out, "user 'alice': email must be a non-empty string")
	if out, ok := e.validateYAML("version: 1\n" + builtins + `
users:
  alice: {group: readonly, scopes: [], hash: null, disabled: true, email: alice@example.net}
`); !ok {
		t.Errorf("an address is refused: %s", out)
	}
}

// An address belongs to one user, compared without regard to case; the
// message names the first user and never the address.
func TestEmailIsUnique(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("alice", "email=alice@example.net"))
	before := string(readFile(t, e.path))
	for _, dup := range []string{"alice@example.net", "ALICE@Example.Net"} {
		out := e.mutate(userSet("bob", "email="+dup))
		contains(t, out, "user 'bob': email is already used by user 'alice'")
		if strings.Contains(strings.ToLower(out), "alice@example") {
			t.Errorf("the refusal echoes the address: %s", out)
		}
	}
	equal(t, string(readFile(t, e.path)), before)
	// the same user may rewrite its own address in another case
	e.mustMutate(userSet("alice", "email=Alice@example.net"))
	// a store file that holds the address twice does not validate
	out, ok := e.validateYAML("version: 1\n" + builtins + `
users:
  alice: {group: readonly, scopes: [], hash: null, disabled: true, email: alice@example.net}
  bob: {group: readonly, scopes: [], hash: null, disabled: true, email: ALICE@EXAMPLE.net}
`)
	if ok {
		t.Fatal("a shared address is valid")
	}
	contains(t, out, "user 'bob': email is already used by user 'alice'")
}

func TestEmailInTheModelJSON(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("alice", "email=alice@example.net"))
	contains(t, e.mustGet("users", "alice"), `"email": "alice@example.net"`)
	if out := e.mustGet("users", "bob"); strings.Contains(out, "email") {
		t.Errorf("bob: %s", out)
	}
}

// A rendered or legacy file cannot hold an address: a replacing import keeps
// the one the existing store has.
func TestImportReplaceKeepsEmail(t *testing.T) {
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edgeSidecars()
	e.mustImport()
	e.mustMutate(userSet("alice", "email=alice@example.net"))
	out := e.mustImport("--replace")
	contains(t, out, "kept the email address of 1 user(s)")
	equal(t, e.mustGet("users", "alice", "email"), "alice@example.net")
	if text, err := os.ReadFile(e.path); err != nil || strings.Count(string(text), "email:") != 1 {
		t.Errorf("the store: %v\n%s", err, text)
	}
}

func TestEmailSinkCarriesNone(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	out, ok := e.validateYAML("version: 1\n" + builtins + `
users:
  root: {group: readonly, scopes: [], hash: null, disabled: true, accounting_sink: true, email: root@example.net}
`)
	if ok {
		t.Fatal("the sink with an address is valid")
	}
	contains(t, out, "user 'root': the accounting sink must not carry an email address")
}
