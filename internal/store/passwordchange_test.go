package store_test

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

// password_change_required (0.2.20) is a user key written only when true: a
// store that never used it is what 0.2.19 wrote, byte for byte.
func TestPasswordChangeRequiredRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	before := string(readFile(t, e.path))
	e.mustMutate(userSet("alice", "password_change_required=true"))
	text := string(readFile(t, e.path))
	if strings.Count(text, "password_change_required: true") != 1 {
		t.Fatalf("the key is not written once:\n%s", text)
	}
	equal(t, e.mustGet("users", "alice", "password_change_required"), "true")
	if out, _ := e.get("users", "bob", "password_change_required"); out != "" {
		t.Errorf("bob has the key: %q", out)
	}
	s, err := store.Load(e.path)
	if err != nil {
		t.Fatal(err)
	}
	m := model.FromStore(s)
	if !m.User("alice").PasswordChangeRequired || m.User("bob").PasswordChangeRequired {
		t.Error("the model does not carry the flag")
	}

	// false is the absence of the key, and the file is the one it was
	e.mustMutate(userSet("alice", "password_change_required=false"))
	equal(t, string(readFile(t, e.path)), before)

	// a user the key was never set on, or cleared on, has no key at all
	e.mustMutate(userSet("bob", "password_change_required=false"))
	equal(t, string(readFile(t, e.path)), before)
}

func TestPasswordChangeRequiredFollowsARename(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("bob", "password_change_required=true"))
	e.mustMutate(func(s *store.Store) error { return s.UserRename("bob", "robert") })
	equal(t, e.mustGet("users", "robert", "password_change_required"), "true")
}

func TestPasswordChangeRequiredValidation(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	contains(t, e.mutate(userSet("alice", "password_change_required=yes")), "password_change_required must be true or false")
	out, ok := e.validateYAML("version: 1\n" + builtins + `
users:
  alice: {group: readonly, scopes: [], hash: null, disabled: true, password_change_required: "yes"}
`)
	if ok {
		t.Fatal("a string is valid")
	}
	contains(t, out, "user 'alice': password_change_required must be true or false")
	if out, ok := e.validateYAML("version: 1\n" + builtins + `
users:
  alice: {group: readonly, scopes: [], hash: null, disabled: true, password_change_required: true}
`); !ok {
		t.Errorf("true is refused: %s", out)
	}
	if f, _ := store.Fields("users"); !strings.Contains(strings.Join(f, ","), ",accounting_sink,password_change_required") {
		t.Errorf("the user fields: %v", f)
	}
}

// A rollback sees the key in a store as it is on disk, and takes it out of
// every user in one write (an older release refuses the key).
func TestRollbackPasswordChange(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("alice", "password_change_required=true"))
	e.mustMutate(userSet("carol", "password_change_required=true"))
	names, err := store.PasswordChangeKeys(e.path)
	if err != nil || strings.Join(names, ",") != "alice,carol" {
		t.Fatalf("keys %v, %v", names, err)
	}
	snapshots := 0
	removed, changed, err := store.RollbackPasswordChange(e.path, func() error { snapshots++; return nil })
	if err != nil || !changed || strings.Join(removed, ",") != "alice,carol" || snapshots != 1 {
		t.Fatalf("removed %v changed %v err %v snapshots %d", removed, changed, err, snapshots)
	}
	if strings.Contains(string(readFile(t, e.path)), "password_change_required") {
		t.Errorf("the key stays:\n%s", readFile(t, e.path))
	}
	if left, _ := store.PasswordChangeKeys(e.path); len(left) != 0 {
		t.Errorf("keys left: %v", left)
	}
	// nothing to remove: the file is not written again
	ino := inode(t, e.path)
	removed, changed, err = store.RollbackPasswordChange(e.path, nil)
	if err != nil || changed || len(removed) != 0 || inode(t, e.path) != ino {
		t.Errorf("second run: %v %v %v", removed, changed, err)
	}
}

// A store that does not validate for another reason still shows its keys.
func TestPasswordChangeKeysReadAnUnvalidatedStore(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("alice", "password_change_required=true"))
	text := strings.Replace(string(readFile(t, e.path)), "version: 1", "version: 2", 1)
	if err := writeFileMode(e.path, text); err != nil {
		t.Fatal(err)
	}
	names, err := store.PasswordChangeKeys(e.path)
	if err != nil || strings.Join(names, ",") != "alice" {
		t.Fatalf("%v %v", names, err)
	}
	if _, _, err := store.RollbackPasswordChange(e.path, nil); err == nil {
		t.Error("the store that does not validate was written")
	}
}
