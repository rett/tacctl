package cli

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// 'tacctl rollback 0.2.20' and the managed scope in every target, on the
// host sandbox. The plan's own cases are internal/lifecycle's.

// rollback0221State is rollbackState with this server enrolled in the scope
// tacctl manages: every user logs in to it without the scope in their own
// list, and tacctl.yaml holds the server address (also the state of the
// rollback to 0.2.21).
func rollback0221State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollbackState(t)
	hs.step("", "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
	return hs
}

// The dry run of 0.2.20 says it adds the scope to the users and removes the
// server address; --apply needs --yes, then the users have the scope in their
// own lists and the key is gone; a second run has nothing to do.
func TestRollback0220AddsTheManagedScopeToTheUsers(t *testing.T) {
	hs := rollback0221State(t)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.20")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.20 (dry run)", "remove server.addresses",
		"add scope 'tacctl' to the users' own scopes   [does]", "add scope tacctl to 4 users: alice, bob, carol, erin",
		"Every user gets the scope of this server's own login in the store", "To convert the state: tacctl rollback 0.2.20 --apply --yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	hs.run(hs.runner(), "rollback", "0.2.20", "--apply")
	hs.expect(1, "", "The warnings above need your decision")
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.20", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	if !strings.Contains(hs.all(), "added scope tacctl to 4 users") || !strings.Contains(hs.all(), "tacctl upgrade --branch 0.2.20") {
		t.Errorf("--apply:\n%s", hs.all())
	}
	if hs.snapshots() == snaps {
		t.Error("no snapshot was taken first")
	}
	for _, u := range []string{"alice", "bob", "carol", "erin"} {
		if !strings.Contains(userBlock(hs.store(), u), "tacctl]") {
			t.Errorf("%s:\n%s", u, userBlock(hs.store(), u))
		}
	}
	if strings.Contains(hs.overrides(), "server:") || !strings.Contains(hs.registry(), "|tacctl|192.0.2.10|") {
		t.Errorf("tacctl.yaml:\n%s\nregistry %q", hs.overrides(), hs.registry())
	}
	hs.run(hs.runner(), "rollback", "0.2.20", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.20 can read.", "")
}

// Every older target adds the scope too.
func TestRollbackOlderTargetsAddTheManagedScope(t *testing.T) {
	for _, v := range []string{"0.2.19", "0.2.18", "0.2.3"} {
		hs := rollback0221State(t)
		hs.run(hs.runner(), "rollback", v)
		if out := hs.all(); !strings.Contains(out, "add scope tacctl to 4 users: alice, bob, carol, erin") || !strings.Contains(out, "remove server.addresses") {
			t.Errorf("%s:\n%s", v, out)
		}
	}
}

// The check against the real release: built from the 0.2.20 tag, its config
// validate refuses the server address before the rollback and reads the
// state after; it renders every user into the server's scope from their own
// lists, and lists the scope with each user.
func TestRollbackRealOldBinary0220(t *testing.T) {
	bin := oldBinaryOf(t, "0.2.20", old0220Flag)
	hs := rollback0221State(t)
	stubs := t.TempDir()
	for _, name := range []string{"systemctl", "logger", "chown"} {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, int) {
		res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: bin, Args: args,
			Env: append(append([]string(nil), hs.env...), "PATH="+stubs+":/usr/bin:/bin", "HOME="+t.TempDir(), "LANG=C.UTF-8")})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return plain(string(res.Stdout) + string(res.Stderr)), res.Code
	}
	if out, code := run("config", "validate"); code != 1 || !strings.Contains(out, "server.addresses: unknown config key") {
		t.Errorf("0.2.20 config validate before: %d\n%s", code, out)
	}
	hs.run(hs.runner(), "rollback", "0.2.20", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	if out, code := run("config", "render"); code != 0 {
		t.Errorf("0.2.20 config render after: %d\n%s", code, out)
	}
	if out, code := run("config", "validate"); code != 0 || !strings.Contains(out, "Configuration is valid.") {
		t.Errorf("0.2.20 config validate after: %d\n%s", code, out)
	}
	if out, code := run("user", "show", "bob"); code != 0 || !strings.Contains(out, "tacctl") {
		t.Errorf("0.2.20 user show after: %d\n%s", code, out)
	}
	r := hs.read("etc/tacquito.yaml")
	if i := strings.Index(r, "- name: bob\n"); i < 0 || !strings.Contains(r[i:i+200], `"tacctl"`) {
		t.Errorf("0.2.20's render: bob is not in the server's scope:\n%s", r)
	}
	if out, code := run("host", "list"); code != 0 || !strings.Contains(out, "authsrv") {
		t.Errorf("0.2.20 host list after: %d\n%s", code, out)
	}
}

// old0220Flag names a 0.2.20 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary0220 -args -old-bin-0220=<path>.
var old0220Flag = flag.String("old-bin-0220", "", "a tacctl 0.2.20 binary built with -tags testknobs (TestRollbackRealOldBinary0220)")
