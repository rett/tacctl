package cli

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/snapshot"
)

// setEmails gives bob and erin of the rollback sandbox an address, as the
// verb does.
func setEmails(hs *hostSandbox) {
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.step("", "user", "email", "erin", "Erin.Jones@Example.NET")
}

// 'tacctl rollback <older release>' with users who have an email address: the
// dry run warns who loses it and writes nothing, --apply needs --yes, then
// takes a snapshot that keeps the addresses, removes the key (an older
// release refuses it), names the snapshot and the way back, and logs the
// snapshot and the users, never an address. Every target does so, the ones
// that return early and 0.2.22, which converted nothing before, included.
func TestRollbackWithAnEmailWarnsSnapshotsAndRemovesTheKey(t *testing.T) {
	for _, target := range []string{"0.2.22", "0.2.21", "0.2.20", "0.2.19", "0.2.18", "0.2.9", "0.2.3"} {
		t.Run(target, func(t *testing.T) {
			hs := rollback0221State(t)
			setEmails(hs)
			before := tree(t, hs.dir)
			hs.run(hs.runner(), "rollback", target)
			hs.expect(0, "This was a dry run: nothing was changed.", "")
			out := hs.all()
			for _, want := range []string{"--apply takes a snapshot of the state first", "remove email of bob", "remove email of erin", emailWarning,
				target + " has no email address of a user (0.2.23): bob, erin have one each", "To convert the state: tacctl rollback " + target + " --apply --yes"} {
				if !strings.Contains(out, want) {
					t.Errorf("the dry run lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "takes no snapshot") || strings.Contains(strings.ToLower(out), "example.net") {
				t.Errorf("the dry run:\n%s", out)
			}
			if !reflectEqual(before, tree(t, hs.dir)) {
				t.Errorf("the dry run changed %q", changedFiles(before, tree(t, hs.dir)))
			}

			hs.run(hs.runner(), "rollback", target, "--apply")
			hs.expect(1, "", "The warnings above need your decision")
			if !strings.Contains(hs.read("state/store.yaml"), "email:") {
				t.Fatal("a refused apply changed the store")
			}

			snaps := hs.snapshots()
			r := hs.runner()
			hs.run(r, "rollback", target, "--apply", "--yes")
			hs.expect(0, "Applying.", "")
			out = hs.all()
			if !strings.Contains(out, "store.yaml: removed the email address of 2 users") {
				t.Errorf("the apply does not say what it removed:\n%s", out)
			}
			if hs.snapshots() != snaps+1 {
				t.Errorf("snapshots %d -> %d", snaps, hs.snapshots())
			}
			snap := newestSnapshot(t, hs)
			id := filepath.Base(snap)
			kept := filepath.Join(hs.dir, "state", "backups-kept", id)
			held, err := os.ReadFile(filepath.Join(snap, "store.yaml"))
			if err != nil || !strings.Contains(string(held), "bob@example.net") || !strings.Contains(string(held), "Erin.Jones@Example.NET") {
				t.Errorf("the snapshot does not keep the addresses (%v):\n%s", err, held)
			}
			for _, want := range []string{
				"The email addresses of 2 users (bob, erin) were removed from the store; " + target + " does not know the key.",
				"They are in snapshot " + id + ", which is kept in " + kept + " (no retention reaches it; " + target + " prunes backups/ by its own):",
				"once 0.2.23 is installed again, 'tacctl backup recover " + id + " --only email' puts them back; 'tacctl backup unkeep " + id + "' removes the kept copy after that.",
				"do not run 'tacctl user email' or 'tacctl user add --email'"} {
				if !strings.Contains(out, want) {
					t.Errorf("--apply lacks %q:\n%s", want, out)
				}
			}
			// the snapshot is kept: a copy no retention reaches holds the addresses,
			// privately, with a note that says what was dropped and not to whom
			copied, err := os.ReadFile(filepath.Join(kept, "store.yaml"))
			if err != nil || string(copied) != string(held) {
				t.Errorf("the kept copy differs from the snapshot (%v)", err)
			}
			if st, err := os.Stat(kept); err != nil || st.Mode().Perm() != 0o700 {
				t.Errorf("the kept directory: %v %v", st, err)
			}
			if st, err := os.Stat(filepath.Join(kept, "store.yaml")); err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("the kept file: %v %v", st, err)
			}
			if info := snapshot.ReadKept(kept); info.Note != "rollback to "+target+": dropped the email addresses of 2 users" || info.User == "" || info.At == "" {
				t.Errorf("the kept record: %+v", info)
			}
			if list := hs.all(); !strings.Contains(list, "kept in") {
				t.Errorf("no word of the kept copy:\n%s", list)
			}
			if listing := plain(hs.run(nil, "backup", "list")); !strings.Contains(listing, id) || !strings.Contains(listing, "snapshot, kept") || !strings.Contains(listing, "rollback to "+target+": dropped the email addresses of 2 users") {
				t.Errorf("backup list:\n%s", listing)
			}
			live := hs.read("state/store.yaml")
			if strings.Contains(live, "email") || !strings.Contains(live, "bob:") || !strings.Contains(live, "erin:") {
				t.Errorf("the store after:\n%s", live)
			}
			// the audit line names the snapshot and the users, never an address
			var line string
			for _, l := range auditLines(r) {
				if strings.Contains(l, "rollback target="+target) {
					line = l
				}
			}
			if !strings.Contains(line, " kept="+id+" email-users=bob,erin by=") {
				t.Errorf("the audit line: %q", line)
			}
			noLoggerHas(t, "rollback", r, "example.net", "Example.NET", "bob@", "Jones")

			// the second dry run has nothing of it left
			hs.run(hs.runner(), "rollback", target)
			hs.expect(0, "", "")
			if out := hs.all(); strings.Contains(out, "email") {
				t.Errorf("a second dry run still lists the key:\n%s", out)
			}
		})
	}
}

// The 0.2.22 target, which converted nothing, takes the snapshot and prints
// its paragraph only when an address stands; without one it is as before.
func TestRollback0222SnapshotFollowsTheAddress(t *testing.T) {
	hs := rollback0221State(t)
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply")
	hs.expect(0, "Nothing to convert", "")
	if out := hs.all(); !strings.Contains(out, "takes no snapshot") || strings.Contains(out, "holds the") {
		t.Errorf("without an address:\n%s", out)
	}
	hs.step("", "user", "email", "bob", "bob@example.net")
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out := hs.all()
	if hs.snapshots() != snaps+1 || strings.Contains(out, "takes no snapshot") || !strings.Contains(out, "holds the 0.2.23 state. Restore it with 0.2.23 only") {
		t.Errorf("with an address (snapshots %d -> %d):\n%s", snaps, hs.snapshots(), out)
	}
	if o := hs.overrides(); strings.Contains(o, "email") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
}

// emailWarning is the title of the warning of the addresses.
const emailWarning = "Email addresses are removed from the store"

// stripEmail is a store without its email lines.
func stripEmail(text string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "email:") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// The way there and back: the rollback removes the addresses after a
// snapshot, and 'backup recover' of the snapshot it names puts them back
// (this release again) for the users that still exist, and only the
// addresses.
func TestRollbackThenRecoverRoundTrip(t *testing.T) {
	hs := rollback0221State(t)
	setEmails(hs)
	before := hs.read("state/store.yaml")
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	id := filepath.Base(newestSnapshot(t, hs))
	removed := hs.read("state/store.yaml")
	if strings.Contains(removed, "email") || removed != stripEmail(before) {
		t.Fatalf("the rollback did more than remove the addresses:\n%s", removed)
	}
	// nothing else changed meanwhile: the recovery gives back the whole store
	hs.run(nil, "backup", "recover", id, "--only", "email", "--yes")
	hs.expect(0, "Recovered 2 items from snapshot "+id+".", "")
	if got := hs.read("state/store.yaml"); got != before {
		t.Errorf("the store after the way there and back differs from the one before:\n--- before\n%s\n--- after\n%s", before, got)
	}
}

// The state of 0.2.22 goes on after the rollback: a user is added and another
// is removed. The recovery restores the address of the user who is left,
// names the one who is gone, and changes nothing but the addresses.
func TestRollbackThenRecoverAfterOtherChanges(t *testing.T) {
	hs := rollback0221State(t)
	setEmails(hs)
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	id := filepath.Base(newestSnapshot(t, hs))
	hs.step("", "user", "add", "frank", "operator", "--hash", testHash, "--scopes", "lab", "--no-change-required")
	hs.stdin = "y\n"
	hs.run(nil, "user", "remove", "bob")
	hs.stdin = ""
	hs.expect(0, "", "")
	mid := hs.read("state/store.yaml")

	hs.run(nil, "backup", "recover", id, "--dry-run")
	hs.expect(0, "This was a dry run", "")
	out := hs.all()
	for _, want := range []string{"bob: skip, no longer exists", "erin: restore"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToLower(out), "example.net") {
		t.Errorf("the dry run shows an address:\n%s", out)
	}
	hs.run(nil, "backup", "recover", id, "--only", "email", "--yes")
	hs.expect(0, "Recovered 1 item from snapshot "+id+".", "")
	live := hs.read("state/store.yaml")
	if !strings.Contains(live, "email: Erin.Jones@Example.NET") || strings.Contains(live, "bob@example.net") {
		t.Errorf("the store after the recovery:\n%s", live)
	}
	if stripEmail(live) != stripEmail(mid) {
		t.Errorf("the recovery changed more than the addresses:\n--- before\n%s\n--- after\n%s", mid, live)
	}
}

// The rollback keeps its snapshot, so it outlives the retention: after more
// than 30 later snapshots (which prune the oldest of backups/, the older
// release's own retention doing the same) the id is gone from backups/, listed
// as kept only, and still recovers the addresses.
func TestRollbackedAddressesSurviveTheRetention(t *testing.T) {
	hs := rollback0221State(t)
	setEmails(hs)
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	id := filepath.Base(newestSnapshot(t, hs))
	for i := 0; i < snapshot.Retention+2; i++ {
		hs.step("", "user", "disable", "carol")
		hs.step("", "user", "enable", "carol")
	}
	if _, err := os.Stat(filepath.Join(hs.dir, "state", "backups", id)); err == nil {
		t.Fatalf("snapshot %s is still in backups/ after %d later changes", id, 2*(snapshot.Retention+2))
	}
	if listing := plain(hs.run(nil, "backup", "list")); !strings.Contains(listing, id) || !strings.Contains(listing, "kept only") {
		t.Errorf("backup list:\n%s", listing)
	}
	hs.run(nil, "backup", "recover", id, "--only", "email", "--dry-run")
	hs.expect(0, "bob: restore", "")
	if out := hs.all(); !strings.Contains(out, "(a kept copy, "+filepath.Join(hs.dir, "state", "backups-kept", id)+")") {
		t.Errorf("the recovery does not name the kept copy:\n%s", out)
	}
	hs.run(nil, "backup", "recover", id, "--only", "email", "--yes")
	hs.expect(0, "Recovered 2 items from snapshot "+id+".", "")
	live := hs.read("state/store.yaml")
	if !strings.Contains(live, "email: bob@example.net") || !strings.Contains(live, "email: Erin.Jones@Example.NET") {
		t.Errorf("the store after the recovery:\n%s", live)
	}
	// the kept copy stays until unkeep removes it
	if _, err := os.Stat(filepath.Join(hs.dir, "state", "backups-kept", id, "store.yaml")); err != nil {
		t.Errorf("the kept copy is gone: %v", err)
	}
	hs.run(nil, "backup", "unkeep", id, "--yes")
	hs.expect(0, "is removed.", "")
	// a rollback again keeps the snapshot it takes; an operator may put a note
	// of their own on it, and keeping it again without one leaves the note
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	id2 := filepath.Base(newestSnapshot(t, hs))
	hs.step("", "backup", "keep", id2, "--note", "the operator's note")
	hs.step("", "backup", "keep", id2)
	if info := snapshot.ReadKept(filepath.Join(hs.dir, "state", "backups-kept", id2)); info.Note != "the operator's note" {
		t.Errorf("the note of %s: %+v", id2, info)
	}
}

// The check against the real release: built from the 0.2.22 tag, its config
// validate refuses the address before the rollback and reads the state after
// it, with the rest of this release's state (the server name, the timing
// scale) untouched.
func TestRollbackRealOldBinary0222(t *testing.T) {
	bin := oldBinaryOf(t, "0.2.22", old0222Flag)
	hs := rollback0221State(t)
	hs.step("", "server", "name", "core-1")
	hs.step("", "config", "devices", "timeout-scale", "3")
	setEmails(hs)
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
	if out, code := run("config", "validate"); code != 1 || !strings.Contains(out, "user 'bob': unknown field 'email'") || !strings.Contains(out, "user 'erin': unknown field 'email'") {
		t.Errorf("0.2.22 config validate before: %d\n%s", code, out)
	}
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	if out, code := run("config", "validate"); code != 0 || !strings.Contains(out, "Configuration is valid.") || strings.Contains(out, "unknown") {
		t.Errorf("0.2.22 config validate after: %d\n%s", code, out)
	}
	if out, code := run("user", "show", "bob"); code != 0 || !strings.Contains(out, "bob") {
		t.Errorf("0.2.22 user show after: %d\n%s", code, out)
	}
	// a store write validates the store; the account sync after it is not under
	// test (the sandbox has no host to sync)
	if out, _ := run("user", "disable", "erin"); !strings.Contains(out, "User 'erin' disabled.") {
		t.Errorf("0.2.22 user disable (a store write) after:\n%s", out)
	}
	if o := hs.overrides(); !strings.Contains(o, "name: core-1") || !strings.Contains(o, "timeout_scale") {
		t.Errorf("tacctl.yaml lost a key of 0.2.22:\n%s", o)
	}
}

// old0222Flag names a 0.2.22 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary0222 -args -old-bin-0222=<path>.
var old0222Flag = flag.String("old-bin-0222", "", "a tacctl 0.2.22 binary built with -tags testknobs (TestRollbackRealOldBinary0222)")

// The snapshot is kept before anything is converted: when the copy cannot be
// made (backups-kept is a regular file), the rollback stops with nothing
// converted, the store still holds the addresses, and no key is removed.
func TestRollbackStopsWhenTheSnapshotCannotBeKept(t *testing.T) {
	for _, target := range []string{"0.2.22", "0.2.21", "0.2.19", "0.2.9", "0.2.3"} {
		t.Run(target, func(t *testing.T) {
			hs := rollback0221State(t)
			setEmails(hs)
			hs.write("state/backups-kept", "not a directory\n", 0o600)
			before := hs.read("state/store.yaml")
			r := hs.runner()
			hs.run(r, "rollback", target, "--apply", "--yes")
			hs.expect(1, "", "Nothing was converted.")
			out := hs.all()
			if !strings.Contains(out, "Could not keep snapshot ") {
				t.Errorf("no word of the kept copy:\n%s", out)
			}
			if got := hs.read("state/store.yaml"); got != before || !strings.Contains(got, "bob@example.net") {
				t.Errorf("the store changed:\n%s", got)
			}
			if strings.Contains(out, "removed the email address") {
				t.Errorf("the apply went on:\n%s", out)
			}
			var failed bool
			for _, l := range auditLines(r) {
				if strings.Contains(l, "rollback target="+target) && strings.Contains(l, "result=failed reason=store") {
					failed = true
				}
			}
			if !failed {
				t.Errorf("no failed audit line: %q", auditLines(r))
			}
			noLoggerHas(t, "rollback", r, "example.net", "Example.NET", "bob@", "Jones")
			// the file is still a file: nothing replaced it
			if b := hs.read("state/backups-kept"); b != "not a directory\n" {
				t.Errorf("backups-kept: %q", b)
			}
		})
	}
}
