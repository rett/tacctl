package cli

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
)

// The security review of the rotation (WP10.5f): what a failed proof may
// remove, one rotation of a host at a time, the entry read again before the
// registry changes, the proof's ssh trusting the pinned keys only, and a
// host with none pinned.

// unpin removes the pinned keys of web1.
func (hs *hostSandbox) unpin(name string) {
	hs.t.Helper()
	_, err := devreg.Mutate(hs.path("state", "devices.yaml"), hs.path("kh", "known_hosts"), nil, func(f *devreg.File) error {
		f.SetHostKeys(name, nil)
		return nil
	})
	if err != nil {
		hs.t.Fatal(err)
	}
}

func pinned(hs *hostSandbox, name string) []string {
	f, err := devreg.Load(hs.path("state", "devices.yaml"))
	if err != nil {
		hs.t.Fatal(err)
	}
	return f.HostKeysOf(name)
}

// A failed proof removes only what this run made. An account that an earlier
// run made (or another operator's concurrent run is using) is adopted, and
// stays: at most the sudoers line this run added is taken out.
func TestRotateFailedProofNeverDeletesAnAdoptedAccount(t *testing.T) {
	hs, rh := rotSandbox(t)
	run := func(createOut string, removeCode int) (string, *rotHost) {
		rh.reset(hs)
		rh.createOut, rh.removeCode = createOut, removeCode
		rh.proof = execx.Result{Code: 255}
		hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
		if hs.code != 1 || hs.registry() != rotRegBefore {
			t.Fatalf("exit %d registry %q\n%s", hs.code, hs.registry(), hs.err.String())
		}
		return plain(hs.out.String() + hs.err.String()), rh
	}
	// Created by this run: removed, with its home.
	all, _ := run("[INFO] origin: created\n[INFO] sudoers-line: added\n", 0)
	if rs := rh.pushes[len(rh.pushes)-1]; scriptKind(rs) != "remove" || !strings.Contains(rs, "REMOVE_HOME=1\n") || !strings.Contains(rs, "SUDOERS_ONLY=0\n") ||
		!strings.Contains(all, "The new account 'deploy2' and its sudoers line were removed from web1; nothing is left there.") {
		t.Errorf("created:\n%s", all)
	}
	// Adopted, the line added by this run: only the line is taken out.
	all, _ = run("[INFO] origin: adopted\n[INFO] sudoers-line: added\n", 0)
	rs := rh.pushes[len(rh.pushes)-1]
	if scriptKind(rs) != "remove" || !strings.Contains(rs, "SUDOERS_ONLY=1\n") || !strings.Contains(rs, "REMOVE_HOME=0\n") ||
		!strings.Contains(all, "The account 'deploy2' was made by an earlier run, not by this one, so it is not deleted.") ||
		!strings.Contains(all, "The sudoers line this run added for 'deploy2' was taken out of /etc/sudoers.d/tacctl-provisioner on web1. Left there: the account 'deploy2', its home and its key") ||
		strings.Contains(all, "were removed from web1; nothing is left there") {
		t.Errorf("adopted, added:\n%s", all)
	}
	// ... and when that fails too, the line is named.
	all, _ = run("[INFO] origin: adopted\n[INFO] sudoers-line: added\n", 1)
	if !strings.Contains(all, "could not be taken out of /etc/sudoers.d/tacctl-provisioner on web1. Left there: the account 'deploy2' with its home and key, and that line.") {
		t.Errorf("adopted, line stays:\n%s", all)
	}
	// Adopted with its line there before (same, or replaced): no script at
	// all; what is left is said.
	for out, want := range map[string]string{
		"[INFO] origin: adopted\n[INFO] sudoers-line: unchanged\n": "was there before this run and is left. Left there: the account 'deploy2'",
		"[INFO] origin: adopted\n[INFO] sudoers-line: changed\n":   "was replaced by this run (it had another); it is left as the rotation wrote it: check it.",
	} {
		all, _ = run(out, 0)
		if rh.has("push:remove") || !strings.Contains(all, want) {
			t.Errorf("%q: %q\n%s", out, rh.events, all)
		}
	}
	// A script that said nothing: nothing is deleted.
	all, _ = run("", 0)
	if rh.has("push:remove") || !strings.Contains(all, "The create script did not say what it did, so nothing was removed.") {
		t.Errorf("no status: %q\n%s", rh.events, all)
	}
}

// One rotation of a host at a time on this server: the second fails at once
// with a clear message, before it touches the host or the registry; the lock
// is released with the first command.
func TestRotateOneAtATimePerHost(t *testing.T) {
	hs, rh := rotSandbox(t)
	unlock, err := hosts.LockHost(hs.path("state", "locks"), "web1")
	if err != nil {
		t.Fatal(err)
	}
	n0 := hs.snapshots()
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	if hs.code != 1 || !strings.Contains(plain(hs.err.String()), "Another rotation of 'web1' is running; nothing was changed.") {
		t.Errorf("busy: %d %q", hs.code, hs.err.String())
	}
	if len(rh.pushes) != 0 || rh.has("run:") || rh.has("proof") || hs.registry() != rotRegBefore || hs.snapshots() != n0 {
		t.Errorf("the second run touched something: %q %q", rh.events, hs.registry())
	}
	// A dry run changes nothing and is not held up.
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--dry-run")
	if hs.code != 0 {
		t.Errorf("dry run while locked: %d %q", hs.code, hs.err.String())
	}
	// Another host is not blocked, and the lock goes with the command.
	unlock()
	rh.reset(hs)
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	if hs.code != 0 {
		t.Fatalf("after unlock: %d %q", hs.code, hs.err.String())
	}
	again, err := hosts.LockHost(hs.path("state", "locks"), "web1")
	if err != nil {
		t.Errorf("the lock was kept after the command: %v", err)
	} else {
		again()
	}
	if fi, err := os.Stat(hs.path("state", "locks", "host-provisioner-web1.lock")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file %v %v", fi, err)
	}
}

// The registry entry is read again under the lock before it is rewritten:
// a 'host move' that ran during the proof is not undone; a 'host target'
// that changed how the host is reached stops the rotation.
func TestRotateReadsTheEntryAgain(t *testing.T) {
	hs, rh := rotSandbox(t)
	rh.onProof = func() { hs.write("state/linux-hosts", "web1|admin@web1.example.net||prod|192.0.2.1|\n", 0o600) }
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	if hs.code != 0 || hs.registry() != "web1|"+rotNewTarget+"||prod|192.0.2.1|"+rh.keyPath+"\n" {
		t.Errorf("move during the proof: %d registry %q\n%s", hs.code, hs.registry(), hs.err.String())
	}

	rh.reset(hs)
	moved := "web1|admin@other.example.net|2222|lab|192.0.2.1|\n"
	rh.onProof = func() { hs.write("state/linux-hosts", moved, 0o600) }
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || hs.registry() != moved || !strings.Contains(all, "How tacctl reaches 'web1' changed while this ran (now admin@other.example.net port 2222); the registry was not rewritten.") {
		t.Errorf("target changed during the proof: %d registry %q\n%s", hs.code, hs.registry(), all)
	}
	if strings.Contains(hs.record("web1"), "provisioner") || rh.has("logger:host provisioner rotate name=web1 old=admin new=deploy2 auth=key by=root") {
		t.Errorf("the rotation was recorded: %s %q", hs.record("web1"), rh.events)
	}

	rh.reset(hs)
	rh.onProof = func() { hs.write("state/linux-hosts", "", 0o600) }
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	if hs.code != 1 || !strings.Contains(plain(hs.err.String()), "The host 'web1' is no longer enrolled; the registry was not changed.") || strings.TrimSpace(hs.registry()) != "" {
		t.Errorf("unenrolled during the proof: %d %q registry %q", hs.code, hs.err.String(), hs.registry())
	}
}

// The proof's ssh trusts the host's pinned keys and nobody else's: a
// known_hosts file made from the pins for this run (removed afterwards),
// strict checking, the pin's name as the alias, no system file. A host that
// has other keys is refused by ssh itself, and the account is taken away.
func TestRotateProofTrustsOnlyThePinnedKeys(t *testing.T) {
	hs, rh := rotSandbox(t)
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	if hs.code != 0 || len(rh.proofs) != 1 {
		t.Fatalf("exit %d %q", hs.code, hs.err.String())
	}
	m := regexp.MustCompile(`-o UserKnownHostsFile=(\S+) -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlias=web1 -o UpdateHostKeys=no`).FindStringSubmatch(rh.proofs[0])
	if m == nil {
		t.Fatalf("proof options: %s", rh.proofs[0])
	}
	if want := "web1 " + hkKey(t, "ed25519").String() + "\n"; rh.knownHosts != want {
		t.Errorf("known_hosts of the proof %q, want %q", rh.knownHosts, want)
	}
	if _, err := os.Stat(m[1]); err == nil {
		t.Errorf("%s left behind", m[1])
	}
	if pins := pinned(hs, "web1"); len(pins) != 1 {
		t.Errorf("pins %v", pins)
	}

	// Another machine answers: ssh refuses it against the pinned file.
	rh.reset(hs)
	rh.realKey = hkKey(t, "rsa").String()
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || !strings.Contains(all, "The proof failed: the new login did not work") || hs.registry() != rotRegBefore ||
		!strings.Contains(all, "The new account 'deploy2' and its sudoers line were removed from web1") {
		t.Errorf("another machine: %d\n%s", hs.code, all)
	}

	// An impostor that prints the pinned keys over a session ssh was told to
	// trust: the keys match, but ssh already refused it (above); with the
	// right known_hosts and other keys printed, the comparison catches it.
	rh.reset(hs)
	rh.proof = execx.Result{Stdout: []byte("tacctl-uid=0\n" + hkKey(t, "rsa").String() + " root@other\n")}
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || !strings.Contains(all, "the host reached is not 'web1' as pinned: its ssh keys differ") || !strings.Contains(all, "Pinned:") || !strings.Contains(all, "On the host:") ||
		!rh.has("logger:host provisioner hostkey-mismatch name=web1") {
		t.Errorf("keys differ: %d\n%s\n%q", hs.code, all, rh.events)
	}
}

// With nothing pinned nothing authenticates the host: --password is refused
// (it would be typed to whoever answers), --key shows the keys the host
// answered with and goes on only when they are confirmed (--yes confirms).
func TestRotateHostWithoutPins(t *testing.T) {
	hs, rh := rotSandbox(t)
	hs.unpin("web1")
	hs.tty = func() bool { return true }
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--password", "--yes")
	if hs.code != 1 || !strings.Contains(plain(hs.err.String()), "--password is refused: no ssh host key is pinned for 'web1'") || len(rh.pushes) != 0 || hs.registry() != rotRegBefore {
		t.Errorf("password: %d %q %q", hs.code, hs.err.String(), rh.events)
	}
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--password", "--dry-run")
	if hs.code != 1 || !strings.Contains(plain(hs.err.String()), "--password is refused") {
		t.Errorf("password dry run: %d %q", hs.code, hs.err.String())
	}

	// --key --yes: the plan says so, the proof's ssh has no pinned file, the
	// keys are listed, and the registry follows.
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || hs.registry() != "web1|"+rotNewTarget+"||lab|192.0.2.1|"+rh.keyPath+"\n" {
		t.Fatalf("key: %d %q\n%s", hs.code, hs.registry(), all)
	}
	for _, w := range []string{"no host key is pinned, so ssh goes by your own known_hosts and the keys the host shows are listed afterwards for you to confirm",
		"web1: no host key is pinned, so nothing but your own known_hosts vouched for the host. It answered with:", hkKey(t, "ed25519").Fingerprint(), "--yes: continuing with these keys"} {
		if !strings.Contains(all, w) {
			t.Errorf("output lacks %q\n%s", w, all)
		}
	}
	if strings.Contains(rh.proofs[0], "UserKnownHostsFile") || strings.Contains(rh.proofs[0], "StrictHostKeyChecking") {
		t.Errorf("proof options without pins: %s", rh.proofs[0])
	}
}

// Not confirmed means not trusted: the answer "no" is a failed proof, and the
// new account goes again.
func TestRotateUnpinnedKeysNotConfirmed(t *testing.T) {
	h := newHarness(t, nil)
	h.app.Stdin = strings.NewReader("n\n")
	inv := &invocation{app: h.app, ctx: context.Background()}
	r := &rotation{o: rotateOpts{name: "web1"}}
	proof := hosts.Proof{Connected: true, UID: "0", Keys: []byte(hkKey(t, "ed25519").String() + " root@web1\n")}
	if got := inv.proofProblem(r, proof); got != "the host's ssh keys were not confirmed" {
		t.Errorf("answer n: %q", got)
	}
	h = newHarness(t, nil)
	h.app.Stdin = strings.NewReader("y\n")
	inv = &invocation{app: h.app, ctx: context.Background()}
	if got := inv.proofProblem(r, proof); got != "" {
		t.Errorf("answer y: %q", got)
	}
	if shown := h.out.String() + h.err.String(); !strings.Contains(shown, hkKey(t, "ed25519").Fingerprint()) {
		t.Errorf("the keys were not shown: %q", shown)
	}
	// No keys read: nothing to confirm.
	inv = &invocation{app: newHarness(t, nil).app, ctx: context.Background()}
	if got := inv.proofProblem(r, hosts.Proof{Connected: true, UID: "0", KeysErr: hosts.ErrKeysUnread}); !strings.Contains(got, "nothing to confirm it is 'web1'") {
		t.Errorf("no keys: %q", got)
	}
}

// The hosts container and bats suites do not run here; the docs are held to
// what is true: the proof's host check, the lock and the adoption rule are
// said in the manual page, the README and the usage, and the old claims are
// gone.
func TestRotateDocsSayWhatIsTrue(t *testing.T) {
	man, err := os.ReadFile(filepath.Join("..", "..", "man", "tacctl.1"))
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	man = []byte(strings.ReplaceAll(string(man), `\-`, "-"))
	for name, text := range map[string]string{"man": string(man), "README": string(readme)} {
		for _, bad := range []string{"another machine fails the proof", "cannot succeed against another machine", "every administrator's 'tacctl host sync' reads it", "is how a re-run adopts the account"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s still says %q", name, bad)
			}
		}
	}
	for _, want := range []string{"/var/lib/tacctl-provisioner", "UserKnownHostsFile", "another rotation", "GECOS", "sudoers line last"} {
		if !strings.Contains(string(man), want) {
			t.Errorf("the manual page does not say %q", want)
		}
	}
	for _, want := range []string{"/var/lib/tacctl-provisioner", "pinned"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("the README does not say %q", want)
		}
	}
}
