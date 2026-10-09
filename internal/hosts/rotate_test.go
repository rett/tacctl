package hosts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

const proofKeys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqetQQZxbhY2eMxJy6V4Kz5mUqGzvYvpYbpRRUjoo root@web1\n"

// The proof is a login in a NEW connection with the new account's
// credentials only: no shared connection, the key file and nothing else for
// --key (password and keyboard-interactive off, BatchMode without a
// terminal), and for --password public keys off. It runs sudo for id -u and
// reads the host's keys in the same connection.
func TestProveLoginKey(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	e.AsUser, e.AuthSock = "alice", "/run/agent"
	f.On([]string{"sudo"}, execx.Result{Stdout: []byte(proofMarker + "0\n" + proofKeys)})
	p := e.ProveLogin(context.Background(), Login{Target: "deploy2@web1", Port: "2222", Identity: "/home/user/key", Auth: AuthKey})
	if !p.Connected || p.UID != "0" || string(p.Keys) != proofKeys || p.KeysErr != nil {
		t.Fatalf("proof %+v", p)
	}
	want := "sudo -u alice -H env SSH_AUTH_SOCK=/run/agent ssh -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o ForwardAgent=no -o ClearAllForwardings=yes " +
		"-o GSSAPIAuthentication=no -o HostbasedAuthentication=no " +
		"-o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes -p 2222 -i /home/user/key -T deploy2@web1 " + ProofCommand(AuthKey)
	if got := f.Argvs(); len(got) != 1 || got[0] != want {
		t.Errorf("argv %q\nwant %q", got, want)
	}
	if !strings.Contains(ProofCommand(AuthKey), "u=$(sudo -n id -u) || exit 7; echo tacctl-uid=$u; cat /etc/ssh/ssh_host_*_key.pub") {
		t.Errorf("command %q", ProofCommand(AuthKey))
	}

	// Sudo that does not give root, a failed login and a login that prints
	// no keys.
	for name, c := range map[string]struct {
		res  execx.Result
		want Proof
	}{
		"not root":   {execx.Result{Stdout: []byte(proofMarker + "1000\n" + proofKeys)}, Proof{Connected: true, UID: "1000", Keys: []byte(proofKeys)}},
		"ssh fails":  {execx.Result{Code: 255}, Proof{}},
		"sudo fails": {execx.Result{Code: 7}, Proof{}},
		"no keys":    {execx.Result{Stdout: []byte(proofMarker + "0\n")}, Proof{Connected: true, UID: "0", KeysErr: ErrKeysUnread}},
	} {
		f := &fake.Runner{}
		e.Runner = f
		f.On([]string{"sudo"}, c.res)
		got := e.ProveLogin(context.Background(), Login{Target: "deploy2@web1", Identity: "/k", Auth: AuthKey})
		if got.Connected != c.want.Connected || got.UID != c.want.UID || got.KeysErr != c.want.KeysErr || string(got.Keys) != string(c.want.Keys) {
			t.Errorf("%s: %+v want %+v", name, got, c.want)
		}
	}
}

func TestProveLoginPassword(t *testing.T) {
	e, out, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	e.TTY, e.StdinTTY = func() bool { return true }, func() bool { return true }
	// A prompt, the typed newline, then the id and the keys: only the
	// prompt reaches the screen.
	f.On([]string{"ssh"}, execx.Result{Stdout: []byte("[sudo] password for deploy2 on web1: \r\n" + proofMarker + "0\r\n" + proofKeys)})
	p := e.ProveLogin(context.Background(), Login{Target: "deploy2@web1", Identity: "/ignored", Auth: AuthPassword})
	if !p.Connected || p.UID != "0" || string(p.Keys) != proofKeys {
		t.Fatalf("proof %+v", p)
	}
	argv := f.Argvs()[0]
	for _, want := range []string{"-o ControlMaster=no -o ControlPath=none", "-o GSSAPIAuthentication=no -o HostbasedAuthentication=no", "-o PubkeyAuthentication=no", "-o PreferredAuthentications=password,keyboard-interactive",
		" -o LogLevel=ERROR -t deploy2@web1 u=$(sudo -p '[sudo] password for %u on %H: ' id -u) || exit 7; echo tacctl-uid=$u; cat /etc/ssh/ssh_host_*_key.pub"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv lacks %q: %s", want, argv)
		}
	}
	for _, not := range []string{"IdentitiesOnly", "-i ", "BatchMode", "PasswordAuthentication=no"} {
		if strings.Contains(argv, not) {
			t.Errorf("argv has %q: %s", not, argv)
		}
	}
	if got := out.String(); got != "[sudo] password for deploy2 on web1: \r\n" {
		t.Errorf("screen %q", got)
	}
}

func TestProofWriterAndParse(t *testing.T) {
	// The marker split over two writes: what came before it was shown, the
	// rest is kept and not shown.
	var screen bytes.Buffer
	w := &proofWriter{out: &screen}
	for _, chunk := range []string{"login banner\n", "[sudo] pw: \n" + proofMarker[:5], proofMarker[5:] + "0\n", "ssh-ed25519 AAAA x\n"} {
		_, _ = w.Write([]byte(chunk))
	}
	uid, keys := parseProof(w.buf.Bytes())
	if uid != "0" || string(keys) != "ssh-ed25519 AAAA x\n" {
		t.Errorf("parse %q %q", uid, keys)
	}
	if strings.Contains(screen.String(), "ssh-ed25519") || !strings.HasPrefix(screen.String(), "login banner\n[sudo] pw: \n") {
		t.Errorf("screen %q", screen.String())
	}
	if uid, keys := parseProof([]byte("Permission denied\n")); uid != "" || keys != nil {
		t.Errorf("no marker: %q %q", uid, keys)
	}
}

// Every access to the key file runs as the invoking user, never as root.
func TestKeyFileAccessRunsAsInvokingUser(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	e.AsUser = "alice"
	f.On([]string{"sudo", "-u", "alice", "-H", "stat"}, execx.Result{Stdout: []byte("1001 600 regular file\n")})
	f.On([]string{"sudo", "-u", "alice", "-H", "cat"}, execx.Result{Stdout: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq user@host\n")})
	f.On([]string{"sudo", "-u", "alice", "-H", "ssh-keygen", "-l"}, execx.Result{Stdout: []byte("256 SHA256:abcdef tacctl-provisioner (ED25519)\n")})
	ctx := context.Background()
	st := e.StatAsUser(ctx, "/home/user/key")
	if !st.Exists || !st.Regular || st.UID != 1001 || st.Mode != 0o600 {
		t.Errorf("stat %+v", st)
	}
	pub, err := e.PublicKeyOf(ctx, "/home/user/key")
	if err != nil || pub != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq tacctl-provisioner" {
		t.Errorf("public key %q %v", pub, err)
	}
	if fp := e.Fingerprint(ctx, pub); fp != "256 SHA256:abcdef (ED25519)" {
		t.Errorf("fingerprint %q", fp)
	}
	if err := e.GenerateKey(ctx, "/home/user/new"); err != nil {
		t.Errorf("generate: %v", err)
	}
	if n := f.Count("sudo"); n != len(f.Argvs()) {
		t.Errorf("a call not run as alice: %q", f.Argvs())
	}
	for _, a := range f.Argvs() {
		if !strings.HasPrefix(a, "sudo -u alice -H ") {
			t.Errorf("call %q", a)
		}
	}
	if !f.Called("sudo", "-u", "alice", "-H", "ssh-keygen", "-t", "ed25519", "-f", "/home/user/new", "-C", "tacctl-provisioner") {
		t.Errorf("keygen call: %q", f.Argvs())
	}
	// Not through sudo: as the process itself.
	e.AsUser = ""
	f.Reset()
	e.StatAsUser(ctx, "/k")
	if got := f.Argvs(); len(got) != 1 || got[0] != "stat -L -c %u %a %F -- /k" {
		t.Errorf("without sudo %q", got)
	}
	// A path that cannot be stat'ed, a key that is not one.
	f.On([]string{"stat"}, execx.Result{Code: 1})
	if st := e.StatAsUser(ctx, "/nope"); st.Exists {
		t.Errorf("stat of nothing %+v", st)
	}
	f.On([]string{"ssh-keygen", "-y"}, execx.Result{Stdout: []byte("garbage\n")})
	if _, err := e.PublicKeyOf(ctx, "/nope"); err == nil {
		t.Error("garbage accepted as a public key")
	}
}

func TestSSHDPasswordAuth(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"ssh"}, execx.Result{Stdout: []byte("port 22\npasswordauthentication no\nkbdinteractiveauthentication no\n")})
	if v, ok := e.SSHDPasswordAuth(context.Background(), "admin@web1", "", ""); !ok || v != "no" {
		t.Errorf("value %q %v", v, ok)
	}
	if a := f.Argvs()[0]; !strings.Contains(a, `/usr/sbin/sshd)" -T`) || !strings.Contains(a, "sudo -n") {
		t.Errorf("command %s", a)
	}
	f.On([]string{"ssh"}, execx.Result{Code: 1})
	if _, ok := e.SSHDPasswordAuth(context.Background(), "admin@web1", "", ""); ok {
		t.Error("a failed read gave a value")
	}
}

// The rotation keeps its first connection open across the steps it runs
// over it, and closes it when told to.
func TestRunScriptKeepOpen(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"ssh"}, execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")})
	e.KeepOpen = true
	if code, _, err := e.RunRotateScript(context.Background(), "admin@web1", "", "", []byte("echo\n")); err != nil || code != 0 {
		t.Fatalf("run: %d %v", code, err)
	}
	if f.CalledRegexp(`-O exit`) {
		t.Errorf("closed while kept open: %q", f.Argvs())
	}
	e.CloseSession(context.Background(), "admin@web1", "", "")
	if !f.CalledRegexp(`-O exit admin@web1$`) {
		t.Errorf("not closed: %q", f.Argvs())
	}
}

// With the host's pinned keys the proof's ssh checks the host against those
// keys alone, strictly, under the pin's name; the invoking user's
// known_hosts and the system's are not consulted. Without pins it adds
// nothing (the user's own known_hosts decides).
func TestProveLoginChecksThePinnedKeys(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"ssh"}, execx.Result{Stdout: []byte(proofMarker + "0\n" + proofKeys)})
	l := Login{Target: "deploy2@web1.example.net", Identity: "/k", Auth: AuthKey, KnownHosts: "/tmp/x/known_hosts", HostKeyAlias: "web1"}
	if p := e.ProveLogin(context.Background(), l); !p.Connected {
		t.Fatalf("proof %+v", p)
	}
	argv := f.Argvs()[0]
	for _, want := range []string{"-o UserKnownHostsFile=/tmp/x/known_hosts", "-o GlobalKnownHostsFile=/dev/null", "-o StrictHostKeyChecking=yes", "-o HostKeyAlias=web1", "-o UpdateHostKeys=no"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv lacks %q: %s", want, argv)
		}
	}
	for _, auth := range []string{AuthKey, AuthPassword} {
		if strings.Contains(strings.Join(ProofOptions(auth, "", ""), " "), "KnownHosts") || strings.Contains(strings.Join(ProofOptions(auth, "", ""), " "), "StrictHostKeyChecking") {
			t.Errorf("%s without pins: %q", auth, ProofOptions(auth, "", ""))
		}
		if !strings.Contains(strings.Join(ProofOptions(auth, "/f", "web1"), " "), "-o StrictHostKeyChecking=yes -o HostKeyAlias=web1") {
			t.Errorf("%s with pins: %q", auth, ProofOptions(auth, "/f", "web1"))
		}
	}
}

func TestTempKnownHosts(t *testing.T) {
	path, cleanup, err := TempKnownHosts("web1", []string{"ssh-ed25519 AAAA1", "ssh-rsa AAAA2"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "web1 ssh-ed25519 AAAA1\nweb1 ssh-rsa AAAA2\n" {
		t.Errorf("known_hosts %q", data)
	}
	// The invoking user's ssh must be able to read it: public keys only.
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("file %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("dir %v %v", fi, err)
	}
	cleanup()
	if _, err := os.Stat(path); err == nil {
		t.Error("not removed")
	}
	if _, _, err := TempKnownHosts("web1", []string{"ssh-ed25519 AAAA\nweb1 ssh-rsa BBBB"}); err == nil {
		t.Error("a key with a newline was accepted")
	}
}

// The invoking user's ssh reads the file whatever umask tacctl runs with
// (as root under sudo it can be 077).
func TestTempKnownHostsIgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	path, cleanup, err := TempKnownHosts("web1", []string{"ssh-ed25519 AAAA1"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("file %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("dir %v %v", fi, err)
	}
}

// RunRotateScript reads what the create script said it did, passes the
// output on unchanged, and gives the script a terminal on the host even
// without one here (so a lost connection hangs it up).
func TestRunRotateScriptStatusAndHangUp(t *testing.T) {
	e, out, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	e.TTY, e.StdinTTY = func() bool { return false }, func() bool { return false }
	f.Func(func(c execx.Cmd) bool { return c.Name == "ssh" }, func(c execx.Cmd) (execx.Result, error) {
		last := c.Args[len(c.Args)-1]
		if strings.HasPrefix(last, "trap 'rm -f") {
			if c.Stdout != nil {
				_, _ = c.Stdout.Write([]byte("[INFO] Adopting the existing provisioning account 'x'.\r\n[INFO] origin: adopted\r\n[INFO] sudoers-line: ch"))
				_, _ = c.Stdout.Write([]byte("anged\r\n"))
			}
			return execx.Result{}, nil
		}
		return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
	})
	code, st, err := e.RunRotateScript(context.Background(), "admin@web1", "", "", []byte("echo\n"))
	if err != nil || code != 0 {
		t.Fatalf("run: %d %v", code, err)
	}
	if st != (RotateStatus{Origin: OriginAdopted, Sudoers: SudoersChanged}) {
		t.Errorf("status %+v", st)
	}
	if !strings.Contains(out.String(), "origin: adopted") {
		t.Errorf("output not passed on: %q", out.String())
	}
	if !f.CalledRegexp(` -tt admin@web1 trap 'rm -f`) {
		t.Errorf("no terminal forced: %q", f.Argvs())
	}
	if e.HangUp {
		t.Error("HangUp left set")
	}
	// The line before the sudoers line is not a status.
	var sw = &statusWriter{w: io.Discard}
	_, _ = sw.Write([]byte("[INFO] origin: created and more\n[WARN] origin: adopted\n"))
	if sw.st != (RotateStatus{}) {
		t.Errorf("status from a non-status line: %+v", sw.st)
	}
}

func TestParseRotateState(t *testing.T) {
	a, u := ParseRotateState("account=deploy2\nuid=1500\nssh_dir=1\n")
	if a != "deploy2" || u != "1500" {
		t.Errorf("%q %q", a, u)
	}
	if a, u := ParseRotateState("garbage"); a != "" || u != "" {
		t.Errorf("%q %q", a, u)
	}
}

// One rotation of a host at a time: the second fails at once with a
// message that names the host; the lock goes with the first.
func TestLockHost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "locks")
	unlock, err := LockHost(dir, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockHost(dir, "web1"); !errors.Is(err, ErrRotationBusy) {
		t.Errorf("second lock: %v", err)
	}
	other, err := LockHost(dir, "web2")
	if err != nil {
		t.Errorf("another host: %v", err)
	} else {
		other()
	}
	unlock()
	again, err := LockHost(dir, "web1")
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	again()
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("dir %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "host-provisioner-web1.lock")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file %v %v", fi, err)
	}
}

// Two commands changing the same record at once keep both changes.
func TestRecordsUpdateIsLocked(t *testing.T) {
	rs := Records{Dir: filepath.Join(t.TempDir(), "hosts")}
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			for n := 0; n < 50; n++ {
				done2 := rs.Update("web1", func(r *Record) {
					if i == 0 {
						r.Provisioner = &ProvisionerRecord{New: "n", At: "t"}
					} else {
						r.Facts = &FactsRecord{OSName: "x"}
					}
				})
				if done2 != nil {
					done <- done2
					return
				}
			}
			done <- nil
		}(i)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	r, err := rs.Load("web1")
	if err != nil || r.Provisioner == nil || r.Facts == nil {
		t.Errorf("record %+v %v", r, err)
	}
}
