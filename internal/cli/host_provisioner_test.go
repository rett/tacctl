package cli

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
)

// 'host provisioner <name> rotate': the order of the steps through the
// scripted runner, what each refusal leaves untouched, a failed proof that
// takes the new account away again, --remove-old, the audit lines, and a
// password that never passes through tacctl.

const (
	rotPub        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqetQQZxbhY2eMxJy6V4Kz5mUqGzvYvpYbpRRUjoo user@host"
	rotRegBefore  = "web1|admin@web1.example.net||lab|192.0.2.1|\n"
	rotOldTarget  = "admin@web1.example.net"
	rotNewTarget  = "deploy2@web1.example.net"
	rotFingerLine = "256 SHA256:Zm9vYmFyYmF6 tacctl-provisioner (ED25519)"
	rotFingerText = "256 SHA256:Zm9vYmFyYmF6 (ED25519)"
)

// rotHost scripts a host for the rotation: what the ssh steps answer, and
// a log of what happened in which order.
type rotHost struct {
	t       *testing.T
	events  []string
	pushes  []string
	proofs  []string
	files   map[string]string
	keyPath string

	createCode, removeCode int
	proof                  execx.Result
	probe                  string
	accounts               string
	sshd                   string
	regAt                  map[string]string
	read                   func() string

	// createOut is what the create script prints (its status lines);
	// state is root's record of the account the dry run reads ("" none).
	createOut, state string
	// realKey is the host key the host really has: the proof's ssh, run
	// with a known_hosts file of pinned keys, refuses the host (255) when
	// that file does not hold it. knownHosts is that file as the proof saw it.
	realKey    string
	knownHosts string
	// onProof runs when the proof's ssh is called (something else changing
	// the registry meanwhile).
	onProof func()
}

const rotCreated = "[INFO] origin: created\n[INFO] sudoers-line: added\n"

// rotKeys is what the host offers as its ssh keys (the pinned one).
func rotKeys(t *testing.T) string { return hkKey(t, "ed25519").String() + " root@web1\n" }

func newRotHost(t *testing.T, keyPath string) *rotHost {
	rh := &rotHost{t: t, keyPath: keyPath, files: map[string]string{}, regAt: map[string]string{}, probe: "sudo",
		proof: execx.Result{Stdout: []byte("tacctl-uid=0\n" + rotKeys(t))}, createOut: rotCreated, realKey: hkKey(t, "ed25519").String()}
	rh.files[keyPath] = "1000 600 regular file\n"
	rh.files[keyPath+".pub"] = "1000 644 regular file\n"
	rh.files[filepath.Dir(keyPath)] = "1000 755 directory\n"
	return rh
}

func scriptKind(s string) string {
	switch {
	case strings.Contains(s, "create the provisioning account"):
		return "create"
	case strings.Contains(s, "remove a provisioning account"):
		return "remove"
	}
	return "?"
}

// script adds the rotation's answers to r.
func (rh *rotHost) script(r *fake.Runner) {
	r.Func(func(c execx.Cmd) bool { return c.Name == "logger" }, func(c execx.Cmd) (execx.Result, error) {
		rh.events = append(rh.events, "logger:"+c.Args[len(c.Args)-1])
		return execx.Result{}, nil
	})
	r.Func(func(c execx.Cmd) bool {
		if c.Name != "ssh" {
			return false
		}
		last := c.Args[len(c.Args)-1]
		return strings.Contains(strings.Join(c.Args, " "), "mktemp") || strings.Contains(last, "tacctl-uid=") ||
			strings.HasPrefix(last, "trap 'rm -f") || last == hosts.ProbeCommand || last == hosts.AccountsCommand || strings.Contains(last, "sshd)\" -T") || strings.Contains(last, hosts.RotateStateDir)
	}, func(c execx.Cmd) (execx.Result, error) {
		joined := strings.Join(c.Args, " ")
		last := c.Args[len(c.Args)-1]
		kind := ""
		if n := len(rh.pushes); n > 0 {
			kind = scriptKind(rh.pushes[n-1])
		}
		switch {
		case strings.Contains(joined, "mktemp"):
			b, _ := io.ReadAll(c.Stdin)
			rh.pushes = append(rh.pushes, string(b))
			rh.events = append(rh.events, "push:"+scriptKind(string(b)))
			return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
		case strings.Contains(last, "tacctl-uid="):
			rh.events = append(rh.events, "proof")
			rh.proofs = append(rh.proofs, joined)
			rh.regAt["proof"] = rh.read()
			if rh.onProof != nil {
				rh.onProof()
			}
			// A pinned-keys file: ssh, strict, refuses a host that has
			// none of its keys.
			if m := regexp.MustCompile(`UserKnownHostsFile=(\S+)`).FindStringSubmatch(joined); m != nil {
				data, err := os.ReadFile(m[1])
				if err != nil {
					return execx.Result{Code: 255}, nil
				}
				rh.knownHosts = string(data)
				if !strings.Contains(rh.knownHosts, rh.realKey) {
					return execx.Result{Code: 255}, nil
				}
			}
			return rh.proof, nil
		case strings.Contains(last, hosts.RotateStateDir):
			if rh.state == "" {
				return execx.Result{Code: 1}, nil
			}
			return execx.Result{Stdout: []byte(rh.state)}, nil
		case strings.HasPrefix(last, "trap 'rm -f"):
			rh.events = append(rh.events, "run:"+kind+"@"+c.Args[len(c.Args)-2])
			rh.regAt["run:"+kind] = rh.read()
			if kind == "create" {
				return execx.Result{Code: rh.createCode, Stdout: []byte(rh.createOut)}, nil
			}
			return execx.Result{Code: rh.removeCode}, nil
		case last == hosts.ProbeCommand:
			return execx.Result{Stdout: []byte(rh.probe + "\n")}, nil
		case last == hosts.AccountsCommand:
			return execx.Result{Stdout: []byte(rh.accounts)}, nil
		default: // sshd -T
			if rh.sshd == "" {
				return execx.Result{Code: 1}, nil
			}
			return execx.Result{Stdout: []byte("port 22\npasswordauthentication " + rh.sshd + "\n")}, nil
		}
	})
	// The invoking user's key file, as that user sees it.
	r.Func(func(c execx.Cmd) bool { return c.Name == "stat" }, func(c execx.Cmd) (execx.Result, error) {
		if out, ok := rh.files[c.Args[len(c.Args)-1]]; ok {
			return execx.Result{Stdout: []byte(out)}, nil
		}
		return execx.Result{Code: 1}, nil
	})
	r.Func(func(c execx.Cmd) bool { return c.Name == "cat" }, func(c execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte(rotPub + "\n")}, nil
	})
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh-keygen" }, func(c execx.Cmd) (execx.Result, error) {
		if len(c.Args) > 0 && c.Args[0] == "-t" {
			rh.events = append(rh.events, "keygen")
			rh.files[rh.keyPath] = "1000 600 regular file\n"
			rh.files[rh.keyPath+".pub"] = "1000 644 regular file\n"
			return execx.Result{}, nil
		}
		return execx.Result{Stdout: []byte(rotFingerLine + "\n")}, nil
	})
}

func (rh *rotHost) eventIndex(prefix string) int {
	for i, e := range rh.events {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

func (rh *rotHost) has(prefix string) bool { return rh.eventIndex(prefix) >= 0 }

// rotSandbox enrolls web1 at admin@web1.example.net with its keys pinned
// and returns the sandbox and the scripted host.
func rotSandbox(t *testing.T) (*hostSandbox, *rotHost) {
	t.Helper()
	hs := newHostSandbox(t)
	keyDir := filepath.Join(hs.dir, "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rh := newRotHost(t, filepath.Join(keyDir, "web1"))
	rh.read = hs.registry
	ed := hkKey(t, "ed25519")
	r := hs.factsRunner("ssh_connection=198.51.100.9 50022 192.0.2.50 22\n")
	scan("web1.example.net", ed)(r)
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.ReadKeysCommand },
		func(execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: []byte(ed.String() + " root@web1\n")}, nil
		})
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	if hs.registry() != rotRegBefore {
		t.Fatalf("registry %q", hs.registry())
	}
	return hs, rh
}

// reset puts the registry and the scripted host back as the sandbox began,
// so one sandbox serves several scenarios of a test.
func (rh *rotHost) reset(hs *hostSandbox) {
	hs.write("state/linux-hosts", rotRegBefore, 0o600)
	_ = os.Remove(filepath.Join(hs.dir, "state", "hosts", "web1.json"))
	rh.events, rh.pushes, rh.proofs = nil, nil, nil
	rh.createCode, rh.removeCode = 0, 0
	rh.createOut, rh.state, rh.knownHosts, rh.onProof = rotCreated, "", "", nil
	rh.realKey = hkKey(rh.t, "ed25519").String()
	rh.proof = execx.Result{Stdout: []byte("tacctl-uid=0\n" + rotKeys(rh.t))}
	rh.regAt = map[string]string{}
}

// rotRun runs 'host provisioner ...' on a runner scripted by rh.
func (hs *hostSandbox) rotRun(rh *rotHost, args ...string) string {
	hs.t.Helper()
	r := hs.runner()
	rh.script(r)
	return hs.run(r, append([]string{"host", "provisioner"}, args...)...)
}

func (hs *hostSandbox) snapshots() int {
	m, _ := filepath.Glob(filepath.Join(hs.dir, "state", "backups", "2*"))
	return len(m)
}

func (hs *hostSandbox) record(name string) string {
	data, _ := os.ReadFile(filepath.Join(hs.dir, "state", "hosts", name+".json"))
	return string(data)
}

// The order of the steps: the account is created over the login in use,
// proved in a new connection, and only then does the registry change; the
// old account stays.
func TestRotateWithKey(t *testing.T) {
	hs, rh := rotSandbox(t)
	n0 := hs.snapshots()
	out := plain(hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes"))
	all := plain(out + hs.err.String())
	if hs.code != 0 {
		t.Fatalf("exit %d\n%s", hs.code, all)
	}
	// The plan.
	for _, want := range []string{
		"Rotate the provisioning account of web1", "Login now:       " + rotOldTarget, "New account:     deploy2 (key login)",
		"useradd -m -U -s /bin/bash -c 'tacctl provisioning account' -K UID_MAX=79999 -K GID_MAX=79999 deploy2",
		"/etc/sudoers.d/tacctl-provisioner: deploy2 ALL=(ALL:ALL) NOPASSWD: ALL", rh.keyPath + "  " + rotFingerText,
		"'sudo -n id -u' and must print 0; its ssh trusts the host's pinned keys only",
		"Registry:        " + strings.TrimSuffix(rotRegBefore, "\n"),
		"  becomes:       web1|" + rotNewTarget + "||lab|192.0.2.1|" + rh.keyPath,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q\n%s", want, out)
		}
	}
	// The order.
	want := []string{"push:create", "run:create@" + rotOldTarget, "proof", "logger:host provisioner rotate name=web1 old=admin new=deploy2 auth=key by=root"}
	var got []string
	for _, e := range rh.events {
		for _, w := range want {
			if e == w {
				got = append(got, e)
			}
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("events %q", rh.events)
	}
	if rh.has("push:remove") || rh.has("run:remove") {
		t.Errorf("the old account was touched: %q", rh.events)
	}
	// Nothing changed until the proof held.
	if rh.regAt["run:create"] != rotRegBefore || rh.regAt["proof"] != rotRegBefore {
		t.Errorf("registry before the proof: %q %q", rh.regAt["run:create"], rh.regAt["proof"])
	}
	if got := hs.registry(); got != "web1|"+rotNewTarget+"||lab|192.0.2.1|"+rh.keyPath+"\n" || hs.snapshots() != n0+1 {
		t.Errorf("registry %q, snapshots %d", got, hs.snapshots()-n0)
	}
	if rec := hs.record("web1"); !strings.Contains(rec, `"old": "admin"`) || !strings.Contains(rec, `"new": "deploy2"`) ||
		!strings.Contains(rec, `"auth": "key"`) || !strings.Contains(rec, `"old_removed": false`) {
		t.Errorf("record %s", rec)
	}
	// The proof: a fresh connection, the new account's key only, sudo -n.
	if len(rh.proofs) != 1 {
		t.Fatalf("proofs %q", rh.proofs)
	}
	for _, w := range []string{"-o ControlMaster=no -o ControlPath=none", "-o IdentitiesOnly=yes", "-o PreferredAuthentications=publickey", "-o PasswordAuthentication=no", "-o KbdInteractiveAuthentication=no",
		"-o GSSAPIAuthentication=no", "-o HostbasedAuthentication=no",
		"-o GlobalKnownHostsFile=/dev/null", "-o StrictHostKeyChecking=yes", "-o HostKeyAlias=web1",
		"-o BatchMode=yes", "-i " + rh.keyPath, " -T " + rotNewTarget + " u=$(sudo -n id -u)"} {
		if !strings.Contains(rh.proofs[0], w) {
			t.Errorf("proof lacks %q: %s", w, rh.proofs[0])
		}
	}
	// The create script: what the host runs.
	cs := rh.pushes[0]
	for _, w := range []string{"ACCOUNT=deploy2\n", "AUTH=key\n", "PUBKEY=ssh-ed25519\\ AAAAC3NzaC1lZDI1NTE5AAAAIOMqqetQQZxbhY2eMxJy6V4Kz5mUqGzvYvpYbpRRUjoo\\ tacctl-provisioner\n",
		"UID_FIRST=80000\n", "FORBIDDEN=80000-89999\\ 20000-29999\n"} {
		if !strings.Contains(cs, w) {
			t.Errorf("create script lacks %q", w)
		}
	}
	if !strings.Contains(all, "The old login 'admin' is still on web1. Remove it, over the new one: tacctl host provisioner web1 rotate deploy2 --key "+rh.keyPath+" --remove-old") {
		t.Errorf("no hint about the old login:\n%s", all)
	}
	if !strings.Contains(all, "Host 'web1' is now reached at "+rotNewTarget) {
		t.Errorf("no result line:\n%s", all)
	}
}

// Refusals leave everything as it was: no script copied, no snapshot, no
// registry change.
func TestRotateRefusals(t *testing.T) {
	hs, rh := rotSandbox(t)
	hs.loopback()
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--scope", "lab", "--build-on-host")
	hs.write("state/linux-hosts", hs.registry()+
		"web2|web2.example.net||lab|192.0.2.1|\n"+
		"rootbox|root@rootbox.example.net||lab|192.0.2.1|\n"+
		"alicebox|alice@alicebox.example.net||lab|192.0.2.1|\n", 0o600)
	before, n0 := hs.registry(), hs.snapshots()
	key := rh.keyPath
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"nope", "rotate", "deploy2", "--key", key, "--yes"}, "No enrolled host named 'nope'."},
		{[]string{"web1", "rotate", "deploy2", "--yes"}, "Give --key <file> or --password (one of them)."},
		{[]string{"web1", "rotate", "deploy2", "--key", key, "--password", "--yes"}, "Give --key <file> or --password (one of them)."},
		{[]string{"web1", "rotate", "deploy2", "--password", "--yes"}, "--password needs a terminal"},
		{[]string{"web1", "rotate", "root", "--key", key, "--yes"}, "cannot be 'root'"},
		{[]string{"web1", "rotate", "admin", "--key", key, "--yes"}, "'admin' is the login tacctl uses for web1 now"},
		{[]string{"web1", "rotate", "carol", "--key", key, "--yes"}, "'carol' is a tacctl user"},
		{[]string{"web1", "rotate", "Bad Name", "--key", key, "--yes"}, "Invalid account name 'Bad Name'"},
		{[]string{"web1", "rotate", "deploy2", "--key", key, "--remove-home", "--yes"}, "--remove-home goes with --remove-old."},
		{[]string{"authsrv", "rotate", "deploy2", "--key", key, "--yes"}, "'authsrv' is this server (enrolled with --local)"},
		{[]string{"web2", "rotate", "deploy2", "--key", key, "--remove-old", "--yes"}, "--remove-old needs a registry target with an explicit user"},
		{[]string{"rootbox", "rotate", "deploy2", "--key", key, "--remove-old", "--yes"}, "The old login is 'root'; there is nothing to remove."},
		{[]string{"alicebox", "rotate", "deploy2", "--key", key, "--remove-old", "--yes"}, "The old login 'alice' is a tacctl user"},
		{[]string{"web1", "rotate", "deploy2", "--key", key}, "Confirm with --yes."},
		{[]string{"web1", "rotate", "deploy2", "--key", filepath.Join(hs.dir, "nodir", "k"), "--yes"}, "does not exist; nothing was changed."},
		{[]string{"web1", "rotate", "deploy2", "--key", filepath.Join(hs.dir, "keys", "web9"), "--yes"}, "generating it needs a terminal"},
		{[]string{"web1", "rotate", "deploy2", "--key", filepath.Join(hs.dir, "keys"), "--yes"}, "is not a regular file"},
		{[]string{"web1", "rotate", "deploy2", "--key"}, "--key needs a file."},
		{[]string{"web1", "rotate", "deploy2", "--key", key, "--bogus"}, "Unknown option: '--bogus'"},
		{[]string{"web1", "bogus", "deploy2", "--key", key}, "The only one is 'rotate'."},
		{[]string{"web1", "rotate"}, "Usage: tacctl host provisioner <name> rotate <user>"},
		{nil, "Usage: tacctl host provisioner <name> rotate <user>"},
	} {
		hs.rotRun(rh, c.args...)
		if hs.code != 1 || !strings.Contains(plain(hs.err.String()), c.err) {
			t.Errorf("%v: %d %q", c.args, hs.code, hs.err.String())
		}
		if hs.registry() != before || hs.snapshots() != n0 || len(rh.pushes) != 0 || rh.has("logger") || rh.has("run:") || rh.has("proof") {
			t.Errorf("%v changed something: %q %q", c.args, hs.registry(), rh.events)
		}
	}
}

// A missing key is made by ssh-keygen (as the invoking user, on the
// terminal) before anything is created, and recorded as the identity.
func TestRotateGeneratesTheKey(t *testing.T) {
	hs, rh := rotSandbox(t)
	hs.tty = func() bool { return true }
	newKey := filepath.Join(hs.dir, "keys", "fresh")
	rh.keyPath = newKey
	delete(rh.files, newKey)
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", newKey, "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Generating "+newKey) {
		t.Fatalf("exit %d\n%s", hs.code, all)
	}
	if i, j := rh.eventIndex("keygen"), rh.eventIndex("push:create"); i < 0 || j < 0 || i > j {
		t.Errorf("events %q", rh.events)
	}
	if !strings.HasSuffix(strings.TrimSpace(hs.registry()), "|"+newKey) {
		t.Errorf("registry %q", hs.registry())
	}
	// Without a terminal, --dry-run still says what would happen.
	hs.tty = nil
	rh.reset(hs)
	rh.keyPath = filepath.Join(hs.dir, "keys", "later")
	out := plain(hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--dry-run"))
	if hs.code != 0 || !strings.Contains(out, "does not exist; ssh-keygen -t ed25519 makes it, as you") || rh.has("keygen") {
		t.Errorf("dry run: %d\n%s", hs.code, out)
	}
}

// The password is typed into the host's own passwd and into ssh's and
// sudo's prompts: nothing of it is in an argument, an environment, a script,
// a log line, the output, the registry, the record or a snapshot; the
// registry identity is cleared, and the proof does not use keys.
func TestRotateWithPasswordNeverSeesIt(t *testing.T) {
	hs, rh := rotSandbox(t)
	hs.tty = func() bool { return true }
	const secret = "Sup3r-S3cret-typed"
	hs.stdin = secret + "\n"
	hs.write("keys/old-id", "x", 0o600)
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|"+hs.path("keys", "old-id")+"\n", 0o600)
	rh.proof = execx.Result{Stdout: []byte("[sudo] password for deploy2 on web1: \r\ntacctl-uid=0\r\n" + rotKeys(t))}
	r := hs.runner()
	rh.script(r)
	hs.run(r, "host", "provisioner", "web1", "rotate", "deploy2", "--password", "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 {
		t.Fatalf("exit %d\n%s", hs.code, all)
	}
	if got := hs.registry(); got != "web1|"+rotNewTarget+"||lab|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	// What ran.
	var runArgv string
	for _, a := range r.Argvs() {
		if strings.Contains(a, "trap 'rm -f") && strings.Contains(a, "bash /tmp/tacctl") {
			runArgv = a
		}
	}
	if !strings.Contains(runArgv, " -t admin@web1.example.net ") || !strings.Contains(runArgv, "sudo -p '[sudo] password for %u on %H: '") || !strings.Contains(runArgv, "-i "+hs.path("keys", "old-id")) {
		t.Errorf("create run %s", runArgv)
	}
	if len(rh.proofs) != 1 || !strings.Contains(rh.proofs[0], "-o PubkeyAuthentication=no") || strings.Contains(rh.proofs[0], " -i ") || strings.Contains(rh.proofs[0], "IdentitiesOnly") ||
		!strings.Contains(rh.proofs[0], "sudo -p '[sudo] password for %u on %H: ' id -u") {
		t.Errorf("proof %q", rh.proofs)
	}
	if cs := rh.pushes[0]; !strings.Contains(cs, "AUTH=password\n") || strings.Contains(cs, "PUBKEY=ssh-") || !strings.Contains(cs, "SUDOERS_LINE=deploy2\\ ALL=\\(ALL:ALL\\)\\ ALL\n") {
		t.Errorf("password script header:\n%s", cs[:min(len(cs), 900)])
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "host provisioner rotate name=web1 old=admin new=deploy2 auth=password by=root") {
		t.Errorf("audit line: %q", r.Argvs())
	}
	// The secret: only a terminal-carrying ssh (-t) ever gets the stream it
	// is typed on.
	for _, rec := range r.Records() {
		argv := strings.Join(rec.Cmd.Argv(), " ")
		if strings.Contains(argv, secret) || strings.Contains(strings.Join(rec.Cmd.Env, "\n"), secret) || strings.Contains(strings.Join(rec.Cmd.UserEnv, "\n"), secret) {
			t.Errorf("secret in a call: %s", argv)
		}
		if strings.Contains(string(rec.Stdin), secret) && (rec.Cmd.Name != "ssh" || !strings.Contains(argv, " -t ")) {
			t.Errorf("secret on the stdin of %s", argv)
		}
	}
	for _, s := range append(append([]string(nil), rh.pushes...), rh.events...) {
		if strings.Contains(s, secret) {
			t.Errorf("secret in %q", s)
		}
	}
	if strings.Contains(all, secret) {
		t.Errorf("secret in the output:\n%s", all)
	}
	_ = filepath.WalkDir(hs.dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if data, _ := os.ReadFile(p); strings.Contains(string(data), secret) {
				t.Errorf("secret in %s", p)
			}
		}
		return nil
	})
}

// A proof that fails removes the new account and its sudoers line again,
// over the login in use, logs the failed step and leaves the registry.
func TestRotateFailedProofRemovesTheAccount(t *testing.T) {
	hs, rh := rotSandbox(t)
	for _, c := range []struct {
		name  string
		proof execx.Result
		why   string
	}{
		{"ssh fails", execx.Result{Code: 255}, "the new login did not work"},
		{"not root", execx.Result{Stdout: []byte("tacctl-uid=1001\n")}, "the new login reached sudo as UID 1001, not root"},
		{"another host", execx.Result{Stdout: []byte("tacctl-uid=0\n" + hkKey(t, "rsa").String() + " root@other\n")}, "the host reached is not 'web1' as pinned: its ssh keys differ"},
		{"no keys", execx.Result{Stdout: []byte("tacctl-uid=0\n")}, "the host's ssh keys could not be read over the new login"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rh.reset(hs)
			rh.proof = c.proof
			n0 := hs.snapshots()
			hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
			all := plain(hs.out.String() + hs.err.String())
			if hs.code != 1 || !strings.Contains(all, "The proof failed: "+c.why) {
				t.Fatalf("exit %d\n%s", hs.code, all)
			}
			if !strings.Contains(all, "The new account 'deploy2' and its sudoers line were removed from web1; nothing is left there. The registry is unchanged.") {
				t.Errorf("no word on the removal:\n%s", all)
			}
			// Create, proof, then the removal over the login in use.
			i, j, k := rh.eventIndex("run:create"), rh.eventIndex("proof"), rh.eventIndex("run:remove@"+rotOldTarget)
			if i < 0 || j < i || k < j {
				t.Errorf("events %q", rh.events)
			}
			rs := rh.pushes[len(rh.pushes)-1]
			if scriptKind(rs) != "remove" || !strings.Contains(rs, "ACCOUNT=deploy2\n") || !strings.Contains(rs, "REMOVE_HOME=1\n") || strings.Contains(rs, "SUDOERS_ONLY=1\n") {
				t.Errorf("removal script:\n%s", rs[:min(len(rs), 500)])
			}
			if !rh.has("logger:host provisioner rotate name=web1 old=admin new=deploy2 auth=key step=prove by=root") {
				t.Errorf("no audit line: %q", rh.events)
			}
			if rh.has("logger:host provisioner rotate name=web1 old=admin new=deploy2 auth=key by=root") {
				t.Errorf("the rotation was logged as done")
			}
			if hs.registry() != rotRegBefore || hs.snapshots() != n0 || strings.Contains(hs.record("web1"), "provisioner") {
				t.Errorf("changed: %q %d", hs.registry(), hs.snapshots()-n0)
			}
		})
	}
	// The removal fails too: what is left is named.
	rh.reset(hs)
	rh.proof = execx.Result{Code: 255}
	rh.removeCode = 1
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || !strings.Contains(all, "The new account 'deploy2' could not be removed from web1. Left there: the account 'deploy2' with its home, and its line in /etc/sudoers.d/tacctl-provisioner.") ||
		hs.registry() != rotRegBefore {
		t.Errorf("removal failed: %d\n%s", hs.code, all)
	}
}

// A creation that fails changes nothing: no proof, no removal, no registry
// change.
func TestRotateCreationFails(t *testing.T) {
	hs, rh := rotSandbox(t)
	rh.createCode = 1
	n0 := hs.snapshots()
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--yes")
	if hs.code != 1 || !strings.Contains(plain(hs.err.String()), "The account 'deploy2' could not be created on web1 (see above); the registry was not changed.") {
		t.Errorf("exit %d %q", hs.code, hs.err.String())
	}
	if rh.has("proof") || rh.has("push:remove") || rh.has("logger") || hs.registry() != rotRegBefore || hs.snapshots() != n0 {
		t.Errorf("events %q registry %q", rh.events, hs.registry())
	}
}

// --remove-old runs last, as the new account (its login and key), after the
// registry changed; a failed removal leaves the registry on the new account
// and says how to finish; a re-run with the new account as the login still
// knows the old one from the host's record.
func TestRotateRemoveOld(t *testing.T) {
	hs, rh := rotSandbox(t)
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--remove-old", "--yes")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "The old account 'admin' is removed from web1.") {
		t.Fatalf("exit %d\n%s", hs.code, all)
	}
	reg := "web1|" + rotNewTarget + "||lab|192.0.2.1|" + rh.keyPath + "\n"
	i, j, k := rh.eventIndex("logger:host provisioner rotate "), rh.eventIndex("push:remove"), rh.eventIndex("run:remove@"+rotNewTarget)
	if i < 0 || j < i || k < j || rh.regAt["run:remove"] != reg {
		t.Errorf("events %q registry at removal %q", rh.events, rh.regAt["run:remove"])
	}
	rs := rh.pushes[len(rh.pushes)-1]
	for _, w := range []string{"ACCOUNT=admin\n", "REMOVE_HOME=0\n"} {
		if !strings.Contains(rs, w) {
			t.Errorf("removal script lacks %q", w)
		}
	}
	if !rh.has("logger:host provisioner remove-old name=web1 old=admin new=deploy2 by=root") || !strings.Contains(hs.record("web1"), `"old_removed": true`) {
		t.Errorf("events %q record %s", rh.events, hs.record("web1"))
	}
	// The session it ran over is the new account's: its key, its target.
	var runArgv string
	for _, a := range hs.sandbox.runner.Argvs() {
		if strings.Contains(a, "bash /tmp/tacctl") && strings.Contains(a, rotNewTarget) {
			runArgv = a
		}
	}
	if !strings.Contains(runArgv, "-i "+rh.keyPath) {
		t.Errorf("removal ran as %q", runArgv)
	}

	// With --remove-home the home goes too.
	rh.reset(hs)
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--remove-old", "--remove-home", "--yes")
	if rs := rh.pushes[len(rh.pushes)-1]; hs.code != 0 || !strings.Contains(rs, "REMOVE_HOME=1\n") {
		t.Errorf("--remove-home: %d\n%s", hs.code, rs[:min(len(rs), 400)])
	}

	// A failed removal: the registry stays on the new account.
	rh.reset(hs)
	reg = "web1|" + rotNewTarget + "||lab|192.0.2.1|" + rh.keyPath + "\n"
	rh.removeCode = 1
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--remove-old", "--yes")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || !strings.Contains(all, "The old account 'admin' could not be removed from web1 (see above). The registry already reaches the new account;") ||
		!strings.Contains(all, "Try again: tacctl host provisioner web1 rotate deploy2 --key "+rh.keyPath+" --remove-old") ||
		hs.registry() != reg || strings.Contains(hs.record("web1"), `"old_removed": true`) {
		t.Errorf("failed removal: %d\n%s", hs.code, all)
	}
	// The re-run: the registry points at the new account, the record names
	// the old one.
	rh.removeCode = 0
	rh.events, rh.pushes = nil, nil
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--remove-old", "--yes")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "The old account 'admin' is removed from web1.") || rh.has("push:create") || rh.has("proof") ||
		!rh.has("run:remove@"+rotNewTarget) || !strings.Contains(hs.record("web1"), `"old_removed": true`) {
		t.Errorf("re-run: %d\n%s\n%q", hs.code, all, rh.events)
	}
	// And once it is done, there is nothing to resume: the new account is
	// simply the login in use.
	rh.events, rh.pushes = nil, nil
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--remove-old", "--yes")
	if hs.code != 1 || !strings.Contains(hs.err.String(), "is the login tacctl uses for web1 now") || len(rh.pushes) != 0 {
		t.Errorf("done: %d %q", hs.code, hs.err.String())
	}
}

func TestRemoveOldRefusal(t *testing.T) {
	for _, c := range []struct {
		old, new string
		user     bool
		target   string
		want     string
	}{
		{"admin", "deploy2", false, "deploy2@h", ""},
		{"", "deploy2", false, "deploy2@h", "There is no old account to remove."},
		{"deploy2", "deploy2", false, "deploy2@h", "The old and the new account are both 'deploy2'"},
		{"root", "deploy2", false, "deploy2@h", "The old login is 'root'; there is nothing to remove."},
		{"alice", "deploy2", true, "deploy2@h", "The old login 'alice' is a tacctl user"},
		{"admin", "deploy2", false, "admin@h", "The registry does not reach the host as 'deploy2' yet"},
		{"admin", "deploy2", false, "h", "The registry does not reach the host as 'deploy2' yet"},
		{"admin", "deploy", false, "deploy2@h", "The registry does not reach the host as 'deploy' yet"},
	} {
		if got := removeOldRefusal(c.old, c.new, c.user, c.target); !strings.Contains(got, c.want) || (c.want == "") != (got == "") {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

// --dry-run prints the plan and reads the host (the login, the account, the
// sshd setting); it changes and copies nothing.
func TestRotateDryRun(t *testing.T) {
	hs, rh := rotSandbox(t)
	rh.sshd = "no"
	rh.accounts = "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
	n0 := hs.snapshots()
	out := plain(hs.rotRun(rh, "web1", "rotate", "deploy2", "--password", "--dry-run"))
	_ = out
	// --password needs a terminal even for the plan.
	if hs.code != 1 {
		t.Fatalf("password dry run without terminal: %d", hs.code)
	}
	hs.tty = func() bool { return true }
	out = plain(hs.rotRun(rh, "web1", "rotate", "deploy2", "--password", "--dry-run"))
	all := plain(out + hs.err.String())
	for _, w := range []string{"New account:     deploy2 (password login)", "typed into the host's own passwd on this terminal; tacctl never sees it",
		"sudoers.d/tacctl-provisioner: deploy2 ALL=(ALL:ALL) ALL", "The login on web1 reaches root through sudo without a password.",
		"No account 'deploy2' on web1; the rotation creates it.", "sshd on web1: passwordauthentication no; a --password proof would always fail there.",
		"Dry run: nothing was changed."} {
		if !strings.Contains(all, w) {
			t.Errorf("dry run lacks %q\n%s", w, all)
		}
	}
	if hs.code != 0 || hs.registry() != rotRegBefore || hs.snapshots() != n0 || len(rh.pushes) != 0 || rh.has("logger") || rh.has("run:") || rh.has("proof") {
		t.Errorf("dry run changed something: %d %q", hs.code, rh.events)
	}
	// The account exists: adopted when it carries the marker, refused
	// otherwise.
	rh.accounts += "deploy2:x:1500:1500:" + hosts.RotateMarker + ",,,:/home/deploy2:/bin/bash\n"
	rh.sshd = "yes"
	// Root's record on the host agrees: adopted.
	rh.state = "account=deploy2\nuid=1500\nssh_dir=1\n"
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--dry-run")
	if all := plain(hs.out.String() + hs.err.String()); hs.code != 0 || !strings.Contains(all, "The account 'deploy2' (UID 1500) was made by tacctl (root's record on web1 agrees); the rotation adopts it and empties its ~/.ssh.") ||
		!strings.Contains(all, "sshd on web1: passwordauthentication yes") {
		t.Errorf("recorded: %d\n%s", hs.code, all)
	}
	// The marker comment alone is no proof: no record, refused.
	rh.state = ""
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--dry-run")
	if all := plain(hs.out.String() + hs.err.String()); !strings.Contains(all, "exists on web1 and no readable record shows that tacctl made it (the comment field is not proof); the rotation would refuse it.") {
		t.Errorf("marker only:\n%s", all)
	}
	rh.state = "account=deploy2\nuid=1499\n"
	hs.rotRun(rh, "web1", "rotate", "deploy2", "--key", rh.keyPath, "--dry-run")
	if all := plain(hs.out.String() + hs.err.String()); !strings.Contains(all, "root's record of it names UID 1499; the rotation would refuse it.") {
		t.Errorf("record of another uid:\n%s", all)
	}
	// A login that cannot be made fails the dry run, as the rotation would.
	rh.probe = ""
	r := hs.runner()
	rh.script(r)
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" && c.Args[len(c.Args)-1] == hosts.ProbeCommand },
		func(execx.Cmd) (execx.Result, error) { return execx.Result{Code: 255}, nil })
	hs.run(r, "host", "provisioner", "web1", "rotate", "deploy2", "--key", rh.keyPath, "--dry-run")
	if hs.code != 1 || !strings.Contains(plain(hs.err.String()), "Could not log in to "+rotOldTarget+" (ssh failed, see above); the rotation would fail the same way.") {
		t.Errorf("ssh fails: %d %q", hs.code, hs.err.String())
	}
}

// --- the gate ------------------------------------------------------------------------

// The gate: every tier below the superuser is refused, the engineer too
// (Linux host deployment is the superuser's).
func TestRotateGate(t *testing.T) {
	sb := newSandbox(t, true)
	// carol is read-only, bob an operator (no tier override here).
	for _, c := range []struct{ user, groups string }{{"carol", "carol tac-users tac-readonly"}, {"bob", "bob tac-users tac-operator"}} {
		sb.cfgRun("", []string{"host", "provisioner", "web1", "rotate", "deploy2", "--password"}, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", c.user}, execx.Result{Stdout: []byte(c.groups + "\n")})
		}, "SUDO_USER="+c.user)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl host provisioner' is not permitted for the") {
			t.Errorf("%s: %d %q", c.user, sb.code, sb.stderr())
		}
	}
	eng := engineerSandbox(t)
	eng.asEngineer("", "host", "provisioner", "web1", "rotate", "deploy2", "--password")
	if eng.code != 1 || !strings.Contains(eng.stderr(), "'tacctl host provisioner' is not permitted for the engineer tier.") {
		t.Errorf("engineer: %d %q", eng.code, eng.stderr())
	}
}
