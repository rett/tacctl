package hosts

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// hupWrapper starts the script in the background, waits until it is inside
// visudo (the account and root's record exist by then, the sudoers line is
// not in place yet: the visudo stub sleeps), hangs it up and reports how it
// ended.
const hupWrapper = `bash "$HUP_SCRIPT" &
pid=$!
for _ in $(seq 1 1000); do
    if grep -q visudo "$ST/calls.log" 2>/dev/null; then break; fi
    /usr/bin/sleep 0.02
done
kill -HUP "$pid"
wait "$pid"
echo "script-exit=$?"
`

// A hang-up while the create script runs (the ssh session drops) ends it
// through the trap: the account it made, root's record of it and the sudoers
// line it was writing are gone.
func TestRotateCreateHangUpRemovesWhatItMade(t *testing.T) {
	h := newStubHost(t)
	path := filepath.Join(h.dir, "hup.sh")
	if err := os.WriteFile(path, testScript(t, h.createKey("deploy2", testRange, testAvoid...)), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "bash", Args: []string{"-c", hupWrapper},
		Stdin: strings.NewReader(""), Env: h.env("STUB_VISUDO_SLEEP=5", "HUP_SCRIPT="+path)})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout) + string(res.Stderr)
	if !strings.Contains(out, "script-exit=130") {
		t.Errorf("the script did not end on the hang-up (130):\n%s\n%s", out, h.calls())
	}
	if !strings.Contains(h.calls(), "visudo") || !strings.Contains(h.calls(), "useradd") {
		t.Fatalf("the hang-up did not arrive inside visudo:\n%s\n%s", out, h.calls())
	}
	if h.uidOf("deploy2") != "" || strings.Contains(h.read("group"), "deploy2:") {
		t.Errorf("the account is still there:\n%s\n%s", out, h.calls())
	}
	if fileExists(filepath.Join(h.state, "deploy2")) {
		t.Error("root's record of the account is still there")
	}
	if su, _ := os.ReadFile(h.sudoers); strings.Contains(string(su), "deploy2") {
		t.Errorf("the sudoers line is still there:\n%s", su)
	}
	if !strings.Contains(h.calls(), "userdel") {
		t.Errorf("the account was not removed with userdel:\n%s", h.calls())
	}
}

// The script that goes to a host reads no knob from its environment: the
// variables of the test copy (TACCTL_ROTATE_*) do nothing to it. The stub
// tools make it get past the root check here (the stub id says 0), and it then
// works on the real locations (/var/lib/tacctl-provisioner, which a user that
// is not root cannot write, so it stops there and takes back what the stubs
// made), never on the scratch ones the variables name.
func TestProductionRotateScriptIgnoresTheEnvironment(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: the production script would run for real")
	}
	h := newStubHost(t)
	script := h.createKey("deploy2", testRange, testAvoid...)
	if !bytes.Contains(script, []byte("\nROTATE_TEST=0\n")) || bytes.Contains(script, []byte("ROTATE_TEST=\"${")) {
		t.Fatal("the production script does not fix ROTATE_TEST")
	}
	path := filepath.Join(h.dir, "prod.sh")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "bash", Args: []string{path},
		Stdin: strings.NewReader(""), Env: h.env("TACCTL_ROTATE_TEST=1", "ROTATE_TEST=1", "TACCTL_ROTATE_TEST_TTY=1")})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout) + string(res.Stderr)
	if res.Code != 1 || !strings.Contains(out, RotateStateDir) || strings.Contains(out, h.state) {
		t.Errorf("exit %d:\n%s", res.Code, out)
	}
	if fileExists(h.sudoers) || fileExists(filepath.Join(h.state, "deploy2")) || fileExists(h.state) {
		t.Errorf("the production script wrote to the redirected locations:\n%s", h.calls())
	}
}
