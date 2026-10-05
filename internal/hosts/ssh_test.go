package hosts

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/ui"
)

func TestSSHCmd(t *testing.T) {
	s := SSH{Options: DefaultSSHOptions}
	want := "ssh -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=~/.ssh/tacctl-%C -o ControlPersist=60 web1 true"
	if got := strings.Join(s.Cmd("web1", "true").Argv(), " "); got != want {
		t.Errorf("plain\n got %s\nwant %s", got, want)
	}
	s = SSH{AsUser: "admin", AuthSock: "/run/agent", Options: []string{"-o", "X=1"}, Batch: true, Port: "2222", Identity: "/k"}
	want = "sudo -u admin -H env SSH_AUTH_SOCK=/run/agent ssh -o X=1 -o BatchMode=yes -p 2222 -i /k -T web1 cmd"
	if got := strings.Join(s.Cmd("-T", "web1", "cmd").Argv(), " "); got != want {
		t.Errorf("as user\n got %s\nwant %s", got, want)
	}
	s.AuthSock = ""
	if got := s.Cmd("x").Argv(); !reflect.DeepEqual(got[:5], []string{"sudo", "-u", "admin", "-H", "ssh"}) {
		t.Errorf("no agent: %q", got)
	}
}

func TestRemoteCommand(t *testing.T) {
	r := "/tmp/tacctl.AbCd1234"
	got := RemoteCommand(r, []string{"--accounts-only", "--allow-uid-mismatch", "--remove-home"}, false)
	want := `trap 'rm -f /tmp/tacctl.AbCd1234' EXIT; trap 'exit 130' HUP INT TERM; if [ "$(id -u)" = 0 ]; then bash /tmp/tacctl.AbCd1234 --accounts-only --allow-uid-mismatch --remove-home; else if sudo -n true 2>/dev/null; then sudo -n bash /tmp/tacctl.AbCd1234 --accounts-only --allow-uid-mismatch --remove-home; else echo '[ERROR] sudo on this host needs a password and there is no terminal to ask on. Run tacctl host from a terminal, allow passwordless sudo for this login, or log in as root.' >&2; false; fi; fi`
	if got != want {
		t.Errorf("no tty\n got %s\nwant %s", got, want)
	}
	got = RemoteCommand(r, nil, true)
	want = `trap 'rm -f /tmp/tacctl.AbCd1234' EXIT; trap 'exit 130' HUP INT TERM; if [ "$(id -u)" = 0 ]; then bash /tmp/tacctl.AbCd1234 ; else sudo -p '[sudo] password for %u on %H: ' bash /tmp/tacctl.AbCd1234 ; fi`
	if got != want {
		t.Errorf("tty\n got %s\nwant %s", got, want)
	}
	// Anything a shell would read specially is quoted.
	for in, out := range map[string]string{"a,b": "a,b", "x;reboot": "'x;reboot'", "it's": `'it'\''s'`, "": "''", "$(id)": "'$(id)'"} {
		if got := remoteWord(in); got != out {
			t.Errorf("remoteWord(%q) = %s, want %s", in, got, out)
		}
	}
}

func scriptFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "script")
	writeFile(t, p, "echo hi\n")
	return p
}

func TestRunScriptThreeCalls(t *testing.T) {
	e, _, errb := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	var pushed string
	f.Func(func(c execx.Cmd) bool { return strings.Contains(strings.Join(c.Args, " "), "mktemp") }, func(c execx.Cmd) (execx.Result, error) {
		b, _ := io.ReadAll(c.Stdin)
		pushed = string(b)
		return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
	})
	f.Func(func(c execx.Cmd) bool { return contains(c.Args, "-T") }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Code: 7}, nil
	})
	code, err := e.RunScript(context.Background(), "admin@web1", "2222", "", scriptFile(t), []string{"--allow-uid-mismatch"})
	if err != nil || code != 7 {
		t.Fatalf("code %d %v", code, err)
	}
	if pushed != "echo hi\n" {
		t.Errorf("pushed %q", pushed)
	}
	argvs := f.Argvs()
	if len(argvs) != 3 {
		t.Fatalf("calls %q", argvs)
	}
	opts := "ssh -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=~/.ssh/tacctl-%C -o ControlPersist=60 -o BatchMode=yes -p 2222 "
	if argvs[0] != opts+"admin@web1 "+copyCommand {
		t.Errorf("copy %s", argvs[0])
	}
	if argvs[1] != opts+"-T admin@web1 "+RemoteCommand("/tmp/tacctl.AbCd1234", []string{"--allow-uid-mismatch"}, false) {
		t.Errorf("run %s", argvs[1])
	}
	if argvs[2] != opts+"-O exit admin@web1" {
		t.Errorf("close %s", argvs[2])
	}
	if errb.Len() != 0 {
		t.Errorf("stderr %q", errb.String())
	}

	// A terminal: -t, the sudo prompt that names the host, no BatchMode.
	e.TTY, e.StdinTTY = func() bool { return true }, func() bool { return true }
	f.Reset()
	if code, _ := e.RunScript(context.Background(), "web1", "", "", scriptFile(t), nil); code != 0 {
		t.Errorf("tty code %d", code)
	}
	if a := f.Argvs()[1]; !strings.Contains(a, " -t web1 ") || !strings.Contains(a, "sudo -p '[sudo] password for %u on %H: '") || strings.Contains(a, "BatchMode") {
		t.Errorf("tty run %s", a)
	}
}

func TestRunScriptCopyFailures(t *testing.T) {
	e, _, errb := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"ssh"}, execx.Result{Code: 255})
	if code, err := e.RunScript(context.Background(), "web1", "", "", scriptFile(t), nil); code != 1 || err != nil {
		t.Errorf("copy failed: %d %v", code, err)
	}
	if !strings.Contains(errb.String(), "Could not copy the script to web1 (ssh failed).") || f.Count("ssh") != 1 {
		t.Errorf("copy failed: %q %q", errb.String(), f.Argvs())
	}
	errb.Reset()
	f = &fake.Runner{}
	e.Runner = f
	f.On([]string{"ssh"}, execx.Result{Stdout: []byte("/tmp/x; rm -rf /\n")})
	if code, _ := e.RunScript(context.Background(), "web1", "", "", scriptFile(t), nil); code != 1 {
		t.Errorf("odd reply: %d", code)
	}
	if !strings.Contains(errb.String(), "Unexpected reply from web1 while copying the script.") {
		t.Errorf("odd reply: %q", errb.String())
	}
	// Interrupted while copying: the command ends, nothing more is run.
	f = &fake.Runner{}
	e.Runner = f
	ctx, cancel := context.WithCancel(context.Background())
	f.Func(func(execx.Cmd) bool { return true }, func(execx.Cmd) (execx.Result, error) {
		cancel()
		return execx.Result{Code: 130}, nil
	})
	if _, err := e.RunScript(ctx, "web1", "", "", scriptFile(t), nil); err != ui.ErrInterrupted || f.Count("ssh") != 1 {
		t.Errorf("interrupted: %v %d", err, f.Count("ssh"))
	}
}

func TestRunScriptLocalAndAttached(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"bash"}, execx.Result{Code: 3})
	code, err := e.RunScript(context.Background(), Local, "", "", "/s.sh", []string{"--accounts-only"})
	if code != 3 || err != nil || f.Argvs()[0] != "bash /s.sh --accounts-only" {
		t.Errorf("local: %d %v %q", code, err, f.Argvs())
	}
	// Attached hands the child tacctl's own streams and a context that a
	// signal does not cancel.
	ctx, cancel := context.WithCancel(context.Background())
	var childCtx context.Context
	r := &ctxRunner{Runner: f, seen: &childCtx}
	in := strings.NewReader("")
	out := ui.Output{Stdout: io.Discard, Stderr: io.Discard}
	cancel()
	code, intr, err := Attached(ctx, r, execx.Cmd{Name: "bash"}, in, out)
	if code != 3 || !intr || err != nil || childCtx.Err() != nil {
		t.Errorf("attached: %d %v %v %v", code, intr, err, childCtx.Err())
	}
	if c := f.Calls()[1]; c.Stdout != io.Discard || c.Stderr != io.Discard {
		t.Errorf("streams %+v", c)
	}
}

// ctxRunner records the context Start was given.
type ctxRunner struct {
	*fake.Runner
	seen *context.Context
}

func (r *ctxRunner) Start(ctx context.Context, c execx.Cmd) (execx.Process, error) {
	*r.seen = ctx
	return r.Runner.Start(context.Background(), c)
}

func TestEnvDefaults(t *testing.T) {
	e := &Env{Stdin: strings.NewReader("")}
	if e.stdinTTY() {
		t.Error("a reader is no terminal")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	e.Stdin = null
	if e.stdinTTY() {
		t.Error("/dev/null is no terminal")
	}
	_ = e.tty() // whatever the test runs under; it must not panic
	if e.machine() == "" || e.now().IsZero() {
		t.Error("defaults")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
