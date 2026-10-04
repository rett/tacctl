package execx

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestArgv(t *testing.T) {
	c := Cmd{Name: "ssh", Args: []string{"-p", "22", "host"}}
	if got := c.Argv(); !reflect.DeepEqual(got, []string{"ssh", "-p", "22", "host"}) {
		t.Errorf("plain: %q", got)
	}
	c.AsUser = "alice"
	if got := c.Argv(); !reflect.DeepEqual(got, []string{"sudo", "-u", "alice", "-H", "ssh", "-p", "22", "host"}) {
		t.Errorf("AsUser: %q", got)
	}
	c.UserEnv = []string{"SSH_AUTH_SOCK=/run/agent"}
	want := []string{"sudo", "-u", "alice", "-H", "env", "SSH_AUTH_SOCK=/run/agent", "ssh", "-p", "22", "host"}
	if got := c.Argv(); !reflect.DeepEqual(got, want) {
		t.Errorf("AsUser+env: %q", got)
	}
}

func TestRealRun(t *testing.T) {
	r := Real{}
	ctx := context.Background()
	res, err := r.Run(ctx, Cmd{Name: "sh", Args: []string{"-c", "echo out; echo err >&2; exit 3"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "out\n" || string(res.Stderr) != "err\n" || res.Code != 3 {
		t.Errorf("Run = %+v", res)
	}
	res, err = r.Run(ctx, Cmd{Name: "sh", Args: []string{"-c", "cat; pwd; echo $K"}, Stdin: strings.NewReader("in\n"), Dir: "/", Env: []string{"K=v"}})
	if err != nil || string(res.Stdout) != "in\n/\nv\n" {
		t.Errorf("stdin/dir/env: %q %v", res.Stdout, err)
	}
	var o bytes.Buffer
	res, err = r.Run(ctx, Cmd{Name: "echo", Args: []string{"streamed"}, Stdout: &o})
	if err != nil || o.String() != "streamed\n" || len(res.Stdout) != 0 {
		t.Errorf("stream: %q %q %v", o.String(), res.Stdout, err)
	}
	res, err = r.Run(ctx, Cmd{Name: "sh", Args: []string{"-c", "kill -TERM $$"}})
	if err != nil || res.Code != 128+int(syscall.SIGTERM) {
		t.Errorf("signalled: %+v %v", res, err)
	}
	res, err = r.Run(ctx, Cmd{Name: "tacctl-no-such-program"})
	if !errors.Is(err, exec.ErrNotFound) || res.Code != 127 {
		t.Errorf("not found: %+v %v", res, err)
	}
	res, err = r.Run(ctx, Cmd{Name: "/etc/hostname"})
	if err == nil || res.Code != 126 {
		t.Errorf("not executable: %+v %v", res, err)
	}
}

func TestRealStartCancel(t *testing.T) {
	r := Real{}
	ctx, cancel := context.WithCancel(context.Background())
	p, err := r.Start(ctx, Cmd{Name: "sleep", Args: []string{"30"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Pid() <= 0 {
		t.Errorf("Pid = %d", p.Pid())
	}
	time.AfterFunc(50*time.Millisecond, cancel)
	res, err := p.Wait()
	if !errors.Is(err, context.Canceled) || res.Code != 128+int(syscall.SIGKILL) {
		t.Errorf("cancelled: %+v %v", res, err)
	}

	p, err = r.Start(context.Background(), Cmd{Name: "sleep", Args: []string{"30"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if res, err := p.Wait(); err != nil || res.Code != 128+int(syscall.SIGTERM) {
		t.Errorf("Signal: %+v %v", res, err)
	}
}

func TestRealLookPath(t *testing.T) {
	if p, err := (Real{}).LookPath("sh"); err != nil || !strings.HasSuffix(p, "/sh") {
		t.Errorf("LookPath(sh) = %q %v", p, err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := (Real{}).LookPath("sh"); err == nil {
		t.Error("LookPath ignores PATH")
	}
}

// Exec is execve(2); only its failure path can run inside a test.
func TestRealExecFailure(t *testing.T) {
	if err := (Real{}).Exec("/nonexistent/tacctl", []string{"tacctl"}, nil); err == nil {
		t.Error("Exec of a missing file returned nil")
	}
}
