package fake

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"syscall"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

func TestRunScriptAndRecord(t *testing.T) {
	var f Runner
	ctx := context.Background()
	f.On([]string{"systemctl", "is-active"}, execx.Result{Stdout: []byte("active\n")})
	f.On([]string{"systemctl", "is-active", "freeradius"}, execx.Result{Stdout: []byte("inactive\n"), Code: 3})

	res, err := f.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"is-active", "tacquito"}})
	if err != nil || string(res.Stdout) != "active\n" || res.Code != 0 {
		t.Errorf("tacquito: %+v %v", res, err)
	}
	res, err = f.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"is-active", "freeradius"}})
	if err != nil || res.Code != 3 {
		t.Errorf("newest rule must win: %+v %v", res, err)
	}
	res, err = f.Run(ctx, execx.Cmd{Name: "logger", Args: []string{"-t", "tacctl"}})
	if err != nil || res.Code != 0 || len(res.Stdout) != 0 {
		t.Errorf("unscripted: %+v %v", res, err)
	}
	want := []string{"systemctl is-active tacquito", "systemctl is-active freeradius", "logger -t tacctl"}
	if got := f.Argvs(); !reflect.DeepEqual(got, want) {
		t.Errorf("Argvs = %q", got)
	}
	if len(f.Calls()) != 3 {
		t.Errorf("Calls = %d", len(f.Calls()))
	}
}

func TestStreamsAndAsUser(t *testing.T) {
	var f Runner
	f.On([]string{"sudo", "-u", "alice"}, execx.Result{Stdout: []byte("out"), Stderr: []byte("err")})
	var o, e bytes.Buffer
	c := execx.Cmd{Name: "ssh", Args: []string{"host"}, AsUser: "alice", UserEnv: []string{"SSH_AUTH_SOCK=/s"}, Stdout: &o, Stderr: &e}
	res, err := f.Run(context.Background(), c)
	if err != nil || o.String() != "out" || e.String() != "err" || res.Stdout != nil || res.Stderr != nil {
		t.Errorf("streams: %+v %v %q %q", res, err, o.String(), e.String())
	}
	if got := f.Argvs()[0]; got != "sudo -u alice -H env SSH_AUTH_SOCK=/s ssh host" {
		t.Errorf("argv = %q", got)
	}
}

func TestMissingAndLookPath(t *testing.T) {
	var f Runner
	if p, err := f.LookPath("systemctl"); err != nil || p != "/fake/bin/systemctl" {
		t.Errorf("LookPath = %q %v", p, err)
	}
	if p, err := f.LookPath("/usr/bin/x"); err != nil || p != "/usr/bin/x" {
		t.Errorf("absolute LookPath = %q %v", p, err)
	}
	f.Missing("podman")
	if _, err := f.LookPath("podman"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing LookPath err = %v", err)
	}
	res, err := f.Run(context.Background(), execx.Cmd{Name: "podman"})
	if !errors.Is(err, ErrNotFound) || res.Code != 127 {
		t.Errorf("missing Run = %+v %v", res, err)
	}
	if _, err := f.Start(context.Background(), execx.Cmd{Name: "podman"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing Start err = %v", err)
	}
}

func TestStartAndCancel(t *testing.T) {
	var f Runner
	boom := errors.New("boom")
	f.When(func(c execx.Cmd) bool { return c.Name == "tacquito" }, execx.Result{Code: 1}, boom)
	p, err := f.Start(context.Background(), execx.Cmd{Name: "tacquito"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if res, err := p.Wait(); !errors.Is(err, boom) || res.Code != 1 || p.Pid() == 0 {
		t.Errorf("Wait = %+v %v", res, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Run(ctx, execx.Cmd{Name: "x"}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled Run err = %v", err)
	}
}

func TestExec(t *testing.T) {
	var f Runner
	if err := f.Exec("/bin/x", []string{"x", "a"}, []string{"K=V"}); err != nil {
		t.Fatal(err)
	}
	f.ExecErr = errors.New("ENOENT")
	if err := f.Exec("/bin/y", []string{"y"}, nil); err == nil {
		t.Error("ExecErr not returned")
	}
	want := []ExecCall{{Path: "/bin/x", Argv: []string{"x", "a"}, Env: []string{"K=V"}}, {Path: "/bin/y", Argv: []string{"y"}}}
	if got := f.Execs(); !reflect.DeepEqual(got, want) {
		t.Errorf("Execs = %+v", got)
	}
}
