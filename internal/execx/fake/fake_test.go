package fake

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
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

func TestSeq(t *testing.T) {
	var f Runner
	ctx := context.Background()
	f.Seq([]string{"systemctl", "restart"}, execx.Result{Code: 1, Stderr: []byte("Job failed\n")}, execx.Result{})
	var codes []int
	for range 3 {
		res, err := f.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"restart", "tacquito"}})
		if err != nil {
			t.Fatal(err)
		}
		codes = append(codes, res.Code)
	}
	if !reflect.DeepEqual(codes, []int{1, 0, 0}) {
		t.Errorf("codes = %v (the last result repeats)", codes)
	}
	var g Runner
	g.Seq([]string{"x"})
	if res, err := g.Run(ctx, execx.Cmd{Name: "x"}); err != nil || res.Code != 0 {
		t.Errorf("empty Seq = %+v %v", res, err)
	}
}

func TestFailAndFunc(t *testing.T) {
	var f Runner
	ctx := context.Background()
	f.Fail([]string{"visudo"}, 1, "bad sudoers")
	res, _ := f.Run(ctx, execx.Cmd{Name: "visudo", Args: []string{"-cf", "x"}})
	if res.Code != 1 || string(res.Stderr) != "bad sudoers\n" {
		t.Errorf("Fail = %+v", res)
	}

	// A Func rule sees the input and may call back into the Runner.
	f.OnFunc([]string{"python3"}, func(c execx.Cmd) (execx.Result, error) {
		in, _ := io.ReadAll(c.Stdin)
		f.Called("never")
		return execx.Result{Stdout: []byte(strings.ToUpper(string(in)))}, nil
	})
	res, err := f.Run(ctx, execx.Cmd{Name: "python3", Stdin: strings.NewReader("abc")})
	if err != nil || string(res.Stdout) != "ABC" {
		t.Errorf("OnFunc = %+v %v", res, err)
	}
	f.Func(func(c execx.Cmd) bool { return c.Dir == "/srv" }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Code: 9}, nil
	})
	if res, _ := f.Run(ctx, execx.Cmd{Name: "git", Dir: "/srv"}); res.Code != 9 {
		t.Errorf("Func = %+v", res)
	}
}

func TestRecordsAndAssertions(t *testing.T) {
	var f Runner
	ctx := context.Background()
	_, _ = f.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"restart", "tacquito"}})
	_, _ = f.Run(ctx, execx.Cmd{Name: "python3", Args: []string{"-c", "x"}, Stdin: strings.NewReader("s3cret")})
	_, _ = f.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"restart", "freeradius"}})

	if !f.Called("systemctl", "restart", "tacquito") || f.Called("systemctl", "stop") || f.Called("ssh") {
		t.Error("Called wrong")
	}
	if f.Count("systemctl") != 2 || f.Count("systemctl", "restart", "freeradius") != 1 || f.Count() != 3 {
		t.Errorf("Count: %d %d %d", f.Count("systemctl"), f.Count("systemctl", "restart", "freeradius"), f.Count())
	}
	if !f.CalledRegexp(`^systemctl restart (tacquito|freeradius)$`) || f.CalledRegexp(`^systemctl stop`) {
		t.Error("CalledRegexp wrong")
	}
	recs := f.Records()
	if len(recs) != 3 || recs[0].Stdin != nil || string(recs[1].Stdin) != "s3cret" {
		t.Errorf("Records = %+v", recs)
	}
	// The input stays readable from the recorded Cmd.
	if b, _ := io.ReadAll(f.Calls()[1].Stdin); string(b) != "s3cret" {
		t.Errorf("recorded Stdin = %q", b)
	}
	// The secret went to stdin, not argv.
	if f.ArgvContains("s3cret") || !f.ArgvContains("freeradius") {
		t.Error("ArgvContains wrong")
	}
	f.Reset()
	if len(f.Calls()) != 0 || len(f.Execs()) != 0 || f.Called("systemctl") {
		t.Error("Reset kept calls")
	}
}

func TestStrict(t *testing.T) {
	f := Runner{Strict: true}
	ctx := context.Background()
	f.On([]string{"id"}, execx.Result{Stdout: []byte("adm\n")})
	if res, err := f.Run(ctx, execx.Cmd{Name: "id", Args: []string{"-nG"}}); err != nil || string(res.Stdout) != "adm\n" {
		t.Errorf("scripted: %+v %v", res, err)
	}
	res, err := f.Run(ctx, execx.Cmd{Name: "ss", Args: []string{"-ltn"}})
	if !errors.Is(err, ErrUnscripted) || res.Code != 127 || !strings.Contains(err.Error(), "ss -ltn") {
		t.Errorf("unscripted: %+v %v", res, err)
	}
	if _, err := f.Start(ctx, execx.Cmd{Name: "ss"}); !errors.Is(err, ErrUnscripted) {
		t.Errorf("unscripted Start err = %v", err)
	}
	if f.Count("ss") != 2 {
		t.Error("an unscripted call must still be recorded")
	}
}

func TestInstallAndSignals(t *testing.T) {
	var f Runner
	f.Missing("tacquito")
	f.Install("tacquito", "/usr/local/bin/tacquito")
	if p, err := f.LookPath("tacquito"); err != nil || p != "/usr/local/bin/tacquito" {
		t.Errorf("Install: %q %v", p, err)
	}
	f.Missing("tacquito")
	if _, err := f.LookPath("tacquito"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Missing after Install: %v", err)
	}
	p, err := f.Start(context.Background(), execx.Cmd{Name: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Signal(syscall.SIGINT)
	_ = p.Signal(syscall.SIGTERM)
	if got := f.Signals(); !reflect.DeepEqual(got, []os.Signal{syscall.SIGINT, syscall.SIGTERM}) {
		t.Errorf("Signals = %v", got)
	}
}
