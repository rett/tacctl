package hosts

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

func TestScanTarget(t *testing.T) {
	for _, c := range []struct {
		target, port string
		host         string
		p            int
		ok           bool
	}{
		{"admin@web1.example.net", "", "web1.example.net", 22, true},
		{"web1.example.net", "2222", "web1.example.net", 2222, true},
		{"root@192.0.2.50", "22", "192.0.2.50", 22, true},
		{"web1", "junk", "web1", 22, true},
		{"web1", "70000", "web1", 22, true},
		{Local, "", "", 0, false},
		{"", "", "", 0, false},
		{"admin@", "", "", 22, false},
	} {
		h, p, ok := ScanTarget(c.target, c.port)
		if h != c.host || p != c.p || ok != c.ok {
			t.Errorf("%q %q: %q %d %v", c.target, c.port, h, p, ok)
		}
	}
}

func TestPinKeys(t *testing.T) {
	var got []string
	var gotErr error
	env := &Env{PinHostKeys: func(_ context.Context, name, host string, port int, session []byte, err error) {
		got = append(got, name+" "+host+" "+strconv.Itoa(port)+" "+string(session))
		gotErr = err
	}}
	env.PinKeys(context.Background(), Entry{Name: "web1", Target: "admin@web1.example.net", Port: "2200"})
	env.PinKeys(context.Background(), Entry{Name: "srv", Target: Local})
	if len(got) != 1 || got[0] != "web1 web1.example.net 2200 " || !errors.Is(gotErr, ErrKeysUnread) {
		t.Errorf("pinned %q %v", got, gotErr)
	}
	(&Env{}).PinKeys(context.Background(), Entry{Name: "web1", Target: "web1"}) // no pinner: nothing
}

// With ReadKeys, a successful run reads the host's public keys over the same
// connection, before it is closed, and PinKeys hands them on; a failed run,
// an empty read and an env without ReadKeys hand none.
func TestRunScriptReadsKeysOverTheSession(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"ssh"}, execx.Result{})
	f.Func(func(c execx.Cmd) bool { return strings.Contains(strings.Join(c.Args, " "), "mktemp") }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
	})
	pub := "ssh-ed25519 AAAA root@web1\n"
	f.Func(func(c execx.Cmd) bool { return c.Args[len(c.Args)-1] == ReadKeysCommand }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte(pub)}, nil
	})
	var session []byte
	var sessErr error
	e.PinHostKeys = func(_ context.Context, _, _ string, _ int, s []byte, err error) { session, sessErr = s, err }
	e.ReadKeys = true
	if code, err := e.RunScript(context.Background(), "admin@web1", "", "", scriptFile(t), nil); code != 0 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	argvs := f.Argvs()
	opts := "ssh -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=~/.ssh/tacctl-%C -o ControlPersist=60 -o BatchMode=yes "
	if len(argvs) != 4 || argvs[2] != opts+"-T admin@web1 "+ReadKeysCommand || argvs[3] != opts+"-O exit admin@web1" {
		t.Fatalf("calls %q", argvs)
	}
	e.PinKeys(context.Background(), Entry{Name: "web1", Target: "admin@web1"})
	if string(session) != pub || sessErr != nil {
		t.Errorf("session %q %v", session, sessErr)
	}
	// Nothing readable: ErrKeysUnread.
	f.Func(func(c execx.Cmd) bool { return c.Args[len(c.Args)-1] == ReadKeysCommand }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Code: 1}, nil
	})
	_, _ = e.RunScript(context.Background(), "admin@web1", "", "", scriptFile(t), nil)
	e.PinKeys(context.Background(), Entry{Name: "web1", Target: "admin@web1"})
	if session != nil || !errors.Is(sessErr, ErrKeysUnread) {
		t.Errorf("unreadable: %q %v", session, sessErr)
	}
	// A failed run reads nothing.
	f.Reset()
	f.Func(func(c execx.Cmd) bool { return strings.Contains(strings.Join(c.Args, " "), "mktemp") }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
	})
	f.Func(func(c execx.Cmd) bool { return contains(c.Args, "-T") }, func(execx.Cmd) (execx.Result, error) { return execx.Result{Code: 3}, nil })
	_, _ = e.RunScript(context.Background(), "admin@web1", "", "", scriptFile(t), nil)
	if f.CalledRegexp(`cat /etc/ssh`) {
		t.Errorf("read after a failed run: %q", f.Argvs())
	}
	// Without ReadKeys: the three calls of before.
	e.ReadKeys = false
	f.Reset()
	f.On([]string{"ssh"}, execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")})
	_, _ = e.RunScript(context.Background(), "admin@web1", "", "", scriptFile(t), nil)
	if len(f.Argvs()) != 3 {
		t.Errorf("calls %q", f.Argvs())
	}
}
