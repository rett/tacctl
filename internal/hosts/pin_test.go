package hosts

import (
	"context"
	"errors"
	"os"
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
	if len(argvs) != 5 || argvs[2] != opts+"-T admin@web1 "+ReadKeysCommand || argvs[3] != opts+"-T admin@web1 "+FactsCommand ||
		argvs[4] != opts+"-O exit admin@web1" {
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
	if f.CalledRegexp(`cat /etc/ssh`) || f.CalledRegexp(`SSH_CONNECTION`) || e.Facts != nil {
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

// The facts: the host's side of SSH_CONNECTION, and the useradd range of
// login.defs with useradd's own defaults for what it does not set.
func TestParseFactsAndUIDWarning(t *testing.T) {
	f := ParseFacts([]byte("ssh_connection=198.51.100.9 50022 192.0.2.50 22\nlogin_defs=present\nUID_MIN\t1000\nUID_MAX   85000\n"))
	if f.Address != "192.0.2.50" || !f.LoginDefs || f.UIDMin != 1000 || f.UIDMax != 85000 || !f.UIDOverlap() {
		t.Errorf("%+v", f)
	}
	w := f.UIDWarning("web1")
	if len(w) != 3 || w[0] != "web1: local useradd there gives out UIDs 1000-85000 (/etc/login.defs UID_MIN/UID_MAX), which overlaps tacctl's 80000-89999:" ||
		!strings.Contains(w[2], "Keep UID_MAX below 80000 in /etc/login.defs on web1 (the default is 60000; tacctl does not change it).") {
		t.Errorf("%q", w)
	}
	for _, c := range []struct {
		in      string
		addr    string
		overlap bool
	}{
		{"ssh_connection=2001:db8::1 1 2001:db8::50 22\nlogin_defs=present\nUID_MAX 79999\n", "2001:db8::50", false},
		{"ssh_connection=::ffff:192.0.2.1 1 ::ffff:192.0.2.50 22\nlogin_defs=present\n", "192.0.2.50", false}, // defaults: 1000-60000
		{"ssh_connection=\n", "", false},                                         // no login.defs: nothing to say
		{"ssh_connection=x y z\nlogin_defs=present\nUID_MIN 90000\n", "", false}, // starts above the range
		{"login_defs=present\nUID_MAX 80000\n", "", true},                        // reaches its first number
		{"login_defs=present\nUID_MIN 89999\nUID_MAX 99999\n", "", true},         // starts at its last
		{"login_defs=present\n#UID_MAX 99999\nUID_MAX 60000\n", "", false},
	} {
		f := ParseFacts([]byte(c.in))
		if f.Address != c.addr || f.UIDOverlap() != c.overlap {
			t.Errorf("%q: %+v", c.in, f)
		}
	}
	if (Facts{}).UIDWarning("x") != nil {
		t.Error("warning without login.defs")
	}
	// --local: 127.0.0.1 and this server's own file.
	dir := t.TempDir()
	if f := LocalFacts(dir + "/none"); f.Address != "127.0.0.1" || f.LoginDefs {
		t.Errorf("%+v", f)
	}
	if err := os.WriteFile(dir+"/login.defs", []byte("UID_MIN 1000\nUID_MAX 60000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if f := LocalFacts(dir + "/login.defs"); !f.LoginDefs || f.UIDMax != 60000 || f.UIDOverlap() {
		t.Errorf("%+v", f)
	}
}
