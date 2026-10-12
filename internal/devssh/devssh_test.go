package devssh_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

const goodPassword = fakedev.DefaultPassword

// transcript writes files into a new directory and returns it.
func transcript(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// configLines is a configuration of n lines.
func configLines(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "set system line %d\n", i)
	}
	return b.String()
}

// target is a Target for the server, with its own host key pinned and the
// default login; the password source counts its calls.
func target(t *testing.T, srv *fakedev.Server, calls *atomic.Int32) devssh.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return devssh.Target{
		Host: host, Port: p, User: fakedev.DefaultUser,
		HostKeys:       []string{srv.HostKey()},
		ConnectTimeout: 5 * time.Second,
		Quiet:          100 * time.Millisecond,
		Password: func() (string, error) {
			if calls != nil {
				calls.Add(1)
			}
			return goodPassword, nil
		},
	}
}

func serve(t *testing.T, dir string, opts ...fakedev.Option) *fakedev.Server {
	t.Helper()
	s := fakedev.New(dir, opts...)
	t.Cleanup(s.Stop)
	return s
}

func dial(t *testing.T, tg devssh.Target) *devssh.Client {
	t.Helper()
	c, err := devssh.Dial(context.Background(), tg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func bg() context.Context { return context.Background() }

func TestPasswordAndKeyboardInteractive(t *testing.T) {
	dir := transcript(t, nil)
	for name, methods := range map[string][]fakedev.AuthMethod{
		"password only":             {fakedev.AuthPassword},
		"keyboard-interactive only": {fakedev.AuthKeyboardInteractive},
		"both":                      {fakedev.AuthPassword, fakedev.AuthKeyboardInteractive},
	} {
		t.Run(name, func(t *testing.T) {
			srv := serve(t, dir, fakedev.WithAuth(methods...))
			var calls atomic.Int32
			c := dial(t, target(t, srv, &calls))
			if got := calls.Load(); got != 1 {
				t.Errorf("password source called %d times, want 1", got)
			}
			if !strings.HasPrefix(c.ServerVersion(), "SSH-2.0-") {
				t.Errorf("ServerVersion = %q", c.ServerVersion())
			}
			if srv.Attempts() != 1 || srv.Logins() != 1 {
				t.Errorf("attempts %d logins %d, want 1 and 1", srv.Attempts(), srv.Logins())
			}
		})
	}
}

func TestWrongPasswordIsOneAttempt(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	tg := target(t, srv, nil)
	const bad = "not-the-password-0123"
	tg.Password = func() (string, error) { return bad, nil }
	_, err := devssh.Dial(bg(), tg)
	if !errors.Is(err, devssh.ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	if strings.Contains(err.Error(), bad) {
		t.Errorf("the password is in the error: %v", err)
	}
	// Both methods are on offer and the password went out once: a batch
	// with a wrong password must not count three failures per device.
	if got := srv.Attempts(); got != 1 {
		t.Errorf("the device saw %d password attempts, want 1", got)
	}
}

func TestPasswordSourceErrorAndNil(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	tg := target(t, srv, nil)
	boom := errors.New("no terminal")
	var calls int
	tg.Password = func() (string, error) { calls++; return "", boom }
	_, err := devssh.Dial(bg(), tg)
	if !errors.Is(err, boom) || errors.Is(err, devssh.ErrAuth) {
		t.Fatalf("err = %v, want the source's error", err)
	}
	if calls != 1 {
		t.Errorf("source called %d times", calls)
	}
	tg.Password = nil
	if _, err := devssh.Dial(bg(), tg); err == nil {
		t.Fatal("a nil password source must be refused")
	}
}

func TestHostKeyPinning(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	other := serve(t, transcript(t, nil), fakedev.WithRandomHostKey())

	t.Run("unpinned is refused without connecting", func(t *testing.T) {
		tg := target(t, srv, nil)
		tg.HostKeys = nil
		tg.Dialer = func(context.Context, string, string) (net.Conn, error) {
			t.Error("a connection was made without a pinned key")
			return nil, errors.New("no")
		}
		var hk devssh.ErrHostKey
		_, err := devssh.Dial(bg(), tg)
		if !errors.As(err, &hk) || !hk.Unpinned() {
			t.Fatalf("err = %v, want ErrHostKey (unpinned)", err)
		}
	})
	t.Run("unparsable pins count as none", func(t *testing.T) {
		tg := target(t, srv, nil)
		tg.HostKeys = []string{"ssh-ed25519 !!!", "garbage", "ssh-rsa AAAA"}
		var hk devssh.ErrHostKey
		if _, err := devssh.Dial(bg(), tg); !errors.As(err, &hk) || !hk.Unpinned() {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a different key is refused and reported", func(t *testing.T) {
		tg := target(t, srv, nil)
		tg.HostKeys = []string{other.HostKey()}
		var hk devssh.ErrHostKey
		_, err := devssh.Dial(bg(), tg)
		if !errors.As(err, &hk) || hk.Unpinned() {
			t.Fatalf("err = %v, want ErrHostKey", err)
		}
		if hk.Offered != srv.HostKey() || !strings.HasPrefix(hk.Fingerprint, "SHA256:") {
			t.Errorf("Offered %q Fingerprint %q", hk.Offered, hk.Fingerprint)
		}
		if srv.Attempts() != 0 {
			t.Error("a password was sent to a device with the wrong host key")
		}
	})
	t.Run("one of several pins is enough", func(t *testing.T) {
		tg := target(t, srv, nil)
		tg.HostKeys = []string{other.HostKey(), srv.HostKey()}
		dial(t, tg)
	})
	t.Run("the default key is the exported one", func(t *testing.T) {
		if srv.HostKey() != fakedev.HostKey() {
			t.Error("fakedev.HostKey differs from a default server's key")
		}
	})
}

func TestShellCLI(t *testing.T) {
	dir := transcript(t, map[string]string{
		"prompt":                         "rtr1#",
		"banner":                         "Authorized use only\n",
		"show running-config.out":        "Building configuration...\nhostname rtr1\n!\nend\n",
		"show version.out":               "# vendor: cisco\n# source: reference\n# ---\nCisco IOS Software\n",
		"show secret.err":                "% Authorization failed.",
		"show ip route 10.0.0.0%2F8.out": "route text\n",
	})
	srv := serve(t, dir)
	c := dial(t, target(t, srv, nil))
	s, err := c.CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	for _, tc := range []struct {
		cmd, want string
		err       bool
	}{
		{"show running-config", "Building configuration...\nhostname rtr1\n!\nend\n", false},
		{"show version", "Cisco IOS Software\n", false},
		{"show ip route 10.0.0.0/8", "route text\n", false},
		{"show secret", "% Authorization failed.\n", false},
		{"show nothing", "% Unknown command: show nothing\n", false},
		{"terminal length 0", "", false},
	} {
		got, err := s.Run(bg(), tc.cmd)
		if err != nil || got != tc.want {
			t.Errorf("Run(%q) = %q, %v; want %q", tc.cmd, got, err, tc.want)
		}
	}
	if _, err := s.Run(bg(), "show version\nreload"); err == nil {
		t.Error("a two-line command must be refused")
	}
	if _, err := c.CLI("nokia"); err == nil {
		t.Error("an unknown vendor must be refused")
	}
}

func TestShellPagingGuard(t *testing.T) {
	cfg := configLines(60)
	for name, files := range map[string]map[string]string{
		"ios marker":  {"prompt": "rtr1#", "paging": "20", "show running-config.out": cfg},
		"junos style": {"prompt": "rtr1#", "paging": "7 junos", "show running-config.out": cfg},
		"no paging":   {"prompt": "rtr1#", "show running-config.out": cfg},
	} {
		t.Run(name, func(t *testing.T) {
			srv := serve(t, transcript(t, files))
			s, err := dial(t, target(t, srv, nil)).CLI(devssh.VendorCisco)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Run(bg(), "show running-config")
			if err != nil || got != cfg {
				t.Fatalf("paged output differs (err %v):\n%q", err, got)
			}
			// 'terminal length 0' turns paging off on the device.
			if _, err := s.Run(bg(), "terminal length 0"); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Run(bg(), "show running-config"); err != nil || got != cfg {
				t.Fatalf("unpaged output differs (err %v)", err)
			}
		})
	}
}

func TestShellWithoutEchoAndWithPTY(t *testing.T) {
	dir := transcript(t, map[string]string{"prompt": "rtr1#", "show version.out": "v1\n"})
	for name, opts := range map[string][]devssh.CLIOption{
		"plain": nil,
		"pty":   {devssh.WithPTY()},
	} {
		t.Run(name, func(t *testing.T) {
			srv := serve(t, dir, fakedev.WithEcho(false))
			s, err := dial(t, target(t, srv, nil)).CLI(devssh.VendorCisco, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := s.Run(bg(), "show version"); err != nil || got != "v1\n" {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestExecCLI(t *testing.T) {
	dir := transcript(t, map[string]string{
		"show configuration | display set.out": "# vendor: juniper\n# transport: ssh\n# ---\nset system host-name sw1\nset system services ssh\n",
		"show denied.err":                      "error: permission denied",
	})
	srv := serve(t, dir)
	c := dial(t, target(t, srv, nil))
	s, err := c.CLI(devssh.VendorJuniper)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(bg(), "show configuration | display set")
	if err != nil || got != "set system host-name sw1\nset system services ssh\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	// ' | no-more' is ignored by the fake when the file has no such name.
	if got, err := s.Run(bg(), "show configuration | display set | no-more"); err != nil || !strings.Contains(got, "host-name sw1") {
		t.Fatalf("no-more: %q, %v", got, err)
	}
	got, err = s.Run(bg(), "show nothing")
	var ce devssh.CommandError
	if !errors.As(err, &ce) || ce.Status != 1 || !strings.Contains(got, "unknown command") {
		t.Fatalf("unknown command: %q, %v", got, err)
	}
	if _, err := s.Run(bg(), "show denied"); !errors.As(err, &ce) {
		t.Fatalf("denied: %v", err)
	}
	// Each command is its own channel; the session stays usable.
	if _, err := s.Run(bg(), "show configuration | display set"); err != nil {
		t.Fatal(err)
	}
}

func TestJunosOverShellChannel(t *testing.T) {
	cfg := configLines(30)
	dir := transcript(t, map[string]string{
		"prompt": "gotest@sw1> ", "paging": "10 junos",
		"show configuration | display set.out": cfg,
	})
	srv := serve(t, dir)
	s, err := dial(t, target(t, srv, nil)).CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(bg(), "show configuration | display set")
	if err != nil || got != cfg {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNetconfRPC(t *testing.T) {
	cfg := "set system host-name sw1\nset system login message \"a < b & c\"\n"
	dir := transcript(t, map[string]string{
		"show configuration | display set.out": cfg,
		"show version.out":                     "Hostname: sw1\n",
		"show secret.err":                      "permission denied",
		"rpc.get-system-information.xml":       "<system-information><host-name>sw1</host-name></system-information>",
	})
	srv := serve(t, dir)
	c := dial(t, target(t, srv, nil))
	n, err := c.NETCONF()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	if caps := n.Capabilities(); len(caps) < 2 || caps[0] != devssh.CapBase10 {
		t.Errorf("capabilities %v", caps)
	}

	reply, err := n.RPC(bg(), devssh.CommandRPC("show configuration | display set"))
	if err != nil {
		t.Fatal(err)
	}
	if text, err := devssh.ReplyText(reply); err != nil || text != cfg {
		t.Errorf("command reply text %q, %v", text, err)
	}
	// The same text from <get-configuration format="set"/>, in the same
	// session (it is reused for further RPCs).
	reply, err = n.RPC(bg(), devssh.RPCGetConfigurationSet)
	if err != nil {
		t.Fatal(err)
	}
	if text, err := devssh.ReplyText(reply); err != nil || text != cfg {
		t.Errorf("get-configuration reply text %q, %v", text, err)
	}
	reply, err = n.RPC(bg(), devssh.CommandRPC("show version"))
	if text, terr := devssh.ReplyText(reply); err != nil || terr != nil || text != "Hostname: sw1\n" {
		t.Errorf("show version: %q %v %v", text, err, terr)
	}
	// A denied command is an rpc-error and does not end the session.
	reply, err = n.RPC(bg(), devssh.CommandRPC("show secret"))
	var re devssh.RPCError
	if !errors.As(err, &re) || re.Message != "permission denied" || reply == "" {
		t.Fatalf("denied: %v (reply %q)", err, reply)
	}
	reply, err = n.RPC(bg(), "<get-system-information/>")
	if err != nil || !strings.Contains(reply, "<host-name>sw1</host-name>") {
		t.Fatalf("after an error: %q, %v", reply, err)
	}
	if _, err := devssh.ReplyText(reply); !errors.Is(err, devssh.ErrProtocol) {
		t.Errorf("ReplyText of a reply without text: %v", err)
	}
	if got := strings.Join(srv.Commands(), ","); !strings.Contains(got, "netconf:command") {
		t.Errorf("server saw %q", got)
	}
}

func TestNetconfFraming(t *testing.T) {
	cfg := "set system host-name sw1\n"
	dir := transcript(t, map[string]string{"show configuration | display set.out": cfg})
	for _, tc := range []struct {
		name    string
		server  fakedev.Framing
		client  devssh.Framing
		wantErr error
	}{
		{"eom both", fakedev.FramingEOM, devssh.FramingEOM, nil},
		{"eom server, auto client", fakedev.FramingEOM, devssh.FramingAuto, nil},
		{"both server, default client", fakedev.FramingBoth, devssh.FramingEOM, nil},
		{"both server, chunked client", fakedev.FramingBoth, devssh.FramingChunked, nil},
		{"chunked server, chunked client", fakedev.FramingChunked, devssh.FramingChunked, nil},
		{"chunked server, auto client", fakedev.FramingChunked, devssh.FramingAuto, nil},
		{"chunked server, default client", fakedev.FramingChunked, devssh.FramingEOM, devssh.ErrProtocol},
		{"eom server, chunked client", fakedev.FramingEOM, devssh.FramingChunked, devssh.ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serve(t, dir, fakedev.WithNetconfFraming(tc.server))
			n, err := dial(t, target(t, srv, nil)).NETCONF(devssh.WithFraming(tc.client))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Several RPCs, one of them large enough for more than one read.
			for range 3 {
				reply, err := n.RPC(bg(), devssh.CommandRPC("show configuration | display set"))
				if text, terr := devssh.ReplyText(reply); err != nil || terr != nil || text != cfg {
					t.Fatalf("%q %v %v", text, err, terr)
				}
			}
		})
	}
}

func TestNetconfLargeReply(t *testing.T) {
	cfg := configLines(20000)
	dir := transcript(t, map[string]string{"show configuration | display set.out": cfg})
	for _, f := range []fakedev.Framing{fakedev.FramingEOM, fakedev.FramingChunked} {
		srv := serve(t, dir, fakedev.WithNetconfFraming(f))
		cf := devssh.FramingEOM
		if f == fakedev.FramingChunked {
			cf = devssh.FramingChunked
		}
		n, err := dial(t, target(t, srv, nil)).NETCONF(devssh.WithFraming(cf))
		if err != nil {
			t.Fatal(err)
		}
		reply, err := n.RPC(bg(), devssh.RPCGetConfigurationSet)
		if text, terr := devssh.ReplyText(reply); err != nil || terr != nil || text != cfg {
			t.Fatalf("framing %v: %d bytes, %v %v", f, len(text), err, terr)
		}
	}
}

func TestNetconfRefused(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithNetconfOff())
	c := dial(t, target(t, srv, nil))
	if _, err := c.NETCONF(); !errors.Is(err, devssh.ErrNoSubsystem) {
		t.Fatalf("err = %v, want ErrNoSubsystem", err)
	}
	// The connection is still good for the CLI.
	if _, err := c.CLI(devssh.VendorJuniper); err != nil {
		t.Fatal(err)
	}
	srv2 := serve(t, transcript(t, map[string]string{"netconf.off": ""}))
	if _, err := dial(t, target(t, srv2, nil)).NETCONF(); !errors.Is(err, devssh.ErrNoSubsystem) {
		t.Fatalf("netconf.off: err = %v", err)
	}
}

func TestConnectTimeout(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithHang(fakedev.HangAccept))
	tg := target(t, srv, nil)
	tg.ConnectTimeout = 150 * time.Millisecond
	_, err := devssh.Dial(bg(), tg)
	if !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func TestSessionTimeouts(t *testing.T) {
	srv := serve(t, transcript(t, map[string]string{"prompt": "rtr1#"}), fakedev.WithHang(fakedev.HangSession))
	tg := target(t, srv, nil)
	tg.ConnectTimeout = 200 * time.Millisecond
	c := dial(t, tg)

	// No prompt ever comes.
	if _, err := c.CLI(devssh.VendorCisco); !errors.Is(err, devssh.ErrTimeout) {
		t.Errorf("shell: err = %v, want ErrTimeout", err)
	}
	// No hello ever comes.
	if _, err := c.NETCONF(); !errors.Is(err, devssh.ErrTimeout) {
		t.Errorf("netconf: err = %v, want ErrTimeout", err)
	}
	// An exec that is never answered ends with the call's deadline.
	s, err := c.CLI(devssh.VendorJuniper)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg(), 150*time.Millisecond)
	defer cancel()
	if _, err := s.Run(ctx, "show version"); !errors.Is(err, devssh.ErrTimeout) {
		t.Errorf("exec: err = %v, want ErrTimeout", err)
	}
}

func TestRunWithADoneContextTouchesNothing(t *testing.T) {
	srv := serve(t, transcript(t, map[string]string{"prompt": "rtr1#", "show version.out": "v\n"}))
	c := dial(t, target(t, srv, nil))
	for _, v := range []string{devssh.VendorCisco, devssh.VendorJuniper} {
		s, err := c.CLI(v)
		if err != nil {
			t.Fatal(err)
		}
		before := len(srv.Commands())
		ctx, cancel := context.WithCancel(bg())
		cancel()
		if _, err := s.Run(ctx, "show version"); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: err = %v, want context.Canceled", v, err)
		}
		if got := srv.Commands(); len(got) != before {
			t.Errorf("%s: the device saw %v", v, got[before:])
		}
		// Nothing was sent, so the session and the client are intact.
		if got, err := s.Run(bg(), "show version"); err != nil || got != "v\n" {
			t.Fatalf("%s: after the done context: %q, %v", v, got, err)
		}
	}
}

// A command that is abandoned mid-way leaves the stream out of step: the
// shell is closed, and says so afterwards.
func TestRunDeadlineClosesShell(t *testing.T) {
	srv := serve(t, transcript(t, map[string]string{"prompt": "rtr1#", "show version.out": "v\n", "show hang.hang": ""}))
	s, err := dial(t, target(t, srv, nil)).CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg(), 200*time.Millisecond)
	defer cancel()
	if _, err := s.Run(ctx, "show hang"); !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if _, err := s.Run(bg(), "show version"); !errors.Is(err, devssh.ErrClosed) {
		t.Fatalf("after the deadline: err = %v, want ErrClosed", err)
	}
}

func TestDialContextScopesClient(t *testing.T) {
	srv := serve(t, transcript(t, map[string]string{"prompt": "rtr1#", "show version.out": "v\n"}))
	ctx, cancel := context.WithCancel(bg())
	c, err := devssh.Dial(ctx, target(t, srv, nil))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	// The client closes itself; the call reports the cancellation.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err = s.Run(bg(), "show version")
		if errors.Is(err, context.Canceled) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close after cancel: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestDeadlineOfDialContext(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithHang(fakedev.HangAccept))
	ctx, cancel := context.WithTimeout(bg(), 100*time.Millisecond)
	defer cancel()
	tg := target(t, srv, nil)
	tg.ConnectTimeout = time.Minute
	if _, err := devssh.Dial(ctx, tg); !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	ctx2, cancel2 := context.WithCancel(bg())
	cancel2()
	if _, err := devssh.Dial(ctx2, tg); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// 32 sessions at once against one fake, over both transports and both CLI
// channel types.
func TestConcurrentSessions(t *testing.T) {
	cfg := configLines(200)
	dir := transcript(t, map[string]string{
		"prompt": "rtr1#", "paging": "50",
		"show configuration | display set.out": cfg,
		"show running-config.out":              cfg,
	})
	srv := serve(t, dir, fakedev.WithNetconfFraming(fakedev.FramingBoth))
	var calls atomic.Int32
	tg := target(t, srv, &calls)

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- func() error {
				c, err := devssh.Dial(bg(), tg)
				if err != nil {
					return fmt.Errorf("session %d: dial: %w", i, err)
				}
				defer func() { _ = c.Close() }()
				var got string
				switch i % 3 {
				case 0:
					s, err := c.CLI(devssh.VendorJuniper)
					if err != nil {
						return err
					}
					got, err = s.Run(bg(), "show configuration | display set")
					if err != nil {
						return err
					}
				case 1:
					s, err := c.CLI(devssh.VendorCisco)
					if err != nil {
						return err
					}
					got, err = s.Run(bg(), "show running-config")
					if err != nil {
						return err
					}
				default:
					ns, err := c.NETCONF(devssh.WithFraming(devssh.FramingAuto))
					if err != nil {
						return err
					}
					reply, err := ns.RPC(bg(), devssh.CommandRPC("show configuration | display set"))
					if err != nil {
						return err
					}
					if got, err = devssh.ReplyText(reply); err != nil {
						return err
					}
				}
				if got != cfg {
					return fmt.Errorf("session %d: %d bytes, want %d", i, len(got), len(cfg))
				}
				return nil
			}()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if srv.Logins() != n {
		t.Errorf("logins = %d, want %d", srv.Logins(), n)
	}
	if calls.Load() != n {
		t.Errorf("password source called %d times, want once per connection (%d)", calls.Load(), n)
	}
}

func TestDialerIsUsed(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	tg := target(t, srv, nil)
	tg.Host, tg.Port = "device.example.net", 0 // never resolved: the dialer decides
	var asked string
	tg.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		asked = address
		return (&net.Dialer{}).DialContext(ctx, network, srv.Addr())
	}
	dial(t, tg)
	if asked != "device.example.net:22" {
		t.Errorf("dialer asked for %q", asked)
	}
}

// A Junos device wraps a command's configuration text in
// <configuration-information>; the text is found at any depth (a capture of
// a real device's reply had this shape).
func TestReplyTextNestedAndDeclared(t *testing.T) {
	reply := `<?xml version="1.0" encoding="us-ascii"?>
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/25.4R1-S2.3/junos" message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<configuration-information>
<configuration-output>
set system host-name sw1
set system login message &quot;hi &lt;there&gt;&quot;
</configuration-output>
</configuration-information>
</rpc-reply>`
	want := "\nset system host-name sw1\nset system login message \"hi <there>\"\n"
	if text, err := devssh.ReplyText(reply); err != nil || text != want {
		t.Errorf("nested reply text %q, %v", text, err)
	}
	if _, err := devssh.ReplyText("<rpc-reply><ok/></rpc-reply>"); !errors.Is(err, devssh.ErrProtocol) {
		t.Errorf("a reply without text: %v", err)
	}
	if _, err := devssh.ReplyText("<rpc-reply><configuration-output>x"); !errors.Is(err, devssh.ErrProtocol) {
		t.Errorf("a truncated reply: %v", err)
	}
}
