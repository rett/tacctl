package devssh_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
	"golang.org/x/crypto/ssh"
)

// bigOutput is a command output past MaxOutput.
func bigOutput() string {
	return strings.Repeat(strings.Repeat("x", 99)+"\n", MaxOutputLines())
}

// MaxOutputLines is the line count of a 100-byte-line output just over
// MaxOutput.
func MaxOutputLines() int { return devssh.MaxOutput/100 + 20000 }

// A device cannot make the client buffer more than MaxOutput of one
// command's output, on any channel type.
func TestMaxOutputEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("writes more than MaxOutput")
	}
	dir := transcript(t, map[string]string{
		"prompt": "rtr1#", "show big.out": bigOutput(), "show small.out": "ok\n",
		"show configuration | display set.out": bigOutput(),
	})
	srv := serve(t, dir)

	t.Run("exec", func(t *testing.T) {
		c := dial(t, target(t, srv, nil))
		s, err := c.CLI(devssh.VendorJuniper)
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Run(bg(), "show big")
		if !errors.Is(err, devssh.ErrOutputTooLarge) || out != "" {
			t.Fatalf("len %d, err %v; want ErrOutputTooLarge", len(out), err)
		}
		// The connection is fine; only that channel was closed.
		if out, err := s.Run(bg(), "show small"); err != nil || out != "ok\n" {
			t.Fatalf("after the overflow: %q, %v", out, err)
		}
	})
	t.Run("shell", func(t *testing.T) {
		c := dial(t, target(t, srv, nil))
		s, err := c.CLI(devssh.VendorCisco)
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Run(bg(), "show big")
		if !errors.Is(err, devssh.ErrOutputTooLarge) || out != "" {
			t.Fatalf("len %d, err %v; want ErrOutputTooLarge", len(out), err)
		}
		if _, err := s.Run(bg(), "show small"); !errors.Is(err, devssh.ErrClosed) {
			t.Fatalf("after the overflow: err = %v, want ErrClosed", err)
		}
	})
	t.Run("netconf", func(t *testing.T) {
		c := dial(t, target(t, srv, nil))
		n, err := c.NETCONF()
		if err != nil {
			t.Fatal(err)
		}
		reply, err := n.RPC(bg(), devssh.CommandRPC("show configuration | display set"))
		if !errors.Is(err, devssh.ErrOutputTooLarge) || reply != "" {
			t.Fatalf("len %d, err %v; want ErrOutputTooLarge", len(reply), err)
		}
		if _, err := n.RPC(bg(), devssh.CommandRPC("show small")); !errors.Is(err, devssh.ErrClosed) {
			t.Fatalf("after the overflow: err = %v, want ErrClosed", err)
		}
	})
}

// Channel opens and requests that a device never answers end with the
// context, as ErrTimeout, and do not hang the caller.
func TestUnansweredChannelCalls(t *testing.T) {
	for name, stage := range map[string]fakedev.Stage{
		"channel never confirmed": fakedev.HangChannel,
		"requests never answered": fakedev.HangRequests,
	} {
		t.Run(name, func(t *testing.T) {
			dir := transcript(t, map[string]string{"prompt": "rtr1#"})
			srv := serve(t, dir, fakedev.WithHang(stage))
			tg := target(t, srv, nil)
			tg.ConnectTimeout = 300 * time.Millisecond
			within := func(t *testing.T, call func(c *devssh.Client) error) {
				t.Helper()
				c := dial(t, tg)
				done := make(chan error, 1)
				go func() { done <- call(c) }()
				select {
				case err := <-done:
					if !errors.Is(err, devssh.ErrTimeout) {
						t.Errorf("err = %v, want ErrTimeout", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("the call did not return")
				}
			}
			t.Run("exec", func(t *testing.T) {
				within(t, func(c *devssh.Client) error {
					s, err := c.CLI(devssh.VendorJuniper)
					if err != nil {
						return err
					}
					ctx, cancel := context.WithTimeout(bg(), 200*time.Millisecond)
					defer cancel()
					_, err = s.Run(ctx, "show version")
					return err
				})
			})
			t.Run("shell", func(t *testing.T) {
				within(t, func(c *devssh.Client) error { _, err := c.CLI(devssh.VendorCisco); return err })
			})
			t.Run("netconf", func(t *testing.T) {
				within(t, func(c *devssh.Client) error { _, err := c.NETCONF(); return err })
			})
		})
	}
}

func TestBlockingPasswordSourceEndsWithTheDeadline(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	tg := target(t, srv, nil)
	release := make(chan struct{})
	defer close(release)
	tg.Password = func() (string, error) { <-release; return "x", nil }
	ctx, cancel := context.WithTimeout(bg(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := devssh.Dial(ctx, tg)
	if !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Dial returned after %v", d)
	}
}

func TestExecWithoutExitStatusIsAnError(t *testing.T) {
	dir := transcript(t, map[string]string{"show version.out": "partial\n"})
	srv := serve(t, dir, fakedev.WithNoExitStatus())
	s, err := dial(t, target(t, srv, nil)).CLI(devssh.VendorJuniper)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Run(bg(), "show version")
	if !errors.Is(err, devssh.ErrClosed) || out != "" {
		t.Fatalf("got %q, %v; want ErrClosed and no output", out, err)
	}
}

// Close returns at once while a command or an RPC is in flight, and the
// call in flight ends with an error.
func TestCloseDoesNotWaitForTheCall(t *testing.T) {
	// inFlight says the device has the call: the test closes only then.
	check := func(t *testing.T, run func() error, closeIt func() error, inFlight func() bool) {
		t.Helper()
		got := make(chan error, 1)
		go func() { got <- run() }()
		deadline := time.Now().Add(10 * time.Second)
		for !inFlight() {
			if time.Now().After(deadline) {
				t.Fatal("the device never saw the call")
			}
			time.Sleep(2 * time.Millisecond)
		}
		closed := make(chan struct{})
		go func() { _ = closeIt(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("Close blocked behind the call in flight")
		}
		select {
		case err := <-got:
			if err == nil {
				t.Error("the call in flight returned no error")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the call in flight did not end")
		}
	}
	t.Run("shell", func(t *testing.T) {
		d := &scripted{
			login: []step{{data: "rtr1#"}},
			perCmd: func(cmd string) []step {
				switch cmd {
				case "":
					return []step{{data: "\r\nrtr1#"}}
				case "show hang":
					return nil
				}
				return []step{{data: cmd + "\r\nrtr1#"}}
			},
		}
		tg, stop := d.start(t)
		defer stop()
		s, err := dial(t, tg).CLI(devssh.VendorCisco)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(bg(), time.Minute)
		defer cancel()
		check(t, func() error { _, err := s.Run(ctx, "show hang"); return err }, s.Close,
			func() bool { return strings.Contains(d.received(), "show hang\n") })
	})
	t.Run("netconf", func(t *testing.T) {
		srv := serve(t, transcript(t, map[string]string{"show hang.hang": ""}))
		n, err := dial(t, target(t, srv, nil)).NETCONF()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(bg(), time.Minute)
		defer cancel()
		check(t, func() error { _, err := n.RPC(ctx, devssh.CommandRPC("show hang")); return err }, n.Close,
			func() bool { return slices.Contains(srv.Commands(), "netconf:command") })
	})
}

func TestRPCBodyAndReplyChecks(t *testing.T) {
	dir := transcript(t, map[string]string{"show version.out": "v\n"})
	srv := serve(t, dir)
	n, err := dial(t, target(t, srv, nil)).NETCONF()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"<get-configuration/>]]>]]><rpc><close-session/></rpc>",
		"</rpc><rpc><close-session/>",
		"<command>unclosed",
	} {
		if _, err := n.RPC(bg(), bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if got := srv.Commands(); len(got) != 0 {
		t.Errorf("the device saw %v", got)
	}
	// Refusing a body does not end the session.
	if reply, err := n.RPC(bg(), devssh.CommandRPC("show version")); err != nil || !strings.Contains(reply, "v") {
		t.Fatalf("after refusals: %q, %v", reply, err)
	}

	// A reply for another message id is refused, and so is its session.
	srv2 := serve(t, dir, fakedev.WithWrongMessageID())
	n2, err := dial(t, target(t, srv2, nil)).NETCONF()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n2.RPC(bg(), devssh.CommandRPC("show version")); !errors.Is(err, devssh.ErrProtocol) {
		t.Fatalf("err = %v, want ErrProtocol", err)
	}
}

func TestDeviceTextIsCleaned(t *testing.T) {
	dir := transcript(t, map[string]string{"show x.err": "denied\n\u202eevil\u0085"})
	srv := serve(t, dir)
	n, err := dial(t, target(t, srv, nil)).NETCONF()
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.RPC(bg(), devssh.CommandRPC("show x"))
	var re devssh.RPCError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v", err)
	}
	if strings.ContainsFunc(re.Message, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		t.Errorf("the message holds control or formatting characters: %q", re.Message)
	}
	if !strings.HasPrefix(re.Message, "denied") {
		t.Errorf("message %q", re.Message)
	}
}

func TestCommandsWithControlCharactersAreRefused(t *testing.T) {
	srv := serve(t, transcript(t, map[string]string{"prompt": "rtr1#"}))
	c := dial(t, target(t, srv, nil))
	for _, v := range []string{devssh.VendorJuniper, devssh.VendorCisco} {
		s, err := c.CLI(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"show\tversion", "show\x1bversion", "show\x7f", "a\x00b", "show\u0085version"} {
			if _, err := s.Run(bg(), bad); err == nil {
				t.Errorf("%s: %q must be refused", v, bad)
			}
		}
	}
	if got := srv.Commands(); len(got) != 0 {
		t.Errorf("the device saw %q", got)
	}
}

// Backspaces and more-prompt look-alikes in the output are output; only the
// erase sequence after a more-prompt answered is removed.
func TestPagingKeepsDeviceText(t *testing.T) {
	cfg := "line a\nwith \x08 backspace\nbanner motd --More--\n" + configLines(30)
	dir := transcript(t, map[string]string{"prompt": "rtr1#", "paging": "5", "show running-config.out": cfg})
	srv := serve(t, dir)
	s, err := dial(t, target(t, srv, nil)).CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(bg(), "show running-config")
	if err != nil || got != cfg {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestLegacyAlgorithmNegotiation(t *testing.T) {
	dir := transcript(t, nil)
	for _, tc := range []struct {
		name string
		opts []fakedev.Option
		// what the handshake error of a client without Legacy names
		algo string
	}{
		{"ssh-rsa host key only", []fakedev.Option{fakedev.WithSHA1RSAHostKey()}, "host key"},
		{"group1-sha1 key exchange only", []fakedev.Option{fakedev.WithKeyExchanges(ssh.InsecureKeyExchangeDH1SHA1)}, "key exchange"},
		{"group-exchange-sha1 key exchange only", []fakedev.Option{fakedev.WithKeyExchanges(ssh.InsecureKeyExchangeDHGEXSHA1)}, "key exchange"},
		{"cbc ciphers only", []fakedev.Option{fakedev.WithCiphers(ssh.InsecureCipherAES128CBC, ssh.InsecureCipherTripleDESCBC)}, "cipher"},
		{"an old device, all three", []fakedev.Option{fakedev.WithLegacy()}, "algorithm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serve(t, dir, tc.opts...)
			tg := target(t, srv, nil)
			_, err := devssh.Dial(bg(), tg)
			// x/crypto words it 'no common algorithm for <what>' ('client to
			// server cipher' for a cipher).
			named := tc.algo == "algorithm" ||
				regexp.MustCompile(`no common algorithm for [^;]*`+tc.algo).MatchString(fmt.Sprint(err))
			if !errors.Is(err, devssh.ErrHandshake) || !named {
				t.Fatalf("without Legacy: err = %v, want a negotiation failure naming %q", err, tc.algo)
			}
			if srv.Attempts() != 0 {
				t.Error("a password was sent although the handshake failed")
			}
			tg.Legacy = true
			dial(t, tg)
		})
	}
}

func TestUnreachableIsClassified(t *testing.T) {
	tg := devssh.Target{
		Host: "192.0.2.1", User: "u", HostKeys: []string{fakedev.HostKey()},
		Password: func() (string, error) { return "x", nil },
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		},
	}
	if _, err := devssh.Dial(bg(), tg); !errors.Is(err, devssh.ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

// Concurrent Close and Run on one client and its sessions are race-free.
func TestConcurrentCloseIsRaceFree(t *testing.T) {
	dir := transcript(t, map[string]string{"prompt": "rtr1#", "show version.out": "v\n"})
	srv := serve(t, dir)
	for range 8 {
		c, err := devssh.Dial(bg(), target(t, srv, nil))
		if err != nil {
			t.Fatal(err)
		}
		s, err := c.CLI(devssh.VendorCisco)
		if err != nil {
			t.Fatal(err)
		}
		n, err := c.NETCONF()
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); _, _ = s.Run(bg(), "show version") }()
		go func() { defer wg.Done(); _, _ = n.RPC(bg(), devssh.CommandRPC("show version")) }()
		go func() { defer wg.Done(); _ = s.Close(); _ = n.Close() }()
		go func() { defer wg.Done(); _ = c.Close() }()
		wg.Wait()
	}
}

func TestQuestionMarkInShellOnly(t *testing.T) {
	srv := serve(t, transcript(t, map[string]string{"prompt": "rtr1#", "show interfaces ?.out": "help\n"}))
	c := dial(t, target(t, srv, nil))
	sh, err := c.CLI(devssh.VendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Run(bg(), "show interfaces ?"); err == nil {
		t.Fatal("a shell command with '?' must be refused")
	}
	if got := srv.Commands(); len(got) != 0 {
		t.Errorf("the device saw %q", got)
	}
	ex, err := c.CLI(devssh.VendorJuniper)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ex.Run(bg(), "show interfaces ?"); err != nil || got != "help\n" {
		t.Errorf("exec: %q, %v", got, err)
	}
}

// A NETCONF device that stopped reading: the write that blocks ends with
// the context, and Close, in either order, returns promptly.
func TestNetconfDeviceThatNeverReads(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithNoRead())
	tg := target(t, srv, nil)
	c, err := devssh.Dial(bg(), tg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.NETCONF()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = n.RPC(ctx, "<get-configuration><!-- "+strings.Repeat("x", 3<<20)+" --></get-configuration>")
	if !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("RPC returned after %v", d)
	}
	closed := make(chan struct{})
	go func() { _ = n.Close(); _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked")
	}
}

// countingConn counts what is written to the connection.
type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// Close with an RPC blocked in its write: the channel is closed under it
// and Close does not wait for the window.
func TestNetconfCloseWithBlockedWrite(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithNoRead())
	tg := target(t, srv, nil)
	// The bytes the client has put on the wire: once a channel window's worth
	// (2 MiB) has gone to a device that reads nothing, the write is blocked
	// (or about to be) and the test closes under it.
	var wrote atomic.Int64
	tg.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &countingConn{Conn: conn, n: &wrote}, nil
	}
	c, err := devssh.Dial(bg(), tg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.NETCONF()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg(), time.Minute)
	defer cancel()
	rpc := make(chan error, 1)
	go func() {
		_, err := n.RPC(ctx, "<get-configuration><!-- "+strings.Repeat("x", 3<<20)+" --></get-configuration>")
		rpc <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for wrote.Load() < 2<<20 {
		if time.Now().After(deadline) {
			t.Fatalf("the client sent only %d bytes", wrote.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { defer close(closed); defer func() { _ = c.Close() }(); _ = n.Close() }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked behind the blocked write")
	}
	select {
	case err := <-rpc:
		if err == nil {
			t.Error("the RPC in flight returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the RPC in flight did not end")
	}
}
