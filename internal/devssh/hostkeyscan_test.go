package devssh_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
	"golang.org/x/crypto/ssh"
)

// scanArgs are the host and port of srv.
func scanArgs(t *testing.T, srv *fakedev.Server) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

// An old device (SHA-1 rsa host key, group1 key exchange, CBC ciphers only)
// is read, and no password is sent.
func TestScanHostKeysLegacyDevice(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithLegacy())
	host, port := scanArgs(t, srv)
	keys, err := devssh.ScanHostKeys(bg(), host, port, 5*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{srv.HostKey()}; !slices.Equal(keys, want) {
		t.Fatalf("keys = %q, want %q", keys, want)
	}
	if srv.Attempts() != 0 || srv.Logins() != 0 {
		t.Errorf("attempts %d, logins %d: a credential was offered", srv.Attempts(), srv.Logins())
	}
}

// A device that needs none of the legacy algorithms is read as well.
func TestScanHostKeysModernDevice(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	host, port := scanArgs(t, srv)
	keys, err := devssh.ScanHostKeys(bg(), host, port, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{fakedev.HostKey()}; !slices.Equal(keys, want) {
		t.Fatalf("keys = %q, want %q", keys, want)
	}
	if srv.Attempts() != 0 {
		t.Error("a password was sent")
	}
}

// A device that holds several key types shows them all, in the order
// ed25519, ecdsa, rsa.
func TestScanHostKeysSeveralTypes(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	// The rsa key first in the server's list, to show the order is the
	// scan's own.
	srv := serve(t, transcript(t, nil), fakedev.WithHostKey(rsaSigner), fakedev.WithExtraHostKeys(ecSigner))
	host, port := scanArgs(t, srv)
	keys, err := devssh.ScanHostKeys(bg(), host, port, 5*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{fakedev.KeyText(ecSigner.PublicKey()), fakedev.KeyText(rsaSigner.PublicKey())}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys = %q, want %q", keys, want)
	}
	if srv.Attempts() != 0 {
		t.Error("a password was sent")
	}
}

func TestScanHostKeysUnreachable(t *testing.T) {
	var dials int
	refuse := func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}
	keys, err := devssh.ScanHostKeys(bg(), "192.0.2.1", 0, time.Second, refuse)
	if !errors.Is(err, devssh.ErrUnreachable) || keys != nil {
		t.Fatalf("keys %q, err %v; want ErrUnreachable", keys, err)
	}
	if dials != 1 {
		t.Errorf("%d connections after a refusal, want 1", dials)
	}
}

// A device that accepts and says nothing is a timeout, not a hang.
func TestScanHostKeysTimeout(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithHang(fakedev.HangAccept))
	host, port := scanArgs(t, srv)
	start := time.Now()
	_, err := devssh.ScanHostKeys(bg(), host, port, 300*time.Millisecond, nil)
	if !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

// A device that is not an ssh server at all is a handshake failure.
func TestScanHostKeysNotSSH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello\r\n"))
			_ = c.Close()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	_, err = devssh.ScanHostKeys(bg(), h, port, 2*time.Second, nil)
	if !errors.Is(err, devssh.ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestScanHostKeysContextCancel(t *testing.T) {
	srv := serve(t, transcript(t, nil), fakedev.WithHang(fakedev.HangAccept))
	host, port := scanArgs(t, srv)
	ctx, cancel := context.WithCancel(bg())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := devssh.ScanHostKeys(ctx, host, port, time.Minute, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("returned after %v", d)
	}
	// Cancelled before the call.
	_, err = devssh.ScanHostKeys(ctx, host, port, time.Minute, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("already cancelled: err = %v, want context.Canceled", err)
	}
}

// pickyDial dials srv through a relay that reads the client's key exchange
// offer (the first binary packet) and drops the connection when it is longer
// than limit bytes, as a device that mishandles a long algorithm offer does.
// lens collects the length of every offer.
type pickyDial struct {
	srv   *fakedev.Server
	limit int
	mu    sync.Mutex
	lens  []int
}

func (p *pickyDial) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	up, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.srv.Addr())
	if err != nil {
		return nil, err
	}
	client, relay := net.Pipe()
	go func() {
		defer func() { _ = relay.Close(); _ = up.Close() }()
		go func() { _, _ = io.Copy(relay, up); _ = relay.Close() }()
		in := bufio.NewReader(relay)
		id, err := in.ReadBytes('\n')
		if err != nil {
			return
		}
		_, _ = up.Write(id)
		var hdr [4]byte
		if _, err := io.ReadFull(in, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(hdr[:]))
		p.mu.Lock()
		p.lens = append(p.lens, n)
		p.mu.Unlock()
		if n > p.limit {
			return
		}
		_, _ = up.Write(hdr[:])
		_, _ = io.CopyN(up, in, int64(n))
		_, _ = io.Copy(up, in)
	}()
	return client, nil
}

func (p *pickyDial) offers() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.lens)
}

// A device that drops a connection whose algorithm offer is long (the Legacy
// lists of Dial plus every host key algorithm) is read with short offers: ed25519
// alone first, with the library's default algorithms.
func TestScanHostKeysShortOfferFirst(t *testing.T) {
	scan := func(srv *fakedev.Server, limit int) ([]string, []int, error) {
		p := &pickyDial{srv: srv, limit: limit}
		host, port := scanArgs(t, srv)
		keys, err := devssh.ScanHostKeys(bg(), host, port, 5*time.Second, p.dial)
		return keys, p.offers(), err
	}

	// The size of the short offer and of the long one, as the scan makes them.
	modern := serve(t, transcript(t, nil))
	_, short, err := scan(modern, 1<<20)
	if err != nil || len(short) == 0 {
		t.Fatalf("modern device: offers %v, err %v", short, err)
	}
	old := serve(t, transcript(t, nil), fakedev.WithLegacy())
	_, long, err := scan(old, 1<<20)
	if err != nil || len(long) < 2 {
		t.Fatalf("old device: offers %v, err %v", long, err)
	}
	longest := slices.Max(long)
	if slices.Max(short) >= longest {
		t.Fatalf("the short offers (%v bytes) are not shorter than the legacy one (%d)", short, longest)
	}
	limit := (slices.Max(short) + longest) / 2

	// A device that drops anything longer: read, with short offers only.
	srv := serve(t, transcript(t, nil))
	keys, offers, err := scan(srv, limit)
	if err != nil || !slices.Equal(keys, []string{fakedev.HostKey()}) {
		t.Fatalf("picky device: keys %q, err %v", keys, err)
	}
	if len(offers) == 0 || slices.Max(offers) > limit {
		t.Errorf("offers %v, want none longer than %d bytes", offers, limit)
	}
	if srv.Attempts() != 0 || srv.Logins() != 0 {
		t.Errorf("attempts %d, logins %d", srv.Attempts(), srv.Logins())
	}

	// One that holds only an rsa key: the other types fail the handshake
	// and are skipped, every offer is short.
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	keys, offers, err = scan(serve(t, transcript(t, nil), fakedev.WithHostKey(rsaSigner)), limit)
	if err != nil || !slices.Equal(keys, []string{fakedev.KeyText(rsaSigner.PublicKey())}) {
		t.Fatalf("rsa-only: keys %q, err %v", keys, err)
	}
	if len(offers) != len(short) || slices.Max(offers) > limit {
		t.Errorf("offers %v, want %d, none longer than %d", offers, len(short), limit)
	}

	// An old device still falls through to the long offer.
	keys, offers, err = scan(serve(t, transcript(t, nil), fakedev.WithLegacy()), 1<<20)
	if err != nil || len(keys) != 1 || slices.Max(offers) != longest {
		t.Errorf("old device: keys %q, offers %v, err %v", keys, offers, err)
	}
}

// blockingDial never connects: it returns when the context it is given ends.
func blockingDial(dials *int) devssh.Dialer {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		*dials++
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

// A connect budget gives up on an address nobody answers at after the budget,
// not after the whole timeout; ScanHostKeys without it waits the timeout.
func TestScanHostKeysConnectBudget(t *testing.T) {
	var dials int
	start := time.Now()
	_, err := devssh.ScanHostKeysTiming(bg(), "192.0.2.1", 0, devssh.ScanTiming{Connect: 200 * time.Millisecond, Handshake: 5 * time.Second}, true, blockingDial(&dials))
	if !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 2*time.Second {
		t.Errorf("took %v, want about the 200ms connect budget", d)
	}
	if dials != 1 {
		t.Errorf("%d connections after a connect timeout, want 1", dials)
	}

	// Without the budget (ScanHostKeys, or a budget that is not shorter than
	// the timeout) the connect runs the whole timeout.
	for name, scan := range map[string]func() error{
		"ScanHostKeys": func() error {
			_, err := devssh.ScanHostKeys(bg(), "192.0.2.1", 0, 600*time.Millisecond, blockingDial(new(int)))
			return err
		},
		"quick unset": func() error {
			_, err := devssh.ScanHostKeysTiming(bg(), "192.0.2.1", 0, devssh.ScanTiming{Connect: 100 * time.Millisecond, Handshake: 600 * time.Millisecond}, false, blockingDial(new(int)))
			return err
		},
		"budget not shorter": func() error {
			_, err := devssh.ScanHostKeysTiming(bg(), "192.0.2.1", 0, devssh.ScanTiming{Connect: 5 * time.Second, Handshake: 600 * time.Millisecond}, true, blockingDial(new(int)))
			return err
		},
	} {
		start = time.Now()
		if err := scan(); !errors.Is(err, devssh.ErrTimeout) {
			t.Errorf("%s: err = %v, want ErrTimeout", name, err)
		}
		if d := time.Since(start); d < 500*time.Millisecond {
			t.Errorf("%s: took %v, want the whole 600ms timeout", name, d)
		}
	}

	// A refused connect is ErrUnreachable at once, with or without a budget.
	refuse := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}
	if _, err := devssh.ScanHostKeysTiming(bg(), "192.0.2.1", 0, devssh.ScanTiming{Connect: 200 * time.Millisecond, Handshake: 5 * time.Second}, true, refuse); !errors.Is(err, devssh.ErrUnreachable) {
		t.Errorf("refused: err = %v, want ErrUnreachable", err)
	}
}

// A server that accepts at once and greets after a delay longer than the
// connect budget but shorter than the handshake budget is read (a real
// device was measured to send its banner about 3 s after the connect), next
// to the dialer that never connects, which is given up on within the connect
// budget.
func TestScanHostKeysConnectBudgetSlowGreeter(t *testing.T) {
	srv := serve(t, transcript(t, nil))
	host, port := scanArgs(t, srv)
	slow := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &lateConn{Conn: c, delay: 600 * time.Millisecond}, nil
	}
	start := time.Now()
	keys, err := devssh.ScanHostKeysTiming(bg(), host, port, devssh.ScanTiming{Connect: 200 * time.Millisecond, Handshake: 5 * time.Second}, true, slow)
	if err != nil || len(keys) == 0 {
		t.Fatalf("keys %q, err %v", keys, err)
	}
	if d := time.Since(start); d < 500*time.Millisecond || d > 4*time.Second {
		t.Errorf("took %v, want the greeting's delay (600ms) and well under the timeout", d)
	}
}

// lateConn delays the first read, as a server slow to send its banner does.
type lateConn struct {
	net.Conn
	delay time.Duration
	once  sync.Once
}

func (c *lateConn) Read(p []byte) (int, error) {
	c.once.Do(func() { time.Sleep(c.delay) })
	return c.Conn.Read(p)
}

// The defaults: the connect budget survives a lost SYN on a link with a
// 600 ms round trip (1 s to retransmit plus the round trip, 3 s being the
// floor) and is shorter than the handshake budget; the other timings are the
// values the scans have always had; zero fields of a ScanTiming are those.
func TestDefaultScanTiming(t *testing.T) {
	d := devssh.DefaultScanTiming()
	if d.Connect < 3*time.Second || d.Connect >= d.Handshake {
		t.Errorf("Connect %v, Handshake %v", d.Connect, d.Handshake)
	}
	if d.Keyscan != 5*time.Second || d.KeyscanRetry != 3*time.Second || d.Handshake != devssh.DefaultConnectTimeout || d.Attempt != 5*time.Second {
		t.Errorf("defaults changed: %+v", d)
	}
	if got := (devssh.ScanTiming{Attempt: time.Second}).WithDefaults(); got.Attempt != time.Second || got.Connect != d.Connect || got.Handshake != d.Handshake {
		t.Errorf("WithDefaults: %+v", got)
	}
}

// satelliteConn adds a round trip to every turn of the conversation: the
// first read after a write waits rtt.
type satelliteConn struct {
	net.Conn
	rtt   time.Duration
	wrote bool
	mu    sync.Mutex
}

func (c *satelliteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.wrote = true
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *satelliteConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	wait := c.wrote
	c.wrote = false
	c.mu.Unlock()
	if wait {
		time.Sleep(c.rtt)
	}
	return c.Conn.Read(p)
}

// A device behind a link with a 600 ms round trip, whose connect takes 1.5 s
// (a lost SYN and the round trip), is read with the defaults, in the quick
// read of a device nothing has answered from yet too. The first two
// connections of the read (the handshake and the first per-type attempt, the
// two budgets) are slowed; the rest are not, to keep the test short.
func TestScanHostKeysTimingSatelliteLink(t *testing.T) {
	t.Parallel()
	srv := serve(t, transcript(t, nil))
	host, port := scanArgs(t, srv)
	var mu sync.Mutex
	dials := 0
	satellite := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dials++
		slow := dials <= 2
		mu.Unlock()
		if slow {
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil || !slow {
			return c, err
		}
		return &satelliteConn{Conn: c, rtt: 600 * time.Millisecond}, nil
	}
	keys, err := devssh.ScanHostKeysTiming(bg(), host, port, devssh.ScanTiming{}, true, satellite)
	if err != nil || len(keys) == 0 {
		t.Fatalf("keys %q, err %v; want a read with the default timing", keys, err)
	}
}
