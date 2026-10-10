package devssh_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"slices"
	"strconv"
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
