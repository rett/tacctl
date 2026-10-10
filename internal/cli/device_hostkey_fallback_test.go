package cli

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
	"golang.org/x/crypto/ssh"
)

// No test of this package reaches a real address through the host-key
// fallback of a legacy-ssh device: it reads nothing unless a test replaces
// keyFallback (or sets realKeyFallback with deviceDialOverride, as the fake
// old device's test does).
func init() {
	keyFallback = func(*invocation) devreg.KeyFallback {
		return func(_ context.Context, address string, port int) ([]devreg.HostKey, error) {
			return nil, errors.New("tests do not dial " + address + ":" + strconv.Itoa(port))
		}
	}
}

// The built-in scan is the fallback for a legacy-ssh device that
// ssh-keyscan reads nothing from, and for no other.
func TestDeviceAddLegacyFallsBackToBuiltinScan(t *testing.T) {
	sb := newSandbox(t, true)
	rsa := hkKey(t, "rsa")
	var calls []string
	prev := keyFallback
	t.Cleanup(func() { keyFallback = prev })
	keyFallback = func(*invocation) devreg.KeyFallback {
		return func(_ context.Context, address string, port int) ([]devreg.HostKey, error) {
			calls = append(calls, address+":"+strconv.Itoa(port))
			return []devreg.HostKey{rsa}, nil
		}
	}

	// ssh-keyscan reads nothing from an old unit; the built-in scan does.
	out := sb.devScan("", scan("192.0.2.2"), "add", "old-ios", "192.0.2.2", "--vendor", "cisco", "--legacy-ssh", "--port", "830")
	if sb.code != 0 || !strings.Contains(out, "Host keys pinned (1)") || !strings.Contains(out, "RSA      "+rsa.Fingerprint()) {
		t.Fatalf("legacy add: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	if len(calls) != 1 || calls[0] != "192.0.2.2:830" {
		t.Errorf("fallback calls %q", calls)
	}
	if !strings.Contains(sb.knownHosts(), "\nold-ios "+rsa.String()+"\n") || !strings.Contains(sb.devices(), "host_keys: [ssh-rsa "+rsa.Blob+"]") {
		t.Errorf("not pinned:\n%s\n%s", sb.devices(), sb.knownHosts())
	}

	// ssh-keyscan's own answer is used as it is: no fallback.
	calls = nil
	sb.devScan("", scan("192.0.2.3", hkKey(t, "ed25519")), "add", "ios2", "192.0.2.3", "--vendor", "cisco", "--legacy-ssh")
	if sb.code != 0 || len(calls) != 0 {
		t.Errorf("keyscan answered: %d, fallback calls %q", sb.code, calls)
	}

	// A device without legacy-ssh that does not answer is refused as before.
	sb.devScan("", scan("192.0.2.4"), "add", "plain", "192.0.2.4", "--vendor", "cisco")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.4 port 22 (ssh-keyscan); nothing was changed.")
	if len(calls) != 0 {
		t.Errorf("fallback called for a device without legacy-ssh: %q", calls)
	}
}

// When the built-in scan reads nothing either, the refusal stays and names
// both reads, with the way on.
func TestDeviceAddLegacyBothScansFail(t *testing.T) {
	sb := newSandbox(t, true)
	prev := keyFallback
	t.Cleanup(func() { keyFallback = prev })
	called := 0
	keyFallback = func(*invocation) devreg.KeyFallback {
		return func(context.Context, string, int) ([]devreg.HostKey, error) {
			called++
			return nil, devssh.ErrHandshake
		}
	}
	sb.devScan("", scan("192.0.2.2"), "add", "old-ios", "192.0.2.2", "--vendor", "cisco", "--legacy-ssh")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.2 port 22 (ssh-keyscan, and tacctl's own ssh client for legacy-ssh); nothing was changed.")
	if !strings.Contains(sb.stderr(), "--no-host-key") || called != 1 {
		t.Errorf("called %d\n%s", called, sb.stderr())
	}
	if strings.Contains(sb.devices(), "old-ios") {
		t.Errorf("registered:\n%s", sb.devices())
	}
}

// End to end against the fake old device: ssh-keyscan reads nothing, the
// built-in client reads its ssh-rsa key (group1 key exchange, CBC ciphers)
// with the fingerprint ssh prints, and sends no password.
func TestDeviceAddLegacyScansTheFakeOldDevice(t *testing.T) {
	sb := newSandbox(t, true)
	srv := fakedev.New(t.TempDir(), fakedev.WithLegacy())
	t.Cleanup(srv.Stop)
	prevDial, prevFallback := deviceDialOverride, keyFallback
	t.Cleanup(func() { deviceDialOverride, keyFallback = prevDial, prevFallback })
	keyFallback = realKeyFallback
	deviceDialOverride = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Addr())
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(srv.HostKey()))
	if err != nil {
		t.Fatal(err)
	}
	out := sb.devScan("", scan("192.0.2.2"), "add", "old-ios", "192.0.2.2", "--vendor", "cisco", "--legacy-ssh")
	if sb.code != 0 || !strings.Contains(out, "RSA      "+ssh.FingerprintSHA256(pub)) {
		t.Fatalf("add: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	if !strings.Contains(sb.devices(), "host_keys: ["+srv.HostKey()+"]") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
	if srv.Attempts() != 0 || srv.Logins() != 0 {
		t.Errorf("attempts %d, logins %d", srv.Attempts(), srv.Logins())
	}
}
