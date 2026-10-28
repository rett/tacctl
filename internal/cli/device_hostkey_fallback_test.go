package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"golang.org/x/crypto/ssh"
)

// The built-in scan is the fallback for a legacy-ssh device that
// ssh-keyscan reads nothing from, and for a device that accepted the
// connection and gave ssh-keyscan's scans no key; a device that did not
// answer at all is not dialled again.
func TestDeviceAddLegacyFallsBackToBuiltinScan(t *testing.T) {
	sb := newSandbox(t, true)
	rsa := hkKey(t, "rsa")
	var calls []string
	sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
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

	// A device without legacy-ssh that did not answer at all (no banner:
	// refused, timed out) is refused as before, the built-in client not asked.
	calls = nil
	sb.devScan("", func(r *fake.Runner) {
		r.On([]string{"ssh-keyscan"}, execx.Result{Stderr: []byte("connect (`192.0.2.4'): Connection refused\n")})
	}, "add", "plain", "192.0.2.4", "--vendor", "cisco")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.4 port 22 (ssh-keyscan); nothing was changed.")
	if len(calls) != 0 {
		t.Errorf("fallback called for a device that did not answer: %q", calls)
	}
}

// A device without legacy-ssh that accepted the connection and gave
// ssh-keyscan's scans (the combined one and the one-type ones) no key is read
// by the built-in client.
func TestDeviceAddFallsBackToBuiltinScanWithoutLegacy(t *testing.T) {
	sb := newSandbox(t, true)
	ed := hkKey(t, "ed25519")
	var calls []string
	sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
		return func(_ context.Context, address string, port int) ([]devreg.HostKey, error) {
			calls = append(calls, address+":"+strconv.Itoa(port))
			return []devreg.HostKey{ed}, nil
		}
	}
	out := sb.devScan("", scan("192.0.2.4"), "add", "plain", "192.0.2.4", "--vendor", "juniper")
	if sb.code != 0 || !strings.Contains(out, "Host keys pinned (1)") || !strings.Contains(out, "ED25519  "+ed.Fingerprint()) {
		t.Fatalf("add: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	if len(calls) != 1 || calls[0] != "192.0.2.4:22" || sb.runner.Count("ssh-keyscan") != 4 {
		t.Errorf("fallback calls %q, ssh-keyscan runs %d (the combined scan and three one-type ones)", calls, sb.runner.Count("ssh-keyscan"))
	}
	if !strings.Contains(sb.devices(), "host_keys: [ssh-ed25519 "+ed.Blob+"]") || strings.Contains(sb.devices(), "legacy_ssh") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
}

// 'device enroll' and 'device collect' find out whether a device needs
// legacy-ssh: a device only the built-in client reads is flagged, one that
// ssh-keyscan reads one type at a time is not.
func TestScanLearningLegacy(t *testing.T) {
	sb := newSandbox(t, true)
	rsa, ed := hkKey(t, "rsa"), hkKey(t, "ed25519")
	var fallbackCalls int
	sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
		return func(context.Context, string, int) ([]devreg.HostKey, error) {
			fallbackCalls++
			return []devreg.HostKey{rsa}, nil
		}
	}
	learn := func(script func(*fake.Runner)) ([]devreg.HostKey, bool, error) {
		r := &fake.Runner{}
		script(r)
		a := app.New(nil, paths.NewEnv(append(append([]string(nil), sb.env...), "SUDO_USER=alice")), "/opt/x/dist/tacctl", 1000,
			app.Stdio{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, r)
		inv := &invocation{ctx: context.Background(), app: a, hooks: sb.hooks}
		return inv.scanLearningLegacy("192.0.2.4", 22)
	}

	// Only the built-in client reads it, with the legacy algorithms.
	keys, legacy, err := learn(scan("192.0.2.4"))
	if err != nil || !legacy || len(keys) != 1 || keys[0] != rsa || fallbackCalls != 1 {
		t.Errorf("only the built-in client: %v legacy=%v err=%v fallback calls %d", keys, legacy, err, fallbackCalls)
	}
	// ssh-keyscan reads it one type at a time: not legacy, no built-in client.
	fallbackCalls = 0
	keys, legacy, err = learn(scanOneAtATime("192.0.2.4", ed))
	if err != nil || legacy || len(keys) != 1 || keys[0] != ed || fallbackCalls != 0 {
		t.Errorf("one type at a time: %v legacy=%v err=%v fallback calls %d", keys, legacy, err, fallbackCalls)
	}
	// Nobody answers (the built-in client, asked once with the legacy
	// algorithms as before, neither): the first scan's error.
	fallbackCalls = 0
	sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
		return func(context.Context, string, int) ([]devreg.HostKey, error) {
			fallbackCalls++
			return nil, devssh.ErrUnreachable
		}
	}
	_, legacy, err = learn(func(r *fake.Runner) {
		r.On([]string{"ssh-keyscan"}, execx.Result{Stderr: []byte("192.0.2.4: Connection timed out\n")})
	})
	if !errors.Is(err, devreg.ErrNoAnswer) || legacy || fallbackCalls != 1 {
		t.Errorf("unreachable: legacy=%v err=%v fallback calls %d", legacy, err, fallbackCalls)
	}
}

// When the built-in scan reads nothing either, the refusal stays and names
// both reads, with the way on.
func TestDeviceAddLegacyBothScansFail(t *testing.T) {
	sb := newSandbox(t, true)
	called := 0
	sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
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
	sb.hooks.keyFallback = realKeyFallback
	sb.hooks.deviceDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
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
