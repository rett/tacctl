package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

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
		return func(_ context.Context, address string, port int, _ bool) ([]devreg.HostKey, error) {
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

	// A device without legacy-ssh whose name does not resolve is refused as
	// before, the built-in client not asked.
	calls = nil
	sb.devScan("", func(r *fake.Runner) {
		r.On([]string{"ssh-keyscan"}, execx.Result{Stderr: []byte(unresolvable("sw1.example.net"))})
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
		return func(_ context.Context, address string, port int, _ bool) ([]devreg.HostKey, error) {
			calls = append(calls, address+":"+strconv.Itoa(port))
			return []devreg.HostKey{ed}, nil
		}
	}
	out := sb.devScan("", scanSilent("192.0.2.4"), "add", "plain", "192.0.2.4", "--vendor", "juniper")
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
		return func(context.Context, string, int, bool) ([]devreg.HostKey, error) {
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
	keys, legacy, err := learn(scanSilent("192.0.2.4"))
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
		return func(context.Context, string, int, bool) ([]devreg.HostKey, error) {
			fallbackCalls++
			return nil, devssh.ErrUnreachable
		}
	}
	_, legacy, err = learn(func(r *fake.Runner) {
		r.On([]string{"ssh-keyscan"}, execx.Result{Stderr: []byte(unresolvable("192.0.2.4"))})
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
		return func(context.Context, string, int, bool) ([]devreg.HostKey, error) {
			called++
			return nil, devssh.ErrHandshake
		}
	}
	sb.devScan("", scan("192.0.2.2"), "add", "old-ios", "192.0.2.2", "--vendor", "cisco", "--legacy-ssh")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.2 port 22 (ssh-keyscan, and tacctl's own ssh client for legacy-ssh); nothing was changed.")
	if !strings.Contains(sb.stderr(), "--no-host-key") || called != 1 {
		t.Errorf("called %d\n%s", called, sb.stderr())
	}
	// A legacy-ssh device's refusal has no by-hand advice, as before.
	if strings.Contains(sb.stderr(), "by hand") {
		t.Errorf("by-hand advice for a legacy device:\n%s", sb.stderr())
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

// A device ssh-keyscan reads nothing from and says nothing about (a server
// slow to greet: ssh-keyscan -T gives up silently) is read by the built-in
// client, whose longer wait is what plain ssh has; both failing names both
// and still gives the by-hand advice.
func TestDeviceAddSilentDeviceFallsBackToBuiltinScan(t *testing.T) {
	sb := newSandbox(t, true)
	ed := hkKey(t, "ed25519")
	var calls []string
	var fbKeys []devreg.HostKey
	var fbErr error
	sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
		return func(_ context.Context, address string, port int, _ bool) ([]devreg.HostKey, error) {
			calls = append(calls, address+":"+strconv.Itoa(port))
			return fbKeys, fbErr
		}
	}
	nothing := func(r *fake.Runner) { r.On([]string{"ssh-keyscan"}, execx.Result{}) }

	fbKeys = []devreg.HostKey{ed}
	out := sb.devScan("", nothing, "add", "srx1", "192.0.2.6", "--vendor", "juniper")
	if sb.code != 0 || !strings.Contains(out, "Host keys pinned (1)") || !strings.Contains(out, "ED25519  "+ed.Fingerprint()) {
		t.Fatalf("add: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	if len(calls) != 1 || calls[0] != "192.0.2.6:22" || sb.runner.Count("ssh-keyscan") != 1 {
		t.Errorf("fallback calls %q, ssh-keyscan runs %d", calls, sb.runner.Count("ssh-keyscan"))
	}

	calls, fbKeys, fbErr = nil, nil, devssh.ErrTimeout
	sb.devScan("", nothing, "add", "srx2", "192.0.2.7", "--vendor", "juniper", "--port", "2222")
	sb.expect(1, "", "No ssh host key could be read from 192.0.2.7 port 2222 (ssh-keyscan, and tacctl's own ssh client); nothing was changed.")
	for _, want := range []string{
		"it may be slow to answer. See what it offers by hand: ssh-keyscan -T 30 -p 2222 -t ed25519 192.0.2.7 (also -t ecdsa, -t rsa).",
		"--host-key SHA256:<fp>",
		"tacctl device hostkey <name> set SHA256:<fp>",
	} {
		if !strings.Contains(sb.stderr(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, sb.stderr())
		}
	}
	if len(calls) != 1 || sb.runner.Count("ssh-keyscan") != 1 {
		t.Errorf("fallback calls %q, ssh-keyscan runs %d", calls, sb.runner.Count("ssh-keyscan"))
	}
}

// The built-in client's connect is bounded shortly for a device nothing has
// answered from yet (quick), not for the others: an address nobody answers at
// costs the connect budget of the default timing (devssh.ScanTiming), and the handshake keeps its own.
func TestRealKeyFallbackQuickBoundsTheConnect(t *testing.T) {
	sb := newSandbox(t, true)
	var dials int
	sb.hooks.deviceDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials++
		<-ctx.Done()
		return nil, ctx.Err()
	}
	a := app.New(nil, paths.NewEnv(append(append([]string(nil), sb.env...), "SUDO_USER=alice")), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, &fake.Runner{})
	inv := &invocation{ctx: context.Background(), app: a, hooks: sb.hooks}
	fb := realKeyFallback(inv)
	quickConnect := devssh.DefaultScanTiming().Connect

	start := time.Now()
	_, err := fb(inv.ctx, "192.0.2.1", 22, true)
	d := time.Since(start)
	if !errors.Is(err, devssh.ErrTimeout) || dials != 1 || d < quickConnect-time.Second/2 || d > quickConnect+2*time.Second {
		t.Errorf("quick: err %v, %d dials, took %v; want ErrTimeout after about %v", err, dials, d, quickConnect)
	}

	// Not quick: the connect has the whole budget, so a context shorter than
	// the quick one is what ends it.
	ctx, cancel := context.WithTimeout(context.Background(), quickConnect+time.Second)
	defer cancel()
	start = time.Now()
	_, err = fb(ctx, "192.0.2.1", 22, false)
	if err == nil || time.Since(start) < quickConnect+time.Second/2 {
		t.Errorf("not quick: err %v after %v, want the connect to outlast the quick budget", err, time.Since(start))
	}
}
