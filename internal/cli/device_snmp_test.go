package cli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/testpty"
)

// The SNMP name hint (docs/plans/0.2.2-plan.md 5.10) in-process: 'device
// add' and 'device check' with a stub lookup (app.App's SNMP), and 'config
// snmp' end to end against internal/snmp's agent on 127.0.0.1. The bats
// files device_snmp.bats and config_snmp.bats pin the command line.

// stubSNMP answers sysName by address; an address it does not know is no
// answer.
type stubSNMP struct {
	names map[string]string
	errs  map[string]error
	// locs answers sysLocation by address (an address not in it is no answer);
	// locErrs are the errors of the location read.
	locs    map[string]string
	locErrs map[string]error
	calls   atomic.Int64
}

func (s *stubSNMP) SysLocation(_ context.Context, addr string) (string, error) {
	s.calls.Add(1)
	if err := s.locErrs[addr]; err != nil {
		return "", err
	}
	if l, ok := s.locs[addr]; ok {
		return l, nil
	}
	return "", &snmp.TimeoutError{Timeout: 2 * time.Second, Tries: 2}
}

func (s *stubSNMP) SysName(_ context.Context, addr string) (string, error) {
	s.calls.Add(1)
	if err := s.errs[addr]; err != nil {
		return "", err
	}
	if n, ok := s.names[addr]; ok {
		return n, nil
	}
	return "", &snmp.TimeoutError{Timeout: 2 * time.Second, Tries: 2}
}

func TestDeviceAddNameHint(t *testing.T) {
	sb := newSandbox(t, true)
	stub := &stubSNMP{names: map[string]string{
		"10.99.0.1": "SW1.site-a.example", "10.99.0.2": "sw2.site-a.example", "10.99.0.5": "WTI", "10.99.0.6": "  ",
	}, errs: map[string]error{"10.99.0.4": &snmp.ReportError{Name: "wrongDigest"}}}
	sb.snmp = stub
	// A match: the first label, without regard to case.
	out := sb.dev("", "add", "sw1", "10.99.0.1", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "  The device calls itself 'SW1.site-a.example' (SNMP sysName).\n") || strings.Contains(out, "!") {
		t.Errorf("match: %d %q", sb.code, out)
	}
	// A mismatch warns; the add goes ahead.
	out = sb.dev("", "add", "core-sw1", "10.99.0.2", "--no-host-key", "--vendor", "juniper")
	want := "[INFO] Device 'core-sw1' registered: 10.99.0.2, juniper.\n" +
		"  The device calls itself 'sw2.site-a.example' (SNMP sysName).\n" +
		"  ! That is not the name given or its --hostname: add --hostname sw2.site-a.example, or register it as sw2.site-a.example.\n"
	if sb.code != 0 || !strings.Contains(out, want) {
		t.Errorf("mismatch: %d %q", sb.code, out)
	}
	// --hostname matches.
	stub.names["10.99.0.9"] = "sw9.site-a.example"
	out = sb.dev("", "add", "core-sw9", "10.99.0.9", "--no-host-key", "--hostname", "sw9.site-a.example")
	if sb.code != 0 || !strings.Contains(out, "calls itself 'sw9.site-a.example'") || strings.Contains(out, "!") {
		t.Errorf("--hostname match: %d %q", sb.code, out)
	}
	// No answer, a report, a generic name (no 'register it as'), an empty one.
	out = sb.dev("", "add", "core-sw3", "10.99.0.3", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "[INFO] No SNMP answer from 10.99.0.3; no name hint.\n") {
		t.Errorf("no answer: %d %q", sb.code, out)
	}
	out = sb.dev("", "add", "core-sw4", "10.99.0.4", "--no-host-key")
	if !strings.Contains(out, "[INFO] No SNMP answer from 10.99.0.4 (wrongDigest (wrong authentication passphrase or protocol)); no name hint.") {
		t.Errorf("report: %q", out)
	}
	out = sb.dev("", "add", "pdu1", "10.99.0.5", "--no-host-key", "--vendor", "wti")
	if !strings.Contains(out, "  The device calls itself 'WTI' (SNMP sysName).\n  ! That is not the name given or its --hostname: add --hostname WTI.\n") {
		t.Errorf("generic: %q", out)
	}
	out = sb.dev("", "add", "core-sw6", "10.99.0.6", "--no-host-key")
	if !strings.Contains(out, "No SNMP answer from 10.99.0.6; no name hint.") {
		t.Errorf("empty: %q", out)
	}
	// --no-lookup asks nothing.
	before := stub.calls.Load()
	out = sb.dev("", "add", "core-sw7", "10.99.0.7", "--no-host-key", "--no-lookup")
	if sb.code != 0 || stub.calls.Load() != before || strings.Contains(out, "SNMP") {
		t.Errorf("--no-lookup: %d %q", sb.code, out)
	}
	if n := strings.Count(sb.devices(), "address:"); n != 8 {
		t.Errorf("%d devices registered, want 8:\n%s", n, sb.devices())
	}
}

func TestDeviceAddNameHintFallbacks(t *testing.T) {
	sb := newSandbox(t, true)
	// No SNMP set up: one line.
	out := sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "[INFO] No name hint: SNMP is not configured ('tacctl config snmp').\n") {
		t.Errorf("not configured: %d %q", sb.code, out)
	}
	// The NAS-Identifier a scan recorded stands in, labelled.
	s := devreg.NewSeen()
	s.Apply("radius", []backend.Sighting{{Time: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Address: "10.99.0.2",
		User: "alice", Outcome: backend.SightAccept, NASID: "rtr2"}})
	s.Updated = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := os.MkdirAll(sb.path("var-lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(sb.path("var-lib", "devices-seen.json")); err != nil {
		t.Fatal(err)
	}
	out = sb.dev("", "add", "core-rtr", "10.99.0.2", "--no-host-key")
	if !strings.Contains(out, "  The device calls itself 'rtr2' (NAS-Identifier seen by a scan).\n  ! That is not the name given or its --hostname: add --hostname rtr2, or register it as rtr2.\n") {
		t.Errorf("NAS-Identifier: %q", out)
	}
	sb.snmp = &stubSNMP{}
	out = sb.dev("", "add", "rtr3", "10.99.0.3", "--no-host-key")
	if !strings.Contains(out, "No SNMP answer from 10.99.0.3; no name hint.") {
		t.Errorf("no answer, no NAS-Identifier: %q", out)
	}
}

func TestDeviceAddOfferedName(t *testing.T) {
	sb := newSandbox(t, true)
	usage := "Usage: tacctl device add [<name>] <address> [options]"
	// No SNMP: refused with the usage line.
	sb.dev("", "add", "10.99.0.1")
	sb.expect(1, "", "No name given, and there is none to offer: SNMP is not configured ('tacctl config snmp').")
	sb.expect(1, "", usage)
	sb.dev("", "add", "not-an-address")
	sb.expect(1, "", "Invalid address 'not-an-address'")
	sb.snmp = &stubSNMP{names: map[string]string{"10.99.0.1": "SW1.Site-A.example", "10.99.0.5": "WTI", "10.99.0.6": "bad name"}}
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"add", "10.99.0.1"}, "No name given; the device calls itself 'SW1.Site-A.example' (SNMP sysName). Give the name to register it under it."},
		{[]string{"add", "10.99.0.1", "--no-lookup"}, "No name given, and --no-lookup reads none from the device."},
		{[]string{"add", "10.99.0.2"}, "No name given, and no SNMP answer from 10.99.0.2 to offer one."},
		{[]string{"add", "10.99.0.5"}, "the device calls itself 'WTI' (SNMP sysName), but it is a generic name."},
		{[]string{"add", "10.99.0.6"}, "but it is not a valid device name."},
	} {
		sb.dev("", c.args...)
		sb.expect(1, "", c.err)
		sb.expect(1, "", usage)
	}
	if sb.devices() != "" {
		t.Errorf("registered without a name:\n%s", sb.devices())
	}
	// At a terminal: offered lowercased, taken on 'y'.
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()
	sb.tty = slave
	if _, err := master.WriteString("n\n"); err != nil {
		t.Fatal(err)
	}
	out := sb.dev("", "add", "10.99.0.1", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "Cancelled; nothing was registered.") || sb.devices() != "" {
		t.Errorf("declined: %d %q", sb.code, out)
	}
	if _, err := master.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	out = sb.dev("", "add", "10.99.0.1", "--no-host-key", "--vendor", "cisco")
	if sb.code != 0 || !strings.Contains(out, "[INFO] Device 'sw1.site-a.example' registered: 10.99.0.1, cisco.") ||
		!strings.Contains(sb.stderr(), "Register 10.99.0.1 as 'sw1.site-a.example'? [y/N]: ") {
		t.Errorf("accepted: %d %q %q", sb.code, out, sb.stderr())
	}
	// The add's own checks apply to the offered name.
	if _, err := master.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	sb.snmp = &stubSNMP{names: map[string]string{"10.99.0.3": "sw1.site-a.example"}}
	sb.dev("", "add", "10.99.0.3", "--no-host-key")
	sb.expect(1, "", "'sw1.site-a.example' is already registered (10.99.0.1)")
}

func TestDeviceCheckSNMPRow(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw1", "10.99.0.1", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw2", "10.99.0.2", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw3", "10.99.0.3", "--no-host-key", "--no-lookup")
	sb.snmp = &stubSNMP{names: map[string]string{"10.99.0.1": "sw1.site-a.example", "10.99.0.2": "other"}}
	out := plain(sb.cfgRun("", []string{"device", "check", "--all"}, nil))
	for _, want := range []string{
		"SNMP name:   sw1.site-a.example  (match)",
		"SNMP name:   other  (differs)",
		"SNMP name:   no answer\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check lacks %q:\n%s", want, out)
		}
	}
	// --json, and without SNMP the reason.
	sb.snmp = nil
	sb.write("state/snmp.yaml", "version: 1\nfrob: x\n", 0o600)
	sb.write("state/tacctl.yaml", "snmp:\n  version: v2c\n", 0o600)
	var js []map[string]any
	if err := json.Unmarshal([]byte(sb.cfgRun("", []string{"device", "check", "--all", "--json"}, nil)), &js); err != nil || len(js) != 3 {
		t.Fatalf("--json: %v %q", err, sb.out.String())
	}
	if js[0]["name"] != "sw1" || js[0]["sysname"] != nil || !strings.Contains(js[0]["sysname_error"].(string), "snmp.yaml: unknown key 'frob'") {
		t.Errorf("--json: %v", js[0])
	}
	sb.snmp = &stubSNMP{names: map[string]string{"10.99.0.2": "other"}}
	if err := json.Unmarshal([]byte(sb.cfgRun("", []string{"device", "check", "sw2", "--json"}, nil)), &js); err != nil || len(js) != 1 ||
		js[0]["sysname"] != "other" || js[0]["sysname_match"] != false {
		t.Errorf("--json: %v %v", err, js)
	}
}

// 'config snmp' against the agent on 127.0.0.1: the credentials go to
// snmp.yaml (0600) and are never printed; 'test' and 'device add' use them.
func TestConfigSNMP(t *testing.T) {
	sb := newSandbox(t, true)
	a := &snmp.Agent{SysName: "sw1.site-a.example", Community: "c0mmunity-x", User: "alice",
		AuthPass: "auth-pass-1", PrivPass: "priv-pass-1", Auth: snmp.AuthSHA256}
	conn, err := a.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	port := strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
	cfg := func(stdin string, args ...string) string {
		t.Helper()
		out := plain(sb.cfgRun(stdin, append([]string{"config", "snmp"}, args...), nil))
		for _, secret := range []string{"c0mmunity-x", "auth-pass-1", "priv-pass-1", "wrong-one"} {
			if strings.Contains(out, secret) || strings.Contains(sb.err.String(), secret) {
				t.Errorf("%v printed a secret", args)
			}
		}
		return out
	}
	out := cfg("")
	if sb.code != 0 || !strings.Contains(out, "Usage: tacctl config snmp <subcommand>") {
		t.Errorf("usage: %d %q", sb.code, out)
	}
	out = cfg("", "show")
	for _, want := range []string{"version:    not set", "port:       161 (default)", "timeout:    2 (default) s, one retry", "community:  not set"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	cfg("", "community")
	sb.expect(1, "", "No terminal to ask for the community on; pipe it in with --stdin.")
	cfg("c0mmunity-x\n", "community", "--stdin")
	if sb.code != 0 {
		t.Fatalf("community: %s", sb.stderr())
	}
	if fi, err := os.Stat(sb.path("state", "snmp.yaml")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snmp.yaml: %v %v", fi, err)
	}
	cfg("", "port", port)
	cfg("", "timeout", "1")
	cfg("", "timeout", "11")
	sb.expect(1, "", "snmp.timeout")
	out = cfg("", "show")
	for _, want := range []string{"version:    v2c", "port:       " + port, "timeout:    1 s", "community:  set"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	out = cfg("", "test", "127.0.0.1")
	if sb.code != 0 || !strings.Contains(out, "127.0.0.1 calls itself 'sw1.site-a.example' (SNMP sysName).") {
		t.Errorf("test: %d %q %q", sb.code, out, sb.stderr())
	}
	// device add uses it, over UDP.
	out = plain(sb.cfgRun("", []string{"device", "add", "sw1", "127.0.0.1", "--no-host-key"}, nil))
	if !strings.Contains(out, "The device calls itself 'sw1.site-a.example' (SNMP sysName).") {
		t.Errorf("device add: %q", out)
	}
	cfg("", "test", "sw1")
	sb.expect(0, "calls itself", "")
	// A wrong community is a timeout.
	cfg("wrong-one\n", "community", "--stdin")
	cfg("", "test", "127.0.0.1")
	sb.expect(1, "", "No answer from 127.0.0.1: no answer (2 tries, 1s each). No agent there, a filter on the way, or a wrong community")
	// v3: the user, its passphrases, the protocols.
	cfg("auth-pass-1\npriv-pass-1\n", "v3-user", "alice", "--auth", "sha256", "--stdin")
	if sb.code != 0 {
		t.Fatalf("v3-user: %s", sb.stderr())
	}
	out = cfg("", "test", "127.0.0.1")
	if sb.code != 0 || !strings.Contains(out, "calls itself 'sw1.site-a.example'") {
		t.Errorf("v3 test: %d %q %q", sb.code, out, sb.stderr())
	}
	cfg("wrong-one\npriv-pass-1\n", "v3-user", "alice", "--stdin")
	cfg("", "test", "127.0.0.1")
	sb.expect(1, "", "127.0.0.1 refused the request: wrongDigest")
	cfg("auth-pass-1\npriv-pass-1\n", "v3-user", "bob", "--stdin")
	cfg("", "test", "127.0.0.1")
	sb.expect(1, "", "127.0.0.1 refused the request: unknownUserName")
	cfg("short\nshort\n", "v3-user", "alice", "--stdin")
	sb.expect(1, "", "at least 8 characters")
	cfg("", "v3-user", "alice", "--auth", "md5", "--stdin")
	sb.expect(1, "", "Unknown --auth 'md5': sha or sha256.")
	cfg("", "frob")
	sb.expect(1, "", "Unknown subcommand: 'frob'")
	// clear: no credentials, no version.
	cfg("", "clear")
	if _, err := os.Stat(sb.path("state", "snmp.yaml")); !os.IsNotExist(err) {
		t.Errorf("snmp.yaml left: %v", err)
	}
	out = cfg("", "show")
	if !strings.Contains(out, "version:    not set") || !strings.Contains(out, "community:  not set") {
		t.Errorf("after clear:\n%s", out)
	}
	cfg("", "test", "127.0.0.1")
	sb.expect(1, "", "Cannot test: SNMP is not configured ('tacctl config snmp').")
}
