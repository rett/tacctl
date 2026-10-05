package cli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// The seen cache, scans, discover, check, the seen columns and the status
// section, in-process. The journal and the auth log are made up relative
// to the real clock (a binary without test knobs has no other); the bats
// file tests/integration/device_scan.bats pins the output at a fixed time.

func journalRec(cursor string, at time.Time, msg string) string {
	b, _ := json.Marshal(map[string]string{"__CURSOR": cursor, "__REALTIME_TIMESTAMP": strconv.FormatInt(at.UnixMicro(), 10), "MESSAGE": msg})
	return string(b) + "\n"
}

func authLine(at time.Time, kind, client, nas, user string) string {
	return at.Format("2006-01-02 15:04:05") + " " + kind + " scope=dmz device=generic client=" + client + " nas=" + nas + " reason='-' user=" + user + "\n"
}

// scanSandbox is the multiscope store with both backends enabled, three
// devices pinned to the ed25519 test key, and a journal and an auth log
// that show them and two strangers.
func scanSandbox(t *testing.T) (*sandbox, func(*fake.Runner), devreg.HostKey) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\n", 0o600)
	ed := hkKey(t, "ed25519")
	keys := func(r *fake.Runner) {
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh-keyscan" }, func(c execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: keyscanOut(c.Args[len(c.Args)-1], ed)}, nil
		})
	}
	for _, d := range [][]string{
		{"core-sw1", "203.0.113.1", "cisco"}, {"edge-fw", "203.0.113.20", "other"},
		{"oob-con1", "203.0.113.9", "wti"}, {"lab-rtr2", "198.51.100.7", "juniper"},
	} {
		sb.devScan("", keys, "add", d[0], d[1], "--vendor", d[2])
		if sb.code != 0 {
			t.Fatalf("add %v: %s", d, sb.stderr())
		}
	}
	now := time.Now()
	journal := journalRec("s=1", now.Add(-2*time.Hour), "INFO: x bcrypt.go:143: accepting user [alice] from [203.0.113.1] using a bcrypt password") +
		journalRec("s=2", now.Add(-time.Hour), "ERROR: x server.go:159: closing connection, unable to read, bad secret detected for ip [203.0.113.20:51234]") +
		journalRec("s=3", now.Add(-50*time.Minute), "INFO: x bcrypt.go:143: accepting user [carol] from [203.0.113.77] using a bcrypt password") +
		journalRec("s=4", now.Add(-40*time.Minute), "ERROR: x server.go:159: closing connection, unable to read, bad secret detected for ip [192.0.2.66:4000]") +
		journalRec("s=5", now.Add(-30*time.Minute), "ERROR: x server.go:159: closing connection, unable to read, no matching prefix secret provider found")
	sb.write("radius-log/tacctl-auth.log",
		authLine(now.Add(-10*24*time.Hour), "Access-Accept", "203.0.113.9", "oob-con-01", "asmith")+
			authLine(now.Add(-3*time.Hour), "Access-Accept", "203.0.113.50", "edge-sw5", "carol"), 0o640)
	script := func(r *fake.Runner) {
		keys(r)
		r.Func(func(c execx.Cmd) bool { return c.Name == "journalctl" }, func(c execx.Cmd) (execx.Result, error) {
			if strings.Contains(strings.Join(c.Args, " "), "--after-cursor") {
				return execx.Result{}, nil
			}
			return execx.Result{Stdout: []byte(journal)}, nil
		})
	}
	return sb, script, ed
}

func TestDeviceScanDiscoverListAndStatus(t *testing.T) {
	sb, script, _ := scanSandbox(t)
	sb.devScan("", script, "stale-days", "7")
	before := sb.devices()

	out := sb.devScan("", script, "scan", "--full")
	if sb.code != 0 {
		t.Fatalf("scan: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, re := range []string{
		`(?m)^  tacacs  journal \S+ \S+ to \S+ \S+ \(5 entries\): 5 sightings of 4 addresses \(1 without an address\)$`,
		`(?m)^  radius  tacctl-auth\.log \S+ \S+ to \S+ \S+ \(2 entries\): 2 sightings of 2 addresses$`,
		`(?m)^  Host keys: 4 entries re-scanned: 4 unchanged$`,
		`(?m)^  Seen: 6 addresses, 3 registered, 3 not \(tacctl device discover\)$`,
		`(?m)^  Notices \(1\):$`,
		`(?m)^    oob-con1  name-mismatch: 203\.0\.113\.9 identifies itself as 'oob-con-01', not 'oob-con1'`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("scan output lacks %s:\n%s", re, out)
		}
	}
	if !sb.runner.Called("journalctl", "-u", "tacquito", "-o", "json", "--no-pager") {
		t.Errorf("journalctl argv %q", sb.runner.Argvs())
	}
	if sb.devices() != before {
		t.Error("a scan wrote devices.yaml")
	}
	if fi, err := os.Stat(sb.path("var-lib", "devices-seen.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("seen cache: %v %v", fi, err)
	}

	// The next scan resumes after the cursor.
	sb.devScan("", script, "scan")
	if !sb.runner.Called("journalctl", "-u", "tacquito", "-o", "json", "--no-pager", "--after-cursor", "s=5") {
		t.Errorf("resume argv %q", sb.runner.Argvs())
	}

	out = sb.dev("", "list")
	for _, re := range []string{
		`(?m)^  core-sw1 +203\.0\.113\.1 +cisco +dmz +configured +\S+ \S+ +alice +tacacs +-$`,
		`(?m)^  edge-fw +203\.0\.113\.20 +other +dmz +configured +rejected \S+ \S+ \(bad secret\) +- +tacacs +-$`,
		`(?m)^  oob-con1 +203\.0\.113\.9 +wti +dmz +configured stale +\S+ \S+ +asmith +radius +name-mismatch$`,
		`(?m)^  lab-rtr2 +198\.51\.100\.7 +juniper +- +unconfigured +never +- +- +-$`,
		`(?m)^  seen data as of \S+ \S+ \(tacctl device scan to refresh\); stale after 7 days$`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("list lacks %s:\n%s", re, out)
		}
	}
	if out = sb.dev("", "list", "--stale"); !strings.Contains(out, "oob-con1") || strings.Contains(out, "core-sw1") {
		t.Errorf("--stale:\n%s", out)
	}
	out = sb.dev("", "show", "oob-con1")
	for _, want := range []string{"Seen by:      asmith via radius", "(1 sighting)", "Identifies:   as 'oob-con-01' (NAS-Identifier)", "(stale: older than 7 days)"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	var js []map[string]any
	if err := json.Unmarshal([]byte(sb.dev("", "list", "--json")), &js); err != nil || js[0]["seen"].(map[string]any)["last_user"] != "alice" {
		t.Errorf("json: %v %v", err, js)
	}

	// Acknowledged: gone from list, notices and status; marked in show.
	sb.dev("", "notice", "oob-con1", "ack", "name-mismatch")
	if out = sb.dev("", "list"); strings.Contains(out, "name-mismatch") {
		t.Errorf("acked notice listed:\n%s", out)
	}
	if out = sb.dev("", "show", "oob-con1"); !strings.Contains(out, "name-mismatch (acknowledged): 203.0.113.9 identifies") {
		t.Errorf("show:\n%s", out)
	}
	out = plain(sb.run("", []string{"status"}))
	if !regexp.MustCompile(`(?m)^  Device notices: none$`).MatchString(out) {
		t.Errorf("status:\n%s", out)
	}
	sb.dev("", "notice", "oob-con1", "unack", "name-mismatch")
	out = plain(sb.run("", []string{"status"}))
	// The section, whole: it ends the report.
	golden := "\n  Device notices: 1 (tacctl device notices)\n" +
		"    oob-con1  name-mismatch: 203.0.113.9 identifies itself as 'oob-con-01', not 'oob-con1' (informational); " +
		"align them: 'tacctl device rename oob-con1 oob-con-01', or name the device (WTI: set the Site ID / unit name in the " +
		"/N network menu (the menu item varies by firmware)), or acknowledge it: 'tacctl device notice oob-con1 ack name-mismatch'\n\n"
	if i := strings.Index(out, "\n  Device notices:"); i < 0 || out[i:] != golden {
		t.Errorf("status section:\n%q\nwant\n%q", out[max(i, 0):], golden)
	}

	// discover: the unregistered addresses that authenticated, with the
	// add line; --all adds the ones only refused.
	out = sb.devScan("", script, "discover")
	for _, re := range []string{
		`(?m)^Unregistered addresses that authenticated \(2\)$`,
		`(?m)^  203\.0\.113\.50 +dmz +- +\S+ \S+ +\S+ \S+ +1 +carol +accept +radius +edge-sw5$`,
		`(?m)^  203\.0\.113\.77 +dmz +- +\S+ \S+ +\S+ \S+ +1 +carol +accept +tacacs +-$`,
		`(?m)^    tacctl device add edge-sw5 203\.0\.113\.50$`,
		`(?m)^    tacctl device add <name> 203\.0\.113\.77$`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("discover lacks %s:\n%s", re, out)
		}
	}
	if out = sb.devScan("", script, "discover", "--all"); !strings.Contains(out, "tacctl device add <name> 192.0.2.66") {
		t.Errorf("discover --all:\n%s", out)
	}
	if out = sb.devScan("", script, "scan", "--backend", "radius"); sb.code != 0 || strings.Contains(out, "  tacacs ") {
		t.Errorf("--backend radius: %q", out)
	}
}

func TestDeviceScanHostKeyNotices(t *testing.T) {
	sb, script, ed := scanSandbox(t)
	rsa := hkKey(t, "rsa")
	changed := func(r *fake.Runner) {
		script(r)
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh-keyscan" }, func(c execx.Cmd) (execx.Result, error) {
			switch c.Args[len(c.Args)-1] {
			case "203.0.113.1":
				return execx.Result{Stdout: keyscanOut("203.0.113.1", otherEd25519(t))}, nil
			case "203.0.113.20":
				return execx.Result{Stdout: keyscanOut("203.0.113.20", ed, rsa)}, nil
			case "203.0.113.9":
				return execx.Result{}, nil
			}
			return execx.Result{Stdout: keyscanOut("x", ed)}, nil
		})
	}
	before := sb.devices()
	out := sb.devScan("", changed, "scan")
	for _, want := range []string{
		"Host keys: 4 entries re-scanned: 1 unchanged, 1 CHANGED, 1 with a new key type, 1 no answer",
		"core-sw1  hostkey-changed: the host key of 'core-sw1' changed",
		"edge-fw  hostkey-added: 'edge-fw' offers a new host key type",
		"oob-con1  hostkey-unreachable: no host key could be read from 'oob-con1' (203.0.113.9 port 22)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan lacks %q:\n%s", want, out)
		}
	}
	if sb.devices() != before {
		t.Error("a scan changed a pin")
	}
	sb.dev("", "notice", "core-sw1", "ack", "hostkey-changed")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "cannot be acknowledged") {
		t.Errorf("ack hostkey-changed: %d %q", sb.code, sb.stderr())
	}
	// Re-pinning clears it: the notice compares with the pin of the moment.
	sb.devScan("y\n", changed, "hostkey", "core-sw1", "accept")
	if out = sb.dev("", "notices", "core-sw1"); strings.Contains(out, "hostkey-changed") {
		t.Errorf("after accept:\n%s", out)
	}
}

func TestDeviceCheck(t *testing.T) {
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
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	sb := newSandbox(t, true)
	ed := hkKey(t, "ed25519")
	sb.devScan("", scan("127.0.0.1", ed), "add", "loop", "127.0.0.1", "--port", port, "--vendor", "cisco")
	if sb.code != 0 {
		t.Fatalf("add: %s", sb.stderr())
	}
	before := sb.devices()
	out := sb.devScan("", scan("127.0.0.1", ed), "check", "loop")
	for _, want := range []string{
		"Check loop (127.0.0.1, cisco)",
		"Scope:       -", // not covered
		"Seen:        no seen data (tacctl device scan)",
		"Reachable:   open (127.0.0.1 port " + port + ")",
		"Host key:    matches the pinned keys",
		"Notices:     none",
	} {
		if !strings.Contains(strings.ReplaceAll(out, "none: no scope's prefixes cover 127.0.0.1 ('tacctl scope prefixes <scope> add <cidr>')", "-"), want) {
			t.Errorf("check lacks %q:\n%s", want, out)
		}
	}
	if sb.devices() != before {
		t.Error("check wrote devices.yaml")
	}
	// No answer: the notice, from the cache check wrote.
	_ = ln.Close()
	out = sb.devScan("", scan("127.0.0.1"), "check", "--all")
	for _, want := range []string{"Reachable:   closed (127.0.0.1 port " + port + ": connection refused)", "Host key:    no answer (pinned: ED25519 ",
		"hostkey-unreachable: no host key could be read from 'loop'"} {
		if !strings.Contains(out, want) {
			t.Errorf("check lacks %q:\n%s", want, out)
		}
	}
	sb.dev("", "check")
	sb.expect(1, "", "Usage: tacctl device check <name>|--all")
	sb.dev("", "check", "loop", "--all")
	sb.expect(1, "", "--all takes no name.")
	sb.dev("", "check", "nope")
	sb.expect(1, "", "Device 'nope' not found.")
}

func TestDeviceScanFlagsAndTier(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "scan", "--full", "--since", "7d")
	sb.expect(1, "", "Give --full or --since, not both.")
	sb.dev("", "scan", "--since", "soon")
	sb.expect(1, "", "Invalid --since 'soon'")
	sb.dev("", "scan", "--backend", "ldap")
	sb.expect(1, "", "Unknown backend 'ldap' (known: tacacs radius).")
	sb.dev("", "scan", "extra")
	sb.expect(1, "", "Usage: tacctl device scan")
	// A read-only caller may list, not scan or probe.
	sb.cfgRun("", []string{"device", "list", "--scan"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}, "SUDO_USER=carol")
	sb.expect(1, "", "--scan and --probe are for the operator tier and up.")
	// Without a seen cache and with an empty registry: '-' and no section.
	out := sb.dev("", "list")
	if !strings.Contains(out, "None. Register one") {
		t.Errorf("%s", out)
	}
	if out = plain(sb.run("", []string{"status"})); strings.Contains(out, "Device notices") {
		t.Errorf("status with no registry has a device section:\n%s", out)
	}
	// A cache that cannot be read is rebuilt by the next scan.
	sb.write("var-lib/devices-seen.json", "{broken", 0o600)
	out = sb.devScan("", func(r *fake.Runner) { r.On([]string{"journalctl"}, execx.Result{}) }, "scan")
	if sb.code != 0 || !strings.Contains(out, "The seen cache could not be read; it was rebuilt from the logs.") {
		t.Errorf("%d %q %q", sb.code, out, sb.stderr())
	}
	if _, err := devreg.LoadSeen(sb.path("var-lib", "devices-seen.json")); err != nil {
		t.Error(err)
	}
}

func TestDeviceListProbe(t *testing.T) {
	sb := newSandbox(t, true)
	ed := hkKey(t, "ed25519")
	sb.devScan("", scan("127.0.0.1", ed), "add", "loop", "127.0.0.1", "--port", "1", "--vendor", "cisco")
	devreg.ProbeDial = func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
	}
	defer func() { devreg.ProbeDial = nil }()
	out := sb.dev("", "list", "--probe")
	if !regexp.MustCompile(`(?m)^  loop +127\.0\.0\.1 .* +- +- +- +timeout +-$`).MatchString(out) || !strings.Contains(out, "REACH: a TCP connect") {
		t.Errorf("%s", out)
	}
}
