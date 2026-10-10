package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh/fakedev"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/testpty"
)

// The device configuration verbs end to end, in-process, against the fake
// device of internal/devssh/fakedev: real ssh and NETCONF on loopback, the
// sandbox's registry and store. The pieces they are built from are tested in
// their packages (devconf, devconf/batch, devssh).

const (
	junosReadCmd = "show configuration | display inheritance no-comments | display set"
	testPassword = "fake-pass-9d41"
)

// staticPasswords is a password source of a test: the password, and what the
// pull told it.
type staticPasswords struct {
	pw       string
	err      error
	accepted int
	rejected int
	asked    int
}

func (s *staticPasswords) Password(context.Context, string) ([]byte, error) {
	s.asked++
	if s.err != nil {
		return nil, s.err
	}
	return []byte(s.pw), nil
}
func (s *staticPasswords) Accepted() { s.accepted++ }
func (s *staticPasswords) Rejected() { s.rejected++ }

// pullBox is a sandbox with a fake device, a login, and registered devices.
type pullBox struct {
	t   *testing.T
	sb  *sandbox
	dir string
	srv *fakedev.Server
	pw  *staticPasswords
}

// newPullBox starts a fake device that accepts alice with testPassword, and
// routes every device dial to it. alice is a superuser of prod and lab in
// the store.
func newPullBox(t *testing.T, opts ...fakedev.Option) *pullBox {
	t.Helper()
	dir := t.TempDir()
	opts = append([]fakedev.Option{fakedev.WithCredentials("alice", testPassword)}, opts...)
	srv := fakedev.New(dir, opts...)
	t.Cleanup(srv.Stop)
	addr := srv.Addr()
	prevDial, prevPW := deviceDialOverride, newDevicePasswords
	deviceDialOverride = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	b := &pullBox{t: t, sb: newSandbox(t, true), dir: dir, srv: srv, pw: &staticPasswords{pw: testPassword}}
	newDevicePasswords = func(*invocation) devicePasswords { return b.pw }
	t.Cleanup(func() { deviceDialOverride, newDevicePasswords = prevDial, prevPW })
	return b
}

// devices writes the registry: name, address and vendor of each, pinned to
// the fake device's key.
func (b *pullBox) devices(entries ...[3]string) {
	b.t.Helper()
	var sb strings.Builder
	sb.WriteString("version: 1\nsettings:\n  stale_days: 30\ndevices:\n")
	for _, e := range entries {
		sb.WriteString("  " + e[0] + ":\n    address: " + e[1] + "\n    vendor: " + e[2] + "\n")
		if e[2] != "pinless" {
			sb.WriteString("    host_keys:\n    - " + b.srv.HostKey() + "\n")
		}
	}
	b.sb.write("state/devices.yaml", strings.ReplaceAll(sb.String(), "pinless", "cisco"), 0o600)
}

// run runs tacctl as alice (the store's superuser of prod and lab).
func (b *pullBox) run(args ...string) string {
	b.t.Helper()
	return plain(b.sb.cfgRun("", args, route, "SUDO_USER=alice"))
}

// invoke is an invocation on the sandbox, for what a verb would compute.
func (b *pullBox) invoke() *invocation {
	b.t.Helper()
	r := &fake.Runner{}
	r.On([]string{"logger"}, execx.Result{})
	route(r)
	a := app.New(nil, paths.NewEnv(append(append([]string(nil), b.sb.env...), "SUDO_USER=alice")), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, r)
	return &invocation{ctx: context.Background(), app: a}
}

// expected is the configuration text of the named registered device as
// tacctl renders it today: what a device that agrees with tacctl runs.
func (b *pullBox) expected(name string) string {
	b.t.Helper()
	inv := b.invoke()
	_, res, err := inv.deviceLoad()
	if err != nil {
		b.t.Fatal(err)
	}
	e, ok := res.Lookup(name, devreg.ScopeFilter{})
	if !ok {
		b.t.Fatalf("no device %s", name)
	}
	r := inv.newManagedRender(managedOptions{}, false)
	r.prepare([]devreg.Entry{e})
	secs, err := r.Expected(e)
	if err != nil {
		b.t.Fatal(err)
	}
	var out []string
	for _, s := range secs {
		out = append(out, s.Lines...)
	}
	text := strings.Join(out, "\n") + "\n"
	if e.Vendor == "cisco" {
		text = "Building configuration...\n\nCurrent configuration : 2000 bytes\n!\n" + text + "end\n"
	}
	return text
}

// serve makes the fake device answer the read command of vendor with text.
func (b *pullBox) serve(vendor, text string) {
	b.t.Helper()
	cmd := junosReadCmd
	if vendor == "cisco" {
		cmd = "show running-config"
	}
	if err := os.WriteFile(filepath.Join(b.dir, cmd+".out"), []byte(text), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

func (b *pullBox) records() *devconf.Records {
	b.t.Helper()
	r, err := devconf.Store{Records: filepath.Join(b.sb.dir, "var-lib", "devices-config.json"),
		Dir: filepath.Join(b.sb.dir, "var-lib", "device-config")}.Load()
	if err != nil {
		b.t.Fatal(err)
	}
	return r
}

// noSecrets fails when text holds any of the values a test fed the device.
func noSecrets(t *testing.T, what, text string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(text, s) {
			t.Errorf("%s holds the secret %q:\n%s", what, s, text)
		}
	}
}

func TestPullJunosOverNetconfThenListShowDiff(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))

	out := b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"lab-j", "ok via netconf", "1 ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if b.pw.accepted != 1 || b.pw.rejected != 0 || b.pw.asked != 1 {
		t.Errorf("password source: asked %d accepted %d rejected %d", b.pw.asked, b.pw.accepted, b.pw.rejected)
	}
	rec, ok := b.records().Of("lab-j")
	if !ok || rec.Result != "ok" || rec.Transport != "netconf" || rec.Netconf != "hello ok" || rec.By != "alice" ||
		rec.Address != "192.168.1.20" || rec.Pulled.IsZero() {
		t.Fatalf("record %+v", rec)
	}
	for _, n := range devconf.SectionNames {
		if s, ok := rec.Sections[n]; !ok || s.State == "differs" || s.State == "missing" {
			t.Errorf("section %s: %+v", n, s)
		}
	}
	// The sections file is 0600 and the directory 0700.
	for p, want := range map[string]os.FileMode{"var-lib/device-config/lab-j.yaml": 0o600, "var-lib/devices-config.json": 0o600,
		"var-lib/device-config": 0o700} {
		st, err := os.Stat(b.sb.path(p))
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	// The audit line names the user, the device, the transport and the result.
	var audit string
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" && strings.Contains(strings.Join(c.Args, " "), "device config pull") {
			audit = strings.Join(c.Args, " ")
		}
	}
	if !strings.Contains(audit, "auth.info") || !strings.Contains(audit, "user=alice device=lab-j transport=netconf result=ok duration=") {
		t.Errorf("audit line %q", audit)
	}
	noSecrets(t, "the audit line", audit, testPassword)
	if b.sb.runner.ArgvContains(testPassword) {
		t.Error("the password reached an argv")
	}

	// device list and show.
	list := b.run("device", "list")
	if !strings.Contains(list, "CONFIG") {
		t.Fatalf("no CONFIG column:\n%s", list)
	}
	for _, l := range strings.Split(list, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "lab-j") && !slicesContain(strings.Fields(l), "ok") {
			t.Errorf("lab-j's row has no ok: %q", l)
		}
	}
	show := b.run("device", "show", "lab-j")
	if !strings.Contains(show, "Configuration: pulled ") || !strings.Contains(show, " by alice over netconf (hello ok), ok; sections: aaa ") {
		t.Errorf("show:\n%s", show)
	}
	cfgList := b.run("device", "config", "list")
	if !strings.Contains(cfgList, "lab-j") || !strings.Contains(cfgList, "netconf") || !strings.Contains(cfgList, "hello ok") {
		t.Errorf("config list:\n%s", cfgList)
	}
	if got := b.run("device", "config", "list", "--stale"); !strings.Contains(got, "None: every device") {
		t.Errorf("--stale:\n%s", got)
	}
	diff := b.run("device", "config", "diff", "lab-j")
	if b.sb.code != 0 || !strings.Contains(diff, "Device lab-j") || !strings.Contains(diff, "aaa") || strings.Contains(diff, "differs") {
		t.Errorf("diff: %d\n%s", b.sb.code, diff)
	}
	if chk := b.run("device", "check", "lab-j"); !strings.Contains(chk, "NETCONF:") || !strings.Contains(chk, "hello ok") {
		t.Errorf("check:\n%s", chk)
	}
}

func slicesContain(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestPullCiscoOverSSH(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"})
	b.serve("cisco", b.expected("lab-c"))
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "ok via ssh") {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	rec, _ := b.records().Of("lab-c")
	if rec == nil || rec.Transport != "ssh" || rec.Result != "ok" || rec.Netconf != "" {
		t.Errorf("record %+v", rec)
	}
	// --transport netconf is not read for Cisco: refused before any login,
	// and the record of the good pull is as it was.
	b.run("device", "config", "pull", "lab-c", "--transport", "netconf")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "NETCONF is not read for Cisco devices") {
		t.Errorf("netconf on cisco: %d %q", b.sb.code, b.sb.stderr())
	}
	if b.srv.Logins() != 1 {
		t.Errorf("logins %d", b.srv.Logins())
	}
	if rec2, _ := b.records().Of("lab-c"); rec2 == nil || rec2.Result != "ok" || !rec2.Pulled.Equal(rec.Pulled) {
		t.Errorf("record after the refusal %+v", rec2)
	}
}

// A Cisco device named with --transport netconf is refused at once (no
// password asked, no login, no record, so it stays 'never' and stale); in a
// run with a Junos device it fails on its own line and the Junos device is
// read.
func TestPullNetconfIsRefusedForCiscoBeforeAnyLogin(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"}, [3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("cisco", b.expected("lab-c"))
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "config", "pull", "lab-c", "--transport", "netconf")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "NETCONF is not read for Cisco devices") ||
		!strings.Contains(b.sb.stderr(), "Nothing was tried.") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if b.pw.asked != 0 || b.srv.Logins() != 0 || b.srv.Attempts() != 0 {
		t.Errorf("a password was asked (%d) or a device dialled (%d logins)", b.pw.asked, b.srv.Logins())
	}
	if _, ok := b.records().Of("lab-c"); ok {
		t.Error("the refusal left a record")
	}
	for _, args := range [][]string{{"device", "config", "diff", "lab-c", "--pull", "--transport", "netconf"}} {
		b.run(args...)
		if b.sb.code != 2 || b.srv.Logins() != 0 || b.pw.asked != 0 {
			t.Errorf("%v: exit %d, %d logins, %d asked", args, b.sb.code, b.srv.Logins(), b.pw.asked)
		}
	}
	// Mixed: the Cisco device fails on its line (exit 1), the other is read.
	out := b.run("device", "config", "pull", "--all", "--transport", "netconf", "--concurrency", "1")
	if b.sb.code != 1 || !strings.Contains(out, "lab-c  failed: NETCONF is not read for Cisco devices") ||
		!strings.Contains(out, "lab-j  ok via netconf") {
		t.Errorf("mixed: exit %d\n%s", b.sb.code, out)
	}
	if b.srv.Logins() != 1 {
		t.Errorf("logins %d", b.srv.Logins())
	}
	if _, ok := b.records().Of("lab-c"); ok {
		t.Error("the failed line of a Cisco device left a record")
	}
	// It is never pulled, so it is listed as stale and shown as never.
	if got := b.run("device", "config", "list", "--stale"); !strings.Contains(got, "lab-c") || !strings.Contains(got, "never") {
		t.Errorf("list --stale:\n%s", got)
	}
}

func TestPullDifferencesAndNoSecretValues(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	text := b.expected("lab-j")
	// A statement missing, a stray server with its own secret, and a stray
	// community: the secret values must reach no output and no file.
	lines := strings.Split(strings.TrimSpace(text), "\n")
	var kept []string
	dropped := ""
	for _, l := range lines {
		if dropped == "" && strings.HasPrefix(l, "set system authentication-order") {
			dropped = l
			continue
		}
		kept = append(kept, l)
	}
	if dropped == "" {
		t.Fatalf("no authentication-order statement in:\n%s", text)
	}
	const strayKey, strayCommunity = "$9$STRAYKEY-SECRET-VALUE", "stray-community-shhh"
	kept = append(kept,
		`set system tacplus-server 192.0.2.99 secret "`+strayKey+`"`,
		`set snmp community `+strayCommunity+` authorization read-only`)
	b.serve("juniper", strings.Join(kept, "\n")+"\n")

	out := b.run("device", "config", "pull", "lab-j", "--diff")
	if b.sb.code != 0 {
		t.Fatalf("a difference is not a failure: exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"ok, differs in", "1 differ", "- " + dropped, "+ set system tacplus-server 192.0.2.99"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	noSecrets(t, "the pull output", out, strayKey, strayCommunity, testPassword)
	noSecrets(t, "stderr", b.sb.stderr(), strayKey, strayCommunity, testPassword)
	for _, f := range []string{"var-lib/devices-config.json", "var-lib/device-config/lab-j.yaml"} {
		noSecrets(t, f, b.sb.read(f), strayKey, strayCommunity, testPassword)
	}
	// diff, from the stored sections; --json; --exit-code.
	diff := b.run("device", "config", "diff", "lab-j")
	if b.sb.code != 0 || !strings.Contains(diff, "- "+dropped) || !strings.Contains(diff, "1 differ") {
		t.Errorf("diff: %d\n%s", b.sb.code, diff)
	}
	noSecrets(t, "the diff", diff, strayKey, strayCommunity)
	b.run("device", "config", "diff", "lab-j", "--exit-code")
	if b.sb.code != 2 {
		t.Errorf("--exit-code: %d", b.sb.code)
	}
	js := b.run("device", "config", "diff", "lab-j", "--json", "--section", "aaa")
	noSecrets(t, "the diff json", js, strayKey, strayCommunity)
	var docs []diffDeviceJSON
	if err := json.Unmarshal([]byte(js), &docs); err != nil || len(docs) != 1 || docs[0].Name != "lab-j" || docs[0].Status != "differs" ||
		len(docs[0].Sections) != 1 || docs[0].Sections[0].Name != "aaa" {
		t.Errorf("diff json: %v\n%s", err, js)
	}
	// The same device is stale, and listed so.
	for _, flag := range []string{"--stale", "--differs"} {
		if got := b.run("device", "config", "list", flag); !strings.Contains(got, "lab-j") || !strings.Contains(got, "differs") {
			t.Errorf("list %s:\n%s", flag, got)
		}
	}
	for _, flag := range []string{"--never", "--failed"} {
		if got := b.run("device", "config", "list", flag); strings.Contains(got, "lab-j") {
			t.Errorf("list %s has lab-j:\n%s", flag, got)
		}
	}
}

// A change on the tacctl side makes a device stale without a new pull.
func TestListIsComputedAgainstTodaysRendering(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "config", "pull", "lab-j")
	if got := b.run("device", "config", "list", "--stale"); strings.Contains(got, "lab-j") {
		t.Fatalf("stale before the change:\n%s", got)
	}
	b.sb.cfgRun("", []string{"config", "mgmt-acl", "add", "198.51.100.0/24"}, route, "SUDO_USER=alice")
	if b.sb.code != 0 {
		t.Fatalf("mgmt-acl add: %d %q", b.sb.code, b.sb.stderr())
	}
	got := b.run("device", "config", "list", "--stale")
	if !strings.Contains(got, "lab-j") || !strings.Contains(got, "differs") || !strings.Contains(got, "mgmt-acl") {
		t.Errorf("stale after the change:\n%s", got)
	}
	// 'device list' reads the record only: it still says ok.
	for _, l := range strings.Split(b.run("device", "list"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "lab-j") && !slicesContain(strings.Fields(l), "ok") {
			t.Errorf("device list row %q", l)
		}
	}
	// --pull refreshes.
	diff := b.run("device", "config", "diff", "lab-j", "--pull", "--exit-code")
	if b.sb.code != 2 || !strings.Contains(diff, "mgmt-acl") {
		t.Errorf("diff --pull: %d\n%s", b.sb.code, diff)
	}
}

func TestPullWrongPasswordStopsTheBatch(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-a", "192.168.1.21", "juniper"}, [3]string{"lab-b", "192.168.1.22", "juniper"},
		[3]string{"lab-c", "192.168.1.23", "juniper"})
	b.serve("juniper", "set system host-name x\n")
	b.pw.pw = "not-the-password"
	out := b.run("device", "config", "pull", "--all", "--concurrency", "1")
	if b.sb.code != 1 {
		t.Errorf("exit %d", b.sb.code)
	}
	if !strings.Contains(out, "failed: authentication failed") || !strings.Contains(out, "stopped at the first authentication failure: 2 not started") {
		t.Errorf("output:\n%s", out)
	}
	if b.srv.Attempts() != 1 {
		t.Errorf("the wrong password was presented %d times", b.srv.Attempts())
	}
	if b.pw.rejected != 1 || b.pw.accepted != 0 {
		t.Errorf("rejected %d accepted %d", b.pw.rejected, b.pw.accepted)
	}
	noSecrets(t, "the output", out+b.sb.stderr(), "not-the-password", testPassword)
	rec, _ := b.records().Of("lab-a")
	if rec == nil || rec.Result != "auth-failed" {
		t.Errorf("record %+v", rec)
	}
	if _, ok := b.records().Of("lab-b"); ok {
		t.Error("a device that was not started has a record")
	}
}

func TestPullRefusals(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"nopin", "192.168.1.21", "pinless"})
	// An unpinned device (devices() leaves "pinless" without a key) is refused
	// before any connection, with the hint.
	out := b.run("device", "config", "pull", "nopin")
	if b.sb.code != 1 || !strings.Contains(out, "failed: no host key is pinned for the device") ||
		!strings.Contains(out, "tacctl device hostkey nopin accept") {
		t.Errorf("unpinned: %d\n%s", b.sb.code, out)
	}
	if b.srv.Logins() != 0 || b.srv.Attempts() != 0 {
		t.Errorf("a device without a pinned key was dialled: %d logins", b.srv.Logins())
	}
	for _, c := range []struct {
		env  []string
		args []string
		err  string
		code int
	}{
		{nil, []string{"device", "config", "pull", "lab-j"}, "logs in to the devices as the user who invoked it", 1},
		{[]string{"SUDO_USER=root"}, []string{"device", "config", "pull", "lab-j"}, "logs in to the devices as the user who invoked it", 1},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull"}, "Name the devices to pull, or select them with --all", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "lab-j", "--all"}, "not both", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--stale"}, "--all is every device", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "nope"}, "Device 'nope' not found.", 1},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--transport", "carrier-pigeon"}, "--transport takes auto, netconf or ssh", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--concurrency", "0"}, "--concurrency takes a number", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--concurrency", "9"}, "--concurrency 9 is above device.config.max_concurrency (8)", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--timeout", "5"}, "--timeout takes seconds per device, 10 to 600", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--max-failures", "0"}, "--max-failures takes", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--vendor", "other"}, "--vendor takes cisco, juniper or wti", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--bogus"}, "Unknown option: '--bogus'", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "pull", "--all", "--server", "not a host!"}, "--server takes the IPv4 address", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "diff", "--all", "--pull", "--source", "10.0.0.0/8"}, "--source takes the IPv4 address", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "diff", "lab-j", "--transport", "ssh"}, "--transport is for --pull", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "diff", "lab-j", "--section", "nope"}, "--section takes sections of", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "list", "--transport", "x"}, "--transport takes netconf, ssh or none", 2},
		{[]string{"SUDO_USER=alice"}, []string{"device", "config", "forget"}, "Name the devices to forget, or give --all.", 2},
	} {
		b.sb.cfgRun("", c.args, route, c.env...)
		if b.sb.code != c.code || !strings.Contains(b.sb.stderr()+b.sb.out.String(), c.err) {
			t.Errorf("%v %v: exit %d, stderr %q stdout %q (want %d, %q)", c.env, c.args, b.sb.code, b.sb.stderr(), b.sb.out.String(), c.code, c.err)
		}
	}
	if b.srv.Logins() != 0 {
		t.Errorf("a refusal dialled the device: %d logins", b.srv.Logins())
	}
}

func TestPullNeedsAPassword(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.pw.err = errNoPassword
	b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "a password is needed and no terminal or cached password is available") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if b.srv.Logins() != 0 {
		t.Error("dialled without a password")
	}
	if _, ok := b.records().Of("lab-j"); ok {
		t.Error("a record without an attempt")
	}
}

func TestPullHostKeyMismatchRaisesTheNotice(t *testing.T) {
	b := newPullBox(t, fakedev.WithRandomHostKey())
	// The registry pins the default key; the device offers another.
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	f, _ := os.ReadFile(b.sb.path("state", "devices.yaml"))
	b.sb.write("state/devices.yaml", strings.ReplaceAll(string(f), b.srv.HostKey(), fakedev.HostKey()), 0o600)
	out := b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 1 || !strings.Contains(out, "failed: the device offered a host key") || !strings.Contains(out, "not pinned") {
		t.Errorf("exit %d\n%s", b.sb.code, out)
	}
	rec, _ := b.records().Of("lab-j")
	if rec == nil || rec.Result != "host-key-mismatch" {
		t.Errorf("record %+v", rec)
	}
	if n := b.run("device", "show", "lab-j"); !strings.Contains(n, "hostkey-changed") {
		t.Errorf("no hostkey notice:\n%s", n)
	}
	if b.srv.Attempts() != 0 {
		t.Error("a password was sent to a device whose key is not the pinned one")
	}
	if b.pw.rejected != 0 {
		t.Error("a host key mismatch is not a rejected password")
	}
}

func TestPullWTIAndSelectorsSkipWhatIsNotRead(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"pdu1", "192.168.1.40", "wti"})
	b.serve("juniper", b.expected("lab-j"))
	out := b.run("device", "config", "pull", "--all")
	if b.sb.code != 0 || !strings.Contains(out, "lab-j") || strings.Contains(out, "pdu1  ") || !strings.Contains(out, "skipped 1 (pdu1)") {
		t.Errorf("--all: %d\n%s", b.sb.code, out)
	}
	// Named, the unit is recorded as unsupported and the run is not ok.
	out = b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 1 || !strings.Contains(out, "WTI units are not read in this release") {
		t.Errorf("named wti: %d\n%s", b.sb.code, out)
	}
	rec, _ := b.records().Of("pdu1")
	if rec == nil || rec.Result != "unsupported" {
		t.Errorf("record %+v", rec)
	}
	// 'device list' shows '-' for it; show says why.
	for _, l := range strings.Split(b.run("device", "list"), "\n") {
		f := strings.Fields(l)
		if len(f) > 3 && f[0] == "pdu1" && !slicesContain(f, "-") {
			t.Errorf("row %q", l)
		}
	}
	if show := b.run("device", "show", "pdu1"); !strings.Contains(show, "Configuration: not read (WTI units are not read") {
		t.Errorf("show:\n%s", show)
	}
	// The WTI-only selection asked for no password.
	b.pw.asked = 0
	b.run("device", "config", "pull", "pdu1")
	if b.pw.asked != 0 {
		t.Errorf("asked for a password for a WTI unit")
	}
}

func TestPullJSONLines(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-c", "192.168.1.30", "cisco"})
	b.serve("juniper", b.expected("lab-j")+"set system tacplus-server 192.0.2.99 secret \"$9$JSONSTRAYVALUE\"\n")
	b.serve("cisco", b.expected("lab-c"))
	out := b.run("device", "config", "pull", "--all", "--json", "--concurrency", "1")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	noSecrets(t, "the json", out, "JSONSTRAYVALUE", testPassword)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines:\n%s", len(lines), out)
	}
	seen := map[string]pullJSON{}
	for _, l := range lines[:2] {
		var j pullJSON
		if err := json.Unmarshal([]byte(l), &j); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		seen[j.Name] = j
	}
	if j := seen["lab-j"]; j.Status != "ok" || j.Transport != "netconf" || j.Netconf != "hello ok" || len(j.DiffersIn) == 0 ||
		j.Result != "ok" || j.Vendor != "juniper" || j.Scope != "lab" {
		t.Errorf("lab-j %+v", j)
	}
	if j := seen["lab-c"]; j.Status != "ok" || j.Transport != "ssh" {
		t.Errorf("lab-c %+v", j)
	}
	var sum struct {
		Summary map[string]any `json:"summary"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &sum); err != nil || sum.Summary["differ"] != float64(1) || sum.Summary["exit"] != float64(0) ||
		sum.Summary["ok"] != float64(1) {
		t.Errorf("summary %q: %v", lines[2], err)
	}
}

// lockedBuf is an output the test reads while the command writes it.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// start runs tacctl as alice in the background and returns what it prints
// and the channel its exit status arrives on, so a test can watch the run.
func (b *pullBox) start(out *lockedBuf, args ...string) chan int {
	b.t.Helper()
	r := &fake.Runner{}
	r.On([]string{"systemctl"}, execx.Result{})
	r.On([]string{"logger"}, execx.Result{})
	r.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	fakePasswd(r)
	route(r)
	a := app.New(args, paths.NewEnv(append(append([]string(nil), b.sb.env...), "SUDO_USER=alice")), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: out, Stderr: &bytes.Buffer{}}, r)
	a.SNMP = b.sb.snmp
	a.Resolve = b.sb.resolve
	a.Paths.ConsoleCommand = b.sb.consoleCommand()
	code := make(chan int, 1)
	go func() {
		code <- exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.0-test", Commit: "c", Date: "d"}), a.Out)
	}()
	return code
}

// waitUntil polls cond until it holds, failing the test at the deadline: a
// state the test waits for, never a fixed pause.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// never fails when cond holds at any poll of the grace period: for a state
// that must not come, which can only be shown for a bounded time.
func never(t *testing.T, what string, grace time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(grace)
	for time.Now().Before(end) {
		if cond() {
			t.Fatalf("%s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// served is how often the fake device served cmd so far.
func (b *pullBox) served(cmd string) int {
	n := 0
	for _, c := range b.srv.Commands() {
		if c == cmd {
			n++
		}
	}
	return n
}

// The two stages of Ctrl-C, on the interrupt seam (no signal reaches the
// process): the first stops starting devices and lets the running one go
// on, the second cuts it off, and the run ends 130.
func TestPullInterruptStagesExit130(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-a", "192.168.1.20", "juniper"}, [3]string{"lab-b", "192.168.1.21", "juniper"})
	// The read never answers: lab-a stays running until it is cut off.
	if err := os.WriteFile(filepath.Join(b.dir, junosReadCmd+".hang"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan struct{}) // unbuffered: a send returns when the runner took it
	prev := interruptSource
	interruptSource = func() <-chan struct{} { return ch }
	t.Cleanup(func() { interruptSource = prev })

	out := &lockedBuf{}
	code := b.start(out, "device", "config", "pull", "--all", "--concurrency", "1", "--transport", "ssh")
	waitUntil(t, "the device to have the read command", func() bool { return b.served(junosReadCmd) == 1 })
	ch <- struct{}{} // the first Ctrl-C
	waitUntil(t, "the second device to be reported not started", func() bool { return strings.Contains(out.String(), "lab-b  not started") })
	// The running device is not cut off by the first: it is still there.
	never(t, "the first Ctrl-C ended the running device or the run", 300*time.Millisecond, func() bool {
		return len(code) > 0 || strings.Contains(out.String(), "lab-a  interrupted")
	})
	ch <- struct{}{} // the second
	var status int
	select {
	case status = <-code:
	case <-time.After(15 * time.Second):
		t.Fatal("the run did not end after the second Ctrl-C")
	}
	got := out.String()
	if status != 130 || !strings.Contains(got, "lab-a  interrupted") || !strings.Contains(got, "interrupted: 1 not started") {
		t.Errorf("exit %d\n%s", status, got)
	}
	if b.srv.Logins() != 1 {
		t.Errorf("the second device was started: %d logins", b.srv.Logins())
	}
	rec, _ := b.records().Of("lab-a")
	if rec == nil || rec.Result != "interrupted" {
		t.Errorf("record %+v", rec)
	}
	if _, ok := b.records().Of("lab-b"); ok {
		t.Error("a device that was not started has a record")
	}
}

// The same with real SIGINTs, which reach the runner through its signal
// handler: each is sent when the state it acts on has been seen, the second
// only after the first has been handled.
func TestPullInterruptBySignal(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-a", "192.168.1.20", "juniper"}, [3]string{"lab-b", "192.168.1.21", "juniper"})
	if err := os.WriteFile(filepath.Join(b.dir, junosReadCmd+".hang"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out := &lockedBuf{}
	code := b.start(out, "device", "config", "pull", "--all", "--concurrency", "1", "--transport", "ssh")
	// The device has the read: the runner (and its handler) are in place.
	waitUntil(t, "the device to have the read command", func() bool { return b.served(junosReadCmd) == 1 })
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the second device to be reported not started", func() bool { return strings.Contains(out.String(), "lab-b  not started") })
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-code:
		if status != 130 {
			t.Errorf("exit %d\n%s", status, out.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run did not end after the second SIGINT")
	}
}

// 'diff --pull' ends with the pull's status: a device whose pull failed is a
// failure even when the last good pull is shown for it, and an interrupt is
// 130; the diffs are printed all the same.
func TestDiffPullExitStatusFollowsThePull(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-a", "192.168.1.20", "juniper"}, [3]string{"lab-b", "192.168.1.21", "juniper"})
	b.serve("juniper", b.expected("lab-a"))
	b.run("device", "config", "pull", "--all")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	// A wrong password: the first device is auth-failed, the second never
	// started; the stored diffs of both are printed and the run failed.
	b.pw.pw = "not-the-password-4"
	out := b.run("device", "config", "diff", "--all", "--pull", "--concurrency", "1", "--exit-code")
	if b.sb.code != 1 {
		t.Errorf("wrong password: exit %d\n%s", b.sb.code, out)
	}
	for _, want := range []string{"lab-a  failed: authentication failed", "lab-b  not started", "the pull failed (authentication failed); this is the last good pull",
		"  aaa         ok", "2 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	js := b.run("device", "config", "diff", "--all", "--pull", "--concurrency", "1", "--json")
	var docs []diffDeviceJSON
	if err := json.Unmarshal([]byte(js), &docs); err != nil || len(docs) != 2 || docs[0].Status != "failed" || docs[1].Status != "failed" ||
		len(docs[0].Sections) == 0 || !strings.Contains(docs[0].Reason, "last good pull") {
		t.Errorf("json: %v\n%s", err, js)
	}
	if b.sb.code != 1 {
		t.Errorf("json: exit %d", b.sb.code)
	}
	noSecrets(t, "the output", out+js, "not-the-password-4")

	// Interrupted: 130, whatever the stored diffs say. The read never answers;
	// both Ctrl-Cs are sent once the device has it, the second after the
	// runner took the first.
	b.pw.pw = testPassword
	if err := os.WriteFile(filepath.Join(b.dir, junosReadCmd+".hang"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan struct{})
	prev := interruptSource
	interruptSource = func() <-chan struct{} { return ch }
	t.Cleanup(func() { interruptSource = prev })
	before := b.served(junosReadCmd)
	out2 := &lockedBuf{}
	code := b.start(out2, "device", "config", "diff", "lab-a", "--pull", "--transport", "ssh")
	waitUntil(t, "the device to have the read command", func() bool { return b.served(junosReadCmd) > before })
	ch <- struct{}{}
	ch <- struct{}{}
	select {
	case status := <-code:
		if status != 130 {
			t.Errorf("interrupted: exit %d\n%s", status, out2.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run did not end")
	}
}

func TestForgetAndCarry(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-k", "192.168.1.21", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "config", "pull", "--all")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	// A rename carries the record, a removal drops it.
	b.run("device", "rename", "lab-k", "lab-kk")
	recs := b.records()
	if _, ok := recs.Of("lab-kk"); !ok {
		t.Error("the record did not follow the rename")
	}
	if _, ok := recs.Of("lab-k"); ok {
		t.Error("the old name still has a record")
	}
	if _, err := os.Stat(b.sb.path("var-lib", "device-config", "lab-kk.yaml")); err != nil {
		t.Errorf("sections file: %v", err)
	}
	b.run("device", "remove", "lab-kk", "-y")
	if _, ok := b.records().Of("lab-kk"); ok {
		t.Error("the record survived the removal")
	}
	// forget.
	out := b.run("device", "config", "forget", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "Forgot the configuration record of 'lab-j'.") {
		t.Errorf("forget: %d %q", b.sb.code, out)
	}
	if _, ok := b.records().Of("lab-j"); ok {
		t.Error("record survived forget")
	}
	if _, err := os.Stat(b.sb.path("var-lib", "device-config", "lab-j.yaml")); !os.IsNotExist(err) {
		t.Errorf("sections file: %v", err)
	}
	if out := b.run("device", "config", "forget", "lab-j"); !strings.Contains(out, "No configuration record for 'lab-j'.") {
		t.Errorf("forget twice: %q", out)
	}
	b.run("device", "config", "pull", "lab-j")
	if out := b.run("device", "config", "forget", "--all"); b.sb.code != 0 || !strings.Contains(out, "Forgot the configuration records of 1 device.") {
		t.Errorf("forget --all: %d %q", b.sb.code, out)
	}
	if got := b.run("device", "config", "list"); !strings.Contains(got, "never") {
		t.Errorf("list after forget:\n%s", got)
	}
}

// A lower tier gets what its tier says and no more: the operator lists, the
// engineer pulls and diffs the devices of their own scopes, forget is the
// superuser's.
func TestDeviceConfigTiers(t *testing.T) {
	b := newPullBox(t)
	// bob is an engineer of lab (tacctl.yaml says the operator group is one);
	// his device login is bob's.
	b.srv.Stop()
	srv := fakedev.New(b.dir, fakedev.WithCredentials("bob", testPassword))
	t.Cleanup(srv.Stop)
	addr := srv.Addr()
	deviceDialOverride = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	b.srv = srv
	b.sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"prod-j", "10.99.0.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	asBob := func(args ...string) string {
		return plain(b.sb.cfgRun("", args, func(r *fake.Runner) {
			route(r)
			r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
		}, "SUDO_USER=bob"))
	}
	out := asBob("device", "config", "pull", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "lab-j") || !strings.Contains(out, "ok via netconf") {
		t.Fatalf("engineer pull: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	// The scope's secret read is logged for the engineer, never its value.
	var logged bool
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" && strings.Contains(strings.Join(c.Args, " "), "secret-read kind=scope name=lab by=bob") {
			logged = true
		}
	}
	if !logged {
		t.Error("no secret-read line for the engineer's pull")
	}
	asBob("device", "config", "pull", "prod-j")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Device 'prod-j' not found.") {
		t.Errorf("another scope's device: %d %q", b.sb.code, b.sb.stderr())
	}
	if out := asBob("device", "config", "pull", "--all"); b.sb.code != 0 || strings.Contains(out, "prod-j") {
		t.Errorf("--all is all of mine: %d\n%s", b.sb.code, out)
	}
	if out := asBob("device", "config", "list"); b.sb.code != 0 || !strings.Contains(out, "lab-j") || strings.Contains(out, "prod-j") {
		t.Errorf("engineer list: %d\n%s", b.sb.code, out)
	}
	asBob("device", "config", "forget", "lab-j")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device config forget' is not permitted for the engineer tier.") {
		t.Errorf("engineer forget: %d %q", b.sb.code, b.sb.stderr())
	}

	// An operator may list, and nothing else of it.
	b.sb.write("state/tacctl.yaml", "{}\n", 0o600)
	asOp := func(args ...string) string { return b.sb.asUser("bob", "tac-operator", append([]string{}, args...)...) }
	if out := asOp("device", "config", "list"); b.sb.code != 0 || !strings.Contains(out, "lab-j") {
		t.Errorf("operator list: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	for _, sub := range []string{"show", "pull", "diff", "forget"} {
		asOp("device", "config", sub, "lab-j")
		if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device config "+sub+"' is not permitted for the operator tier.") {
			t.Errorf("operator %s: %d %q", sub, b.sb.code, b.sb.stderr())
		}
	}
	// Refused verbs logged a tier denial.
	var denied bool
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" && strings.Contains(strings.Join(c.Args, " "), "tier DENY user=bob tier=operator cmd=device config forget") {
			denied = true
		}
	}
	if !denied {
		t.Error("the operator's refusal was not logged as a tier denial")
	}
	// A read-only user is stopped by the gate.
	b.sb.asUser("carol", "tac-readonly", "device", "config", "list")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device config' is not permitted for the readonly tier.") {
		t.Errorf("readonly: %d %q", b.sb.code, b.sb.stderr())
	}
}

func TestConfigDevicesSettings(t *testing.T) {
	sb := newSandbox(t, true)
	out := plain(sb.cfgRun("", []string{"config", "devices"}, nil))
	for _, w := range []string{"max-concurrency: 8   (default;", "transport:       auto   (default;", "timeout:         90 s   (default;"} {
		if sb.code != 0 || !strings.Contains(out, w) {
			t.Errorf("show lacks %q: %d\n%s", w, sb.code, out)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"max-concurrency", "16"}, "The most devices read at once set to 16."},
		{[]string{"transport", "ssh"}, "The default transport set to ssh."},
		{[]string{"timeout", "120"}, "The time one device may take set to 120 s."},
	} {
		out := plain(sb.cfgRun("", append([]string{"config", "devices"}, c.args...), nil))
		if sb.code != 0 || !strings.Contains(out, c.want) {
			t.Errorf("%v: %d %q %q", c.args, sb.code, out, sb.stderr())
		}
	}
	out = plain(sb.cfgRun("", []string{"config", "devices", "show"}, nil))
	for _, w := range []string{"max-concurrency: 16   (set;", "transport:       ssh   (set;", "timeout:         120 s   (set;"} {
		if !strings.Contains(out, w) {
			t.Errorf("show lacks %q:\n%s", w, out)
		}
	}
	if y := sb.read("state/tacctl.yaml"); !strings.Contains(y, "max_concurrency: 16") || !strings.Contains(y, "transport: ssh") || !strings.Contains(y, "timeout: 120") {
		t.Errorf("tacctl.yaml:\n%s", y)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"max-concurrency", "0"}, "device.config.max_concurrency"},
		{[]string{"max-concurrency", "65"}, "device.config.max_concurrency"},
		{[]string{"max-concurrency", "many"}, "device.config.max_concurrency"},
		{[]string{"transport", "carrier-pigeon"}, "device.config.transport"},
		{[]string{"timeout", "9"}, "device.config.timeout"},
		{[]string{"timeout", "601"}, "device.config.timeout"},
	} {
		sb.cfgRun("", append([]string{"config", "devices"}, c.args...), nil)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.want) {
			t.Errorf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
	}
	// Superuser only: an operator is refused.
	sb.asUser("bob", "tac-operator", "config", "devices", "timeout", "30")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "not permitted for the operator tier") {
		t.Errorf("operator: %d %q", sb.code, sb.stderr())
	}
}

// --concurrency is held to the cap of device.config.max_concurrency, which a
// superuser sets; the refusal says who can raise it.
func TestPullConcurrencyIsHeldToTheCap(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	b.run("config", "devices", "max-concurrency", "4")
	out := b.run("device", "config", "pull", "lab-j", "--concurrency", "5")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--concurrency 5 is above device.config.max_concurrency (4).") ||
		!strings.Contains(b.sb.stderr(), "tacctl config devices max-concurrency <n>") || out != "" {
		t.Errorf("above the cap: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	b.run("device", "config", "pull", "lab-j", "--concurrency", "4")
	if b.sb.code != 0 {
		t.Errorf("at the cap: %d %q", b.sb.code, b.sb.stderr())
	}
	b.run("config", "devices", "transport", "ssh")
	b.run("device", "config", "pull", "lab-j")
	if rec, _ := b.records().Of("lab-j"); rec == nil || rec.Transport != "ssh" {
		t.Errorf("the configured transport was not used: %+v", rec)
	}
	b.run("device", "config", "pull", "lab-j", "--transport", "netconf")
	if rec, _ := b.records().Of("lab-j"); rec == nil || rec.Transport != "netconf" {
		t.Errorf("--transport did not replace the setting: %+v", rec)
	}
}

// NETCONF off: 'auto' reads over ssh and says why, 'netconf' fails and does
// not fall back, 'ssh' does not probe.
func TestPullTransports(t *testing.T) {
	b := newPullBox(t, fakedev.WithNetconfOff())
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	out := b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "ok via ssh (netconf: port closed)") {
		t.Errorf("auto: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-j"); rec == nil || rec.Netconf != "port closed" || rec.Transport != "ssh" || rec.NetconfAt.IsZero() {
		t.Errorf("record %+v", rec)
	}
	if chk := b.run("device", "check", "lab-j"); !strings.Contains(chk, "NETCONF:") || !strings.Contains(chk, "port closed") {
		t.Errorf("check:\n%s", chk)
	}
	out = b.run("device", "config", "pull", "lab-j", "--transport", "netconf")
	if b.sb.code != 1 || !strings.Contains(out, "failed: NETCONF is not enabled on the device") {
		t.Errorf("netconf: %d\n%s", b.sb.code, out)
	}
	for _, c := range b.srv.Commands() {
		if strings.HasPrefix(c, "netconf:") {
			t.Errorf("a NETCONF RPC was served: %v", b.srv.Commands())
		}
	}
	n := b.srv.Logins()
	b.run("device", "config", "pull", "lab-j", "--transport", "ssh")
	if b.sb.code != 0 || b.srv.Logins() != n+1 {
		t.Errorf("ssh: %d", b.sb.code)
	}
	// A check of a device never pulled says how to probe it.
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-n", "192.168.1.21", "juniper"})
	if chk := b.run("device", "check", "lab-n"); !strings.Contains(chk, "NETCONF:") || !strings.Contains(chk, "not probed") {
		t.Errorf("check lab-n:\n%s", chk)
	}
}

// The CONFIG column and the show block say each state of a record.
func TestConfigStatesRendered(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/devices.yaml", "version: 1\nsettings:\n  stale_days: 30\ndevices:\n"+
		"  d-ok: {address: 192.168.1.1, vendor: cisco}\n"+
		"  d-diff: {address: 192.168.1.2, vendor: cisco}\n"+
		"  d-never: {address: 192.168.1.3, vendor: juniper}\n"+
		"  d-failed: {address: 192.168.1.4, vendor: juniper}\n"+
		"  d-wti: {address: 192.168.1.5, vendor: wti}\n"+
		"  d-unsup: {address: 192.168.1.7, vendor: cisco}\n"+
		"  d-nosc: {address: 198.51.100.8, vendor: cisco}\n"+
		"  d-other: {address: 192.168.1.6, vendor: other}\n", 0o600)
	sb.write("var-lib/devices-config.json", `{"version":1,"updated":"2026-10-09T12:00:00Z","devices":{
"d-ok":{"vendor":"cisco","transport":"ssh","pulled":"2026-10-09T12:00:00Z","by":"alice","result":"ok","secrets_visible":true,
  "sections":{"aaa":{"state":"ok"},"roles":{"state":"ok"},"netconf":{"state":"n/a"}}},
"d-diff":{"vendor":"cisco","transport":"ssh","pulled":"2026-10-09T12:00:00Z","by":"alice","result":"ok","secrets_visible":true,
  "sections":{"aaa":{"state":"differs"},"snmp":{"state":"missing"}}},
"d-failed":{"vendor":"juniper","result":"timeout"},
"d-unsup":{"vendor":"cisco","result":"unsupported"},
"d-wti":{"vendor":"wti","result":"unsupported"}}}`, 0o600)
	out := plain(sb.run("", []string{"device", "list"}))
	want := map[string]string{"d-ok": "ok", "d-diff": "differs", "d-never": "never", "d-failed": "failed", "d-wti": "-", "d-other": "-", "d-unsup": "failed", "d-nosc": "-"}
	// (d-nosc is in no scope: a pull refuses it, so it is not 'never'.)
	// The CONFIG column: the word under its heading, whatever the columns
	// before it hold.
	at := -1
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, "CONFIG"); i >= 0 && strings.Contains(l, "NAME") {
			at = i
		}
	}
	if at < 0 {
		t.Fatalf("no CONFIG column:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) > 4 && want[f[0]] != "" && len(l) > at {
			if got := strings.Fields(l[at:])[0]; got != want[f[0]] {
				t.Errorf("%s: CONFIG %q, want %q: %q", f[0], got, want[f[0]], l)
			}
			delete(want, f[0])
		}
	}
	if len(want) != 0 {
		t.Errorf("rows not found: %v\n%s", want, out)
	}
	show := plain(sb.run("", []string{"device", "show", "d-diff"}))
	if !strings.Contains(show, "sections: aaa differs, snmp missing") {
		t.Errorf("show d-diff:\n%s", show)
	}
	if show := plain(sb.run("", []string{"device", "show", "d-failed"})); !strings.Contains(show, "never pulled, timeout (the last attempt)") {
		t.Errorf("show d-failed:\n%s", show)
	}
	if show := plain(sb.run("", []string{"device", "show", "d-never"})); !strings.Contains(show, "never pulled (tacctl device config pull d-never)") {
		t.Errorf("show d-never:\n%s", show)
	}
	js := plain(sb.run("", []string{"device", "list", "--json"}))
	var devs []deviceJSON
	if err := json.Unmarshal([]byte(js), &devs); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range devs {
		got[d.Name] = d.Config
	}
	if got["d-ok"] != "ok" || got["d-diff"] != "differs" || got["d-never"] != "never" || got["d-failed"] != "failed" ||
		got["d-wti"] != "" || got["d-other"] != "" {
		t.Errorf("json configs %v", got)
	}
	// The state is the operator tier's: a read-only user's list has no column,
	// no row in show and no field in the JSON; an operator's has all three.
	ro := sb.asUser("carol", "tac-readonly", "device", "list")
	if sb.code != 0 || strings.Contains(ro, "CONFIG") || !strings.Contains(ro, "d-ok") {
		t.Errorf("read-only list: %d\n%s", sb.code, ro)
	}
	if ro := sb.asUser("carol", "tac-readonly", "device", "show", "d-ok"); sb.code != 0 || strings.Contains(ro, "Configuration") {
		t.Errorf("read-only show: %d\n%s", sb.code, ro)
	}
	if ro := sb.asUser("carol", "tac-readonly", "device", "list", "--json"); sb.code != 0 || strings.Contains(ro, `"config"`) || !strings.Contains(ro, "d-ok") {
		t.Errorf("read-only list --json: %d\n%s", sb.code, ro)
	}
	op := sb.asUser("bob", "tac-operator", "device", "list")
	if sb.code != 0 || !strings.Contains(op, "CONFIG") {
		t.Errorf("operator list: %d\n%s", sb.code, op)
	}
	if op := sb.asUser("bob", "tac-operator", "device", "show", "d-ok"); !strings.Contains(op, "Configuration: pulled ") {
		t.Errorf("operator show:\n%s", op)
	}
}

// The password is typed at the terminal without echo, once, and used for
// every device; the real terminal source (not the test's) is exercised on a
// pty.
func TestPullPromptsOnTheTerminalOnce(t *testing.T) {
	b := newPullBox(t)
	newDevicePasswords = func(inv *invocation) devicePasswords { return &terminalPasswords{inv: inv} }
	b.devices([3]string{"lab-a", "192.168.1.21", "juniper"}, [3]string{"lab-b", "192.168.1.22", "juniper"})
	b.serve("juniper", "set system host-name x\n")
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	b.sb.tty = slave
	var shown strings.Builder
	var mu sync.Mutex
	prompted := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		sent := false
		for {
			n, err := master.Read(buf)
			mu.Lock()
			shown.Write(buf[:n])
			ready := !sent && strings.Contains(shown.String(), "Password for alice")
			mu.Unlock()
			if ready {
				sent = true
				close(prompted)
				_, _ = master.WriteString(testPassword + "\r")
			}
			if err != nil {
				return
			}
		}
	}()
	out := plain(b.sb.run("", []string{"device", "config", "pull", "--all"}, "SUDO_USER=alice"))
	select {
	case <-prompted:
	default:
		t.Fatalf("no prompt; output %q err %q", out, b.sb.stderr())
	}
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	if n := b.srv.Attempts(); n != 2 {
		t.Errorf("two devices, %d password presentations", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Count(shown.String(), "Password for alice (device login): ") != 1 {
		t.Errorf("terminal: %q", shown.String())
	}
	if strings.Contains(shown.String()[strings.Index(shown.String(), "device login): ")+15:], testPassword) {
		t.Errorf("the password was echoed: %q", shown.String())
	}
	noSecrets(t, "the output", out+b.sb.stderr(), testPassword)
}

// Without a terminal and without a cached password the verb refuses.
func TestPullWithoutTerminalRefuses(t *testing.T) {
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		_ = f.Close()
		t.Skip("this process has a controlling terminal, which the prompt would use")
	}
	b := newPullBox(t)
	newDevicePasswords = func(inv *invocation) devicePasswords { return &terminalPasswords{inv: inv} }
	b.devices([3]string{"lab-a", "192.168.1.21", "juniper"})
	b.run("device", "config", "pull", "lab-a")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "a password is needed and no terminal or cached password is available") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if b.srv.Logins() != 0 {
		t.Error("dialled")
	}
}

// A device that never answers costs its timeout and nothing else: the line
// says so, the record says timeout, the run exits 1.
func TestPullTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("the shortest timeout is 10 s")
	}
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	if err := os.WriteFile(filepath.Join(b.dir, junosReadCmd+".hang"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out := b.run("device", "config", "pull", "lab-j", "--transport", "ssh", "--timeout", "10")
	if b.sb.code != 1 || !strings.Contains(out, "failed: timed out") {
		t.Errorf("exit %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-j"); rec == nil || rec.Result != "timeout" {
		t.Errorf("record %+v", rec)
	}
}

// A sections file that cannot be read is no last good pull: said once, the
// device is never (and stale), diff says to pull, and the next pull writes
// the file again.
func TestCorruptSectionsFileIsRecoveredByTheNextPull(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	file := b.sb.path("var-lib", "device-config", "lab-j.yaml")
	if err := os.WriteFile(file, []byte("aaa: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := b.run("device", "config", "list", "--stale")
	if b.sb.code != 0 || !strings.Contains(out, "lab-j") || !strings.Contains(out, "never") {
		t.Errorf("list: %d\n%s", b.sb.code, out)
	}
	if n := strings.Count(b.sb.stderr(), "The stored sections of 'lab-j' cannot be read"); n != 1 {
		t.Errorf("said %d times: %q", n, b.sb.stderr())
	}
	b.run("device", "config", "diff", "lab-j")
	if b.sb.code != 1 || !strings.Contains(b.sb.out.String(), "the stored sections of the last pull cannot be read") ||
		!strings.Contains(b.sb.out.String(), "tacctl device config pull lab-j") {
		t.Errorf("diff: %d %q %q", b.sb.code, b.sb.out.String(), b.sb.stderr())
	}
	// A pull selected by --stale reads it and rewrites the file.
	out = b.run("device", "config", "pull", "--stale")
	if b.sb.code != 0 || !strings.Contains(out, "lab-j  ok via netconf") {
		t.Fatalf("pull --stale: %d\n%s", b.sb.code, out)
	}
	if got := b.run("device", "config", "list", "--stale"); !strings.Contains(got, "None: every device") {
		t.Errorf("after the pull:\n%s", got)
	}
	if b.run("device", "config", "diff", "lab-j"); b.sb.code != 0 {
		t.Errorf("diff after the pull: %d", b.sb.code)
	}
	// A statement with characters a YAML reader rejects is kept readable.
	b.serve("juniper", b.expected("lab-j")+"set snmp location \"Rack\x7f4 x\u0085y\"\n")
	b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	if got := b.run("device", "config", "list"); b.sb.code != 0 || strings.Contains(b.sb.stderr(), "cannot be read") {
		t.Errorf("list after unsafe characters: %d %q\n%s", b.sb.code, b.sb.stderr(), got)
	}
}
