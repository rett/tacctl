package cli

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh/fakedev"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/testpty"
)

// 'device onboard' and the one-shot local login '--login' (D136) end to
// end, in process, against the fake Junos device's configure model: a blank
// device with a local account (admin) and a root login, and alice's TACACS+
// login beside them.

const (
	localAccount  = "admin"
	localPassword = "local-pw-5e1f"
	rootPassword  = "root-pw-77ab"
	onboardAddr   = "192.168.1.31"
	// aliceTemplate is the template user (and class) the rendering gives
	// alice's group
	aliceTemplate = "RW-CLASS"
)

// blankDevice is a configure model with no TACACS+ server: the device a
// person racked and gave a local account.
const blankDevice = `set system host-name sw-lab-5
set system domain-name lab.example.net
set system time-zone UTC
set system root-authentication encrypted-password "$6$fakeRoot$fakeRootHash"
set system login user admin class super-user
set system login user admin authentication encrypted-password "$6$fakeSalt$fakeAdminHash"
set system services ssh
set snmp location "Lab rack 2"
`

// newOnboardBox is a pull box whose fake device is the blank configure
// model. The terminal's local password prompt is answered by the test
// (hooks.passwordPrompt), as a person types it.
func newOnboardBox(t *testing.T, opts ...fakedev.Option) *pullBox {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join("..", "..", "tests", "fixtures", "devconf", "fake", "junos-apply")
	for _, f := range []string{"class", "device", "switch", "show chassis hardware.out"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b := newPullBoxIn(t, dir, opts...)
	b.knob("config.set", blankDevice)
	b.knob("local", localAccount+" "+localPassword+" super-user\nbgadmin "+localPassword+" super-user\n")
	b.knob("root", rootPassword+"\n")
	b.knob("echo.plain", "")
	// alice's TACACS+ login maps to her group's template user (D136's proof)
	b.knob("template", "alice "+aliceTemplate+" "+aliceTemplate+"\n")
	b.sb.hooks.passwordPrompt = func(_ *os.File, prompt string) ([]byte, error) {
		switch {
		case strings.HasPrefix(prompt, "Password of root "):
			return []byte(rootPassword), nil
		case strings.HasPrefix(prompt, "Password of "):
			return []byte(localPassword), nil
		}
		return nil, askpass.ErrNoTerminal
	}
	return b
}

// knob writes a file of the fake device's directory.
func (b *pullBox) knob(name, text string) {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.dir, name), []byte(text), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

// onboard runs 'device onboard' as alice with ssh-keyscan answering the fake
// device's key, on a terminal with the lines of typed typed ahead; typed "-"
// is no terminal at all.
func (b *pullBox) onboard(typed string, args ...string) string {
	b.t.Helper()
	key := b.key()
	b.sb.script = func(r *fake.Runner) {
		route(r)
		scan(onboardAddr, key)(r)
	}
	defer func() { b.sb.script, b.sb.tty = nil, nil }()
	if typed != "-" {
		holdTTY(b.t, b.sb, typed)
	}
	return plain(b.sb.run("", append([]string{"device", "onboard"}, args...), "SUDO_USER=alice"))
}

func (b *pullBox) key() devreg.HostKey {
	b.t.Helper()
	k, err := devreg.ParseHostKey(b.srv.HostKey())
	if err != nil {
		b.t.Fatal(err)
	}
	return k
}

// committed is the configuration the fake device runs now.
func (b *pullBox) committed() string {
	b.t.Helper()
	data, err := os.ReadFile(filepath.Join(b.dir, "committed.set"))
	if err != nil {
		return blankDevice
	}
	return string(data)
}

func TestOnboardEndToEnd(t *testing.T) {
	b := newOnboardBox(t)
	out := b.onboard("y\nsw-lab-5\n", onboardAddr, "--login", localAccount)
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{
		onboardAddr + " offers:", "192.168.1.31  Junos 25.4R1-S2.3", "device reports host name sw-lab-5; no TACACS+ or RADIUS server",
		"Device 'sw-lab-5' registered: 192.168.1.31, juniper.", "From the device: location \"Lab rack 2\"\n",
		"sw-lab-5  read as local:admin:", "checked: shape", "first-time plan", "committing as admin, verifying as alice",
		"sw-lab-5  applied (", "The local account 'admin' was not probed: a login would send its password to the TACACS+ server.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if err := b.sb.stderr(); !strings.Contains(err, "Trust these keys and send the local password of 'admin' to 192.168.1.31? [y/N]") ||
		!strings.Contains(err, "Type the device name to go on:") {
		t.Errorf("the questions: %q", err)
	}
	// the change landed; the local account and root were not touched, no
	// break-glass user is in the first plan
	got := b.committed()
	if !strings.Contains(got, "set system tacplus-server 10.0.0.42") || !strings.Contains(got, "set system authentication-order tacplus") {
		t.Errorf("committed:\n%s", got)
	}
	for _, l := range strings.Split(blankDevice, "\n") {
		if strings.Contains(l, "login user admin") || strings.Contains(l, "root-authentication") {
			if !strings.Contains(got, strings.ReplaceAll(l, `"`, "")) && !strings.Contains(got, l) {
				t.Errorf("the local account changed: %q not in\n%s", l, got)
			}
		}
	}
	for _, c := range b.srv.Commands() {
		if strings.Contains(c, "login user admin") || strings.Contains(c, "root-authentication") || strings.Contains(c, "breakglass") {
			t.Errorf("typed on the device: %q", c)
		}
	}
	// the registry: pinned key, the device's own values
	_, res, err := b.invoke().deviceLoad()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := res.Lookup("sw-lab-5", devreg.ScopeFilter{})
	// the hostname field is never the device's: ssh would dial it
	if !ok || len(e.HostKeys) != 1 || e.HostKeys[0] != b.srv.HostKey() || e.Location != "Lab rack 2" || e.Hostname != "" || e.Vendor != "juniper" {
		t.Errorf("entry %+v", e)
	}
	// every read after the commit is alice's TACACS+ login, the plain view
	// included; the local account read only before it
	if n := strings.Count(strings.Join(b.srv.ExecsBy("alice"), "\n"), "show configuration | display set"); n == 0 {
		t.Errorf("no plain view on alice's login: %q", b.srv.ExecsBy("alice"))
	}
	// the record: the convergence read was alice's own login
	rec, ok := b.records().Of("sw-lab-5")
	if !ok || rec.Applied == nil || rec.Applied.Result != devconf.AppliedApplied || rec.Applied.Kind != devconf.AppliedKindOnboard ||
		rec.LocalLogin() || !rec.UserPulled || rec.By != "alice" {
		t.Errorf("record %+v applied %+v", rec, rec.Applied)
	}
	// the TACACS+ password was asked once, after the review, and stored
	// only once the fresh login took it; the local one never reached it
	if b.pw.asked != 1 || b.pw.accepted != 1 || b.pw.rejected != 0 {
		t.Errorf("tacacs password: asked %d accepted %d rejected %d", b.pw.asked, b.pw.accepted, b.pw.rejected)
	}
	noSecrets(t, "the output", out+b.sb.stderr(), localPassword, testPassword)
	al := b.auditLines("device onboard")
	if len(al) != 2 || !strings.Contains(al[0], "device onboard user=alice device=sw-lab-5 approved=1 shape=") || !strings.Contains(al[0], " mode=attended") ||
		!strings.Contains(al[1], "device onboard user=alice device=sw-lab-5 addr=192.168.1.31 login=local:admin result=applied") {
		t.Errorf("audit %q", al)
	}
	for _, l := range al {
		noSecrets(t, "the audit", l, localPassword, testPassword)
	}
	// a second onboard of the address is the normal flow's
	b.onboard("y\n", onboardAddr, "--login", localAccount)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "is registered as 'sw-lab-5' and was read as your own login") {
		t.Errorf("again: %d %q", b.sb.code, b.sb.stderr())
	}
}

// --check registers, reads and checks as the local account and commits
// nothing; with --host-key no question is asked.
func TestOnboardCheckWithHostKey(t *testing.T) {
	b := newOnboardBox(t)
	out := b.onboard("", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check", "--name", "sw-new")
	if b.sb.code != 0 || !strings.Contains(out, "matches --host-key") || !strings.Contains(out, "sw-new  checked: shape") ||
		!strings.Contains(out, "nothing was committed: --check ends") {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if strings.Contains(b.sb.stderr(), "Trust these keys") || b.pw.asked != 0 {
		t.Errorf("asked: %q, tacacs password asked %d", b.sb.stderr(), b.pw.asked)
	}
	if got := b.committed(); strings.Contains(got, "tacplus-server") {
		t.Errorf("committed:\n%s", got)
	}
	rec, ok := b.records().Of("sw-new")
	if !ok || rec.Login != "local:admin" || rec.UserPulled || rec.Applied == nil || rec.Applied.Result != devconf.AppliedChecked {
		t.Errorf("record %+v", rec)
	}
	// taken again by a later onboard (never read as alice), whose identity
	// is the pinned key; a --name that is not the registered one is refused
	b.onboard("", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check", "--name", "other")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "registered as 'sw-new' by an earlier onboard") {
		t.Errorf("other name: %d %q", b.sb.code, b.sb.stderr())
	}
	out = b.onboard("", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check")
	if b.sb.code != 0 || !strings.Contains(out, "is registered already") || !strings.Contains(out, "sw-new  checked:") {
		t.Errorf("again: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
}

// Without a terminal the identity is --host-key's or nothing, and the
// commit needs one; a declined question sends nothing; a wrong --host-key
// sends nothing.
func TestOnboardRefusalsSendNothing(t *testing.T) {
	b := newOnboardBox(t)
	for _, c := range []struct {
		typed string
		args  []string
		code  int
		want  string
	}{
		{"-", []string{onboardAddr, "--login", localAccount}, 2, "No terminal to answer the identity question on"},
		{"-", []string{onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint()}, 2, "No terminal to review the change on"},
		{"-", []string{onboardAddr}, 2, "--login <local-user> names the device's local account"},
		{"-", []string{onboardAddr, "--login", "bad name"}, 2, "--login takes the name of one of the device's local accounts"},
		{"-", []string{onboardAddr, "--login", localAccount, "--check", "--section", "breakglass"}, 2, "--section takes sections of"},
		{"n\n", []string{onboardAddr, "--login", localAccount}, 1, "Not trusted. Nothing was sent."},
		{"", []string{onboardAddr, "--login", localAccount, "--check", "--host-key", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, 1, "No host key 192.168.1.31 offers matches"},
		{"", []string{"198.51.100.9", "--login", localAccount, "--check", "--host-key", b.key().Fingerprint()}, 1, "No scope answers 198.51.100.9"},
	} {
		b.onboard(c.typed, c.args...)
		if b.sb.code != c.code || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%v: exit %d %q (want %d %q)", c.args, b.sb.code, b.sb.stderr(), c.code, c.want)
		}
	}
	if b.srv.Attempts() != 0 || strings.Contains(b.sb.devices(), "sw-lab-5") {
		t.Errorf("a refusal sent a password (%d) or registered:\n%s", b.srv.Attempts(), b.sb.devices())
	}
}

// A device that has a TACACS+ server already is the normal flow's: refused
// after the pre-flight, nothing registered.
func TestOnboardRefusesADeviceWithAServer(t *testing.T) {
	b := newOnboardBox(t)
	b.knob("config.set", blankDevice+"set system tacplus-server 192.0.2.10 secret \"$9$fakeSecretValue1\"\n")
	b.onboard("", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "refused: the device already has a TACACS+ or RADIUS server; it is reached by the normal flow (device add, device config pull)") {
		t.Errorf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if strings.Contains(b.sb.devices(), "sw-lab-5") {
		t.Error("registered")
	}
	al := b.auditLines("device onboard")
	if len(al) != 1 || !strings.Contains(al[0], "login=local:admin result=refused") {
		t.Errorf("audit %q", al)
	}
}

// A fresh TACACS+ login refused after the commit rolls the change back and
// leaves the local account as it was; the password is not stored, and the
// local account is probed.
func TestOnboardRefusedFreshLoginRollsBack(t *testing.T) {
	b := newOnboardBox(t)
	b.knob("verify.fail", "deny\n")
	out := b.onboard("y\nsw-lab-5\n", onboardAddr, "--login", localAccount)
	if b.sb.code != 1 || !strings.Contains(out, "sw-lab-5  rolled back") || !strings.Contains(out, "the change was rolled back and the local account 'admin' is as it was") {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if !strings.Contains(out, "The local account 'admin' was not probed") || strings.Contains(out, "still logs in") {
		t.Errorf("the local account was probed:\n%s", out)
	}
	if got := b.committed(); strings.Contains(got, "tacplus-server") || !strings.Contains(got, "login user admin authentication") {
		t.Errorf("committed:\n%s", got)
	}
	if b.pw.accepted != 0 || b.pw.rejected != 0 {
		t.Errorf("the refused fresh login told the cache: accepted %d rejected %d", b.pw.accepted, b.pw.rejected)
	}
	if rec, ok := b.records().Of("sw-lab-5"); !ok || rec.Applied == nil || rec.Applied.Result != devconf.AppliedRolledBack || !rec.LocalLogin() {
		t.Errorf("record %+v", rec)
	}
}

// root's shell is a csh: every session runs the CLI through the fixed
// wrapper command.
func TestOnboardAsRootUsesTheWrapper(t *testing.T) {
	b := newOnboardBox(t)
	out := b.onboard("", onboardAddr, "--login", "root", "--host-key", b.key().Fingerprint(), "--check")
	if b.sb.code != 0 || !strings.Contains(out, "read as local:root:") || !strings.Contains(out, "checked: shape") {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	cmds := b.srv.Commands()
	if !slices.Contains(cmds, rootCLICommand) {
		t.Errorf("the wrapper was not the remote command: %q", cmds)
	}
	for _, c := range cmds {
		if strings.Contains(c, "Command not found") {
			t.Errorf("a csh command: %q", c)
		}
	}
}

// --- --login on pull, diff and plan --------------------------------------------------

// trun runs tacctl as alice on a terminal (the local password is asked on
// one; hooks.passwordPrompt answers it).
func (b *pullBox) trun(args ...string) string {
	b.t.Helper()
	master, slave, err := testpty.Open()
	if err != nil {
		b.t.Skip("no pty:", err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()
	b.sb.tty = slave
	b.sb.script = route
	defer func() { b.sb.tty, b.sb.script = nil, nil }()
	return plain(b.sb.run("", args, "SUDO_USER=alice"))
}

// loginBox is the blank device registered (pinned) as sw-lab-5.
func loginBox(t *testing.T) *pullBox {
	t.Helper()
	b := newOnboardBox(t)
	b.devices([3]string{"sw-lab-5", onboardAddr, "juniper"}, [3]string{"sw-other", "192.168.1.32", "juniper"})
	return b
}

// One device by name: anything else is a usage error before a password is
// asked or a device dialled.
func TestPullLoginSelectionIsAUsageError(t *testing.T) {
	b := loginBox(t)
	for _, args := range [][]string{
		{"device", "config", "pull", "--all", "--login", localAccount},
		{"device", "config", "pull", "--scope", "lab", "--login", localAccount},
		{"device", "config", "pull", "--vendor", "juniper", "--login", localAccount},
		{"device", "config", "pull", "--stale", "--login", localAccount},
		{"device", "config", "pull", "sw-lab-5,sw-other", "--login", localAccount},
		{"device", "config", "pull", "sw-lab-5", "sw-other", "--login", localAccount},
		{"device", "config", "diff", "sw-lab-5", "--login", localAccount},
		{"device", "config", "plan", "sw-lab-5", "--login", localAccount},
		{"device", "config", "plan", "--all", "--pull", "--login", localAccount},
		{"device", "config", "pull", "sw-lab-5", "--login", "a b"},
		{"device", "config", "pull", "sw-lab-5", "--login", "root", "--transport", "netconf"},
	} {
		b.run(args...)
		if b.sb.code != 2 {
			t.Errorf("%v: exit %d %q", args, b.sb.code, b.sb.stderr())
		}
	}
	if b.srv.Attempts() != 0 {
		t.Error("a password was sent")
	}
}

// --login is the superuser's: an engineer is the tier denial, logged.
func TestPullLoginIsTheSuperusersOnly(t *testing.T) {
	b := loginBox(t)
	b.sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	out := plain(b.sb.cfgRun("", []string{"device", "config", "pull", "sw-lab-5", "--login", localAccount}, func(r *fake.Runner) {
		route(r)
		idAs("bob", "tac-users tac-operator")(r)
	}, "SUDO_USER=bob"))
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device config pull --login' is not permitted for the engineer tier") {
		t.Errorf("exit %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	if al := b.auditLines("tier DENY"); len(al) != 1 || !strings.Contains(al[0], "cmd=device config pull --login") {
		t.Errorf("audit %q", al)
	}
	if b.srv.Attempts() != 0 {
		t.Error("a password was sent")
	}
}

// The local login never touches the password cache: a cache that holds the
// user's own password is neither asked, nor stored into (the agent's Store
// event fails the test), nor told to forget; the local password reached the
// device and nothing else.
func TestPullLoginNeverTouchesTheCache(t *testing.T) {
	c := newCacheAgent(t)
	b := loginBox(t)
	if err := c.ag.Store([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	before := c.stored()
	b.sb.hooks.devicePasswords = func(inv *invocation) devicePasswords {
		t.Error("the local login asked the invoking user's password source")
		return &terminalPasswords{inv: inv, client: c.cl}
	}
	b.sb.hooks.localPasswords = func(inv *invocation, account, where string) *terminalPasswords {
		// the real source, handed a cache client all the same: it must not
		// use it
		tp := (*hooks)(nil).newLocalPasswords(inv, account, where)
		tp.client = c.cl
		return tp
	}
	b.sb.tty = nil
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	b.sb.tty = slave
	out := plain(b.sb.run("", []string{"device", "config", "pull", "sw-lab-5", "--login", localAccount}, "SUDO_USER=alice"))
	b.sb.tty = nil
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if got := c.stored(); got != before {
		t.Errorf("the local login stored into the cache (%d events, %d before)", got, before)
	}
	c.mu.Lock()
	for _, e := range c.events {
		if e.Kind == askpass.EventForgotten {
			t.Error("the local login made the cache forget")
		}
	}
	c.mu.Unlock()
	if got := c.peek(t); got != testPassword {
		t.Errorf("the cache lost the user's password: %q", got)
	}
	if n := b.srv.Attempts(); n != 1 {
		t.Errorf("%d password presentations (one connection, one send)", n)
	}
	rec, ok := b.records().Of("sw-lab-5")
	if !ok || rec.Login != "local:admin" || rec.By != "alice" || rec.UserPulled {
		t.Errorf("record %+v", rec)
	}
	al := b.auditLines("device config pull")
	if len(al) != 2 || !strings.Contains(al[0], "device config pull user=alice device=sw-lab-5 login=local:admin") ||
		!strings.Contains(al[1], "result=ok") || !strings.Contains(al[1], "login=local:admin") {
		t.Errorf("audit %q", al)
	}
	noSecrets(t, "the output", out+b.sb.stderr(), localPassword)
}

// The local source: no cache call whatever its client, Accepted and
// Rejected do nothing, and Done zeroes the very bytes Password returned.
func TestLocalPasswordsZeroedAtDone(t *testing.T) {
	c := newCacheAgent(t)
	if err := c.ag.Store([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	before := c.stored()
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	hk := &hooks{passwordPrompt: func(_ *os.File, prompt string) ([]byte, error) {
		if !strings.HasPrefix(prompt, "Password of root on sw (192.0.2.1) (a local account; asked once, never kept): ") {
			t.Errorf("prompt %q", prompt)
		}
		return []byte(localPassword), nil
	}}
	a := app.New(nil, paths.NewEnv(nil), "/opt/x/dist/tacctl", 0, app.Stdio{Stdin: slave}, &fake.Runner{})
	tp := &terminalPasswords{inv: &invocation{ctx: context.Background(), app: a, hooks: hk}, client: c.cl, local: "root", where: "sw (192.0.2.1)"}
	pw, err := tp.Password(context.Background(), "root")
	if err != nil || string(pw) != localPassword {
		t.Fatalf("%q %v", pw, err)
	}
	tp.Accepted()
	tp.Rejected()
	if string(pw) != localPassword {
		t.Error("Accepted or Rejected zeroed what the caller still uses")
	}
	tp.Done()
	for _, x := range pw {
		if x != 0 {
			t.Fatalf("not zeroed at Done: %q", pw)
		}
	}
	if c.stored() != before || c.peek(t) != testPassword {
		t.Error("the local source used the cache")
	}
}

// A local login goes only to a device with a pinned key; root only to a
// device never read as the user's own login, through the wrapper.
func TestPullLoginRefusalsAndRoot(t *testing.T) {
	b := newOnboardBox(t)
	b.devices([3]string{"sw-lab-5", onboardAddr, "juniper"}, [3]string{"sw-nokey", "192.168.1.33", "pinless"})
	b.sb.write("state/devices.yaml", strings.Replace(b.sb.read("state/devices.yaml"), "vendor: cisco", "vendor: juniper", 1), 0o600)
	b.trun("device", "config", "pull", "sw-nokey", "--login", localAccount)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "has no pinned host key, and a local password goes only to a device whose key was verified") {
		t.Errorf("pinless: %d %q", b.sb.code, b.sb.stderr())
	}
	out := b.trun("device", "config", "plan", "sw-lab-5", "--pull", "--login", "root")
	if b.sb.code != 0 || !strings.Contains(out, "set system tacplus-server") {
		t.Fatalf("plan --pull --login root: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if !slices.Contains(b.srv.Commands(), rootCLICommand) {
		t.Errorf("no wrapper: %q", b.srv.Commands())
	}
	if rec, ok := b.records().Of("sw-lab-5"); !ok || rec.Login != "local:root" {
		t.Errorf("record %+v", rec)
	}
	// once read as alice, root is refused; another local account is not
	b.trun("device", "config", "pull", "sw-lab-5")
	if b.sb.code != 0 {
		t.Fatalf("pull as alice: %d %q", b.sb.code, b.sb.stderr())
	}
	b.trun("device", "config", "diff", "sw-lab-5", "--pull", "--login", "root")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "--login root is for a device that was never read as your own login") {
		t.Errorf("root after alice: %d %q", b.sb.code, b.sb.stderr())
	}
	b.trun("device", "config", "pull", "sw-lab-5", "--login", localAccount)
	if rec, ok := b.records().Of("sw-lab-5"); b.sb.code != 0 || !ok || rec.Login != "local:admin" || !rec.UserPulled {
		t.Errorf("admin after alice: %d %q %+v", b.sb.code, b.sb.stderr(), rec)
	}
	b.trun("device", "config", "pull", "sw-lab-5", "--login", "root")
	if b.sb.code != 1 {
		t.Errorf("root after a local pull over alice's: %d", b.sb.code)
	}
	// a wrong local password is the pull's auth failure, and nothing more
	b.sb.hooks.passwordPrompt = func(*os.File, string) ([]byte, error) { return []byte("wrong"), nil }
	b.trun("device", "config", "pull", "sw-lab-5", "--login", localAccount)
	if b.sb.code != 1 || !strings.Contains(b.sb.out.String()+b.sb.stderr(), "refused the password of its local account 'admin'") {
		t.Errorf("wrong password: %d %q %q", b.sb.code, b.sb.out.String(), b.sb.stderr())
	}
}

// Any local account works as admin does, a break-glass account included:
// nothing about its name is special but root's (D136).
func TestLocalLoginTakesAnyLocalAccount(t *testing.T) {
	b := newOnboardBox(t)
	out := b.onboard("", onboardAddr, "--login", "bgadmin", "--host-key", b.key().Fingerprint(), "--check")
	if b.sb.code != 0 || !strings.Contains(out, "sw-lab-5  read as local:bgadmin:") || !strings.Contains(out, "checked: shape") {
		t.Fatalf("onboard: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	b.trun("device", "config", "pull", "sw-lab-5", "--login", "bgadmin")
	if rec, ok := b.records().Of("sw-lab-5"); b.sb.code != 0 || !ok || rec.Login != "local:bgadmin" {
		t.Errorf("pull: %d %q %+v", b.sb.code, b.sb.stderr(), rec)
	}
	if slices.Contains(b.srv.Commands(), rootCLICommand) {
		t.Error("the root wrapper for a local account that is not root")
	}
}

// A break-glass hold refuses a local login as it refuses every pull, and
// onboard, before anything is sent.
func TestLocalLoginRefusedWhileHeld(t *testing.T) {
	b := loginBox(t)
	b.sb.write("state/tacctl.yaml", "breakglass_hold:\n  sw-lab-5:\n    address: "+onboardAddr+"\n    since: '2026-10-13T00:00:00Z'\n    by: alice\n    reason: console recovery\n", 0o600)
	b.trun("device", "config", "pull", "sw-lab-5", "--login", "bgadmin")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "break-glass is held on sw-lab-5") || !strings.Contains(b.sb.stderr(), "release it first") {
		t.Errorf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	b.onboard("", onboardAddr, "--login", "bgadmin", "--host-key", b.key().Fingerprint(), "--check")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "break-glass is held on sw-lab-5") || !strings.Contains(b.sb.stderr(), "release it first") {
		t.Errorf("onboard: %d %q", b.sb.code, b.sb.stderr())
	}
	if b.srv.Attempts() != 0 {
		t.Error("a password was sent")
	}
}

// The TACACS+ proof is the rendered template user, never a local account
// of the person's name: a fresh login whose 'Current user' is the person
// (a local account 'alice' with her password, logged in through the local
// password) or whose class is not the template's rolls the change back.
func TestOnboardProofNeedsTheTemplateUser(t *testing.T) {
	for _, c := range []struct{ name, template string }{
		{"a local account", ""},
		{"another class", "alice " + aliceTemplate + " RO-CLASS\n"},
		{"another template", "alice RO-CLASS RO-CLASS\n"},
	} {
		b := newOnboardBox(t)
		b.knob("template", c.template)
		out := b.onboard("y\nsw-lab-5\n", onboardAddr, "--login", localAccount)
		if b.sb.code != 1 || !strings.Contains(out, "sw-lab-5  rolled back: verification failed (the fresh login: ") {
			t.Errorf("%s: exit %d\n%s\n%s", c.name, b.sb.code, out, b.sb.stderr())
		}
		if got := b.committed(); strings.Contains(got, "tacplus-server") {
			t.Errorf("%s: committed:\n%s", c.name, got)
		}
	}
}

// A device with a local account of the invoking user's name, '--login'
// naming the user's own name, and a --section without aaa are refused
// before the change is sent.
func TestOnboardRefusesAProofThatCouldBeLocal(t *testing.T) {
	b := newOnboardBox(t)
	b.onboard("-", onboardAddr, "--login", "alice", "--check", "--host-key", b.key().Fingerprint())
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "'alice' is your own login") {
		t.Errorf("--login alice: %d %q", b.sb.code, b.sb.stderr())
	}
	b.onboard("-", onboardAddr, "--login", localAccount, "--check", "--section", "roles,snmp")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--section must include aaa") {
		t.Errorf("--section: %d %q", b.sb.code, b.sb.stderr())
	}
	if b.srv.Attempts() != 0 {
		t.Errorf("a refusal sent a password (%d)", b.srv.Attempts())
	}
	b.knob("config.set", blankDevice+"set system login user alice class super-user\n")
	b.onboard("y\nsw-lab-5\n", onboardAddr, "--login", localAccount)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "the device has a local account named 'alice', your own login") {
		t.Errorf("local alice: %d %q", b.sb.code, b.sb.stderr())
	}
	if strings.Contains(b.sb.devices(), "sw-lab-5") || b.pw.asked != 0 {
		t.Errorf("registered or asked (%d):\n%s", b.pw.asked, b.sb.devices())
	}
}

// Nothing logs in as the local account after the commit, root included (a
// login would send its password to the TACACS+ server): the run says it was
// not probed, and the fake sees no attempt for the account after alice's
// fresh login.
func TestOnboardNeverProbes(t *testing.T) {
	for _, acct := range []string{"root", localAccount} {
		b := newOnboardBox(t)
		out := b.onboard("y\nsw-lab-5\n", onboardAddr, "--login", acct, "--json")
		if b.sb.code != 0 || !strings.Contains(out, `"status":"applied"`) {
			t.Fatalf("%s: exit %d\n%s\n%s", acct, b.sb.code, out, b.sb.stderr())
		}
		if !strings.Contains(out, `"probe":"not-probed"`) || strings.Contains(out, "still logs in") || strings.Contains(out, "is refused while") {
			t.Errorf("%s: probe field:\n%s", acct, out)
		}
		users := b.srv.AttemptUsers()
		last := -1
		for i, u := range users {
			if u == "alice" {
				last = i
			}
		}
		if last < 0 {
			t.Fatalf("%s: no fresh TACACS+ login in %q", acct, users)
		}
		for _, u := range users[last+1:] {
			if u == acct {
				t.Errorf("%s: a login as the local account after the commit: %q", acct, users)
			}
		}
		// the text run says the same
		b2 := newOnboardBox(t)
		out = b2.onboard("y\nsw-lab-5\n", onboardAddr, "--login", acct)
		want := "The local account '" + acct + "' was not probed: a login would send its password to the TACACS+ server."
		if !strings.Contains(out, want) {
			t.Errorf("%s: missing %q in\n%s", acct, want, out)
		}
	}
}

// A record file that cannot be read is not 'never read as you': --login
// root and the taking over of an earlier onboard are refused.
func TestLocalLoginRefusesAnUnreadableRecordFile(t *testing.T) {
	b := newOnboardBox(t)
	b.onboard("", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check")
	if b.sb.code != 0 {
		t.Fatalf("check: %d %q", b.sb.code, b.sb.stderr())
	}
	recs := filepath.Join(b.sb.dir, "var-lib", "devices-config.json")
	if err := os.WriteFile(recs, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	attempts := b.srv.Attempts()
	b.onboard("", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "is not known, so it is not taken over") {
		t.Errorf("onboard: %d %q", b.sb.code, b.sb.stderr())
	}
	b.trun("device", "config", "pull", "sw-lab-5", "--login", "root")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "--login root is only for a device that never was") {
		t.Errorf("root: %d %q", b.sb.code, b.sb.stderr())
	}
	if b.srv.Attempts() != attempts {
		t.Errorf("a refusal sent a password")
	}
}

// What the device reports reaches the terminal without its control
// characters: 'show version', the name it calls itself, its snmp values.
func TestOnboardEscapesDeviceText(t *testing.T) {
	b := newOnboardBox(t)
	esc := "\x1b]0;owned\x07"
	b.knob("device", "hostname sw\x1b[31mlab\nmodel ex4300"+esc+"\njunos 25.4R1\x1b[2J\n")
	b.knob("config.set", strings.Replace(blankDevice, "set system host-name sw-lab-5", "set system host-name sw\x1b[31mlab", 1)+
		"set snmp description \"rack\x1b[2Jtop\"\n")
	// the name it calls itself is no name: asked for, and nothing typed
	out := b.onboard("\n", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check")
	all := out + b.sb.stderr()
	if b.sb.code == 0 || !strings.Contains(all, "The device calls itself 'sw?[31mlab'") {
		t.Errorf("no name: %d %q", b.sb.code, all)
	}
	out = b.onboard("", onboardAddr, "--login", localAccount, "--host-key", b.key().Fingerprint(), "--check", "--name", "sw-x", "--json")
	all += out + b.sb.stderr()
	if !strings.Contains(all, "ex4300?]0;owned?") || !strings.Contains(all, "device reports host name sw?[31mlab") {
		t.Errorf("not shown escaped:\n%q", all)
	}
	if strings.ContainsAny(all, "\x1b\x07") {
		t.Errorf("a control character reached the terminal:\n%q", all)
	}
}

func TestHasAAAServerForms(t *testing.T) {
	for _, c := range []struct {
		line string
		want bool
	}{
		{"set system tacplus-server 192.0.2.1 secret x", true},
		{"set system radius-server 192.0.2.1 secret x", true},
		{"set groups base system tacplus-server 192.0.2.1 secret x", true},
		{"set groups base system radius-server 192.0.2.1 port 1812", true},
		{"set system accounting destination tacplus server 192.0.2.1 secret x", true},
		{"set system accounting destination radius server 192.0.2.1 secret x", true},
		{"set groups g system accounting destination tacplus server 192.0.2.1", true},
		{"deactivate system tacplus-server 192.0.2.1", true},
		{"set system accounting destination tacplus", false},
		{"set system login user tacplus-server class super-user", false},
		{"set access radius-server 192.0.2.1 secret x", false},
		{"set snmp description tacplus-server", false},
	} {
		if got := hasAAAServer(c.line + "\n"); got != c.want {
			t.Errorf("%q: %v", c.line, got)
		}
	}
	if !hasLocalUser("set groups g system login user Alice class x\n", "alice") || hasLocalUser("set system login user alicex class x\n", "alice") {
		t.Error("hasLocalUser")
	}
}
