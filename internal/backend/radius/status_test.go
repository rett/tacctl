package radius_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
)

// Ports of the status and log tests of tests/integration/radius.bats, and of
// the read-only contract verbs of tests/unit/render_radius.bats.

const logTime = "2006-01-02 15:04:05"

// plantLogs is plant_logs: an auth log with old and recent lines, a detail
// file with two records and a daemon log. It returns the time stamp of the
// recent lines.
func plantLogs(t *testing.T, r *renv) string {
	t.Helper()
	now := r.now.Format(logTime)
	old := r.now.Add(-72 * time.Hour).Format(logTime)
	l := r.m.L
	if err := os.MkdirAll(l.LogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, l.AuthLog, old+" Access-Reject scope=lab client=172.16.0.9 nas=sw9 reason='not an enabled user of this scope' user=mallory\n"+
		old+" Access-Accept scope=lab client=172.16.0.9 nas=sw9 reason='-' user=alice\n"+
		now+" Access-Accept scope=prod client=10.1.2.3 nas=core1 reason='-' user=alice\n"+
		now+" Access-Reject scope=lab client=172.16.0.9 nas=sw9 reason='tacctl_pap: Crypt digest does not match \"known good\" digest' user=bob\n"+
		now+" Access-Reject scope=prod client=10.1.2.3 nas=core1 reason='not an enabled user of this scope' user=alice bob\n")
	writeFile(t, l.AcctLog, "Fri Oct  2 10:00:00 2026\n\tUser-Name = \"alice\"\n\tAcct-Status-Type = Start\n\tAcct-Session-Id = \"s1\"\n\n"+
		"Fri Oct  2 10:05:00 2026\n\tUser-Name = \"alice\"\n\tAcct-Status-Type = Stop\n\tAcct-Session-Id = \"s1\"\n\n")
	writeFile(t, l.DaemonLog, "Fri Oct  2 10:00:00 2026 : Info: Ready to process requests\n")
	return now
}

func status(t *testing.T, r *renv, part backend.StatusPart) string {
	t.Helper()
	var b strings.Builder
	if err := r.m.Status(context.Background(), part, &b); err != nil {
		t.Fatalf("status %s: %v", part, err)
	}
	return strip(b.String())
}

// "status: each backend has its section; the RADIUS one shows service,
// listeners, notes, accounting and counts" (the RADIUS section's parts).
func TestStatusSections(t *testing.T) {
	r := newEnv(t)
	r.up()
	plantLogs(t, r)
	svc := status(t, r, backend.StatusService)
	contains(t, svc, "Service:              active (freeradius.service)\n")
	contains(t, svc, "Since:                Fri 2026-10-02 10:00:00 UTC\n")
	contains(t, svc, "PID:                  4242\n")
	contains(t, svc, "Memory:               2.0 MB\n")
	contains(t, svc, "Listening (auth):     0.0.0.0:1812/udp\n")
	contains(t, svc, "Listening (acct):     0.0.0.0:1813/udp\n")
	cfg := status(t, r, backend.StatusConfig)
	contains(t, cfg, "Config:               "+r.m.L.Conf+"\n")
	contains(t, cfg, "Authentication:       PAP against the store's bcrypt hashes (no CHAP, MS-CHAP or EAP)\n")
	contains(t, cfg, "Command rules:        not enforced over RADIUS (commands.<group> of: operator)\n")
	contains(t, cfg, "Secrets:              beyond what every RADIUS client takes (63 characters, no space, ASCII): lab, prod-inner\n")
	contains(t, cfg, "Connection filters:   enforced (4 allow, 2 deny)\n")
	contains(t, cfg, "Vendor attributes:    not sent (no scope enables one: tacctl scope vendor-attrs <scope> enable <vendor>)\n")
	acct := status(t, r, backend.StatusAccounting)
	if !strings.HasPrefix(acct, "  Accounting log:       ") || !strings.HasSuffix(acct, " (2 records)\n") {
		t.Errorf("accounting: %q", acct)
	}
	act := status(t, r, backend.StatusActivity)
	want := "\n  Authentication (last 24 hours, from tacctl-auth.log):\n    Accepted:           1\n    Rejected:           2\n\n" +
		"  Recent Rejects (last 5):\n"
	if !strings.HasPrefix(act, want) {
		t.Errorf("activity:\n%s", act)
	}
	contains(t, act, "user=bob\n")
	contains(t, act, "user=alice bob\n")
	notContains(t, act, "mallory")
	// Colours: the rejects are red.
	var b strings.Builder
	_ = r.m.Status(context.Background(), backend.StatusActivity, &b)
	contains(t, b.String(), "    \033[0;31m"+r.now.Format(logTime)+" Access-Reject ")
}

// A stopped daemon is shown as such; nothing listens.
func TestStatusStoppedDaemon(t *testing.T) {
	r := newEnv(t)
	r.up()
	r.setActive("freeradius", false)
	svc := status(t, r, backend.StatusService)
	contains(t, svc, "Service:              inactive (freeradius.service)\n")
	contains(t, svc, "port 1812/udp not detected\n")
	contains(t, svc, "port 1813/udp not detected\n")
	notContains(t, svc, "Since:")
	notContains(t, svc, "PID:")
	// Colours: inactive is red, a bound port green.
	var b strings.Builder
	_ = r.m.Status(context.Background(), backend.StatusService, &b)
	contains(t, b.String(), "\033[0;31minactive\033[0m (freeradius.service)")
	// With no systemctl answer at all the state is "unknown".
	r.run.Missing("systemctl")
	if got := status(t, r, backend.StatusService); !strings.Contains(got, "unknown (freeradius.service)") {
		t.Errorf("no systemctl: %s", got)
	}
}

// Without logs there are no counts to fear: no accounting line, zero counts,
// and "No rejects".
func TestStatusWithoutLogs(t *testing.T) {
	r := newEnv(t)
	r.up()
	if got := status(t, r, backend.StatusAccounting); got != "" {
		t.Errorf("accounting: %q", got)
	}
	act := status(t, r, backend.StatusActivity)
	contains(t, act, "    Accepted:           0\n    Rejected:           0\n")
	contains(t, act, "    No rejects in the last 24 hours\n")
}

// The status of a part this module does not have is unsupported and writes
// nothing; the summary is the vendor line alone.
func TestStatusSummaryAndUnsupported(t *testing.T) {
	r := newEnv(t)
	r.up()
	if got := status(t, r, backend.StatusSummary); got != "  Vendor attributes:    not sent (no scope enables one: tacctl scope vendor-attrs <scope> enable <vendor>)\n" {
		t.Errorf("summary: %q", got)
	}
	var b strings.Builder
	err := r.m.Status(context.Background(), "frobnicate", &b)
	wantCode(t, err, 2)
	if b.Len() != 0 {
		t.Error("wrote something")
	}
}

// With nothing enabled the summary says so; with a scope enabled or an
// address tagged it counts them.
func TestStatusVendorLine(t *testing.T) {
	r := newEnv(t)
	r.up()
	if _, err := r.apply(r.mutate(scopeSet("lab", "vendor_attrs=cisco"))); err != nil {
		t.Fatal(err)
	}
	if _, err := r.apply(r.mutate(scopeSet("prod", "devices=10.9.9.9/32=juniper"))); err != nil {
		t.Fatal(err)
	}
	want := "  Vendor attributes:    enabled for 1 of 4 scope(s), 1 tagged address(es) (tacctl scope list)\n"
	if got := status(t, r, backend.StatusSummary); got != want {
		t.Errorf("summary: %q", got)
	}
	contains(t, status(t, r, backend.StatusConfig), want)
	// Only tagged addresses: still sent.
	if _, err := r.apply(r.mutate(scopeSet("lab", "vendor_attrs="))); err != nil {
		t.Fatal(err)
	}
	contains(t, status(t, r, backend.StatusSummary), "enabled for 0 of 4 scope(s), 1 tagged address(es)")
}

// "log: --backend radius shows the auth log and the daemon log; failures are
// the last day's rejects".
func TestLogTailFailuresSearchAccounting(t *testing.T) {
	r := newEnv(t)
	r.up()
	plantLogs(t, r)
	ctx := context.Background()
	run := func(sub string, args ...string) string {
		t.Helper()
		var b strings.Builder
		if err := r.m.Log(ctx, sub, args, &b); err != nil {
			t.Fatalf("log %s: %v\n%s", sub, err, r.stderr)
		}
		return strip(b.String())
	}
	tail := run("tail", "2")
	contains(t, tail, "\nRecent RADIUS Authentications ("+r.m.L.AuthLog+")\n--------------------------------------------\n")
	contains(t, tail, " user=alice bob\n")
	notContains(t, tail, "user=mallory")
	contains(t, tail, "\nFreeRADIUS Daemon Log ("+r.m.L.DaemonLog+")\n--------------------------------------------\n")
	contains(t, tail, "Ready to process requests\n")
	if !strings.HasPrefix(tail, "\nRecent RADIUS") || !strings.HasSuffix(tail, "\n\n") {
		t.Errorf("tail framing: %q", tail)
	}
	if n := strings.Count(tail, "Access-"); n != 2 {
		t.Errorf("tail 2 showed %d lines", n)
	}

	fail := run("failures")
	contains(t, fail, "RADIUS Authentication Failures (last 24 hours)\n")
	contains(t, fail, "Crypt digest does not match")
	notContains(t, fail, "user=mallory")
	notContains(t, fail, "Access-Accept")

	search := run("search", "mallory")
	contains(t, search, "RADIUS log entries matching 'mallory'\n")
	contains(t, search, "user=mallory\n")
	// A case-blind basic regular expression: '.' and an alternation.
	if got := run("search", `ACCEPT.*USER=ALICE$`); strings.Count(got, "Access-Accept") != 2 {
		t.Errorf("regexp search:\n%s", got)
	}
	if got := run("search", `mallory\|ready`); !strings.Contains(got, "user=mallory") || !strings.Contains(got, "Ready to process") {
		t.Errorf("alternation:\n%s", got)
	}
	contains(t, run("search", "nobody-at-all"), "  No matches found.\n")

	acc := func(args ...string) string {
		t.Helper()
		var b strings.Builder
		if err := r.m.Accounting(ctx, "tail", args, &b); err != nil {
			t.Fatal(err)
		}
		return strip(b.String())
	}
	a1 := acc("1")
	contains(t, a1, "Recent RADIUS Accounting Records\n")
	contains(t, a1, "Acct-Status-Type = Stop")
	notContains(t, a1, "Acct-Status-Type = Start")
	if a2 := acc(); !strings.Contains(a2, "Start") || !strings.Contains(a2, "Stop") {
		t.Errorf("default count shows %q", a2)
	}
}

// What tail, search, failures and accounting say when there is nothing.
func TestLogsWithoutFiles(t *testing.T) {
	r := newEnv(t)
	r.up()
	ctx := context.Background()
	var b strings.Builder
	if err := r.m.Log(ctx, "tail", nil, &b); err != nil {
		t.Fatal(err)
	}
	if got := strip(b.String()); got != "\nRecent RADIUS Authentications ("+r.m.L.AuthLog+")\n--------------------------------------------\n  No log entries found.\n\n" {
		t.Errorf("tail: %q", got)
	}
	b.Reset()
	_ = r.m.Log(ctx, "failures", nil, &b)
	contains(t, strip(b.String()), "  No failures in the last 24 hours\n")
	b.Reset()
	_ = r.m.Accounting(ctx, "tail", nil, &b)
	contains(t, strip(b.String()), "  No accounting log found at "+r.m.L.AcctLog+"\n")
	// search without a term is an error, on stderr; a bad tail count too.
	b.Reset()
	r.reset()
	err := r.m.Log(ctx, "search", nil, &b)
	wantCode(t, err, 1)
	contains(t, r.stderr.String(), "Usage: tacctl log search <username>")
	if b.Len() != 0 {
		t.Errorf("wrote %q", b.String())
	}
	plantLogs(t, r)
	b.Reset()
	r.reset()
	err = r.m.Log(ctx, "tail", []string{"many"}, &b)
	wantCode(t, err, 1)
	contains(t, r.stderr.String(), "tail: invalid number of lines: 'many'")
}

// "log clear --backend radius: truncates the three logs after a yes".
func TestLogClear(t *testing.T) {
	r := newEnv(t)
	r.up()
	plantLogs(t, r)
	ctx := context.Background()
	var b strings.Builder
	if err := r.m.Log(ctx, "clear", []string{"-y"}, &b); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{r.m.L.AuthLog, r.m.L.AcctLog, r.m.L.DaemonLog} {
		st, err := os.Stat(f)
		if err != nil || st.Size() != 0 {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
	out := strip(b.String())
	contains(t, out, "Clear RADIUS logs\n")
	contains(t, out, "[WARN] This truncates "+r.m.L.AuthLog+", "+r.m.L.AcctLog+" and "+r.m.L.DaemonLog+".\n")
	contains(t, out, "[WARN] Historical authentication and accounting records will be lost.\n")
	contains(t, out, "[INFO] RADIUS logs cleared.\n")
}

// A clear without -y asks; anything but y or Y (and a closed stdin) cancels.
func TestLogClearAsks(t *testing.T) {
	for _, c := range []struct {
		in      string
		cleared bool
	}{{"y\n", true}, {"Y\n", true}, {"yes\n", false}, {"n\n", false}, {"", false}} {
		r := newEnv(t)
		r.up()
		plantLogs(t, r)
		r.env.Stdin = strings.NewReader(c.in)
		var b strings.Builder
		if err := r.m.Log(context.Background(), "clear", nil, &b); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(r.m.L.AuthLog)
		if cleared := st.Size() == 0; cleared != c.cleared {
			t.Errorf("answer %q: cleared %v", c.in, cleared)
		}
		if !c.cleared {
			contains(t, strip(b.String()), "[INFO] Cancelled.\n")
		}
	}
}

// An unknown sub-command is unsupported (exit 2) and writes nothing.
func TestLogUnsupported(t *testing.T) {
	r := newEnv(t)
	var b strings.Builder
	wantCode(t, r.m.Log(context.Background(), "nope", nil, &b), 2)
	wantCode(t, r.m.Accounting(context.Background(), "nope", nil, &b), 2)
	if b.Len() != 0 {
		t.Error("wrote something")
	}
}

// "last login: the newest Access-Accept of exactly that user; a longer name
// ending the same does not count".
func TestLastLogin(t *testing.T) {
	r := newEnv(t)
	r.up()
	now := plantLogs(t, r)
	ctx := context.Background()
	got := func(user string) string {
		t.Helper()
		ts, err := r.m.LastLogin(ctx, user)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	if got("alice") != now {
		t.Errorf("alice: %q (want %q)", got("alice"), now)
	}
	// 'user=alice bob' was rejected, and is neither alice's nor bob's login.
	if got("bob") != "never" {
		t.Errorf("bob: %q", got("bob"))
	}
	if got("ghost") != "never" {
		t.Errorf("ghost: %q", got("ghost"))
	}
	// Through the Set: the newest any enabled backend knows of.
	if got := r.set.LastLogin(ctx, "alice"); got != now {
		t.Errorf("set: %q", got)
	}
	// An unreadable or absent log is "never".
	if err := os.Remove(r.m.L.AuthLog); err != nil {
		t.Fatal(err)
	}
	if got("alice") != "never" {
		t.Errorf("no log: %q", got("alice"))
	}
	r.tac.LastLoginAt = ""
}

// "secret_constraints: the interoperability advice".
func TestSecretConstraints(t *testing.T) {
	r := newEnv(t)
	if got := r.m.SecretConstraints(); got != (backend.Constraints{MaxLen: 63, Charset: "[!-~]"}) {
		t.Errorf("%+v", got)
	}
}

// "describe: no import command (a hand edit cannot be adopted)".
func TestDescribe(t *testing.T) {
	r := newEnv(t)
	d := r.m.Describe()
	want := backend.Description{Protocol: "radius", Impl: "freeradius", Units: []string{"freeradius.service"},
		User: "freerad", ConfigDir: r.m.L.Dir, LogDir: r.m.L.LogDir}
	if d.Protocol != want.Protocol || d.Impl != want.Impl || strings.Join(d.Units, ",") != strings.Join(want.Units, ",") ||
		d.User != want.User || d.ConfigDir != want.ConfigDir || d.LogDir != want.LogDir || d.ImportCmd != "" {
		t.Errorf("%+v", d)
	}
	rr := newEnv(t, rhel)
	if d := rr.m.Describe(); d.Units[0] != "radiusd.service" || d.User != "radiusd" || d.ImportCmd != "" {
		t.Errorf("rhel: %+v", d)
	}
	if r.m.ID() != "radius" {
		t.Error(r.m.ID())
	}
	if got := strings.Join(r.m.Artifacts(), ","); got != r.m.L.Conf+","+r.m.L.Users+","+r.m.L.Dict {
		t.Errorf("artifacts %s", got)
	}
}

// "installed: needs the daemon and something of tacctl's (drop-in or
// rendered config)".
func TestInstalled(t *testing.T) {
	r := newEnv(t)
	l := r.m.L
	if r.m.Installed() {
		t.Error("the package alone is not tacctl's install")
	}
	writeFile(t, l.Conf, "")
	if !r.m.Installed() {
		t.Error("a rendered config is")
	}
	if err := os.Remove(l.Conf); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(l.DropIn[:strings.LastIndex(l.DropIn, "/")], 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, l.DropIn, "")
	if !r.m.Installed() {
		t.Error("so is the drop-in")
	}
	if err := os.Chmod(l.Bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if r.m.Installed() {
		t.Error("a daemon that is not executable is not installed")
	}
	if err := os.Remove(l.Bin); err != nil {
		t.Fatal(err)
	}
	if r.m.Installed() {
		t.Error("no daemon")
	}
}

// "device_vars: the ports of the built-in listeners and the scope's secret".
func TestDeviceVars(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	ctx := context.Background()
	v, err := r.m.DeviceVars(ctx, "cisco", "prod")
	if err != nil {
		t.Fatal(err)
	}
	if v["AUTH_PORT"] != "1812" || v["ACCT_PORT"] != "1813" || v["SECRET"] != "prod-secret-0123456789abcdef" || len(v) != 3 {
		t.Errorf("%v", v)
	}
	r.enableList("radius")
	if err := r.env.Conf.SetJSON("listeners.radius.auth", `{"network": "udp", "address": "10.1.1.1:11812", "role": "auth"}`); err != nil {
		t.Fatal(err)
	}
	v, _ = r.m.DeviceVars(ctx, "juniper", "prod")
	if v["AUTH_PORT"] != "11812" || v["ACCT_PORT"] != "1813" {
		t.Errorf("%v", v)
	}
	// No scope, or one that does not exist: the ports only.
	for _, scope := range []string{"", "nowhere"} {
		v, _ = r.m.DeviceVars(ctx, "cisco", scope)
		if _, ok := v["SECRET"]; ok || len(v) != 2 {
			t.Errorf("scope %q: %v", scope, v)
		}
	}
}

// The module passes the contract test every module must.
func TestContract(t *testing.T) {
	r := newEnv(t)
	faketest.CheckContract(t, r.m)
	faketest.CheckContract(t, newEnv(t, rhel).m)
}

// The lifecycle phases are WP3.3c's: a phase of the lifecycle is reported
// as not implemented; one the module does not know is a no-op.
func TestLifecyclePlaceholders(t *testing.T) {
	r := newEnv(t)
	ctx := context.Background()
	for _, p := range backend.InstallPhases {
		if err := r.m.Install(ctx, p, "/tree"); err == nil || !strings.Contains(err.Error(), "WP3.3c") {
			t.Errorf("install %s: %v", p, err)
		}
	}
	if r.m.Install(ctx, "nope", "/tree") != nil || r.m.Upgrade(ctx, "nope", "/tree") != nil || r.m.Uninstall(ctx, "nope", false) != nil {
		t.Error("an unknown phase is not a no-op")
	}
	// The phases radius has no work in are no-ops.
	if r.m.Upgrade(ctx, backend.PhasePreflight, "/tree") != nil || r.m.Upgrade(ctx, backend.PhaseBuild, "/tree") != nil ||
		r.m.Uninstall(ctx, backend.PhaseProgram, false) != nil || r.m.Uninstall(ctx, backend.PhaseAccount, false) != nil {
		t.Error("a phase without work failed")
	}
}

// The factory registered with the default registry makes the module, with
// the family TACCTL_RADIUS_FAMILY names.
func TestRegisteredFactory(t *testing.T) {
	r := newEnv(t, rhel)
	reg := backend.Default()
	if !reg.Has(backend.RADIUS) {
		t.Fatal("radius is not registered")
	}
	set := backend.NewSet(reg, r.env)
	b, err := set.Get(backend.RADIUS)
	if err != nil {
		t.Fatal(err)
	}
	if d := b.Describe(); d.Units[0] != "radiusd.service" {
		t.Errorf("%+v", d)
	}
}
