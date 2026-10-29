package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// What the timing scale is applied to (0.2.22): the host-key scans, the
// sessions, the SNMP timeout and the time of a pull. A scale of 1 changes
// nothing; an option typed on the command line wins.

// The three levels are read from their files: the device's registry entry,
// the scope's key and the server's key, and a hand-edited value outside the
// bounds is skipped (config validate says so).
func TestTimeoutScaleOfReadsTheThreeLevels(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"sat-j", "192.168.1.20", "juniper"}, [3]string{"sat-c", "192.168.1.30", "cisco"})
	sb := b.sb
	inv := sb.scaleInv()
	if got := inv.timeoutScaleOf("lab", 0); got.N != 1 || got.From != scaleFromBuiltIn {
		t.Errorf("nothing set: %+v", got)
	}
	sb.cfgRun("", []string{"config", "devices", "timeout-scale", "2"}, nil)
	sb.said(0, "The timeout scale of the whole server set to 2.")
	inv = sb.scaleInv()
	if got := inv.timeoutScaleOf("lab", 0); got.N != 2 || got.From != scaleFromGlobal {
		t.Errorf("server's: %+v", got)
	}
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "4"}, nil)
	inv = sb.scaleInv()
	if got := inv.timeoutScaleOf("lab", 0); got.N != 4 || got.From != scaleFromScope {
		t.Errorf("scope's: %+v", got)
	}
	if got := inv.timeoutScaleOf("other", 0); got.N != 2 || got.From != scaleFromGlobal {
		t.Errorf("another scope follows the server's: %+v", got)
	}
	sb.dev("", "timeout-scale", "sat-j", "6")
	e := inv.scaleAt("192.168.1.20")
	if e != 6 {
		t.Errorf("scaleAt a device with its own scale: %d", e)
	}
	if e := inv.scaleAt("192.168.1.30"); e != 4 {
		t.Errorf("scaleAt a device of the scope: %d", e)
	}
	// an address no device is at takes its scope's
	if e := inv.scaleAt("192.168.1.99"); e != 4 {
		t.Errorf("scaleAt an unregistered address of the scope: %d", e)
	}
	// a hand-edited value outside the bounds is skipped
	sb.write("state/tacctl.yaml", "device:\n  timeout_scale: 11\ntimeout_scale_scope:\n  lab: 0\n", 0o640)
	inv = sb.scaleInv()
	if got := inv.timeoutScaleOf("lab", 0); got.N != 1 || got.From != scaleFromBuiltIn {
		t.Errorf("values outside the bounds: %+v", got)
	}
}

// keyscanT is the -T of every ssh-keyscan the run made, in order.
func keyscanT(sb *sandbox) []string {
	var out []string
	for _, c := range sb.runner.Calls() {
		if c.Name != "ssh-keyscan" {
			continue
		}
		for i, a := range c.Args {
			if a == "-T" && i+1 < len(c.Args) {
				out = append(out, c.Args[i+1])
			}
		}
	}
	return out
}

// 'device add' scans with the scale in force for the address: the scope's
// here, and the timing reaches both ssh-keyscan and the built-in client.
func TestHostKeyScanUsesTheScale(t *testing.T) {
	sb := newSandbox(t, true)
	var got []devssh.ScanTiming
	sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
		return func(_ context.Context, _ string, _ int, _ bool, tm devssh.ScanTiming) ([]devreg.HostKey, error) {
			got = append(got, tm)
			return []devreg.HostKey{hkKey(t, "rsa")}, nil
		}
	}
	// scale 1: ssh-keyscan -T 5, the built-in client at the defaults
	sb.devScan("", scan("192.168.1.50", hkKey(t, "ed25519")), "add", "x1", "192.168.1.50", "--vendor", "cisco")
	if sb.code != 0 || strings.Join(keyscanT(sb), " ") != "5" {
		t.Errorf("scale 1: %d, -T %q\n%s", sb.code, keyscanT(sb), sb.stderr())
	}
	sb.devScan("", nil, "add", "old1", "192.168.1.51", "--vendor", "cisco", "--legacy-ssh", "--no-lookup")
	if len(got) != 1 || got[0] != devssh.DefaultScanTiming() {
		t.Errorf("scale 1: the fallback was given %+v, want the defaults", got)
	}

	// the scope's scale: 3
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "3"}, nil)
	sb.said(0, "timeout scale: 3")
	got = nil
	sb.devScan("", scan("192.168.1.52", hkKey(t, "ed25519")), "add", "x3", "192.168.1.52", "--vendor", "cisco")
	if sb.code != 0 || strings.Join(keyscanT(sb), " ") != "15" {
		t.Errorf("scale 3: %d, -T %q\n%s", sb.code, keyscanT(sb), sb.stderr())
	}
	sb.devScan("", nil, "add", "old3", "192.168.1.53", "--vendor", "cisco", "--legacy-ssh", "--no-lookup")
	if want := (devssh.ScanTiming{}).Scaled(3); len(got) != 1 || got[0] != want || got[0].Handshake != 30*time.Second {
		t.Errorf("scale 3: the fallback was given %+v, want %+v", got, want)
	}

	// a device's own scale wins over its scope's
	sb.dev("", "timeout-scale", "old3", "10")
	got = nil
	sb.devScan("", nil, "hostkey", "old3", "accept", "--yes")
	if len(got) != 1 || got[0].Handshake != 100*time.Second || got[0].Attempt != 50*time.Second {
		t.Errorf("device scale 10: the fallback was given %+v", got)
	}
}

// The re-scan of 'device scan' and 'device check' reads each target with the
// timing of its own scale (KeyTarget.Timing).
func TestKeyTargetsCarryTheScale(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "2"}, nil)
	inv := sb.scaleInv()
	mk := func(name, addr, scope string, own int) devreg.Entry {
		return devreg.Entry{Device: devreg.Device{Name: name, Address: addr, Vendor: "cisco", TimeoutScale: own, HostKeys: []string{"ssh-ed25519 AAAA"}},
			Source: devreg.SourceDevice, Scope: scope}
	}
	ts := inv.keyTargets([]devreg.Entry{mk("a", "192.168.1.1", "lab", 0), mk("b", "192.168.1.2", "lab", 7), mk("c", "192.0.2.9", "", 0)}, false)
	if len(ts) != 3 {
		t.Fatalf("targets %+v", ts)
	}
	for i, want := range []int{2, 7, 1} {
		if ts[i].Timing != (devssh.ScanTiming{}).Scaled(want) {
			t.Errorf("%s: timing %+v, want scale %d", ts[i].Name, ts[i].Timing, want)
		}
	}
	if ts[2].Timing != devssh.DefaultScanTiming() {
		t.Errorf("an unscaled target is not at the defaults: %+v", ts[2].Timing)
	}
}

// The session to a device connects within the budget its scale gives.
func TestDeviceSessionsUseTheScale(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "3"}, nil)
	inv := sb.scaleInv()
	e := func(own int) devreg.Entry {
		return devreg.Entry{Device: devreg.Device{Name: "a", Address: "192.168.1.1", Vendor: "juniper", TimeoutScale: own}, Source: devreg.SourceDevice, Scope: "lab"}
	}
	for own, want := range map[int]time.Duration{0: 30 * time.Second, 5: 50 * time.Second} {
		if got := inv.deviceTarget(e(own), "alice", nil).ConnectTimeout; got != want {
			t.Errorf("scale %d: ConnectTimeout %v, want %v", own, got, want)
		}
	}
	plain := devreg.Entry{Device: devreg.Device{Name: "p", Address: "192.0.2.1", Vendor: "juniper"}, Source: devreg.SourceDevice}
	if got := inv.deviceTarget(plain, "alice", nil).ConnectTimeout; got != devssh.DefaultConnectTimeout {
		t.Errorf("a device of no scope: %v, want %v", got, devssh.DefaultConnectTimeout)
	}
}

// 'tacctl ssh' passes the connect timeout of the scale in force.
func TestSSHConnectTimeoutUsesTheScale(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	sb.dev("", "timeout-scale", "lab-rtr2", "4")
	sb.sshRun("alice", func(r *fake.Runner) { r.On([]string{"sudo"}, execx.Result{}) }, "ssh", "lab-rtr2")
	if argv := sb.sshArgv(); !strings.Contains(argv, "-o ConnectTimeout=40 ") || strings.Contains(argv, "ConnectTimeout=10") {
		t.Errorf("scale 4: %s", argv)
	}
	sb.sshRun("alice", func(r *fake.Runner) { r.On([]string{"sudo"}, execx.Result{}) }, "ssh", "core-sw1")
	if argv := sb.sshArgv(); !strings.Contains(argv, "-o ConnectTimeout=10 ") {
		t.Errorf("scale 1: %s", argv)
	}
}

// The SNMP wait is the timeout times the scale, never above the most SNMP
// takes, and the three shows say so.
func TestSNMPTimeoutUsesTheScale(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"sat-j", "192.168.1.20", "juniper"})
	sb := b.sb
	sb.scopeSNMP("lab-community-1\nlab-community-1\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "version", "v2c")
	timeout := func() time.Duration {
		t.Helper()
		c, problem := sb.scaleInv().snmpConfigFor("lab")
		if problem != "" {
			t.Fatal(problem)
		}
		return c.Timeout
	}
	if got := timeout(); got != 2*time.Second {
		t.Errorf("scale 1: %v", got)
	}
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "3"}, nil)
	if got := timeout(); got != 6*time.Second {
		t.Errorf("scale 3: %v", got)
	}
	if out := sb.scopeSNMP("", "lab", "show"); !strings.Contains(out, "x 3 (timing scale) = 6 s on the wire, never above 10 s") {
		t.Errorf("scope snmp show:\n%s", out)
	}
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "10"}, nil)
	if got := timeout(); got != 10*time.Second {
		t.Errorf("scale 10 is held to the maximum: %v", got)
	}
	// the device's own timeout is scaled too, and so is its own scale
	sb.dev("", "snmp", "sat-j", "timeout", "4")
	sb.dev("", "timeout-scale", "sat-j", "2")
	d := sb.scaleInv().deviceNamed("sat-j")
	own, err := sb.scaleInv().deviceSNMPOwnOf(*d)
	if err != nil {
		t.Fatal(err)
	}
	c, problem := sb.scaleInv().snmpConfigOwn("lab", own)
	if c.Timeout != 8*time.Second {
		t.Errorf("device timeout 4 s at scale 2: %v (%s)", c.Timeout, problem)
	}
	out := sb.dev("", "snmp", "sat-j", "show")
	if !strings.Contains(out, "timeout:    4 s, one retry") || !strings.Contains(out, "x 2 (timing scale) = 8 s on the wire, never above 10 s") {
		t.Errorf("device snmp show:\n%s", out)
	}
	// the default's show names it too, at its own scale
	sb.cfgRun("", []string{"config", "devices", "timeout-scale", "5"}, nil)
	if out := plain(sb.cfgRun("", []string{"config", "snmp", "show"}, nil)); !strings.Contains(out, "x 5 (timing scale) = 10 s on the wire") {
		t.Errorf("config snmp:\n%s", out)
	}
}

// At scale 1 the shows say nothing of a scale.
func TestSNMPShowsAtScaleOneAreUnchanged(t *testing.T) {
	sb := newSandbox(t, true)
	if out := sb.scopeSNMP("", "lab", "show"); strings.Contains(out, "timing scale") {
		t.Errorf("scope snmp show:\n%s", out)
	}
	if out := plain(sb.cfgRun("", []string{"config", "snmp", "show"}, nil)); strings.Contains(out, "timing scale") {
		t.Errorf("config snmp:\n%s", out)
	}
}

// The per-device time of a run is the setting scaled for each device unless a
// time was typed, and a run of unscaled devices is untouched.
func TestScaleJobTimeouts(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "3"}, nil)
	inv := sb.scaleInv()
	entry := func(name, scope string, own int) devreg.Entry {
		return devreg.Entry{Device: devreg.Device{Name: name, Address: "192.0.2.1", TimeoutScale: own}, Scope: scope}
	}
	var seen = map[string]time.Duration{}
	job := func(name string, status batch.Status) batch.Job {
		return batch.Job{Name: name, Do: func(ctx context.Context) batch.Result {
			if dl, ok := ctx.Deadline(); ok {
				seen[name] = time.Until(dl).Round(10 * time.Second)
			}
			if status == batch.StatusFailed {
				<-ctx.Done()
				return batch.Result{Status: batch.StatusFailed, Err: ctx.Err()}
			}
			return batch.Result{Status: status}
		}}
	}
	base := 90 * time.Second

	// nobody scaled: the same time, the same jobs
	entries := []devreg.Entry{entry("a", "other", 0), entry("b", "", 0)}
	jobs := []batch.Job{job("a", batch.StatusOK), job("b", batch.StatusOK)}
	if got, out := inv.scaleJobTimeouts(entries, jobs, base, false); got != base || len(out) != 2 {
		t.Errorf("unscaled: %v %d", got, len(out))
	}
	// a typed time wins over every scale
	entries = []devreg.Entry{entry("a", "lab", 0), entry("b", "lab", 9)}
	jobs = []batch.Job{job("a", batch.StatusOK), job("b", batch.StatusOK)}
	if got, out := inv.scaleJobTimeouts(entries, jobs, 25*time.Second, true); got != 25*time.Second || len(out) != 2 {
		t.Errorf("typed: %v", got)
	}
	// the same scale for all: one budget, jobs untouched
	jobs = []batch.Job{job("a", batch.StatusOK), job("b", batch.StatusOK)}
	entries = []devreg.Entry{entry("a", "lab", 0), entry("b", "lab", 0)}
	if got, _ := inv.scaleJobTimeouts(entries, jobs, base, false); got != 270*time.Second {
		t.Errorf("one scale for all: %v", got)
	}
	// different scales: the run's budget is the longest, a shorter job is held
	// to its own, and an overrun is a timeout
	entries = []devreg.Entry{entry("a", "other", 0), entry("b", "lab", 0), entry("c", "lab", 10)}
	jobs = []batch.Job{job("a", batch.StatusOK), job("b", batch.StatusOK), job("c", batch.StatusOK)}
	got, out := inv.scaleJobTimeouts(entries, jobs, base, false)
	if got != 600*time.Second || len(out) != 3 {
		t.Fatalf("mixed: %v %d", got, len(out))
	}
	ctx, cancel := context.WithTimeout(context.Background(), got)
	defer cancel()
	for _, j := range out {
		_ = j.Do(ctx)
	}
	if seen["a"] != 90*time.Second || seen["b"] != 270*time.Second {
		t.Errorf("deadlines a=%v b=%v (c has the run's own)", seen["a"], seen["b"])
	}
	if _, ok := seen["c"]; !ok {
		t.Error("the longest job did not run")
	}
}

// A job held to a time shorter than the run's is a timeout when it overruns
// it, and its own result otherwise.
func TestHoldToTimeout(t *testing.T) {
	slow := batch.Job{Name: "a", Do: func(ctx context.Context) batch.Result {
		<-ctx.Done()
		return batch.Result{Status: batch.StatusFailed, Err: ctx.Err()}
	}}
	r := holdToTimeout(slow, 30*time.Millisecond).Do(context.Background())
	if r.Status != batch.StatusTimeout || r.Reason != "timeout after 30ms" {
		t.Errorf("an overrun: %+v", r)
	}
	// the run's own deadline passing first is not the job's timeout
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := holdToTimeout(slow, time.Hour).Do(ctx); r.Status != batch.StatusFailed {
		t.Errorf("the run ended first: %+v", r)
	}
	// a failure of the job's own, before its deadline, stays one
	bad := batch.Job{Name: "b", Do: func(context.Context) batch.Result {
		return batch.Result{Status: batch.StatusFailed, Reason: "authentication failed"}
	}}
	if r := holdToTimeout(bad, time.Hour).Do(context.Background()); r.Status != batch.StatusFailed || r.Reason != "authentication failed" {
		t.Errorf("a failure: %+v", r)
	}
}

// A pull of a scaled device runs as it does at scale 1: the session connects
// with its scaled budget and the pull is recorded.
func TestPullOfAScaledDevice(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "timeout-scale", "lab-j", "3")
	b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %q", b.sb.code, b.sb.stderr())
	}
	if rec, _ := b.records().Of("lab-j"); rec == nil || rec.Result != "ok" {
		t.Errorf("record %+v", rec)
	}
}

// --timeout typed on the command line is the device's time, whatever the
// scale: a device at scale 10 that never answers costs the 10 s typed, not the
// 100 s the scale would give.
func TestTypedTimeoutWinsOverTheScale(t *testing.T) {
	if testing.Short() {
		t.Skip("the shortest timeout is 10 s")
	}
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	if err := os.WriteFile(filepath.Join(b.dir, junosReadCmd+".hang"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	b.run("device", "timeout-scale", "lab-j", "10")
	start := time.Now()
	out := b.run("device", "config", "pull", "lab-j", "--transport", "ssh", "--timeout", "10")
	if b.sb.code != 1 || !strings.Contains(out, "failed: timed out") {
		t.Errorf("exit %d\n%s", b.sb.code, out)
	}
	if d := time.Since(start); d > 40*time.Second {
		t.Errorf("took %v: the scale replaced the typed --timeout", d)
	}
}
