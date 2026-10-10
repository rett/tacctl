package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// 'tacctl rollback' (D73 of docs/plans/0.2.4-plan.md) on the host sandbox of
// host_test.go: a 0.2.4 state built with the verbs that write the formats
// 0.2.3 does not read, then rolled back. rollback.bats pins the command
// lines; the files' conversions are tested in internal/{conf,console,devreg,
// tier,lifecycle}.

// step runs one verb of the state's building and fails the test unless it
// exits 0.
func (hs *hostSandbox) step(stdin string, args ...string) {
	hs.t.Helper()
	hs.stdin = stdin
	hs.run(nil, args...)
	hs.stdin = ""
	if hs.code != 0 {
		hs.t.Fatalf("%v: exit %d\n%s%s", args, hs.code, hs.out.String(), hs.err.String())
	}
}

// rollbackState is a 0.2.4 install: the settings 0.2.3 has (an engineer
// group at tier engineer, per-scope SNMP settings and credentials, a
// break-glass user, a device with a location, space completion off, an
// engineer-sudo list), and 0.2.4's: the device.config keys, the password
// cache's tiers, two devices with SNMP settings of their own (and
// credentials), the records of a pull, and the sudoers drop-ins as 0.2.4
// writes them.
func rollbackState(t *testing.T) *hostSandbox {
	t.Helper()
	hs := newHostSandbox(t)
	hs.sudoersEnv()
	hs.step("", "group", "add", "engineer", "15", "EN-CLASS")
	hs.step("", "group", "edit", "engineer", "tier", "engineer")
	hs.step("", "user", "add", "erin", "engineer", "--hash", testHash, "--scopes", "lab")
	hs.step("", "scope", "snmp", "lab", "version", "v2c")
	hs.step("", "scope", "snmp", "lab", "contact", "NOC, building 2")
	hs.step("lab-community-1\nlab-community-1\n", "scope", "snmp", "lab", "community", "--stdin")
	hs.step("", "scope", "breakglass", "lab", "add", "bg-admin")
	hs.step("", "device", "add", "sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	hs.step("", "device", "add", "sw2", "10.99.0.2", "--vendor", "juniper", "--no-host-key")
	hs.step("", "device", "add", "sw3", "10.99.0.3", "--vendor", "cisco", "--no-host-key")
	hs.step("", "device", "location", "sw1", "Rack 4, DC1")
	hs.step("", "console", "space-completion", "off")
	hs.step("", "config", "linux", "engineer-sudo", "/usr/bin/systemctl")
	// 0.2.4's.
	hs.step("", "device", "snmp", "sw1", "version", "v3")
	hs.step("", "device", "snmp", "sw1", "port", "2161")
	hs.step("", "device", "snmp", "sw1", "timeout", "4")
	hs.step("", "device", "snmp", "sw1", "clients", "add", "10.1.0.0/16")
	hs.step("sw2-community\nsw2-community\n", "device", "snmp", "sw2", "community", "--stdin")
	hs.step("", "console", "password-cache", "tiers", "engineer,superuser")
	hs.step("", "config", "devices", "max-concurrency", "16")
	hs.step("", "config", "devices", "transport", "ssh")
	hs.step("", "config", "devices", "timeout", "120")
	hs.write("var-lib/devices-config.json", "{\"version\": 1, \"devices\": {}}\n", 0o600)
	hs.write("var-lib/device-config/sw1.yaml", "aaa: []\n", 0o600)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers(), 0o640)
	hs.write("sudoers.d/tacctl", tier.GroupSudoers("ops"), 0o640)
	hs.write("var-lib/tier-pinned", "", 0o644)
	return hs
}

// sudoersEnv points the two sudoers drop-ins into the sandbox (the host
// sandbox leaves them at /etc/sudoers.d).
func (hs *hostSandbox) sudoersEnv() {
	hs.env = append(hs.env, "TACCTL_TIER_SUDOERS_FILE="+hs.path("sudoers.d", "tacctl-tiers"), "TACCTL_SUDOERS_FILE="+hs.path("sudoers.d", "tacctl"))
}

// sudoersInstall scripts 'install' as the real one does for the sandbox: the
// checked temporary file is copied to its destination.
func sudoersInstall(r *fake.Runner) {
	r.Func(func(c execx.Cmd) bool { return c.Name == "install" }, func(c execx.Cmd) (execx.Result, error) {
		data, err := os.ReadFile(c.Args[len(c.Args)-2])
		if err == nil {
			err = os.WriteFile(c.Args[len(c.Args)-1], data, 0o640)
		}
		return execx.Result{}, err
	})
}

// tree is every regular file under dir, by path, with its bytes.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[p] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func changedFiles(before, after map[string]string) []string {
	var out []string
	for p, b := range before {
		if a, ok := after[p]; !ok || a != b {
			out = append(out, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// all is stdout and stderr, without colours.
func (hs *hostSandbox) all() string { return plain(hs.out.String() + hs.err.String()) }

// Versions other than 0.2.3 are refused with the reason, and nothing is read
// for writing; 0.2.2 is refused with the two steps that reach it.
func TestRollbackRefusesOtherVersions(t *testing.T) {
	hs := rollbackState(t)
	before := tree(t, hs.dir)
	for _, c := range []struct{ arg, want string }{
		{"0.2.2", "prepares the state for 0.2.3 only (0.2.2 is older)"},
		{"0.2.1", "Rolling back to 0.2.1 is not supported from this release"},
		{"0.1.16", "is older"},
		{"0.2.4", "prepares the state for 0.2.3 only"},
		{"0.3.0", "prepares the state for 0.2.3 only"},
		{"main", "is not a release this tacctl knows"},
	} {
		for _, extra := range [][]string{nil, {"--apply", "--yes"}} {
			hs.run(nil, append([]string{"rollback", c.arg}, extra...)...)
			hs.expect(1, "", c.want)
			if !strings.Contains(hs.err.String(), "Nothing was changed.") && !strings.Contains(hs.err.String(), "Usage: tacctl rollback") {
				t.Errorf("%s: %q", c.arg, hs.err.String())
			}
		}
	}
	hs.run(nil, "rollback", "0.2.2")
	for _, want := range []string{"Go back one release at a time", "tacctl rollback 0.2.3 --apply", "tacctl upgrade --branch 0.2.3",
		"0.2.3's prepares the state for 0.2.2", "tacctl backup restore"} {
		if !strings.Contains(hs.err.String(), want) {
			t.Errorf("0.2.2: no %q in %q", want, hs.err.String())
		}
	}
	if !reflectEqual(before, tree(t, hs.dir)) {
		t.Errorf("a refused rollback changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

func reflectEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestRollbackUsage(t *testing.T) {
	hs := rollbackState(t)
	before := tree(t, hs.dir)
	for _, args := range [][]string{{"rollback"}, {"rollback", "0.2.3", "extra"}, {"rollback", "0.2.3", "--bogus"}, {"rollback", "--apply"},
		{"rollback", "0.2.3", "--apply", "--apply"}, {"rollback", "0.2.3", "--yes=1"}} {
		hs.run(nil, args...)
		hs.expect(1, "", "Usage: tacctl rollback <version> [--apply] [--yes] [--hosts]")
	}
	if !reflectEqual(before, tree(t, hs.dir)) {
		t.Error("a usage changed a file")
	}
}

// The dry run is the default: it lists every step and every warning and
// writes nothing, not a byte, not a snapshot, not a lock file, and runs no
// program.
func TestRollbackDryRunWritesNothing(t *testing.T) {
	hs := rollbackState(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.3"}, {"rollback", "0.2.3", "--hosts"}, {"rollback", "v0.2.3"}, {"rollback", "0.2.3", "--yes"}} {
		r := hs.runner()
		hs.run(r, args...)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if !reflectEqual(before, tree(t, hs.dir)) {
			t.Errorf("%v changed %q", args, changedFiles(before, tree(t, hs.dir)))
		}
		if hs.snapshots() != snaps || len(r.Execs()) != 0 || r.Called("ssh") || r.Called("systemctl") || r.Called("visudo") || r.Called("install") {
			t.Errorf("%v: a snapshot, an ssh, a restart or a sudoers install: %q", args, r.Argvs())
		}
	}
	hs.run(nil, "rollback", "0.2.3", "--hosts")
	out := hs.all()
	state := hs.path("state")
	for _, want := range []string{
		"Roll back to 0.2.3 (dry run)",
		"1. " + state + "/tacctl.yaml: remove the keys 0.2.3 does not know   [does]",
		"remove device.config.max_concurrency", "remove device.config.transport", "remove device.config.timeout",
		"2. " + state + "/console.yaml: write it the way 0.2.3 reads it   [does]",
		"remove settings.password_cache: tiers engineer,superuser, idle 15 min, max 8 h",
		"3. " + state + "/devices.yaml: remove the per-device SNMP settings   [does]",
		"remove the snmp map of sw1 (version v3, port 2161, timeout 4 s, 1 client range)", "remove the snmp map of sw2 (version v2c)",
		"4. put back the sudoers drop-ins 0.2.3 writes   [does]",
		"rewrite " + hs.path("sudoers.d", "tacctl-tiers"), "rewrite " + hs.path("sudoers.d", "tacctl"),
		"5. leave " + state + "/snmp/devices (the devices' own SNMP credentials)   [leaves]", "1 file (mode 0600, kept): sw2",
		"6. leave the configuration records in " + hs.path("var-lib") + "   [leaves]",
		"leaves " + hs.path("var-lib", "devices-config.json"), "leaves " + hs.path("var-lib", "device-config") + " (1 file)",
		"7. leave " + state + "/store.yaml untouched",
		"8. the enrolled Linux hosts (--hosts)   [leaves]", "no host is synced",
		"Warnings (--apply refuses without --yes while any applies)",
		"1. Settings 0.2.3 cannot use are dropped",
		"sw1: version v3, port 2161, timeout 4 s, 1 client range", "sw2: version v2c",
		"device.config.max_concurrency=16, device.config.transport=ssh, device.config.timeout=120",
		"The password cache's settings of console.yaml are removed",
		"restore it with 0.2.4",
		"To convert the state: tacctl rollback 0.2.3 --apply --yes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	// What 0.2.3 has is not touched, and no host is synced for --hosts.
	for _, not := range []string{"linux.engineer_sudo", "snmp_scope", "breakglass_scope", "TAC_REVOKE_ENGINEER", "tier-pinned", "Engineers become superusers", "Add --hosts"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run names %q:\n%s", not, out)
		}
	}
}

// --apply refuses while a warning applies and --yes is missing; nothing is
// changed, not even a snapshot.
func TestRollbackApplyNeedsYes(t *testing.T) {
	hs := rollbackState(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	hs.run(nil, "rollback", "0.2.3", "--apply")
	hs.expect(1, "Warnings (--apply refuses without --yes", "The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed.")
	hs.run(nil, "rollback", "0.2.3", "--apply", "--hosts")
	hs.expect(1, "", "need your decision")
	if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps {
		t.Errorf("a refused apply changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

// The round trip: --apply --yes converts the state; store.yaml is
// byte-identical; every converted file is one a 0.2.3 reader accepts (the
// fixtures below, and the real 0.2.3 binary in TestRollbackRealOldBinary);
// what 0.2.3 ignores is left; a second --apply changes nothing, not even a
// snapshot.
func TestRollbackRoundTrip(t *testing.T) {
	hs := rollbackState(t)
	storeBefore := hs.store()
	before := tree(t, hs.dir)
	snaps := hs.snapshots()

	// The 0.2.4 form is what the fixtures refuse.
	problems := old023Problems(t, hs)
	for _, want := range []string{"tacctl.yaml: device.config.max_concurrency", "tacctl.yaml: device.config.transport", "tacctl.yaml: device.config.timeout",
		"console.yaml: settings.password_cache", "devices.yaml: device 'sw1' has snmp", "devices.yaml: device 'sw2' has snmp"} {
		if !slices.Contains(problems, want) {
			t.Errorf("the 0.2.4 state is not refused for %q: %q", want, problems)
		}
	}

	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.3", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out := hs.all()
	for _, want := range []string{"Config snapshot saved to", "state/tacctl.yaml: removed 3 keys", "state/console.yaml: removed settings.password_cache",
		"state/devices.yaml: removed the SNMP settings of 2 devices",
		"sudoers.d/tacctl-tiers: rewritten with the text 0.2.3 writes", "sudoers.d/tacctl: rewritten with the text 0.2.3 writes",
		"Next steps", "tacctl upgrade --branch 0.2.3", "holds the 0.2.4 state. Restore it with 0.2.4 only"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	// visudo checked both before the install; no service was restarted.
	if !r.CalledRegexp(`^visudo -cf .*/tmp\.`) || len(r.Execs()) != 0 || r.Called("systemctl") || r.Called("ssh") {
		t.Errorf("calls: %q", r.Argvs())
	}
	// The snapshot is taken first and holds the 0.2.4 form (the devices'
	// credentials included).
	if hs.snapshots() != snaps+1 {
		t.Fatalf("snapshots %d -> %d", snaps, hs.snapshots())
	}
	snap := newestSnapshot(t, hs)
	for _, rel := range []string{"tacctl.yaml", "console.yaml", "devices.yaml"} {
		b, err := os.ReadFile(filepath.Join(snap, rel))
		if err != nil || string(b) != before[hs.path("state", rel)] {
			t.Errorf("the snapshot's %s is not the state before (%v)", rel, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(snap, "snmp", "devices", "sw2.yaml")); err != nil || string(b) != before[hs.path("state", "snmp", "devices", "sw2.yaml")] {
		t.Errorf("the snapshot's snmp/devices/sw2.yaml is not the credentials before (%v)", err)
	}
	if b, _ := os.ReadFile(filepath.Join(snap, "store.yaml")); string(b) != storeBefore {
		t.Error("the snapshot's store.yaml differs")
	}

	// (a) store.yaml byte-identical.
	if hs.store() != storeBefore {
		t.Error("store.yaml changed")
	}
	// (b) every converted file is accepted by a 0.2.3 reader.
	if p := old023Problems(t, hs); len(p) != 0 {
		t.Errorf("a 0.2.3 reader refuses the converted state: %q", p)
	}
	// What the rollback leaves is as it was.
	after := tree(t, hs.dir)
	converted := map[string]bool{hs.path("state", "tacctl.yaml"): true, hs.path("state", "console.yaml"): true, hs.path("state", "devices.yaml"): true,
		hs.path("sudoers.d", "tacctl-tiers"): true, hs.path("sudoers.d", "tacctl"): true}
	for _, p := range changedFiles(before, after) {
		if converted[p] || strings.Contains(p, "/state/backups/") || strings.Contains(p, ".lock") {
			continue
		}
		t.Errorf("the rollback changed %s", strings.TrimPrefix(p, hs.dir))
	}
	for _, kept := range []string{hs.path("state", "snmp", "lab.yaml"), hs.path("state", "snmp", "devices", "sw2.yaml"),
		hs.path("var-lib", "devices-config.json"), hs.path("var-lib", "device-config", "sw1.yaml"), hs.path("var-lib", "tier-pinned")} {
		if a, ok := after[kept]; !ok || a != before[kept] {
			t.Errorf("%s was not left alone", kept)
		}
	}
	// The sudoers files are 0.2.3's text.
	if after[hs.path("sudoers.d", "tacctl-tiers")] != tier.Sudoers023() || after[hs.path("sudoers.d", "tacctl")] != tier.GroupSudoers023("ops") {
		t.Error("a sudoers drop-in is not 0.2.3's text")
	}
	// Settings 0.2.3 has stay.
	ov := hs.overrides()
	for _, kept := range []string{"engineer: engineer", "engineer_sudo:", "snmp_scope:", "breakglass_scope:"} {
		if !strings.Contains(ov, kept) {
			t.Errorf("tacctl.yaml lost %q:\n%s", kept, ov)
		}
	}
	if c := hs.read("state/console.yaml"); !strings.Contains(c, "list_max: 40") || !strings.Contains(c, "engineer: enable") || !strings.Contains(c, "space_completion: false") || strings.Contains(c, "password_cache") {
		t.Errorf("console.yaml:\n%s", c)
	}
	if d := hs.read("state/devices.yaml"); !strings.Contains(d, "location: 'Rack 4, DC1'") || strings.Contains(d, "snmp") {
		t.Errorf("devices.yaml:\n%s", d)
	}

	// Idempotence: nothing to convert, no snapshot, no byte changes.
	r = hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.3", "--apply", "--yes")
	hs.expect(0, "Nothing to convert: every file is one 0.2.3 can read.", "")
	if hs.snapshots() != snaps+1 || r.Called("install") {
		t.Errorf("the second apply took a snapshot or installed: %d %q", hs.snapshots(), r.Argvs())
	}
	if now := tree(t, hs.dir); !reflectEqual(after, now) {
		t.Errorf("the second apply changed %q", changedFiles(after, now))
	}
	// The dry run of a converted state has nothing left to do.
	hs.run(nil, "rollback", "0.2.3")
	if o := hs.all(); strings.Contains(o, "[does]") || !strings.Contains(o, "nothing to remove (every key is one 0.2.3 has)") || strings.Contains(o, "Warnings") {
		t.Errorf("a converted state:\n%s", o)
	}
}

func newestSnapshot(t *testing.T, hs *hostSandbox) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(hs.dir, "state", "backups", "2*"))
	if len(m) == 0 {
		t.Fatal("no snapshot")
	}
	sort.Strings(m)
	return m[len(m)-1]
}

// old023Problems is what a reader of 0.2.3 refuses in the state, as
// fixtures of its three parsers (the tacctl.yaml schema, console.yaml and
// devices.yaml at the 0.2.3 tag): "<file>: <key>" for each.
func old023Problems(t *testing.T, hs *hostSandbox) []string {
	t.Helper()
	var out []string
	c := conf.Load(hs.path("state", "tacctl.yaml"), conf.DefaultBackends)
	for _, k := range c.RollbackKeys023() {
		out = append(out, "tacctl.yaml: "+k)
	}
	if b, err := os.ReadFile(hs.path("state", "console.yaml")); err == nil {
		v, err := pyyaml.LoadBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		root := v.(*yamlpy.Map)
		for section, known := range map[string][]string{
			"tiers": {"readonly", "operator", "engineer", "superuser"},
			"settings": {"idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports", "space_completion",
				"system_shell", "system_shell_tiers", "forwarding_tiers"},
		} {
			if sub, ok := root.Get(section); ok {
				for k := range sub.(*yamlpy.Map).All() {
					if !slices.Contains(known, k) {
						out = append(out, "console.yaml: "+section+"."+k)
					}
				}
			}
		}
	}
	if b, err := os.ReadFile(hs.path("state", "devices.yaml")); err == nil {
		v, err := pyyaml.LoadBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		known := []string{"address", "vendor", "hostname", "description", "location", "port", "legacy_ssh", "host_keys", "ack"}
		if devs, ok := v.(*yamlpy.Map).Get("devices"); ok && devs != nil {
			for name, d := range devs.(*yamlpy.Map).All() {
				for k := range d.(*yamlpy.Map).All() {
					if !slices.Contains(known, k) {
						out = append(out, "devices.yaml: device '"+name+"' has "+k)
					}
				}
			}
		}
	}
	return out
}

// A state without a dropped setting needs no answer: --apply goes through
// (here only the sudoers drop-in is 0.2.4's).
func TestRollbackNoWarningsNoYes(t *testing.T) {
	hs := newHostSandbox(t)
	hs.sudoersEnv()
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers(), 0o640)
	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.3", "--apply")
	hs.expect(0, "Applying.", "")
	if b := hs.read("sudoers.d/tacctl-tiers"); b != tier.Sudoers023() {
		t.Errorf("the tiers drop-in:\n%s", b)
	}
	if hs.store() != fixture(t, "store.multiscope.yaml") {
		t.Error("store.yaml changed")
	}
}

// A drop-in that visudo rejects stays as it was, is reported, and does not
// undo the files; an edited one is left with the reason.
func TestRollbackSudoersFailures(t *testing.T) {
	hs := rollbackState(t)
	r := hs.runner()
	r.On([]string{"visudo"}, execx.Result{Code: 1})
	before := hs.read("sudoers.d/tacctl-tiers")
	hs.run(r, "rollback", "0.2.3", "--apply", "--yes")
	hs.expect(0, "Not rewritten: ", "")
	if o := hs.all(); !strings.Contains(o, "Not rewritten: "+hs.path("sudoers.d", "tacctl-tiers")+": visudo validation failed") {
		t.Errorf("output:\n%s", o)
	}
	if hs.read("sudoers.d/tacctl-tiers") != before || strings.Contains(hs.overrides(), "device:") {
		t.Error("the drop-in changed, or the files were not converted")
	}

	hs = rollbackState(t)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers()+"# local\n", 0o640)
	r = hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.3")
	hs.expect(0, "leaves "+hs.path("sudoers.d", "tacctl-tiers")+": it is not the text this release writes", "")
}

// The gate: only a superuser. No tier row names 'rollback', so the default
// (superuser only) holds; an engineer, an operator and a readonly user are
// refused before the command runs, with and without --apply --hosts.
func TestRollbackIsTheSuperusersAlone(t *testing.T) {
	sb := engineerSandbox(t)
	before := tree(t, sb.dir)
	for _, args := range [][]string{{"rollback", "0.2.3"}, {"rollback", "0.2.3", "--apply", "--yes", "--hosts"}, {"rollback"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
			t.Errorf("engineer %v: %d %q", args, sb.code, sb.stderr())
		}
	}
	// Operator and readonly users of the plain sandbox (no tier settings).
	plainSb := newSandbox(t, true)
	plainBefore := tree(t, plainSb.dir)
	for _, g := range []struct{ user, groups, tier string }{{"bob", "bob tac-users tac-operator", "operator"}, {"carol", "carol tac-users tac-readonly", "readonly"}} {
		plainSb.cfgRun("", []string{"rollback", "0.2.3", "--apply", "--yes", "--hosts"}, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", g.user}, execx.Result{Stdout: []byte(g.groups + "\n")})
		}, "SUDO_USER="+g.user)
		if plainSb.code != 1 || !strings.Contains(plainSb.stderr(), "is not permitted for the "+g.tier+" tier") {
			t.Errorf("%s: %d %q", g.tier, plainSb.code, plainSb.stderr())
		}
	}
	if !reflectEqual(before, tree(t, sb.dir)) || !reflectEqual(plainBefore, tree(t, plainSb.dir)) {
		t.Error("a refused caller changed a file")
	}
}

// --hosts is accepted and touches no host: no ssh, no script pushed, no
// sync, and the dry run says there is nothing to do.
func TestRollbackHostsIsAccepted(t *testing.T) {
	hs := rollbackState(t)
	hs.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\nweb1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.3", "--apply", "--yes", "--hosts")
	hs.expect(0, "Applying.", "")
	if r.Called("ssh") || hs.pushed != "" {
		t.Errorf("a host was touched: %q", r.Argvs())
	}
	if strings.Contains(hs.all(), "Taking the engineers' sudo off") {
		t.Errorf("a host step ran:\n%s", hs.all())
	}
}

// The strongest check: where the 0.2.3 tag is in this repository and go is
// there, build that release (testknobs, as the bats suite does) from a
// 'git archive' and run its config validate, console show and device list
// against the state, before and after the rollback. Before, each refuses
// the 0.2.4 form with the message that motivated the step; after, each
// accepts it.
// -args -old-bin=<binary> names one built that way, to skip the build.
func TestRollbackRealOldBinary(t *testing.T) {
	bin := oldBinary(t)
	hs := rollbackState(t)
	stubs := t.TempDir()
	for _, name := range []string{"systemctl", "logger", "chown"} {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, int) {
		res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: bin, Args: args,
			Env: append(append([]string(nil), hs.env...), "PATH="+stubs+":/usr/bin:/bin", "HOME="+t.TempDir(), "LANG=C.UTF-8")})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return plain(string(res.Stdout) + string(res.Stderr)), res.Code
	}

	// Before: the 0.2.4 state is refused, file by file.
	out, code := run("config", "validate")
	if code != 1 || !strings.Contains(out, "device.config.timeout: unknown config key") || !strings.Contains(out, "device.config.transport: unknown config key") {
		t.Errorf("0.2.3 config validate before: %d\n%s", code, out)
	}
	if out, code = run("console", "show"); code != 1 || !strings.Contains(out, "settings: unknown key 'password_cache'") {
		t.Errorf("0.2.3 console show before: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 1 || !strings.Contains(out, "device 'sw1': unknown key 'snmp'") {
		t.Errorf("0.2.3 device list before: %d\n%s", code, out)
	}

	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.3", "--apply", "--yes")
	hs.expect(0, "Applying.", "")

	// After.
	out, code = run("config", "validate")
	if code != 0 || strings.Contains(out, "unknown config key") || !strings.Contains(out, "Configuration is valid.") {
		t.Errorf("0.2.3 config validate after: %d\n%s", code, out)
	}
	if out, code = run("console", "show"); code != 0 || strings.Contains(out, "unknown") || !strings.Contains(out, "list-max: 40") {
		t.Errorf("0.2.3 console show after: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 0 || !strings.Contains(out, "sw1") || !strings.Contains(out, "sw2") || !strings.Contains(out, "sw3") {
		t.Errorf("0.2.3 device list after: %d\n%s", code, out)
	}
	// The device locations (0.2.3's own) are still there, and its SNMP
	// settings are the scope's.
	if out, code = run("device", "show", "sw1"); code != 0 || !strings.Contains(out, "Rack 4, DC1") {
		t.Errorf("0.2.3 device show after: %d\n%s", code, out)
	}
	if out, code = run("scope", "snmp", "lab", "show"); code != 0 || !strings.Contains(out, "v2c") {
		t.Errorf("0.2.3 scope snmp show after: %d\n%s", code, out)
	}
	// 0.2.3 writes its own forms again, and reads what it wrote.
	if out, code = run("device", "location", "sw3", "Rack 9"); code != 0 {
		t.Errorf("0.2.3 device location: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 0 {
		t.Errorf("0.2.3 device list after its own write: %d\n%s", code, out)
	}
}

// oldBinaryFlag names a 0.2.3 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary -args -old-bin=<path>.
var oldBinaryFlag = flag.String("old-bin", "", "a tacctl 0.2.3 binary built with -tags testknobs (TestRollbackRealOldBinary)")

// oldBinary is the 0.2.3 tacctl, built into a temp directory from an archive
// of its tag with the test knobs on. A test is skipped, naming what is
// missing, only when git, tar, go or the tag is genuinely absent; a build
// that fails is a failure.
func oldBinary(t *testing.T) string {
	t.Helper()
	if *oldBinaryFlag != "" {
		return *oldBinaryFlag
	}
	if testing.Short() {
		t.Skip("building the 0.2.3 release takes a while; -short skips it (-args -old-bin=<binary built from the 0.2.3 tag with -tags testknobs> skips the build)")
	}
	ctx := context.Background()
	r := execx.Real{}
	do := func(dir, name string, args ...string) (execx.Result, error) {
		res, err := r.Run(ctx, execx.Cmd{Name: name, Args: args, Dir: dir})
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("exit status %d: %s%s", res.Code, res.Stdout, res.Stderr)
		}
		return res, err
	}
	// The prerequisites: where one is genuinely absent the test is skipped
	// and says which. Once they are all here a failure FAILS: a release that
	// does not build must not pass for a skip. CI must fetch the tags (git
	// fetch --tags) or this test never runs there.
	for _, tool := range []string{"git", "tar"} {
		if _, err := r.LookPath(tool); err != nil {
			t.Skipf("%s is not installed, so the 0.2.3 tag cannot be archived and built; the converted files are checked by the fixtures of its parsers only", tool)
		}
	}
	if _, err := do("", "git", "rev-parse", "-q", "--verify", "0.2.3^{commit}"); err != nil {
		t.Skipf("the 0.2.3 tag is not in this repository (CI must fetch tags: git fetch --tags), so that release cannot be built; the converted files are checked by the fixtures of its parsers only (%v)", err)
	}
	goBin := "go"
	if _, err := r.LookPath(goBin); err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // the toolchain that runs this test, when it is not in PATH
		if _, err := os.Stat(goBin); err != nil {
			t.Skip("the go toolchain is not available, so the 0.2.3 tag cannot be built")
		}
	}
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "src.tar")
	// The archive holds the directory it is run in, not the repository: run
	// it at the top (it once archived internal/cli only, and the build,
	// failing for want of go.mod, was skipped).
	top, err := do("", "git", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("git rev-parse --show-toplevel: %v", err)
	}
	if _, err := do(strings.TrimSpace(string(top.Stdout)), "git", "archive", "-o", archive, "0.2.3"); err != nil {
		t.Fatalf("git archive of the 0.2.3 tag failed: %v", err)
	}
	src := filepath.Join(tmp, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := do("", "tar", "-x", "-f", archive, "-C", src); err != nil {
		t.Fatalf("tar failed: %v", err)
	}
	bin := filepath.Join(tmp, "tacctl-0.2.3")
	if _, err := do(src, goBin, "build", "-trimpath", "-buildvcs=false", "-tags", "testknobs", "-o", bin, "./cmd/tacctl"); err != nil {
		t.Fatalf("the 0.2.3 release did not build: %v", err)
	}
	return bin
}

// The completion: the one version it takes, then the flags not yet typed.
func TestRollbackCompletion(t *testing.T) {
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"rollback", ""}, []string{"0.2.3"}},
		{[]string{"rollback", "0.2.3", ""}, []string{"--apply", "--yes", "--hosts"}},
		{[]string{"rollback", "0.2.3", "--apply", ""}, []string{"--yes", "--hosts"}},
		{[]string{"rollback", "0.2.3", "--apply", "--yes", "--hosts", ""}, nil},
		{[]string{"rollback", "--h"}, []string{"--hosts"}},
	} {
		got, _ := completeWords(t, liveNames, c.words...)
		slices.Sort(got)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%q: offered %q, want %q", c.words, got, want)
		}
	}
	// The top level offers the verb.
	got, _ := completeWords(t, liveNames, "")
	if !slices.Contains(got, "rollback") {
		t.Errorf("the top level lacks rollback: %q", got)
	}
}
