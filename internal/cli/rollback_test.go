package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// 'tacctl rollback' (D50 of docs/plans/0.2.3-plan.md) on the host sandbox of
// host_test.go: a 0.2.3 state built with the verbs that write the formats
// 0.2.2 does not read, then rolled back. rollback.bats pins the command
// lines; the files' conversions are tested in internal/{conf,console,devreg,
// lifecycle}.

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

// rollbackState is a 0.2.3 install: an engineer group at priv-lvl 15 with a
// user in lab (the scope of this server), per-scope SNMP settings and
// credentials, a break-glass user, a device with a location, space
// completion off, an engineer-sudo list, the registry with this server and
// two hosts, a host record with a provisioner entry, and the engineer sshd
// drop-in with the tier marker.
func rollbackState(t *testing.T) *hostSandbox {
	t.Helper()
	hs := newHostSandbox(t)
	hs.step("", "group", "add", "engineer", "15", "EN-CLASS")
	hs.step("", "group", "edit", "engineer", "tier", "engineer")
	hs.step("", "user", "add", "erin", "engineer", "--hash", testHash, "--scopes", "lab")
	hs.step("", "scope", "snmp", "lab", "version", "v2c")
	hs.step("", "scope", "snmp", "lab", "contact", "NOC, building 2")
	hs.step("", "scope", "snmp", "lab", "clients", "add", "10.1.0.0/16")
	hs.step("lab-community-1\nlab-community-1\n", "scope", "snmp", "lab", "community", "--stdin")
	hs.step("", "scope", "snmp", "prod", "port", "1161")
	hs.step("", "scope", "breakglass", "lab", "add", "bg-admin")
	hs.step("", "device", "add", "sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	hs.step("", "device", "add", "sw2", "10.99.0.2", "--vendor", "juniper", "--no-host-key")
	hs.step("", "device", "location", "sw1", "Rack 4, DC1")
	hs.step("", "console", "space-completion", "off")
	hs.step("", "config", "linux", "engineer-sudo", "/usr/bin/systemctl")
	hs.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\nweb1|admin@web1.example.net||lab|192.0.2.1|\ndb1|admin@db1.example.net||prod|192.0.2.1|\n", 0o600)
	recs := hosts.Records{Dir: hs.path("state", "hosts")}
	if err := recs.Update("web1", func(r *hosts.Record) {
		r.Provisioner = &hosts.ProvisionerRecord{At: "2026-10-01T00:00:00Z", By: "root", Old: "admin", New: "deploy", Auth: "key"}
	}); err != nil {
		t.Fatal(err)
	}
	hs.write("sshd_config.d/00-tacctl-engineer.conf", "# Managed by tacctl\nMatch Group tac-engineer\n  AllowTcpForwarding no\n", 0o644)
	hs.write("var-lib/tier-pinned", "", 0o644)
	return hs
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

// A version that is not 0.2.2 is refused with the reason, and nothing is
// read for writing.
func TestRollbackRefusesOtherVersions(t *testing.T) {
	hs := rollbackState(t)
	before := tree(t, hs.dir)
	for _, c := range []struct{ arg, want string }{
		{"0.2.1", "Rolling back to 0.2.1 is not supported"},
		{"0.2.0", "older than 0.2.2"},
		{"0.1.16", "older than 0.2.2"},
		{"0.2.3", "prepares the state for 0.2.2 only"},
		{"0.3.0", "prepares the state for 0.2.2 only"},
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
	// The reason for 0.2.1 names what is not covered and the way out.
	hs.run(nil, "rollback", "0.2.1")
	for _, want := range []string{"0.2.2 changed the state as well", "tacctl backup restore"} {
		if !strings.Contains(hs.err.String(), want) {
			t.Errorf("0.2.1: no %q in %q", want, hs.err.String())
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
	for _, args := range [][]string{{"rollback"}, {"rollback", "0.2.2", "extra"}, {"rollback", "0.2.2", "--bogus"}, {"rollback", "--apply"},
		{"rollback", "0.2.2", "--apply", "--apply"}, {"rollback", "0.2.2", "--yes=1"}} {
		hs.run(nil, args...)
		hs.expect(1, "", "Usage: tacctl rollback <version> [--apply] [--yes] [--hosts]")
	}
	if !reflectEqual(before, tree(t, hs.dir)) {
		t.Error("a usage changed a file")
	}
}

// The dry run is the default: it lists every step and every warning and
// writes nothing, not a byte, not a snapshot, not a lock file.
func TestRollbackDryRunWritesNothing(t *testing.T) {
	hs := rollbackState(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.2"}, {"rollback", "0.2.2", "--hosts"}, {"rollback", "v0.2.2"}, {"rollback", "0.2.2", "--yes"}} {
		hs.run(nil, args...)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if !reflectEqual(before, tree(t, hs.dir)) {
			t.Errorf("%v changed %q", args, changedFiles(before, tree(t, hs.dir)))
		}
		if hs.snapshots() != snaps || len(hs.sandbox.runner.Execs()) != 0 || hs.sandbox.runner.Called("ssh") || hs.sandbox.runner.Called("systemctl") {
			t.Errorf("%v: a snapshot, an ssh or a restart: %q", args, hs.sandbox.runner.Argvs())
		}
	}
	hs.run(nil, "rollback", "0.2.2", "--hosts")
	out := hs.all()
	state := hs.path("state")
	for _, want := range []string{
		"Roll back to 0.2.2 (dry run)",
		"1. " + state + "/tacctl.yaml: remove the keys 0.2.2 does not know   [does]",
		"remove linux.engineer_sudo", "remove snmp_scope.lab.version", "remove snmp_scope.lab.contact", "remove snmp_scope.lab.clients",
		"remove snmp_scope.prod.port", "remove breakglass_scope.lab.users",
		"keep every tier.<group> setting",
		"2. " + state + "/console.yaml: write it the way 0.2.2 reads it   [does]",
		"remove tiers.engineer: enable", "remove settings.space_completion: false",
		"3. " + state + "/devices.yaml: remove the per-device location   [does]", "remove the location of 1 device: sw1",
		"4. move aside " + state + "/snmp (the scopes' SNMP credentials) to " + state + "/snmp.rolled-back-<timestamp>   [does]", "moves " + state + "/snmp/lab.yaml",
		"5. leave the host records in " + state + "/hosts   [leaves]", "1 record has a provisioner entry (the last 'host provisioner rotate'): web1",
		"6. leave the engineer sshd drop-in", "leaves " + hs.path("sshd_config.d", "00-tacctl-engineer.conf"),
		"7. remove the tier-pin marker so the next upgrade pins again   [does]", "removes " + hs.path("var-lib", "tier-pinned"),
		"8. leave " + state + "/store.yaml untouched",
		"9. re-render the enabled backends from the store (config render)   [does]",
		"10. take the engineers' sudo off the enrolled Linux hosts (--hosts)   [does]",
		"authsrv (scope 'lab') is this tacctl server: not synced",
		"sync web1 (scope 'lab') with TAC_REVOKE_ENGINEER=1", "sync db1 (scope 'prod') with TAC_REVOKE_ENGINEER=1",
		"Warnings (--apply refuses without --yes while any applies)",
		"1. Engineers become superusers under 0.2.2",
		"This server (host authsrv, scope 'lab'): erin (group engineer, engineer now) become superusers of tacctl here",
		"Host web1 (scope 'lab'): erin (group engineer, engineer now) join tac-superuser (full sudo) at the next 0.2.2 sync",
		"2. Groups change tier", "group engineer (priv-lvl 15): engineer now, superuser under 0.2.2 (higher)",
		"3. Settings 0.2.2 cannot use are dropped",
		"linux.engineer_sudo (/usr/bin/systemctl) is removed from tacctl.yaml",
		"of lab, prod are removed from tacctl.yaml", "The credentials (lab.yaml, mode 0600) are moved from " + state + "/snmp/ to a snmp.rolled-back-<timestamp> directory beside it, and are in the snapshot.",
		"Break-glass users are removed from tacctl.yaml and are no longer rendered: scope 'lab': bg-admin (admin).",
		"The location of 1 device is removed from the device registry (sw1).",
		"To convert the state: tacctl rollback 0.2.2 --apply --yes --hosts",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	// db1 is in prod, where erin is not a member.
	if strings.Contains(out, "Host db1 (scope 'prod'):") {
		t.Errorf("db1 is named although erin is not in prod:\n%s", out)
	}
	// Without --hosts there is no host step and the hint names the flag.
	hs.run(nil, "rollback", "0.2.2")
	if o := hs.all(); strings.Contains(o, "TAC_REVOKE_ENGINEER") || !strings.Contains(o, "Add --hosts to take the engineers' sudo off") ||
		!strings.Contains(o, "To convert the state: tacctl rollback 0.2.2 --apply --yes\n") {
		t.Errorf("without --hosts:\n%s", o)
	}
}

// --apply refuses while a warning applies and --yes is missing; nothing is
// changed, not even a snapshot.
func TestRollbackApplyNeedsYes(t *testing.T) {
	hs := rollbackState(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	hs.run(nil, "rollback", "0.2.2", "--apply")
	hs.expect(1, "Warnings (--apply refuses without --yes", "The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed.")
	hs.run(nil, "rollback", "0.2.2", "--apply", "--hosts")
	hs.expect(1, "", "need your decision")
	if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps {
		t.Errorf("a refused apply changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

// The round trip: --apply --yes converts the state; store.yaml is
// byte-identical; every converted file is one a 0.2.2 reader accepts (the
// fixtures below, and the real 0.2.2 binary in TestRollbackRealOldBinary);
// what 0.2.2 ignores is left; a second --apply changes nothing, not even a
// snapshot.
func TestRollbackRoundTrip(t *testing.T) {
	hs := rollbackState(t)
	storeBefore := hs.store()
	before := tree(t, hs.dir)
	snaps := hs.snapshots()

	// The 0.2.3 form is what the fixtures refuse.
	problems := old022Problems(t, hs)
	for _, want := range []string{"tacctl.yaml: linux.engineer_sudo", "tacctl.yaml: snmp_scope.lab.version", "tacctl.yaml: breakglass_scope.lab.users",
		"console.yaml: tiers.engineer", "console.yaml: settings.space_completion", "devices.yaml: device 'sw1' has location"} {
		if !slices.Contains(problems, want) {
			t.Errorf("the 0.2.3 state is not refused for %q: %q", want, problems)
		}
	}

	hs.run(nil, "rollback", "0.2.2", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out := hs.all()
	for _, want := range []string{"Config snapshot saved to", "state/tacctl.yaml: removed 6 keys", "state/console.yaml: removed tiers.engineer and settings.space_completion",
		"state/devices.yaml: removed the location of 1 device", "state/snmp: moved to ", "state/snmp.rolled-back-",
		"var-lib/tier-pinned: removed (the next upgrade pins the tiers of the groups at priv-lvl 15 again)", "Next steps", "tacctl upgrade --branch 0.2.2",
		"Before upgrading, note the newest entry of 'tacctl backup list'", "That entry is your way back: 'tacctl backup restore <id>'"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	// The snapshot is taken first and holds the 0.2.3 form.
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
	// The credentials the rollback moves aside are in the snapshot.
	if b, err := os.ReadFile(filepath.Join(snap, "snmp", "lab.yaml")); err != nil || string(b) != before[hs.path("state", "snmp", "lab.yaml")] {
		t.Errorf("the snapshot's snmp/lab.yaml is not the credentials before (%v)", err)
	}
	if b, _ := os.ReadFile(filepath.Join(snap, "store.yaml")); string(b) != storeBefore {
		t.Error("the snapshot's store.yaml differs")
	}

	// (a) store.yaml byte-identical.
	if hs.store() != storeBefore {
		t.Error("store.yaml changed")
	}
	// (b) every converted file is accepted by a 0.2.2 reader.
	if p := old022Problems(t, hs); len(p) != 0 {
		t.Errorf("a 0.2.2 reader refuses the converted state: %q", p)
	}
	// What the rollback leaves is as it was.
	after := tree(t, hs.dir)
	converted := map[string]bool{hs.path("state", "tacctl.yaml"): true, hs.path("state", "console.yaml"): true, hs.path("state", "devices.yaml"): true}
	for _, p := range changedFiles(before, after) {
		if converted[p] || strings.Contains(p, "/state/backups/") || strings.Contains(p, "/state/snmp") || strings.HasSuffix(p, "/tier-pinned") || strings.HasSuffix(p, ".lock") || strings.Contains(p, ".lock") {
			continue
		}
		t.Errorf("the rollback changed %s", strings.TrimPrefix(p, hs.dir))
	}
	// The credentials are moved aside (not live under their name, kept whole
	// beside it) and the tier-pin marker is gone.
	if _, ok := after[hs.path("state", "snmp", "lab.yaml")]; ok {
		t.Error("the credentials are still live")
	}
	if _, ok := after[hs.path("var-lib", "tier-pinned")]; ok {
		t.Error("the tier-pin marker is still there")
	}
	if m, _ := filepath.Glob(hs.path("state", "snmp.rolled-back-*", "lab.yaml")); len(m) != 1 || after[m[0]] != before[hs.path("state", "snmp", "lab.yaml")] {
		t.Errorf("the moved credentials: %q", m)
	} else if st, err := os.Stat(m[0]); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the moved credentials' mode: %v %v", st, err)
	}
	for _, kept := range []string{hs.path("state", "hosts", "web1.json"), hs.path("sshd_config.d", "00-tacctl-engineer.conf"), hs.path("state", "linux-hosts")} {
		if a, ok := after[kept]; !ok || a != before[kept] {
			t.Errorf("%s was not left alone", kept)
		}
	}
	// Settings 0.2.2 has stay; the converted console keeps its other settings.
	ov := hs.overrides()
	for _, kept := range []string{"engineer: engineer"} {
		if !strings.Contains(ov, kept) {
			t.Errorf("tacctl.yaml lost %q:\n%s", kept, ov)
		}
	}
	if c := hs.read("state/console.yaml"); !strings.Contains(c, "list_max: 40") || strings.Contains(c, "engineer") {
		t.Errorf("console.yaml:\n%s", c)
	}

	// Idempotence: nothing to convert, no snapshot, no byte changes.
	hs.run(nil, "rollback", "0.2.2", "--apply", "--yes")
	hs.expect(0, "Nothing to convert: every file is one 0.2.2 can read.", "")
	if hs.snapshots() != snaps+1 {
		t.Errorf("the second apply took a snapshot: %d", hs.snapshots())
	}
	if now := tree(t, hs.dir); !reflectEqual(after, now) {
		t.Errorf("the second apply changed %q", changedFiles(after, now))
	}
	// The dry run of a converted state has nothing left to do for the files.
	hs.run(nil, "rollback", "0.2.2")
	if o := hs.all(); strings.Contains(o, "[does]\n       remove") || !strings.Contains(o, "nothing to remove (every key is one 0.2.2 has)") {
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

// old022Problems is what a reader of 0.2.2 refuses in the state, as
// fixtures of its three parsers (the tacctl.yaml schema, console.yaml and
// devices.yaml at the 0.2.2 tag): "<file>: <key>" for each.
func old022Problems(t *testing.T, hs *hostSandbox) []string {
	t.Helper()
	var out []string
	c := conf.Load(hs.path("state", "tacctl.yaml"), conf.DefaultBackends)
	for _, k := range c.RollbackKeys022() {
		out = append(out, "tacctl.yaml: "+k)
	}
	if b, err := os.ReadFile(hs.path("state", "console.yaml")); err == nil {
		v, err := pyyaml.LoadBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		root := v.(*yamlpy.Map)
		for section, known := range map[string][]string{
			"tiers": {"readonly", "operator", "superuser"},
			"settings": {"idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports",
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
		if devs, ok := v.(*yamlpy.Map).Get("devices"); ok && devs != nil {
			for name, d := range devs.(*yamlpy.Map).All() {
				if d.(*yamlpy.Map).Has("location") {
					out = append(out, "devices.yaml: device '"+name+"' has location")
				}
			}
		}
	}
	// The strip the console writer leaves behind is the tier's, too.
	return out
}

// Only the groups and users that become superusers are named: an engineer
// outside the scope of this server, a disabled one and a group that keeps
// its tier are not.
func TestRollbackWarningsNameTheRightUsers(t *testing.T) {
	hs := rollbackState(t)
	hs.step("", "user", "add", "dora", "engineer", "--hash", testHash, "--scopes", "prod")
	hs.step("", "group", "add", "lead", "10", "OP-CLASS")
	hs.step("", "group", "edit", "lead", "tier", "engineer")
	hs.step("", "user", "add", "lena", "lead", "--hash", testHash, "--scopes", "lab")
	hs.step("", "user", "disable", "erin")
	hs.run(nil, "rollback", "0.2.2")
	out := hs.all()
	// erin is disabled and dora is in prod, the scope of db1 and not of this server; lena is not a priv-lvl 15 user.
	if strings.Contains(out, "This server (host authsrv") {
		t.Errorf("the server is named although no one in lab becomes a superuser:\n%s", out)
	}
	if !strings.Contains(out, "Host db1 (scope 'prod'): dora (group engineer, engineer now) join tac-superuser") {
		t.Errorf("dora and db1 are not named:\n%s", out)
	}
	if strings.Contains(out, "lena (") || strings.Contains(out, "erin (") {
		t.Errorf("a user who does not become a superuser is named:\n%s", out)
	}
	// lead (priv-lvl 10, engineer) drops to operator under 0.2.2.
	if !strings.Contains(out, "group lead (priv-lvl 10): engineer now, operator under 0.2.2 (lower)") {
		t.Errorf("lead's tier change:\n%s", out)
	}
}

// A state that needs no answer needs no --yes: --apply goes through.
func TestRollbackNoWarningsNoYes(t *testing.T) {
	hs := newHostSandbox(t)
	hs.step("", "console", "space-completion", "off")
	hs.run(nil, "rollback", "0.2.2", "--apply")
	hs.expect(0, "Applying.", "")
	if c := hs.read("state/console.yaml"); strings.Contains(c, "space_completion") || strings.Contains(c, "engineer") {
		t.Errorf("console.yaml:\n%s", c)
	}
	if hs.store() != fixture(t, "store.multiscope.yaml") {
		t.Error("store.yaml changed")
	}
}

// A file this release cannot read stops the rollback before anything is
// converted.
func TestRollbackRefusesAnUnreadableFile(t *testing.T) {
	for name, file := range map[string]string{"console.yaml": "state/console.yaml", "devices.yaml": "state/devices.yaml"} {
		hs := rollbackState(t)
		hs.write(file, "version: 1\nfoo: [\n", 0o600)
		before := tree(t, hs.dir)
		hs.run(nil, "rollback", "0.2.2", "--apply", "--yes")
		hs.expect(1, "", "Nothing was changed.")
		if !reflectEqual(before, tree(t, hs.dir)) {
			t.Errorf("%s: %q changed", name, changedFiles(before, tree(t, hs.dir)))
		}
	}
}

// The gate: only a superuser. No tier row names 'rollback', so the default
// (superuser only) holds; an engineer, an operator and a readonly user are
// refused before the command runs, with and without --apply --hosts.
func TestRollbackIsTheSuperusersAlone(t *testing.T) {
	sb := engineerSandbox(t)
	before := tree(t, sb.dir)
	for _, args := range [][]string{{"rollback", "0.2.2"}, {"rollback", "0.2.2", "--apply", "--yes", "--hosts"}, {"rollback"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
			t.Errorf("engineer %v: %d %q", args, sb.code, sb.stderr())
		}
	}
	// Operator and readonly users of the plain sandbox (no tier settings).
	plainSb := newSandbox(t, true)
	plainBefore := tree(t, plainSb.dir)
	for _, g := range []struct{ user, groups, tier string }{{"bob", "bob tac-users tac-operator", "operator"}, {"carol", "carol tac-users tac-readonly", "readonly"}} {
		plainSb.cfgRun("", []string{"rollback", "0.2.2", "--apply", "--yes", "--hosts"}, func(r *fake.Runner) {
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

// --hosts syncs every enrolled host but this server's own entry through
// 'host sync', with TAC_REVOKE_ENGINEER=1 in the script's header (protocol 6
// still), after the snapshot and the conversion.
func TestRollbackHostsSync(t *testing.T) {
	hs := rollbackState(t)
	snaps := hs.snapshots()
	r := hs.runner()
	hs.run(r, "rollback", "0.2.2", "--apply", "--yes", "--hosts")
	hs.expect(0, "web1: synced", "")
	out := hs.all()
	for _, want := range []string{"Taking the engineers' sudo off 2 hosts.", "web1: synced", "db1: synced"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	// The scripts: the last one pushed is db1's (registry order).
	header, _, _ := strings.Cut(hs.pushed, "# --- tacctl Linux client")
	if !strings.Contains(header, "TAC_ENGINEER_SUDO=ALL\nTAC_REVOKE_ENGINEER=1\nTAC_PROTOCOL=6\n") {
		t.Errorf("the header:\n%s", header)
	}
	if strings.Contains(header, "TAC_LOCAL") {
		t.Error("a remote host's script has TAC_LOCAL")
	}
	for _, host := range []string{"admin@web1.example.net", "admin@db1.example.net"} {
		if !r.CalledRegexp(`^ssh .*-T ` + regexp.QuoteMeta(host) + ` .*sudo -n bash /tmp/tacctl\.AbCd1234 --accounts-only`) {
			t.Errorf("%s was not synced: %q", host, r.Argvs())
		}
	}
	// This server is not synced by the rollback (no bash run locally).
	if r.Called("bash") {
		t.Errorf("the server's own entry was synced: %q", r.Argvs())
	}
	// The order: one snapshot, before the files changed; the files are converted.
	if hs.snapshots() != snaps+1 {
		t.Errorf("snapshots %d -> %d", snaps, hs.snapshots())
	}
	if strings.Contains(hs.overrides(), "snmp_scope") || strings.Contains(hs.read("state/console.yaml"), "space_completion") {
		t.Error("the files were not converted")
	}
	// The records of the hosts say the sync ran.
	if rec := hs.record("db1"); !strings.Contains(rec, `"sync"`) {
		t.Errorf("db1's record: %s", rec)
	}
	// A later plain sync does not revoke.
	hs.run(hs.runner(), "host", "sync", "web1")
	hs.expect(0, "web1: synced", "")
	if h, _, _ := strings.Cut(hs.pushed, "# --- tacctl Linux client"); strings.Contains(h, "TAC_REVOKE_ENGINEER") {
		t.Error("an ordinary sync revokes")
	}
	// Idempotent: the same command again syncs the hosts again, converts nothing and takes no snapshot.
	n := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.2", "--apply", "--yes", "--hosts")
	hs.expect(0, "Nothing to convert", "")
	if hs.snapshots() != n {
		t.Errorf("snapshots %d -> %d", n, hs.snapshots())
	}
}

// A host that fails is named, the others are still synced, the exit status
// is 1 and the files are converted all the same.
func TestRollbackHostsFailure(t *testing.T) {
	hs := rollbackState(t)
	hs.runFails = true
	hs.run(nil, "rollback", "0.2.2", "--apply", "--yes", "--hosts")
	hs.expect(1, "", "Not synced: web1, db1. Their engineers may still have sudo there.")
	all := hs.all()
	if !strings.Contains(all, "The rollback did not finish") || !strings.Contains(all, "web1: sync failed") {
		t.Errorf("output:\n%s", all)
	}
	if strings.Contains(hs.overrides(), "snmp_scope") {
		t.Error("the files were not converted")
	}
}

// Without --hosts no host is touched and the next steps say how to do it.
func TestRollbackWithoutHostsTouchesNoHost(t *testing.T) {
	hs := rollbackState(t)
	r := hs.runner()
	hs.run(r, "rollback", "0.2.2", "--apply", "--yes")
	hs.expect(0, "'tacctl rollback 0.2.2 --apply --hosts' does that, before the upgrade", "")
	if r.Called("ssh") || hs.pushed != "" {
		t.Errorf("a host was touched: %q", r.Argvs())
	}
}

// The strongest check: where the 0.2.2 tag is in this repository and go is
// there, build that release (testknobs, as the bats suite does) from a
// 'git archive' and run its config validate, console show and device list
// against the state, before and after the rollback. Before, each refuses
// the 0.2.3 form with the message that motivated the step; after, each
// accepts it, and the one thing its config validate still says is that the
// rendered config is out of date (0.2.3 rendered it; 0.2.2 renders its own
// form at the upgrade, or with config render, after which it is valid).
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

	// Before: the 0.2.3 state is refused, file by file.
	out, code := run("config", "validate")
	if code != 1 || !strings.Contains(out, "linux.engineer_sudo: unknown config key") || !strings.Contains(out, "snmp_scope.lab.version: unknown config key") ||
		!strings.Contains(out, "breakglass_scope.lab.users: unknown config key") {
		t.Errorf("0.2.2 config validate before: %d\n%s", code, out)
	}
	if out, code = run("console", "show"); code != 1 || !strings.Contains(out, "tiers: unknown tier or value for 'engineer'") {
		t.Errorf("0.2.2 console show before: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 1 || !strings.Contains(out, "device 'sw1': unknown key 'location'") {
		t.Errorf("0.2.2 device list before: %d\n%s", code, out)
	}

	hs.run(nil, "rollback", "0.2.2", "--apply", "--yes")
	hs.expect(0, "Applying.", "")

	// After.
	out, code = run("config", "validate")
	if strings.Contains(out, "unknown config key") || !strings.Contains(out, "tacctl.yaml:          valid") || !strings.Contains(out, "Store:                valid") ||
		!strings.Contains(out, "Config structure:     valid") {
		t.Errorf("0.2.2 config validate after: %d\n%s", code, out)
	}
	// The one thing left is the rendered config 0.2.3 wrote.
	if code != 1 || !strings.Contains(out, "Validation failed with 1 error(s).") || !strings.Contains(out, "is out of date with the store") {
		t.Errorf("0.2.2 config validate after (the render): %d\n%s", code, out)
	}
	if out, code = run("console", "show"); code != 0 || strings.Contains(out, "unknown") || !strings.Contains(out, "list-max: 40") {
		t.Errorf("0.2.2 console show after: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 0 || !strings.Contains(out, "sw1") || !strings.Contains(out, "sw2") {
		t.Errorf("0.2.2 device list after: %d\n%s", code, out)
	}
	// 0.2.2 renders its own form, and then everything validates.
	if out, code = run("config", "render"); code != 0 {
		t.Errorf("0.2.2 config render: %d\n%s", code, out)
	}
	if out, code = run("config", "validate"); code != 0 || !strings.Contains(out, "Configuration is valid.") {
		t.Errorf("0.2.2 config validate after its render: %d\n%s", code, out)
	}
	// The hosts' records still read, with the provisioner entry in them.
	if rec := hs.record("web1"); !strings.Contains(rec, "provisioner") {
		t.Errorf("web1's record: %s", rec)
	}
	if out, code = run("host", "list"); code != 0 || !strings.Contains(out, "web1") {
		t.Errorf("0.2.2 host list after: %d\n%s", code, out)
	}
}

// oldBinaryFlag names a 0.2.2 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary -args -old-bin=<path>.
var oldBinaryFlag = flag.String("old-bin", "", "a tacctl 0.2.2 binary built with -tags testknobs (TestRollbackRealOldBinary)")

// oldBinary is the 0.2.2 tacctl, built into a temp directory from an archive
// of its tag with the test knobs on. A test is skipped, naming what is
// missing, only when git, tar, go or the tag is genuinely absent; a build
// that fails is a failure.
func oldBinary(t *testing.T) string {
	t.Helper()
	if *oldBinaryFlag != "" {
		return *oldBinaryFlag
	}
	if testing.Short() {
		t.Skip("building the 0.2.2 release takes a while; -short skips it (-args -old-bin=<binary built from the 0.2.2 tag with -tags testknobs> skips the build)")
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
			t.Skipf("%s is not installed, so the 0.2.2 tag cannot be archived and built; the converted files are checked by the fixtures of its parsers only", tool)
		}
	}
	if _, err := do("", "git", "rev-parse", "-q", "--verify", "0.2.2^{commit}"); err != nil {
		t.Skipf("the 0.2.2 tag is not in this repository (CI must fetch tags: git fetch --tags), so that release cannot be built; the converted files are checked by the fixtures of its parsers only (%v)", err)
	}
	goBin := "go"
	if _, err := r.LookPath(goBin); err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // the toolchain that runs this test, when it is not in PATH
		if _, err := os.Stat(goBin); err != nil {
			t.Skip("the go toolchain is not available, so the 0.2.2 tag cannot be built")
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
	if _, err := do(strings.TrimSpace(string(top.Stdout)), "git", "archive", "-o", archive, "0.2.2"); err != nil {
		t.Fatalf("git archive of the 0.2.2 tag failed: %v", err)
	}
	src := filepath.Join(tmp, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := do("", "tar", "-x", "-f", archive, "-C", src); err != nil {
		t.Fatalf("tar failed: %v", err)
	}
	bin := filepath.Join(tmp, "tacctl-0.2.2")
	if _, err := do(src, goBin, "build", "-trimpath", "-buildvcs=false", "-tags", "testknobs", "-o", bin, "./cmd/tacctl"); err != nil {
		t.Fatalf("the 0.2.2 release did not build: %v", err)
	}
	return bin
}

// The completion: the one version it takes, then the flags not yet typed.
func TestRollbackCompletion(t *testing.T) {
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"rollback", ""}, []string{"0.2.2"}},
		{[]string{"rollback", "0.2.2", ""}, []string{"--apply", "--yes", "--hosts"}},
		{[]string{"rollback", "0.2.2", "--apply", ""}, []string{"--yes", "--hosts"}},
		{[]string{"rollback", "0.2.2", "--apply", "--yes", "--hosts", ""}, nil},
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
