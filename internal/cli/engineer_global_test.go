package cli

import (
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// D48 (docs/plans/0.2.3-plan.md): engineers change no global setting.
// Everything an Engineer row can write is scoped to the scopes the engineer
// is a member of; tacctl.yaml (host.default_method, linux.*, mgmt_acl.*,
// the tiers, ...), console.yaml and the SNMP files stay as they are, or the
// verb refuses.
//
// The test walks tier.Rules. Every Engineer row needs an entry in
// engineerRowCases: the command lines to try (typical use, and each way the
// verb has to refuse a global change), and the keys of tacctl.yaml it may
// change because they belong to a scope (none of the rows does today). A
// new Engineer row with no entry fails the test, so adding one means saying
// here what it writes; one that writes a global key fails unless its key is
// listed as scoped.
//
// Six kinds of state are watched: tacctl.yaml, console.yaml and the SNMP
// files (no change at all, but the keys a row lists as a scope's), store.yaml
// (the same: scopes, users and groups are the superuser's), the staging
// file (a line may come or go only for a scope the engineer is in), the
// device registry (devices.yaml) and the Linux hosts registry (linux-hosts):
// what they hold of another scope is never changed, whatever the case. A
// case marked refused must be refused with that message, exit non-zero and
// leave all six byte-identical: the test fails when a refusal that guards a
// global change is removed.

// engineerCase is one command line an engineer runs.
type engineerCase struct {
	args  []string
	stdin string
	// refused is the text of the refusal the case must get ("": the case
	// may run).
	refused string
}

type engineerRow struct {
	cases []engineerCase
	// scoped are the prefixes of the dotted keys of tacctl.yaml the row may
	// change, because they hold the setting of a scope the engineer is in
	// (the key names the scope, such as "snmp_scope.lab.").
	scoped []string
}

func cases(lines ...string) []engineerCase {
	var out []engineerCase
	for _, l := range lines {
		out = append(out, engineerCase{args: strings.Fields(l)})
	}
	return out
}

// refusedCase is a command line the engineer tier has to refuse with msg.
func refusedCase(msg, line string) engineerCase {
	return engineerCase{args: strings.Fields(line), refused: msg}
}

// ownScopesOfBob are the scopes the engineer of these tests is in.
var ownScopesOfBob = []string{"lab"}

var engineerRowCases = map[string]engineerRow{
	"device add": {cases: cases("device add lab-rtr 192.168.1.2 --no-host-key")},
	// A host is not a device (Linux host deployment is the superuser's): the
	// verbs that write the device registry find no host of their own scope,
	// whose pins and recorded addresses a sync reads.
	"device remove": {cases: append(cases("device remove lab-sw -y", "device remove --all -y"),
		refusedCase("Device 'web1' not found", "device remove web1 -y"), refusedCase("Device 'authsrv' not found", "device remove lab-sw,authsrv -y"))},
	"device rename": {cases: append(cases("device rename lab-sw lab-core"),
		refusedCase("Device 'web1' not found", "device rename web1 webx"), refusedCase("Device '192.168.1.10' not found", "device rename 192.168.1.10 webx"))},
	"device address": {cases: append(cases("device address lab-sw 192.168.1.3"),
		refusedCase("Device 'web1' not found", "device address web1 192.168.1.99"))},
	"device hostname": {cases: append(cases("device hostname lab-sw lab-sw.example.net"),
		refusedCase("Device 'web1' not found", "device hostname web1 web1.example.net"))},
	"device vendor": {cases: append(cases("device vendor lab-sw juniper"),
		refusedCase("Device 'web1' not found", "device vendor web1 cisco"))},
	"device port": {cases: append(cases("device port lab-sw 2222"),
		refusedCase("Device 'web1' not found", "device port web1 2222"))},
	"device description": {cases: append(cases("device description lab-sw core"),
		refusedCase("Device 'web1' not found", "device description web1 core"))},
	"device location": {cases: append(cases("device location lab-sw Rack4", "device location lab-sw clear"),
		refusedCase("Device 'web1' not found", "device location web1 Rack4"))},
	"device legacy-ssh": {cases: append(cases("device legacy-ssh lab-sw enable"),
		refusedCase("Device 'web1' not found", "device legacy-ssh web1 enable"))},
	"device hostkey": {cases: append(cases("device hostkey lab-sw show"),
		refusedCase("Device 'web1' not found", "device hostkey web1 show"),
		refusedCase("Device 'web1' not found", "device hostkey web1 accept -y"),
		refusedCase("Device 'web1' not found", "device hostkey web1 set SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))},
	"device import": {cases: []engineerCase{
		{args: strings.Fields("device import -"), stdin: "lab-new,192.168.1.9\n"},
		{args: strings.Fields("device import - --replace -y"), stdin: "lab-new,192.168.1.9\n"},
		refusedCase("imports from standard input only", "device import /etc/hostname"),
		{args: strings.Fields("device import -"), stdin: "web1,192.168.1.98\n", refused: "is an enrolled host"},
		{args: strings.Fields("device import -"), stdin: "lab-new2,192.168.1.10\n", refused: "belongs to the enrolled host"},
	},
		// A device that arrives ends the staging of its scope: the /32 leaves
		// the prefixes of the engineer's own scope.
		scoped: []string{"scopes.lab.prefixes"}},
	"scope devices": {cases: append(cases("scope devices lab", "scope devices lab set 192.168.1.1 cisco"),
		refusedCase("Scope 'prod' is not one of yours", "scope devices prod set 10.99.0.1 cisco"),
		refusedCase("is not available for tagging", "scope devices lab set 192.168.1.10 cisco"),
		refusedCase("is not available for tagging", "scope devices lab set 192.168.1.0/24 juniper"),
		refusedCase("is not available for tagging", "scope devices lab unset 192.168.0.0/16")),
		scoped: []string{"scopes.lab.devices."}},
	"config cisco": {cases: append(cases("config cisco --scope lab", "config cisco --scope lab --staging 192.168.1.50"),
		refusedCase("Scope 'prod' is not one of yours", "config cisco --scope prod"),
		refusedCase("not found", "config cisco --scope lab --staging 192.168.2.50 --name prod-sw"),
		refusedCase("is not available for staging", "config cisco --scope lab --staging 100.64.0.5"),
		refusedCase("not found", "config cisco --scope lab --staging 192.168.1.60 --name web1"))},
	"config juniper": {cases: cases("config juniper --scope lab", "config juniper --scope lab --staging 192.168.1.51")},
	"config wti":     {cases: cases("config wti --scope lab", "config wti --scope lab --staging 192.168.1.52")},
	// An engineer reads the hosts of their scopes and deploys none: host
	// enroll, sync, move, target, provisioner, unenroll and default-method
	// are the superuser's (no Engineer row). 'host show --check' opens ssh as
	// the invoker and is refused.
	"host list": {cases: cases("host list")},
	"host show": {cases: append(cases("host show web1", "host show web1 --json"),
		refusedCase("logs in to the host over ssh", "host show web1 --check"),
		refusedCase("No enrolled host named 'db1'", "host show db1"))},
	"scope staging": {cases: append(cases("scope staging", "scope staging list"),
		refusedCase("Removing one is the superuser's", "scope staging remove 192.168.1.77/32"),
		refusedCase("Removing one is the superuser's", "scope staging remove 192.168.2.77/32"))},
	"scope secret": {cases: append(cases("scope secret lab show"),
		refusedCase("The engineer tier reads a scope's secret", "scope secret lab set abcdefgh12345678ABCDEFGH"),
		refusedCase("The engineer tier reads a scope's secret", "scope secret lab generate"),
		refusedCase("does not exist", "scope secret prod set abcdefgh12345678ABCDEFGH"),
		refusedCase("does not exist", "scope secret prod show"))},
	"scope show": {cases: append(cases("scope show lab"), refusedCase("does not exist", "scope show prod"))},
	// The engineer reads the SNMP settings of the scopes of their own (the
	// reveal is logged) and changes nothing: every setter, clear and test
	// is refused, another scope does not exist.
	"scope snmp": {cases: append(cases("scope snmp lab show", "scope snmp lab show --reveal", "scope snmp lab clients list",
		"scope snmp lab contact", "scope snmp lab version", "scope snmp lab port", "scope snmp lab timeout"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab community --stdin"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab v3-user alice --stdin"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab version v3"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab clients add 192.0.2.0/24"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab clients remove 192.0.2.0/24"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab contact NOC"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab contact --clear"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab port 162"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab timeout 3"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab clear"),
		refusedCase("The engineer tier reads a scope's SNMP settings", "scope snmp lab test 192.168.1.1"),
		refusedCase("does not exist", "scope snmp prod show --reveal"),
		refusedCase("does not exist", "scope snmp prod community --stdin"),
		refusedCase("does not exist", "scope snmp prod clear"))},
}

// watchedFiles are the files of the state directory an engineer never
// changes but for a scope's keys: tacctl.yaml, console.yaml, everything SNMP
// (snmp.yaml, the per-scope directory D46 adds), store.yaml (users, groups,
// scopes, their secrets and prefixes) and the staging file.
func watchedFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		top := strings.SplitN(rel, string(filepath.Separator), 2)[0]
		watched := top == "tacctl.yaml" || top == "console.yaml" || top == "store.yaml" || top == "staging" || strings.HasPrefix(top, "snmp")
		if d.IsDir() || !watched {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// registries are the device registry and the Linux hosts registry, which hold
// the entries of every scope.
func registries(t *testing.T, sb *sandbox) map[string]string {
	t.Helper()
	return map[string]string{"state/devices.yaml": sb.read("state/devices.yaml"), "state/linux-hosts": sb.read("state/linux-hosts")}
}

// foreignEntries are the entries of the two registries that belong to a
// scope other than lab (ownScopesOfBob): the devices whose address no prefix
// of lab covers, and the hosts registered in another scope. The device
// registry keeps no scope, so it is the address that says.
func foreignEntries(t *testing.T, sb *sandbox, regs map[string]string) map[string]any {
	t.Helper()
	out := map[string]any{}
	dir := t.TempDir()
	devs := filepath.Join(dir, "devices.yaml")
	if err := os.WriteFile(devs, []byte(regs["state/devices.yaml"]), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := devreg.Load(devs)
	if err != nil {
		t.Fatalf("devices.yaml: %v", err)
	}
	lab := []string{"172.16.0.0/12", "192.168.0.0/16"}
	for _, d := range f.Devices {
		own := false
		for _, p := range lab {
			if _, n, err := net.ParseCIDR(p); err == nil && n.Contains(net.ParseIP(d.Address)) {
				own = true
			}
		}
		if !own {
			out["device "+d.Name] = *d
		}
	}
	for _, l := range strings.Split(regs["state/linux-hosts"], "\n") {
		if fld := strings.Split(l, "|"); len(fld) > 3 && !slices.Contains(ownScopesOfBob, fld[3]) {
			out["host "+fld[0]] = l
		}
	}
	return out
}

// stagingChanges are the lines of the staging file that came or went; a line
// is "<cidr>|<scope>|<kind>|<name>|<since>".
func stagingChanges(was, now string) []string {
	count := map[string]int{}
	for _, l := range strings.Split(was, "\n") {
		count[l]--
	}
	for _, l := range strings.Split(now, "\n") {
		count[l]++
	}
	var out []string
	for l, n := range count {
		if n != 0 && l != "" {
			out = append(out, l)
		}
	}
	slices.Sort(out)
	return out
}

// flatKeys are the dotted leaf keys of a tacctl.yaml and their values.
func flatKeys(t *testing.T, path string) map[string]string {
	t.Helper()
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if m, ok := v.(*yamlpy.Map); ok {
			for _, k := range m.Keys() {
				x, _ := m.Get(k)
				walk(prefix+k+".", x)
			}
			return
		}
		out[strings.TrimSuffix(prefix, ".")] = fmt.Sprint(v)
	}
	walk("", conf.Load(path, nil).Overrides())
	return out
}

// changedKeys are the dotted keys of tacctl.yaml that differ between two
// versions of the file.
func changedKeys(t *testing.T, dir, before, after string) []string {
	t.Helper()
	a, b := filepath.Join(dir, "before.yaml"), filepath.Join(dir, "after.yaml")
	if err := os.WriteFile(a, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(after), 0o600); err != nil {
		t.Fatal(err)
	}
	x, y := flatKeys(t, a), flatKeys(t, b)
	var out []string
	for k, v := range x {
		if w, ok := y[k]; !ok || w != v {
			out = append(out, k)
		}
	}
	for k := range y {
		if _, ok := x[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func TestEngineerRowsWriteNoGlobalSetting(t *testing.T) {
	// Every Engineer row has an entry, and every entry a row.
	rows := map[string]bool{}
	for _, r := range tier.Rules {
		if r.Tier != tier.Engineer {
			continue
		}
		key := r.Cmd + " " + r.Sub
		rows[key] = true
		if _, ok := engineerRowCases[key]; !ok {
			t.Errorf("the Engineer row '%s' has no entry in engineerRowCases: say which command lines to try and which keys of tacctl.yaml it may change because they are a scope's", key)
		}
	}
	for key := range engineerRowCases {
		if !rows[key] {
			t.Errorf("engineerRowCases has '%s', which is not an Engineer row", key)
		}
	}
	keys := make([]string, 0, len(engineerRowCases))
	for k := range engineerRowCases {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, key := range keys {
		row := engineerRowCases[key]
		for _, c := range row.cases {
			name := key + ": " + strings.Join(c.args, " ")
			t.Run(name, func(t *testing.T) {
				sb := engineerSandbox(t)
				text, err := console.Defaults().Text()
				if err != nil {
					t.Fatal(err)
				}
				sb.write("state/console.yaml", string(text), 0o600)
				nosyncSetup(t, sb)
				sb.write("state/snmp.yaml", "version: 1\ncommunity: sentinel-community-0123\n", 0o600)
				sb.write("state/snmp/lab.yaml", "version: 1\ncommunity: sentinel-lab-0123\n", 0o600)
				sb.write("state/staging", "192.168.1.77/32|lab|device|lab-new|2026-10-01 10:00\n192.168.2.77/32|prod|device|prod-new|2026-10-01 10:00\n", 0o600)
				// The staging /32s are prefixes of their scopes (the sweep that
				// device and host verbs run forgets one that is not).
				for _, a := range [][]string{{"scope", "prefixes", "lab", "add", "192.168.1.77/32"}, {"scope", "prefixes", "prod", "add", "192.168.2.77/32"}} {
					if sb.cfgRun("", a, nil); sb.code != 0 {
						t.Fatalf("%v: %d %q", a, sb.code, sb.stderr())
					}
				}
				before := watchedFiles(t, sb.path("state"))
				if len(before) < 6 {
					t.Fatalf("the sandbox holds only %v", before)
				}
				inputsBefore := syncInputs(t, sb)
				regsBefore := registries(t, sb)
				foreignBefore := foreignEntries(t, sb, regsBefore)
				if len(foreignBefore) < 2 {
					t.Fatalf("the sandbox holds no foreign entries: %v", foreignBefore)
				}
				sb.cfgRun(c.stdin, c.args, func(r *fake.Runner) {
					r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
					r.On([]string{"getent", "ahostsv4", "192.0.2.50"}, execx.Result{Stdout: []byte("192.0.2.50 STREAM 192.0.2.50\n")})
					r.On([]string{"getent", "ahostsv4", "0.0.0.0"}, execx.Result{Stdout: []byte("0.0.0.0 STREAM 0.0.0.0\n")})
					r.Func(func(c execx.Cmd) bool {
						return c.Name == "ssh" && strings.Contains(strings.Join(c.Args, " "), "mktemp")
					},
						func(execx.Cmd) (execx.Result, error) {
							return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
						})
				}, "SUDO_USER=bob")
				after := watchedFiles(t, sb.path("state"))
				regsAfter := registries(t, sb)
				// The user's condition: nothing a host sync is built from
				// changed, whatever the command line did.
				for _, d := range diffSyncInputs(inputsBefore, syncInputs(t, sb)) {
					t.Errorf("an engineer's '%s' changed an input of a host sync (exit %d): %s", name, sb.code, d)
				}
				if c.refused != "" {
					if sb.code == 0 || !strings.Contains(sb.stderr(), c.refused) {
						t.Errorf("an engineer's '%s' must be refused with %q: exit %d, stderr %q", name, c.refused, sb.code, sb.stderr())
					}
					if !maps.Equal(before, after) {
						t.Errorf("a refused '%s' changed the watched state", name)
					}
					if !maps.Equal(regsBefore, regsAfter) {
						t.Errorf("a refused '%s' changed the device or hosts registry", name)
					}
				}
				// The entries of another scope are never touched, by any case.
				if foreignAfter := foreignEntries(t, sb, regsAfter); !reflect.DeepEqual(foreignBefore, foreignAfter) {
					t.Errorf("an engineer's '%s' changed an entry of a scope that is not theirs (exit %d):\nbefore %v\nafter  %v", name, sb.code, foreignBefore, foreignAfter)
				}
				for rel, was := range before {
					now, ok := after[rel]
					if ok && now == was {
						continue
					}
					switch {
					case rel == "staging" && ok:
						var foreign []string
						for _, l := range stagingChanges(was, now) {
							if f := strings.Split(l, "|"); len(f) < 2 || !slices.Contains(ownScopesOfBob, f[1]) {
								foreign = append(foreign, l)
							}
						}
						if len(foreign) > 0 {
							t.Errorf("an engineer's '%s' changed the staging of a scope that is not theirs: %v (exit %d)", name, foreign, sb.code)
						}
					case (rel == "tacctl.yaml" || rel == "store.yaml") && ok:
						var global []string
						for _, k := range changedKeys(t, t.TempDir(), was, now) {
							if !slices.ContainsFunc(row.scoped, func(p string) bool { return strings.HasPrefix(k, p) }) {
								global = append(global, k)
							}
						}
						if len(global) > 0 {
							t.Errorf("an engineer's '%s' changed the global key(s) %v of %s (exit %d): list them as scoped only if they are a scope's", name, global, rel, sb.code)
						}
					default:
						t.Errorf("an engineer's '%s' changed %s (exit %d)", name, rel, sb.code)
					}
				}
				for rel := range after {
					if _, ok := before[rel]; !ok {
						t.Errorf("an engineer's '%s' created %s (exit %d)", name, rel, sb.code)
					}
				}
			})
		}
	}
}
