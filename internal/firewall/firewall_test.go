package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// sandbox is a state directory with a tacctl.yaml and a scripted runner.
type sandbox struct {
	dir    string
	runner *fake.Runner
	eng    *Engine
}

func newSandbox(t *testing.T, yaml string) *sandbox {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "tacctl.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	p := paths.Resolve(paths.NewEnv([]string{"TACCTL_STATE_DIR=" + state, "TACCTL_SYSTEMD_DIR=" + filepath.Join(dir, "systemd"), "TMPDIR=" + dir}), "", func(string) bool { return false })
	r := &fake.Runner{}
	return &sandbox{dir: dir, runner: r, eng: &Engine{Runner: r, Paths: p, Conf: conf.Load(p.Overrides, []string{"tacacs", "radius"})}}
}

func (sb *sandbox) rules(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(sb.eng.Paths.FirewallRules)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const holdsV4 = `breakglass_hold:
  sw1:
    address: 192.0.2.10
    since: '2026-10-12T13:11:00Z'
    by: alice
    reason: console recovery
`

func TestRenderIPv4OnTheDefaultListener(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	got := SpecOf(sb.eng.Conf).Render()
	for _, want := range []string{
		"table inet tacctl\ndelete table inet tacctl\ntable inet tacctl {\n",
		"\tset held4 {\n\t\ttype ipv4_addr\n\t\telements = { 192.0.2.10 }\n\t}\n",
		"\tset held6 {\n\t\ttype ipv6_addr\n\t}\n",
		"\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n",
		"\t\tip saddr @held4 tcp dport { 49 } reject with tcp reset\n",
		"\t\tip6 saddr @held6 tcp dport { 49 } reject with tcp reset\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rules lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ct state") {
		t.Error("the rules match a connection state: an open session would stay")
	}
}

func TestRenderIPv6AndIPv4TogetherSorted(t *testing.T) {
	sb := newSandbox(t, `breakglass_hold:
  web1:
    address: 2001:db8::10
    since: '2026-10-12T13:11:00Z'
    by: alice
    reason: x
  sw2:
    address: 192.0.2.20
    since: '2026-10-12T13:11:00Z'
    by: alice
    reason: x
  sw1:
    address: 192.0.2.3
    since: '2026-10-12T13:11:00Z'
    by: alice
    reason: x
`)
	got := SpecOf(sb.eng.Conf).Render()
	if !strings.Contains(got, "elements = { 192.0.2.3, 192.0.2.20 }") || !strings.Contains(got, "elements = { 2001:db8::10 }") {
		t.Errorf("the sets:\n%s", got)
	}
}

func TestRenderEveryListenerPort(t *testing.T) {
	sb := newSandbox(t, holdsV4+`listeners:
  tacacs:
    default:
      network: tcp
      address: ":4949"
    lab:
      network: tcp
      address: "192.0.2.1:49"
    mgmt:
      network: tcp6
      address: "[2001:db8::1]:4949"
`)
	if got := Ports(sb.eng.Conf); len(got) != 2 || got[0] != 49 || got[1] != 4949 {
		t.Fatalf("ports %v", got)
	}
	got := SpecOf(sb.eng.Conf).Render()
	if !strings.Contains(got, "tcp dport { 49, 4949 } reject with tcp reset") {
		t.Errorf("the ports:\n%s", got)
	}
	// the RADIUS ports are UDP and never appear
	if strings.Contains(got, "1812") || strings.Contains(got, "udp") {
		t.Errorf("a RADIUS port is in the rules:\n%s", got)
	}
}

func TestRenderEmptySetsAndNoHolds(t *testing.T) {
	sb := newSandbox(t, "")
	got := SpecOf(sb.eng.Conf).Render()
	if strings.Contains(got, "elements") {
		t.Errorf("empty sets must have no elements line (nft rejects it):\n%s", got)
	}
	if !strings.Contains(got, "ip saddr @held4 tcp dport { 49 } reject with tcp reset") {
		t.Errorf("the rules are still there so that a hold only fills the sets:\n%s", got)
	}
}

func TestRenderDropAndOff(t *testing.T) {
	sb := newSandbox(t, holdsV4+"breakglass:\n  firewall: drop\n")
	got := SpecOf(sb.eng.Conf).Render()
	if !strings.Contains(got, "tcp dport { 49 } drop\n") || strings.Contains(got, "reject") {
		t.Errorf("drop:\n%s", got)
	}
	sb = newSandbox(t, holdsV4+"breakglass:\n  firewall: 'off'\n")
	got = SpecOf(sb.eng.Conf).Render()
	if strings.Contains(got, "chain") || strings.Contains(got, "set ") || !strings.Contains(got, "delete table inet tacctl\n") {
		t.Errorf("off must only remove the table:\n%s", got)
	}
	if strings.Contains(got, "table inet tacctl {") {
		t.Errorf("off defines the table:\n%s", got)
	}
}

func TestDefaultModeIsReject(t *testing.T) {
	sb := newSandbox(t, "")
	if m := Mode(sb.eng.Conf); m != Reject {
		t.Errorf("mode %q", m)
	}
	sb = newSandbox(t, "breakglass:\n  firewall: nonsense\n")
	if m := Mode(sb.eng.Conf); m != Reject {
		t.Errorf("a value that is not a setting reads as the default, got %q", m)
	}
}

func TestApplyLoadsTheFileWithNft(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	res := sb.eng.Apply(context.Background())
	if res.State != Applied || res.Refused() != "192.0.2.10 refused on tcp/49 (reject)" {
		t.Fatalf("%+v", res)
	}
	if !sb.runner.Called("nft", "-f", sb.eng.Paths.FirewallRules) {
		t.Errorf("nft was not asked to load the file: %v", sb.runner.Argvs())
	}
	if !strings.Contains(sb.rules(t), "192.0.2.10") {
		t.Error("the file lacks the address")
	}
	if st, _ := os.Stat(sb.eng.Paths.FirewallRules); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	// the boot unit is written and enabled, and nftables.service is never named
	unit, err := os.ReadFile(sb.eng.Paths.FirewallUnit)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Type=oneshot", "ExecStart=/fake/bin/nft -f " + sb.eng.Paths.FirewallRules, "WantedBy=sysinit.target", "Before=network-pre.target tacquito.service"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("the unit lacks %q:\n%s", want, unit)
		}
	}
	if !sb.runner.Called("systemctl", "enable", "--quiet", UnitName) {
		t.Errorf("the unit is not enabled: %v", sb.runner.Argvs())
	}
	for _, c := range sb.runner.Calls() {
		if strings.Contains(strings.Join(c.Argv(), " "), "nftables") && c.Name == "systemctl" {
			t.Errorf("nftables.service was touched: %v", c.Argv())
		}
		for _, a := range c.Argv() {
			if a == "flush" || a == "ruleset" {
				t.Errorf("the ruleset was touched: %v", c.Argv())
			}
		}
	}
}

func TestApplyTwiceChangesNothing(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.eng.Apply(context.Background())
	first := sb.rules(t)
	st1, _ := os.Stat(sb.eng.Paths.FirewallRules)
	n := sb.runner.Count("systemctl", "enable")
	sb.eng.Apply(context.Background())
	st2, _ := os.Stat(sb.eng.Paths.FirewallRules)
	if sb.rules(t) != first || !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("a second apply rewrote the file")
	}
	if sb.runner.Count("systemctl", "enable") != n {
		t.Error("the unit was enabled again")
	}
	if sb.runner.Count("nft", "-f") != 2 {
		t.Errorf("nft ran %d times, want the file loaded each time", sb.runner.Count("nft", "-f"))
	}
}

func TestApplyOffRemovesTheTable(t *testing.T) {
	sb := newSandbox(t, holdsV4+"breakglass:\n  firewall: 'off'\n")
	res := sb.eng.Apply(context.Background())
	if res.State != Removed {
		t.Fatalf("%+v", res)
	}
	if !sb.runner.Called("nft", "-f", sb.eng.Paths.FirewallRules) {
		t.Error("nft did not load the removing file")
	}
	if strings.Contains(sb.rules(t), "table inet tacctl {") {
		t.Error("the file defines the table")
	}
	if _, err := os.Stat(sb.eng.Paths.FirewallUnit); err == nil {
		t.Error("an off setting wrote the boot unit")
	}
}

// Without nft: Failed when the table is to refuse something (an address held,
// a mode that is not off, a port), Idle when it is not, and Idle every time
// until a table of tacctl was loaded (the boot unit, written only after a
// successful load, is the sign of one). The rules file is no sign: it is not
// even created.
func TestApplyWithoutNft(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.runner.Missing("nft")
	res := sb.eng.Apply(context.Background())
	if res.State != Failed || !res.NftMissing || res.Why != "nft is not installed" || res.OK() {
		t.Fatalf("%+v", res)
	}
	if sb.runner.Called("nft") {
		t.Error("nft was run")
	}

	// nothing held: nothing to say, again and again
	sb = newSandbox(t, "")
	sb.runner.Missing("nft")
	for i := 1; i <= 2; i++ {
		res = sb.eng.Apply(context.Background())
		if res.State != Idle || !res.OK() || !res.NftMissing {
			t.Fatalf("no holds, apply %d: %+v", i, res)
		}
	}
	if _, err := os.Stat(sb.eng.Paths.FirewallRules); err == nil {
		t.Error("the rules file was written for a host that cannot load it")
	}
}

func TestApplyWithoutNftAndTheSettingOff(t *testing.T) {
	// off, with and without a hold: no table to load or to fail to load
	for _, yaml := range []string{"breakglass:\n  firewall: 'off'\n", holdsV4 + "breakglass:\n  firewall: 'off'\n"} {
		sb := newSandbox(t, yaml)
		sb.runner.Missing("nft")
		for i := 1; i <= 2; i++ {
			if res := sb.eng.Apply(context.Background()); res.State != Idle || !res.OK() {
				t.Fatalf("off, apply %d: %+v", i, res)
			}
		}
	}
	// no TACACS+ backend: no port, nothing to refuse
	sb := newSandbox(t, holdsV4+"backends:\n  enabled: [radius]\n")
	sb.runner.Missing("nft")
	if res := sb.eng.Apply(context.Background()); res.State != Idle {
		t.Fatalf("no listener: %+v", res)
	}
}

// A table loaded earlier (the boot unit is there) may outlive the package: the
// last hold released, or the setting turned off, is Failed until nft is
// back, and the rules file follows the holds for the boot after it.
func TestApplyWithoutNftAfterATableWasLoaded(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	if res := sb.eng.Apply(context.Background()); res.State != Applied {
		t.Fatalf("%+v", res)
	}
	sb.runner.Missing("nft")
	if err := os.WriteFile(sb.eng.Paths.Overrides, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	sb.eng.Conf = conf.Load(sb.eng.Paths.Overrides, []string{"tacacs", "radius"})
	res := sb.eng.Apply(context.Background())
	if res.State != Failed || !res.NftMissing || !strings.Contains(res.Why, "nft is not installed") {
		t.Fatalf("a table may be live: %+v", res)
	}
	if strings.Contains(sb.rules(t), "192.0.2.10") {
		t.Error("the rules file still lists the released address")
	}
}

// With the setting off the boot unit goes: its being there says a table may be
// live.
func TestApplyOffRemovesTheBootUnit(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.eng.Apply(context.Background())
	if _, err := os.Stat(sb.eng.Paths.FirewallUnit); err != nil {
		t.Fatal("no unit after the first load")
	}
	if err := os.WriteFile(sb.eng.Paths.Overrides, []byte(holdsV4+"breakglass:\n  firewall: 'off'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sb.eng.Conf = conf.Load(sb.eng.Paths.Overrides, []string{"tacacs", "radius"})
	if res := sb.eng.Apply(context.Background()); res.State != Removed {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(sb.eng.Paths.FirewallUnit); err == nil {
		t.Error("the unit is left")
	}
	// ... and without nft afterwards nothing is red
	sb.runner.Missing("nft")
	if res := sb.eng.Apply(context.Background()); res.State != Idle {
		t.Fatalf("%+v", res)
	}
}

func TestApplyNftFails(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.runner.Fail([]string{"nft", "-f"}, 1, "Error: Could not process rule: Operation not supported\nsecond line")
	res := sb.eng.Apply(context.Background())
	if res.State != Failed || !strings.Contains(res.Why, "failed (exit 1): Error: Could not process rule: Operation not supported") || strings.Contains(res.Why, "second line") {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(sb.eng.Paths.FirewallUnit); err == nil {
		t.Error("the boot unit was written for a table that did not load")
	}
}

func TestRemove(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.eng.Apply(context.Background())
	removed, err := sb.eng.Remove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Errorf("removed %v", removed)
	}
	for _, p := range []string{sb.eng.Paths.FirewallRules, sb.eng.Paths.FirewallUnit} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	if !sb.runner.Called("systemctl", "disable", "--quiet", UnitName) {
		t.Errorf("the unit was not disabled: %v", sb.runner.Argvs())
	}
	// again: nothing there, no error
	removed, err = sb.eng.Remove(context.Background())
	if err != nil || len(removed) != 1 {
		t.Errorf("a second removal: %v %v", removed, err)
	}
}

// --- the check --------------------------------------------------------------

const tableJSON = `{"nftables": [{"metainfo": {"version": "1.0.9"}},
 {"table": {"family": "inet", "name": "tacctl", "handle": 1}},
 {"set": {"family": "inet", "name": "held4", "table": "tacctl", "type": "ipv4_addr", "handle": 2, "elem": ["192.0.2.10"]}},
 {"set": {"family": "inet", "name": "held6", "table": "tacctl", "type": "ipv6_addr", "handle": 3}},
 {"chain": {"family": "inet", "table": "tacctl", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}},
 {"rule": {"family": "inet", "table": "tacctl", "chain": "input", "handle": 5, "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@held4"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 49}},
   {"reject": {"type": "tcp reset"}}]}},
 {"rule": {"family": "inet", "table": "tacctl", "chain": "input", "handle": 6, "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "@held6"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 49}},
   {"reject": {"type": "tcp reset"}}]}}]}`

func (sb *sandbox) live(json string) {
	sb.runner.On([]string{"nft", "-j", "list", "table", "inet", "tacctl"}, execx.Result{Stdout: []byte(json)})
}

func TestCheckInSync(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.live(tableJSON)
	c := sb.eng.Check(context.Background())
	if c.State != InSync || len(c.Differences) != 0 || c.Fix != "tacctl config breakglass-firewall reject" {
		t.Fatalf("%v", c)
	}
}

func TestCheckNamesEachDifference(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, json, want string
	}{
		{"an address that is not in the set", holdsV4 + `  sw2:
    address: 192.0.2.11
    since: '2026-10-12T13:11:00Z'
    by: alice
    reason: x
`, tableJSON, "192.0.2.11 is held but missing from the set held4"},
		{"an address that is not held", "", tableJSON, "192.0.2.10 is in the set held4 but not held"},
		{"another verdict", holdsV4 + "breakglass:\n  firewall: drop\n", tableJSON, "the verdict for the set held4 is reject, not drop (breakglass.firewall is drop)"},
		{"other ports", holdsV4 + "listeners:\n  tacacs:\n    default:\n      network: tcp\n      address: \":4949\"\n", tableJSON, "the rule of the set held4 matches tcp/49, not tcp/4949"},
		{"a table that stays when off", holdsV4 + "breakglass:\n  firewall: 'off'\n", tableJSON, "the table inet tacctl exists although breakglass.firewall is off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := newSandbox(t, tc.yaml)
			sb.live(tc.json)
			c := sb.eng.Check(context.Background())
			if c.State != Differs || !strings.Contains(strings.Join(c.Differences, "\n"), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, c)
			}
			if !strings.HasPrefix(c.Fix, "tacctl config breakglass-firewall ") {
				t.Errorf("fix %q", c.Fix)
			}
		})
	}
}

func TestCheckMissingTable(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.runner.Fail([]string{"nft", "-j", "list", "table"}, 1, "Error: No such file or directory\nlist table inet tacctl")
	c := sb.eng.Check(context.Background())
	if c.State != Differs || !strings.Contains(c.Differences[0], "the table inet tacctl is missing, so the server still completes the TCP handshake of 192.0.2.10 on tcp/49") {
		t.Fatalf("%v", c)
	}
	// no holds: a missing table is nothing
	sb = newSandbox(t, "")
	sb.runner.Fail([]string{"nft", "-j", "list", "table"}, 1, "Error: No such file or directory")
	if c := sb.eng.Check(context.Background()); c.State != InSync {
		t.Fatalf("%v", c)
	}
}

func TestCheckUnreadableIsNotAFailure(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.runner.Fail([]string{"nft", "-j", "list", "table"}, 1, "netlink: Error: cannot open: Operation not permitted")
	c := sb.eng.Check(context.Background())
	if c.State != Unreadable || !strings.Contains(c.Why, "Operation not permitted") || len(c.Differences) != 0 {
		t.Fatalf("%v", c)
	}
	sb = newSandbox(t, "")
	sb.runner.Missing("nft")
	if c := sb.eng.Check(context.Background()); c.State != Unreadable || c.Why != "nft is not installed" {
		t.Fatalf("%v", c)
	}
	sb = newSandbox(t, holdsV4)
	sb.runner.Missing("nft")
	if c := sb.eng.Check(context.Background()); c.State != Differs || !strings.Contains(c.Differences[0], InstallCommand) {
		t.Fatalf("held and no nft: %v", c)
	}
}

func TestCheckReadsOnlyItsOwnTable(t *testing.T) {
	sb := newSandbox(t, holdsV4)
	sb.live(tableJSON)
	sb.eng.Check(context.Background())
	for _, c := range sb.runner.Calls() {
		if c.Name == "nft" && strings.Join(c.Args, " ") != "-j list table inet tacctl" {
			t.Errorf("nft was asked %v", c.Args)
		}
	}
}
