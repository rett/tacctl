package lifecycle

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The rollback to 0.2.9 (docs/plans/0.2.10-plan.md) on the sandbox of
// rollback_test.go: a 0.2.10 state is the 0.2.9 one with the transport
// setting, the NETCONF service setting of a scope and of a device, and an
// applied record that names its transport.

// rb029Records has an applied record with a transport, one without (0.2.9's
// own form) and a plain one.
const rb029Records = `{"version": 1, "devices": {
 "lab-rtr2": {"address": "192.0.2.7", "vendor": "juniper", "hostname": "lab-rtr2.example.net",
         "applied": {"at": "2026-10-15T10:00:00Z", "by": "alice", "result": "applied", "id": "tacctl-20261015T100000Z-ab12", "kind": "apply", "via": "netconf"}},
 "core-sw1": {"address": "10.99.0.1", "vendor": "cisco",
         "applied": {"at": "2026-10-14T11:00:00Z", "by": "alice", "result": "applied", "id": "tacctl-20261014T110000Z-cd34", "kind": "apply"}},
 "oob-con1": {"address": "10.99.0.9", "vendor": "wti"}
}}
`

// rb029Devices is rbDevices with a NETCONF service setting on the Junos
// device.
const rb029Devices = `# tacctl device registry (header)
version: 1
settings: {stale_days: 30}
devices:
  core-sw1:
    address: 10.99.0.1
    vendor: cisco
    description: DC1 core
    location: Rack 4, DC1
    config_syntax: modern
    snmp:
      version: v3
      port: 2161
      timeout: 4
      clients: [10.1.0.0/16, 10.2.0.0/16]
  lab-rtr2:
    address: 192.0.2.7
    vendor: juniper
    netconf:
      state: enable
      connection_limit: 5
  oob-con1:
    address: 10.99.0.9
    vendor: wti
    snmp: {port: 1161}
`

const rb029ConfTail = "    transport: netconf\n" +
	"netconf_scope:\n  lab:\n    state: enable\n    connection_limit: 3\n    rate_limit: 10\n"

func newRB029Sandbox(t *testing.T) *rbSandbox {
	t.Helper()
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+rb029ConfTail, 0o640)
	s.write(s.p.DevicesFile, rb029Devices, 0o600)
	s.write(s.p.ConfigRecords, rb029Records, 0o600)
	s.reload()
	s.in.Target = RollbackTarget029
	return s
}

func plan029(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget029
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (s *rbSandbox) reloadKeys029() []string {
	s.reload()
	return s.c.RollbackKeys029()
}

// The dry run lists every step and warning, and the plan writes nothing.
func TestPlanRollback029ListsEveryStep(t *testing.T) {
	s := newRB029Sandbox(t)
	before := s.snapshotOf()
	p := plan029(t, s)
	if p.Target != RollbackTarget029 {
		t.Errorf("target %q", p.Target)
	}
	want := []string{"device.apply.transport", "netconf_scope.lab.state", "netconf_scope.lab.connection_limit", "netconf_scope.lab.rate_limit"}
	if got := p.Keys(); len(got) != len(want) {
		t.Errorf("keys %q, want %q", got, want)
	} else {
		for _, k := range want {
			found := false
			for _, g := range got {
				found = found || g == k
			}
			if !found {
				t.Errorf("keys %q lack %q", got, k)
			}
		}
	}
	st := stepText(p)
	for _, w := range []string{
		s.p.Overrides + ": remove the keys 0.2.9 does not know",
		"remove device.apply.transport", "remove netconf_scope.lab.state",
		s.p.DevicesFile + ": remove the per-device NETCONF service setting",
		"remove the netconf map of lab-rtr2 (enable, connection-limit 5)",
		"leave what 0.2.10 wrote in " + s.p.VarLib,
		"leaves " + s.p.ConfigRecords + " (3 records",
		"1 record has the 'via' field of its 'applied' part",
		"0.2.9 ignores the fields it does not know",
		"leave every other file untouched",
	} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	// Not 0.2.3's steps and no sudoers step: 0.2.10 changed no drop-in.
	for _, not := range []string{"console.yaml: write it the way", "remove the snmp map", "0.2.3", "sudoers drop-ins 0.2.9 writes"} {
		if strings.Contains(st, not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	if !p.Pending() || !p.PendingFiles() || !p.NeedsYes() || len(p.todoSudoers()) != 0 {
		t.Errorf("pending %v files %v yes %v sudoers %d", p.Pending(), p.PendingFiles(), p.NeedsYes(), len(p.todoSudoers()))
	}
	w := warnText(p)
	for _, want := range []string{"Settings 0.2.9 cannot use are dropped", "device.apply.transport=netconf",
		"The NETCONF service setting (scope netconf, device netconf) is removed", "lab-rtr2: enable, connection-limit 5"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if n := strings.Join(p.Notes, "\n"); !strings.Contains(n, "restore it with 0.2.10") {
		t.Errorf("notes:\n%s", n)
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("planning wrote a file")
	}
	// --hosts is accepted and says there is nothing to do.
	s.in.WithHosts = true
	if st := stepText(plan029(t, s)); !strings.Contains(st, "the enrolled Linux hosts (--hosts)") || !strings.Contains(st, "no host is synced") {
		t.Errorf("--hosts:\n%s", st)
	}
}

// --apply removes the keys and the device maps; every other file is
// byte-identical, and a second plan has nothing to do.
func TestApplyRollback029WritesKeysAndDevices(t *testing.T) {
	s := newRB029Sandbox(t)
	before := s.snapshotOf()
	p := plan029(t, s)
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 2 || len(p.NotWritten()) != 0 || len(s.ins) != 0 {
		t.Errorf("done %q not written %q installed %q", done, p.NotWritten(), s.ins)
	}
	after := s.snapshotOf()
	if got := s.reloadKeys029(); len(got) != 0 {
		t.Errorf("keys left: %q", got)
	}
	ov := after[s.p.Overrides]
	for _, gone := range []string{"netconf_scope", "transport: netconf"} {
		if strings.Contains(ov, gone) {
			t.Errorf("tacctl.yaml still has %q:\n%s", gone, ov)
		}
	}
	// 0.2.9's own keys stay, with the transport of the reads.
	for _, kept := range []string{"max_concurrency: 16", "transport: ssh", "timeout: 120", "confirm_timeout: 15", "pause: 30", "engineer_sudo:", "snmp_scope:"} {
		if !strings.Contains(ov, kept) {
			t.Errorf("tacctl.yaml lost %q:\n%s", kept, ov)
		}
	}
	dv := after[s.p.DevicesFile]
	if strings.Contains(dv, "netconf") || strings.Contains(dv, "connection_limit") {
		t.Errorf("devices.yaml still has the netconf map:\n%s", dv)
	}
	for _, kept := range []string{"lab-rtr2", "config_syntax: modern", "Rack 4, DC1", "port: 2161", "oob-con1"} {
		if !strings.Contains(dv, kept) {
			t.Errorf("devices.yaml lost %q:\n%s", kept, dv)
		}
	}
	// Nothing else changed: records, the apply state, console.yaml,
	// store.yaml, credentials and both drop-ins.
	for path, was := range before {
		if path == s.p.Overrides || path == s.p.DevicesFile {
			continue
		}
		if after[path] != was {
			t.Errorf("%s changed", path)
		}
	}
	for path := range after {
		// The registry's lock file appears when devices.yaml is mutated.
		if _, ok := before[path]; !ok && !strings.HasSuffix(path, ".devices.lock") {
			t.Errorf("%s appeared", path)
		}
	}
	// A second run finds nothing to convert.
	s.reload()
	p2 := plan029(t, s)
	if p2.Pending() || p2.NeedsYes() || len(p2.Notes) != 0 {
		t.Errorf("second plan: pending %v warnings %q", p2.Pending(), warnText(p2))
	}
	if st := stepText(p2); !strings.Contains(st, "nothing to remove (device.apply.transport") || !strings.Contains(st, "no device has a NETCONF service setting of its own") {
		t.Errorf("second plan:\n%s", st)
	}
	if done, err := ApplyRollback(p2); err != nil || len(done) != 0 || !reflect.DeepEqual(after, s.snapshotOf()) {
		t.Errorf("second apply: %q %v", done, err)
	}
}

// A state with none of the 0.2.10 settings has nothing to convert, whatever
// the drop-ins say.
func TestRollback029NothingToConvert(t *testing.T) {
	s := newRBSandbox(t)
	s.in.Target = RollbackTarget029
	p := plan029(t, s)
	if p.Pending() || p.NeedsYes() || len(p.Keys()) != 0 {
		t.Errorf("pending %v keys %q", p.Pending(), p.Keys())
	}
	before := s.snapshotOf()
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 || !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Errorf("apply: %q %v", done, err)
	}
}

// A record that says a confirmed commit is pending (or unknown) refuses the
// rollback, to 0.2.9 and to 0.2.3, in the dry run and --apply alike; the
// refusal names the device, the time and what settles it, and nothing is
// changed. A settled record does not.
func TestRollbackRefusesWhileAnApplyIsPending(t *testing.T) {
	for _, target := range []string{RollbackTarget029, RollbackTarget} {
		for _, result := range []string{"pending", "unknown"} {
			s := newRB029Sandbox(t)
			s.in.Target = target
			s.write(s.p.ConfigRecords, `{"version": 1, "devices": {
 "sw1": {"address": "10.99.0.1", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "`+result+`", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "via": "netconf"}},
 "sw2": {"address": "10.99.0.2", "vendor": "juniper", "applied": {"result": "applied"}}}}
`, 0o600)
			before := s.snapshotOf()
			_, err := PlanRollback(s.in)
			var ref *RollbackRefusal
			if !errors.As(err, &ref) {
				t.Fatalf("%s %s: %v", target, result, err)
			}
			text := strings.Join(ref.Lines, "\n")
			for _, want := range []string{"not settled on 1 device", "sw1: " + result, "tacctl-20261013T100000Z-ab12", "by alice",
				"tacctl device config apply sw1 --check", "tacctl device config forget sw1", "Nothing was changed."} {
				if !strings.Contains(text, want) {
					t.Errorf("%s %s: refusal lacks %q:\n%s", target, result, want, text)
				}
			}
			if strings.Contains(text, "sw2") {
				t.Errorf("a settled record is named:\n%s", text)
			}
			if !reflect.DeepEqual(before, s.snapshotOf()) {
				t.Error("a refusal wrote a file")
			}
		}
	}
	// Only settled records: no refusal. A records file that cannot be read
	// cannot rule a window out.
	s := newRB029Sandbox(t)
	if _, err := PlanRollback(s.in); err != nil {
		t.Errorf("settled records: %v", err)
	}
	s.write(s.p.ConfigRecords, "{not json", 0o600)
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "a pending apply cannot be ruled out") {
		t.Errorf("unreadable records: %v", err)
	}
}

// 0.2.3 still works from this release: it removes the 0.2.10 keys and the
// device maps too, and the 0.2.3 parsers accept the result.
func TestRollback023StillWorksFrom0210(t *testing.T) {
	s := newRB029Sandbox(t)
	s.in.Target = RollbackTarget
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Target != RollbackTarget {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, want := range []string{"remove device.apply.transport", "remove netconf_scope.lab.state",
		"remove the netconf map of lab-rtr2 (enable, connection-limit 5)", "and NETCONF service"} {
		if !strings.Contains(st, want) {
			t.Errorf("steps lack %q:\n%s", want, st)
		}
	}
	if strings.Contains(st, "no release knows this key") && strings.Contains(st, "netconf_scope.lab.state  (no release") {
		t.Errorf("a 0.2.10 key is described as unknown:\n%s", st)
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	if problems := old023Problems(t, s); len(problems) != 0 {
		t.Errorf("a 0.2.3 reader refuses the converted state: %q", problems)
	}
}

// CheckRollbackVersion takes 0.2.9 and 0.2.3, with or without a "v", and
// sends 0.2.4 to 0.2.8 the two-step way.
func TestCheckRollbackVersion029(t *testing.T) {
	for _, ok := range []string{"0.2.9", "v0.2.9", "0.2.3", "v0.2.3"} {
		if v, err := CheckRollbackVersion(ok); err != nil || v != strings.TrimPrefix(ok, "v") {
			t.Errorf("%s: %q %v", ok, v, err)
		}
	}
	for _, far := range []string{"0.2.8", "0.2.7", "0.2.4"} {
		_, err := CheckRollbackVersion(far)
		var ref *RollbackRefusal
		if !errors.As(err, &ref) {
			t.Fatalf("%s: %v", far, err)
		}
		text := strings.Join(ref.Lines, "\n")
		for _, want := range []string{"is further back", "tacctl rollback 0.2.9 --apply", "tacctl upgrade --branch 0.2.9", "prepares the state for 0.2.8 and 0.2.3"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: refusal lacks %q:\n%s", far, want, text)
			}
		}
	}
	for _, bad := range []string{"0.2.10", "0.3.0", "0.2.2", "nonsense"} {
		if _, err := CheckRollbackVersion(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}
