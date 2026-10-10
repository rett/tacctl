package cli

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
)

// The render input of a registered device is made once per vendor and scope,
// and the managed sections of each device are then a pure function of it: the
// same for the same device whoever calls and however often, and different
// for a device's own SNMP values and a scope's.
func TestManagedRenderIsPureAndSharedPerScope(t *testing.T) {
	b := newPullBox(t)
	b.sb.dev("", "scope", "snmp", "lab", "version", "v2c")
	b.sb.cfgRun("lab-community-9\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, route)
	b.devices(
		[3]string{"lab-j1", "192.168.1.20", "juniper"}, [3]string{"lab-j2", "192.168.1.21", "juniper"},
		[3]string{"lab-c1", "192.168.1.30", "cisco"}, [3]string{"prod-j", "10.99.0.20", "juniper"},
		[3]string{"pdu", "192.168.1.40", "wti"})
	inv := b.invoke()
	_, res, err := inv.deviceLoad()
	if err != nil {
		t.Fatal(err)
	}
	var entries []devreg.Entry
	for _, n := range []string{"lab-j1", "lab-j2", "lab-c1", "prod-j"} {
		e, ok := res.Lookup(n, devreg.ScopeFilter{})
		if !ok {
			t.Fatalf("no %s", n)
		}
		entries = append(entries, e)
	}
	r := inv.newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	if len(r.base) != 3 {
		t.Errorf("%d bases for 3 (vendor, scope) pairs", len(r.base))
	}
	first := map[string][]devices.Section{}
	for _, e := range entries {
		s, err := r.Expected(e)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		first[e.Name] = s
	}
	// Concurrent calls (the batch's workers) agree with the first, run under
	// -race for the reads they share.
	var wg sync.WaitGroup
	errs := make(chan string, 400)
	for i := 0; i < 8; i++ {
		for _, e := range entries {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, err := r.Expected(e)
				if err != nil || !reflect.DeepEqual(s, first[e.Name]) {
					errs <- e.Name
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for n := range errs {
		t.Errorf("%s: a concurrent Expected differs", n)
	}
	// The device's own values are the SNMP step's: two devices of one scope
	// differ in nothing else.
	l1, l2 := flat(first["lab-j1"]), flat(first["lab-j2"])
	if !strings.Contains(l1, "set snmp community") || l1 == "" {
		t.Errorf("no SNMP statements for lab-j1:\n%s", l1)
	}
	if l1 != l2 {
		t.Errorf("devices of one scope differ:\n%s\n---\n%s", l1, l2)
	}
	if flat(first["prod-j"]) == l1 {
		t.Error("another scope renders the same (its secret differs)")
	}
	// A Cisco device with legacy-ssh is compared with the IOS 12.x syntax.
	if !strings.Contains(flat(first["lab-c1"]), "tacacs server TACACS") {
		t.Errorf("cisco:\n%s", flat(first["lab-c1"]))
	}
	c := entries[2]
	c.LegacySSH = true
	rl := inv.newManagedRender(managedOptions{}, false)
	rl.prepare([]devreg.Entry{c})
	ls, err := rl.Expected(c)
	if err != nil || !strings.Contains(flat(ls), "tacacs-server host") {
		t.Errorf("legacy cisco: %v\n%s", err, flat(ls))
	}
	// A WTI unit and an unprepared device have nothing.
	pdu, _ := res.Lookup("pdu", devreg.ScopeFilter{})
	if _, err := r.Expected(pdu); err == nil {
		t.Error("a WTI unit has an expected configuration")
	}
}

func flat(secs []devices.Section) string {
	var out []string
	for _, s := range secs {
		out = append(out, "["+s.Name+"]")
		out = append(out, s.Lines...)
	}
	return strings.Join(out, "\n")
}

// Every line a comparison can hold is printed with its mark, a secret's
// value is not, and a section that agrees says only so.
func TestPrintDeviceDiffEveryOp(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	rs := []devconf.SectionResult{
		{Name: "aaa", State: devconf.StateDiffers, Lines: []devconf.DiffLine{
			{Op: devconf.OpSame, Text: "set system tacplus-server 192.0.2.10 secret (present, not compared)", Secret: true},
			{Op: devconf.OpMissing, Text: "set system accounting destination tacplus"},
			{Op: devconf.OpExtra, Text: "set system tacplus-server 192.0.2.99 secret (present, not compared)", Secret: true},
			{Op: devconf.OpNotVisible, Text: "set system tacplus-server 192.0.2.10 secret (not visible to this login)", Secret: true},
			{Op: devconf.OpOrder, Text: "system authentication-order: order differs, expected tacplus, password; device password, tacplus"},
			{Op: devconf.OpSame, Text: "set system authentication-order tacplus"},
		}},
		{Name: "roles", State: devconf.StateOK, Lines: []devconf.DiffLine{{Op: devconf.OpSame, Text: "set system login class RO"}}},
		{Name: "mgmt-acl", State: devconf.StateDiffers, Notes: []string{"filter MGMT-ACL is not applied on lo0"}},
		{Name: "snmp", State: devconf.StateMissing, Lines: []devconf.DiffLine{{Op: devconf.OpMissing, Text: "set snmp location x"}}},
		{Name: "netconf", State: devconf.StateNA, Lines: []devconf.DiffLine{{Op: devconf.OpInfo, Text: "set system services netconf ssh"}}},
		{Name: "breakglass", State: devconf.StateNotVisible},
	}
	var out strings.Builder
	inv.app.Out.Stdout = &out
	inv.printDeviceDiff("core-sw1", "lab", "juniper", rs, nil, false, deviceDiffMeta{})
	got := out.String()
	for _, want := range []string{
		"Device core-sw1 (lab, juniper)\n",
		"(the login could not see the device's secrets",
		"  aaa         differs\n",
		"      = set system tacplus-server 192.0.2.10 secret (present, not compared)\n",
		"      - set system accounting destination tacplus\n",
		"      + set system tacplus-server 192.0.2.99 secret (present, not compared)\n",
		"      ? set system tacplus-server 192.0.2.10 secret (not visible to this login)\n",
		"      ! system authentication-order: order differs",
		"  roles       ok\n",
		"      note: filter MGMT-ACL is not applied on lo0\n",
		"  snmp        missing\n",
		"      ~ set system services netconf ssh\n",
		"  netconf     n/a\n",
		"  breakglass  not visible\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "= set system authentication-order tacplus") || strings.Contains(got, "= set system login class RO") {
		t.Errorf("an agreeing statement is printed:\n%s", got)
	}
	// --section limits it.
	out.Reset()
	inv.printDeviceDiff("core-sw1", "lab", "juniper", rs, []string{"snmp"}, true, deviceDiffMeta{})
	if g := out.String(); strings.Contains(g, "aaa") || !strings.Contains(g, "snmp") {
		t.Errorf("--section snmp:\n%s", g)
	}
}
