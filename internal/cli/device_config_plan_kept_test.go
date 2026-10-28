package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// A device whose managed statements are all in place and whose snmp section
// holds statements of its own reads the same everywhere: ok in 'device
// config list' ('snmp +N unmanaged'), consistent in 'device config plan'
// (no item, exit 0, the cover page's word) and with the same N in the plan's
// Kept line and its --json.
func TestPlanReadsTheDevicesOwnStatementsAsTheListDoes(t *testing.T) {
	b := newPullBox(t)
	b.sb.dev("", "scope", "snmp", "lab", "version", "v2c")
	b.sb.cfgRun("lab-community-9\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, route)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	text := b.expected("lab-j") + strings.Join([]string{
		"set snmp name lab-j.example.net",
		"set snmp community other-example authorization read-only",
		"set snmp community other-example clients 192.0.2.10/32",
		"set snmp community other-backup authorization read-write",
		"set snmp trap-options source-address 192.0.2.250",
		"set snmp trap-group other-example version v2",
		"set snmp trap-group other-example targets 198.51.100.7",
		"set snmp trap-group other-backup targets 198.51.100.9",
		"set snmp view OTHER-VIEW oid .1 include",
		"set snmp interface lo0.0",
	}, "\n") + "\n"
	b.serve("juniper", text)
	b.servePlain(text)
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %d\n%s", b.sb.code, out)
	}

	list := b.run("device", "config", "list")
	if b.sb.code != 0 || !strings.Contains(list, "snmp +10 unmanaged") || strings.Contains(list, "differs") {
		t.Fatalf("list: %d\n%s", b.sb.code, list)
	}
	out := b.run("device", "config", "plan", "lab-j", "--exit-code")
	if b.sb.code != 0 {
		t.Errorf("plan: exit %d\n%s", b.sb.code, out)
	}
	flat := strings.Join(strings.Fields(strings.ReplaceAll(out, "\n#", " ")), " ")
	for _, want := range []string{"CONSISTENT: nothing to paste.", "Kept: snmp 10 statements of the device's own (name, communities, trap options, trap groups, views, ...)"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the plan lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"What is irregular", "MONITORING", "PASTE FROM HERE", "other-example", "other-backup"} {
		if strings.Contains(out, bad) {
			t.Errorf("the plan holds %q:\n%s", bad, out)
		}
	}
	consistent := false
	for _, l := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(l, "# Consistent: "); ok {
			consistent = strings.Contains(rest, "snmp")
		}
	}
	if !consistent {
		t.Errorf("snmp is not in the Consistent line:\n%s", out)
	}

	js := b.run("device", "config", "plan", "lab-j", "--json")
	var got []struct {
		Status         string
		Irregularities []any
		Kept           []struct {
			Section string
			Count   int
		}
	}
	if err := json.Unmarshal([]byte(js), &got); err != nil || len(got) != 1 {
		t.Fatalf("json: %v\n%s", err, js)
	}
	if g := got[0]; g.Status != "consistent" || len(g.Irregularities) != 0 || len(g.Kept) != 1 || g.Kept[0].Section != "snmp" || g.Kept[0].Count != 10 {
		t.Errorf("json: %+v", g)
	}
}
