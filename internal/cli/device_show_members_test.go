package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// 'device show' prints the chassis members of the last pull, as 'device
// config show' does, and 'device show --json' carries them; a device with
// none has neither the table nor the key.
func TestDeviceShowPrintsTheChassisMembers(t *testing.T) {
	b := newReportsBox(t)
	out := b.sb.asUser("alice", asSuper, "device", "show", "jsw1")
	i := strings.Index(out, "Chassis members:")
	if b.sb.code != 0 || i < 0 {
		t.Fatalf("show: %d\n%s", b.sb.code, out)
	}
	tbl, _, _ := strings.Cut(out[i:], "\n\n")
	lines := strings.Split(tbl, "\n")
	if len(lines) < 6 || strings.Join(strings.Fields(lines[2]), " ") != "ID ROLE MODEL SERIAL RELEASE STATUS PRIORITY" ||
		strings.Join(strings.Fields(lines[4]), " ") != "0 master EX4300-48T SN000002 25.4R1-S2.3 Prsnt 129" ||
		strings.Join(strings.Fields(lines[5]), " ") != "1 backup EX4300-48T SN000003 25.4R1-S2.3 Prsnt 129" {
		t.Errorf("the table:\n%s", tbl)
	}
	if strings.Index(out, "Notices") > i {
		t.Errorf("the members precede the rows:\n%s", out)
	}
	if out = b.sb.asUser("alice", asSuper, "device", "show", "sw1"); strings.Contains(out, "Chassis members") {
		t.Errorf("a table for a device with no members:\n%s", out)
	}
	// the read-only user is shown no pull data
	if out = b.sb.asUser("carol", asReadonly, "device", "show", "jsw1"); strings.Contains(out, "Chassis members") || strings.Contains(out, "SN000002") {
		t.Errorf("read-only user:\n%s", out)
	}

	var doc struct {
		Serial  string           `json:"serial"`
		Members []map[string]any `json:"members"`
	}
	out = b.sb.asUser("alice", asSuper, "device", "show", "jsw1", "--json")
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Members) != 2 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if m := doc.Members[1]; m["id"] != "1" || m["role"] != "backup" || m["serial"] != "SN000003" || m["priority"].(float64) != 129 || m["model"] != "EX4300-48T" {
		t.Errorf("member: %v", m)
	}
	if out = b.sb.asUser("alice", asSuper, "device", "show", "sw1", "--json"); strings.Contains(out, `"members"`) {
		t.Errorf("a members key for a device with none:\n%s", out)
	}
	if out = b.sb.asUser("carol", asReadonly, "device", "show", "jsw1", "--json"); strings.Contains(out, `"members"`) {
		t.Errorf("read-only json:\n%s", out)
	}
	// the list stays short
	if out = b.sb.asUser("alice", asSuper, "device", "list", "--json"); strings.Contains(out, `"members"`) {
		t.Errorf("list --json has members:\n%s", out)
	}
	_ = devconf.Member{}
}
