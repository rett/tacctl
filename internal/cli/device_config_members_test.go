package cli

import (
	"strings"
	"testing"
)

// The chassis members a pull reads (D319): kept in the pull record, replaced
// on every good pull.

const junosVirtualChassisCmd = "show virtual-chassis status"

// membersFixture is a synthetic output of tests/fixtures/devconf/members.
func membersFixture(t *testing.T, name string) string {
	t.Helper()
	return factsFixture(t, "members/"+name)
}

func TestPullRecordsMembers(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"jsw1", "192.168.1.20", "juniper"})
	b.serve("juniper", "set version 25.4R1-S2.3\n"+b.expected("jsw1"))
	b.answer(junosChassisCmd, membersFixture(t, "synthetic-ex4300-hardware-vc.txt"))
	b.answer(junosVersionCmd, membersFixture(t, "synthetic-ex4300-version-vc.txt"))
	b.answer(junosVirtualChassisCmd, membersFixture(t, "synthetic-ex4300-vc-2.txt"))

	out := b.run("device", "config", "pull", "jsw1")
	if b.sb.code != 0 || !strings.Contains(out, "ok via netconf") {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	rec, _ := b.records().Of("jsw1")
	if rec == nil || len(rec.Members) != 2 {
		t.Fatalf("record %+v", rec)
	}
	if m := rec.Members[0]; m.ID != "0" || m.Role != "master" || m.Model != "EX4300-48T" || m.Serial != "SN000001" ||
		m.Release != "25.4R1-S2.3" || m.Status != "Prsnt" || m.Priority != 129 {
		t.Errorf("member 0: %+v", m)
	}
	if m := rec.Members[1]; m.ID != "1" || m.Role != "backup" || m.Serial != "SN000002" {
		t.Errorf("member 1: %+v", m)
	}
	// the members are no part of the pull's output, its --json or its audit
	// line, as the other facts are not
	b.noSerial("SN000002", "jsw1")

	// A pull replaces them: a device that now answers no table has none, and
	// the old list is not kept.
	b.answer(junosVirtualChassisCmd, "")
	if out := b.run("device", "config", "pull", "jsw1"); b.sb.code != 0 || !strings.Contains(out, "ok via netconf") {
		t.Fatalf("pull with no members: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	rec, _ = b.records().Of("jsw1")
	if rec == nil || rec.Result != "ok" || len(rec.Members) != 0 {
		t.Errorf("record %+v", rec)
	}
}
