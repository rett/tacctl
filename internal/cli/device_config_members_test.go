package cli

import (
	"strings"
	"testing"
)

// The chassis members a pull reads (D319): kept in the pull record, replaced
// on every good pull, and shown by 'device config show'.

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

	// no record yet: nothing to show, no heading
	if out := b.run("device", "config", "show", "jsw1"); strings.Contains(out, "Chassis members") {
		t.Errorf("a heading with no pull:\n%s", out)
	}

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

	// 'device config show' prints them, in a table
	show := b.run("device", "config", "show", "jsw1")
	i := strings.Index(show, "Chassis members:")
	if i < 0 {
		t.Fatalf("no members in:\n%s", show)
	}
	tbl, _, _ := strings.Cut(show[i:], "\n\n")
	lines := strings.Split(tbl, "\n")
	if len(lines) < 5 {
		t.Fatalf("the table:\n%s", tbl)
	}
	head := strings.Fields(lines[2])
	if strings.Join(head, " ") != "ID ROLE MODEL SERIAL RELEASE STATUS PRIORITY" {
		t.Errorf("the columns: %q", lines[2])
	}
	if got := strings.Fields(lines[4]); strings.Join(got, " ") != "0 master EX4300-48T SN000001 25.4R1-S2.3 Prsnt 129" {
		t.Errorf("row 0: %q", lines[4])
	}
	if got := strings.Fields(lines[5]); strings.Join(got, " ") != "1 backup EX4300-48T SN000002 25.4R1-S2.3 Prsnt 129" {
		t.Errorf("row 1: %q", lines[5])
	}
	for _, l := range lines {
		if len(l) > 80 {
			t.Errorf("a line of %d columns: %q", len(l), l)
		}
	}
	// the block follows the data block, before the walkthrough
	if j := strings.Index(show, "Location:"); j < 0 || j > i {
		t.Errorf("the members precede the data block:\n%s", show)
	}
	if strings.Index(show, "Juniper Junos Configuration") < i {
		t.Errorf("the walkthrough precedes the members:\n%s", show)
	}

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
	if show := b.run("device", "config", "show", "jsw1"); strings.Contains(show, "Chassis members") || strings.Contains(show, "SN000001") {
		t.Errorf("members with nothing to show:\n%s", show)
	}
}

// A cell the vendor printed nothing for shows '-'.
func TestShowMembersEmptyCells(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"jsw1", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("jsw1"))
	// the table alone has no release; a member that is not present has no
	// role and no priority
	b.answer(junosVirtualChassisCmd, membersFixture(t, "synthetic-ex4300-vc-not-present.txt"))
	if out := b.run("device", "config", "pull", "jsw1"); b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	show := b.run("device", "config", "show", "jsw1")
	var row string
	for _, l := range strings.Split(show, "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "2" && strings.Contains(l, "SN000003") {
			row = l
		}
	}
	if got := strings.Join(strings.Fields(row), " "); got != "2 - ex4300-48t SN000003 - NotPrsnt -" {
		t.Errorf("the member that is not present: %q in:\n%s", got, show)
	}
}
