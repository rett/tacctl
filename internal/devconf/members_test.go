package devconf

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// factsEqual compares Facts, which hold a slice.
func factsEqual(a, b Facts) bool { return reflect.DeepEqual(a, b) }

func vcFixture(t *testing.T, name string) string {
	t.Helper()
	return cleanText(capture(t, "members/"+name))
}

func TestJunosMembers(t *testing.T) {
	hw := vcFixture(t, "synthetic-ex4300-hardware-vc.txt")
	ver := vcFixture(t, "synthetic-ex4300-version-vc.txt")
	m0 := Member{ID: "0", Role: "master", Model: "EX4300-48T", Serial: "SN000001", Release: "25.4R1-S2.3", Status: "Prsnt", Priority: 129}
	m1 := Member{ID: "1", Role: "backup", Model: "EX4300-48T", Serial: "SN000002", Release: "25.4R1-S2.3", Status: "Prsnt", Priority: 129}
	m2 := Member{ID: "2", Role: "linecard", Model: "EX4300-48T", Serial: "SN000003", Release: "24.4R2.9", Status: "Prsnt"}
	// the master's own text has no label: the text before the first label
	unlabelled := strings.Replace(ver, "fpc0:\n", "", 1)
	for _, c := range []struct {
		name       string
		vc, hw, sv string
		want       []Member
	}{
		{"two members, hardware and version joined", vcFixture(t, "synthetic-ex4300-vc-2.txt"), hw, ver, []Member{m0, m1}},
		{"three members, the master prints its own label", vcFixture(t, "synthetic-ex4300-vc-3-labelled-master.txt"), hw, ver, []Member{m0, m1, m2}},
		{"the master prints no label", vcFixture(t, "synthetic-ex4300-vc-2.txt"), hw, unlabelled, []Member{m0, m1}},
		{"the table alone: the model and serial number are the table's, no release",
			vcFixture(t, "synthetic-ex4300-vc-2.txt"), "", "",
			[]Member{{ID: "0", Role: "master", Model: "ex4300-48t", Serial: "SN000001", Status: "Prsnt", Priority: 129},
				{ID: "1", Role: "backup", Model: "ex4300-48t", Serial: "SN000002", Status: "Prsnt", Priority: 129}}},
		{"hardware and version refused: the table stands", vcFixture(t, "synthetic-ex4300-vc-2.txt"), "error: permission denied\n", "syntax error\n",
			[]Member{{ID: "0", Role: "master", Model: "ex4300-48t", Serial: "SN000001", Status: "Prsnt", Priority: 129},
				{ID: "1", Role: "backup", Model: "ex4300-48t", Serial: "SN000002", Status: "Prsnt", Priority: 129}}},
		{"a member with no block keeps no release", vcFixture(t, "synthetic-ex4300-vc-3-labelled-master.txt"), hw,
			strings.Join(strings.Split(ver, "\n\n")[:2], "\n\n"),
			[]Member{m0, m1, {ID: "2", Role: "linecard", Model: "EX4300-48T", Serial: "SN000003", Status: "Prsnt"}}},
		{"a member that is not present", vcFixture(t, "synthetic-ex4300-vc-not-present.txt"), "", "",
			[]Member{{ID: "0", Role: "master", Model: "ex4300-48t", Serial: "SN000001", Status: "Prsnt", Priority: 129},
				{ID: "1", Role: "backup", Model: "ex4300-48t", Serial: "SN000002", Status: "Prsnt", Priority: 129},
				{ID: "2", Model: "ex4300-48t", Serial: "SN000003", Status: "NotPrsnt"}}},
		{"a refusal", vcFixture(t, "real-vmx-virtual-chassis-refusal.txt"), hw, ver, nil},
		{"one member is no chassis", vcFixture(t, "synthetic-ex4300-vc-1.txt"), hw, ver, nil},
		{"a syntax error", "                                  ^\nsyntax error, expecting <command>.\n", hw, ver, nil},
		{"empty", "", "", "", nil},
		{"a role of an unknown kind goes to the status",
			"0 (FPC 0)  Prsnt  SN000001  ex4300-48t  129  Master*  N  VC  1  vcp-255/1/0\n1 (FPC 1)  Prsnt  SN000002  ex4300-48t  0  Inactive  N  VC  0  vcp-255/1/0\n", "", "",
			[]Member{{ID: "0", Role: "master", Model: "ex4300-48t", Serial: "SN000001", Status: "Prsnt", Priority: 129},
				{ID: "1", Model: "ex4300-48t", Serial: "SN000002", Status: "Prsnt Inactive"}}},
		{"a row that is not present with its role",
			"0 (FPC 0)  Prsnt  SN000001  ex4300-48t  129  Master*  N  VC  1  vcp-255/1/0\n1 (FPC 1)  NotPrsnt  SN000002  ex4300-48t  0  Linecard  N  VC  0  vcp-255/1/0\n", "", "",
			[]Member{{ID: "0", Role: "master", Model: "ex4300-48t", Serial: "SN000001", Status: "Prsnt", Priority: 129},
				{ID: "1", Role: "linecard", Model: "ex4300-48t", Serial: "SN000002", Status: "NotPrsnt"}}},
		{"an empty serial number column",
			"0 (FPC 0)  Prsnt  ex4300-48t  129  Master*\n1 (FPC 1)  Prsnt  SN000002  ex4300-48t  129  Backup\n", "", "",
			[]Member{{ID: "0", Role: "master", Model: "ex4300-48t", Status: "Prsnt", Priority: 129},
				{ID: "1", Role: "backup", Model: "ex4300-48t", Serial: "SN000002", Status: "Prsnt", Priority: 129}}},
		{"a member listed twice counts once", "0 (FPC 0)  Prsnt  SN000001  ex4300-48t  129  Master*\n0 (FPC 0)  Prsnt  SN000001  ex4300-48t  129  Master*\n", "", "", nil},
		{"rows with only neighbours are not members", "                 1  vcp-255/1/0\n 2  vcp-255/1/1\n", "", "", nil},
	} {
		got := JunosMembers(c.vc, c.hw, c.sv)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", c.name, got, c.want)
		}
	}
}

// The hardware row wins over the table only when it has something to say, and
// a hardware inventory with no header is read by its blank runs.
func TestJunosMembersHardware(t *testing.T) {
	vc := vcFixture(t, "synthetic-ex4300-vc-2.txt")
	hw := "Hardware inventory:\nItem             Version  Part number  Serial number     Description\n" +
		"Chassis                                SN000001          Virtual Chassis\n" +
		"FPC 0            REV 09   650-000001   SN000091          EX4300-48T\n" +
		"FPC 1            REV 09   650-000001                     \n"
	got := JunosMembers(vc, hw, "")
	if len(got) != 2 || got[0].Serial != "SN000091" || got[0].Model != "EX4300-48T" || got[1].Serial != "SN000002" || got[1].Model != "ex4300-48t" {
		t.Errorf("columns: %+v", got)
	}
	noHeader := "Chassis      SN000001   Virtual Chassis\nFPC 0   REV 09   650-000001   SN000092   EX4300-48T\nFPC 1   SN000093   EX4300-48S\n"
	got = JunosMembers(vc, noHeader, "")
	if len(got) != 2 || got[0].Serial != "SN000092" || got[0].Model != "EX4300-48T" || got[1].Serial != "SN000093" || got[1].Model != "EX4300-48S" {
		t.Errorf("no header: %+v", got)
	}
	// 'FPC 10' is not 'FPC 1'
	got = JunosMembers(vc, "FPC 10   REV 09   650-000001   SN000094   EX4300-48T\n", "")
	if len(got) != 2 || got[1].Serial != "SN000002" {
		t.Errorf("FPC 10: %+v", got)
	}
}

func TestIOSMembers(t *testing.T) {
	sw := vcFixture(t, "synthetic-ios-show-switch-3.txt")
	inv := vcFixture(t, "synthetic-ios-inventory-stack-3.txt")
	ver := vcFixture(t, "synthetic-ios-show-version-stack-3.txt")
	m1 := Member{ID: "1", Role: "master", Model: "WS-C3750G-24PS-S", Serial: "SN000004", Release: "12.2(55)SE12", Status: "Ready", Priority: 15}
	m2 := Member{ID: "2", Role: "member", Model: "WS-C3750G-24PS-S", Serial: "SN000005", Release: "12.2(55)SE12", Status: "Ready", Priority: 14}
	m3 := Member{ID: "3", Role: "backup", Model: "WS-C3750G-24PS-S", Serial: "SN000006", Release: "12.2(53)SE2", Status: "Ready", Priority: 13}
	noRel := func(m Member) Member { m.Release = ""; return m }
	for _, c := range []struct {
		name         string
		sw, inv, ver string
		want         []Member
	}{
		{"three switches, joined", sw, inv, ver, []Member{m1, m2, m3}},
		{"no version table: no release", sw, inv, "", []Member{noRel(m1), noRel(m2), noRel(m3)}},
		{"a version output with no table", sw, inv, "% Invalid input detected at '^' marker.\n", []Member{noRel(m1), noRel(m2), noRel(m3)}},
		{"no inventory: the version table gives the model", sw, "", ver, []Member{
			{ID: "1", Role: "master", Model: "WS-C3750G-24PS", Release: "12.2(55)SE12", Status: "Ready", Priority: 15},
			{ID: "2", Role: "member", Model: "WS-C3750G-24PS", Release: "12.2(55)SE12", Status: "Ready", Priority: 14},
			{ID: "3", Role: "backup", Model: "WS-C3750G-24PS", Release: "12.2(53)SE2", Status: "Ready", Priority: 13}}},
		{"entries named like the switches' parts are ignored", sw,
			"NAME: \"Switch 1 - Power Supply 0\", DESCR: \"x\"\nPID: PWR-C1-350WAC, VID: V01, SN: SN000099\n\n" +
				"NAME: \"Switch 1\", DESCR: \"x\"\nPID: WS-C3750G-24PS-S, VID: V05, SN: SN000004\n\n" +
				"NAME: \"3\", DESCR: \"x\"\nPID: WS-C3750G-24PS-S, VID: V05, SN: SN000006\n", "",
			[]Member{{ID: "1", Role: "master", Model: "WS-C3750G-24PS-S", Serial: "SN000004", Status: "Ready", Priority: 15},
				{ID: "2", Role: "member", Status: "Ready", Priority: 14},
				{ID: "3", Role: "backup", Model: "WS-C3750G-24PS-S", Serial: "SN000006", Status: "Ready", Priority: 13}}},
		{"IOS-XE 16.x prints Active for the master", vcFixture(t, "synthetic-iosxe-show-switch-active-3.txt"), "", "", []Member{
			{ID: "1", Role: "master", Status: "Ready", Priority: 15},
			{ID: "2", Role: "backup", Status: "Ready", Priority: 14},
			{ID: "3", Role: "member", Status: "Ready", Priority: 1}}},
		{"the role words in any case", "*1 ACTIVE 0000.5e00.5301 15 V01 Ready\n 2 standby 0000.5e00.5302 14 V01 Ready\n", "", "", []Member{
			{ID: "1", Role: "master", Status: "Ready", Priority: 15},
			{ID: "2", Role: "backup", Status: "Ready", Priority: 14}}},
		{"a switch that is provisioned and a role of an unknown kind",
			"*1       Master 0000.5e00.5301     15     V01     Ready\n 2       Member 0000.0000.0000      0      0      Provisioned\n 3       Unknown 0000.5e00.5303     1     V01     HA sync in progress\n", "", "",
			[]Member{{ID: "1", Role: "master", Status: "Ready", Priority: 15},
				{ID: "2", Role: "member", Status: "Provisioned"},
				{ID: "3", Status: "HA sync in progress Unknown", Priority: 1}}},
		{"a provisioned member with a blank H/W version column is read", vcFixture(t, "synthetic-ios-show-switch-provisioned.txt"), "", "", []Member{
			{ID: "1", Role: "master", Status: "Ready", Priority: 15},
			{ID: "2", Role: "member", Status: "Ready", Priority: 14},
			{ID: "3", Role: "member", Status: "Provisioned", Priority: 1}}},
		{"a blank version column in a row of its own",
			"*1       Master 0000.5e00.5301     15     V01     Ready\n 4  Member 0000.0000.0000  1            Provisioned\n", "", "",
			[]Member{{ID: "1", Role: "master", Status: "Ready", Priority: 15},
				{ID: "4", Role: "member", Status: "Provisioned", Priority: 1}}},
		{"a refusal", vcFixture(t, "real-ios-show-switch-refusal.txt"), inv, ver, nil},
		{"line has invalid autocommand", "Line has invalid autocommand \"show switch\"\n", inv, ver, nil},
		{"one switch is no stack", "Switch/Stack Mac Address : 0000.5e00.5301 - Local Mac Address\n*1       Master 0000.5e00.5301     15     V01     Ready\n", inv, ver, nil},
		{"empty", "", "", "", nil},
	} {
		got := IOSMembers(c.sw, c.inv, c.ver)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", c.name, got, c.want)
		}
	}
}

// Hostile text is cleaned, an over-long field is cut, a negative priority is
// 0 and at most 32 members are kept.
func TestCleanMembers(t *testing.T) {
	hostile := Member{ID: "1\x1b[2J", Role: "master", Model: "A\n  B", Serial: strings.Repeat("x", 300), Release: "15\x07.1", Status: "Pr\x00snt", Priority: -7,
		Components: []Component{{Kind: "fan\x01", Slot: strings.Repeat("y", 300)}}}
	got := CleanFacts(Facts{Members: []Member{hostile}}).Members
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	m := got[0]
	if m.ID != "1?[2J" || m.Model != "A? B" || len(m.Serial) != maxFact || m.Release != "15?.1" || m.Status != "Pr?snt" || m.Priority != 0 {
		t.Errorf("%+v", m)
	}
	if len(m.Components) != 1 || m.Components[0].Kind != "fan?" || len(m.Components[0].Slot) != maxFact {
		t.Errorf("components: %+v", m.Components)
	}
	var many []Member
	for i := 0; i < 33; i++ {
		many = append(many, Member{ID: fmt.Sprint(i), Role: "member"})
	}
	got = CleanFacts(Facts{Members: many}).Members
	if len(got) != 32 || got[31].ID != "31" {
		t.Errorf("%d members, last %+v", len(got), got[len(got)-1])
	}
	if CleanFacts(Facts{Members: []Member{}}).Members != nil {
		t.Error("an empty list stays empty")
	}
	// the readers clean what a device sends
	vc := "0 (FPC 0)  Prsnt  " + strings.Repeat("S", 300) + "  ex\x1b[2J4300  129  Master*\n1 (FPC 1)  Prsnt  SN000002  ex4300  129  Backup\n"
	ms := JunosMembers(vc, "", "")
	if len(ms) != 2 || len(ms[0].Serial) != maxFact || !strings.HasPrefix(ms[0].Model, "ex") {
		t.Errorf("%+v", ms)
	}
	for _, m := range ms {
		for _, s := range []string{m.ID, m.Role, m.Model, m.Serial, m.Release, m.Status} {
			if strings.ContainsAny(s, "\x1b\x00\x07") {
				t.Errorf("control character kept: %q", s)
			}
		}
	}
}

func TestFactsEmptyMembers(t *testing.T) {
	if (Facts{Members: []Member{{ID: "0"}}}).Empty() || !(Facts{Members: []Member{}}).Empty() {
		t.Error("Empty must consider the members")
	}
}

// A member has a list of components in JSON, an empty one, never null.
func TestMemberJSON(t *testing.T) {
	raw, err := json.Marshal(Member{ID: "0", Role: "master", Model: "ex4300-48t", Serial: "SN000001", Release: "25.4R1", Status: "Prsnt", Priority: 129})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"0","role":"master","model":"ex4300-48t","serial":"SN000001","release":"25.4R1","status":"Prsnt","priority":129,"components":[]}`
	if string(raw) != want {
		t.Errorf("%s", raw)
	}
	raw, _ = json.Marshal([]Member{{ID: "1"}})
	if !strings.Contains(string(raw), `"components":[]`) || strings.Contains(string(raw), "null") {
		t.Errorf("in a list: %s", raw)
	}
	raw, _ = json.Marshal(&Member{ID: "1", Components: []Component{{Kind: "fan", Slot: "0", Model: "m", Serial: "SN000009", Status: "ok"}}})
	if !strings.Contains(string(raw), `"components":[{"kind":"fan","slot":"0","model":"m","serial":"SN000009","status":"ok"}]`) {
		t.Errorf("components: %s", raw)
	}
	var back Member
	if err := json.Unmarshal([]byte(want), &back); err != nil || back.Priority != 129 || len(back.Components) != 0 {
		t.Errorf("%+v %v", back, err)
	}
}

// The readers never panic on odd input.
func TestMembersOddInput(t *testing.T) {
	for _, s := range []string{"", "\n\n", "(", "0 (FPC", "0 (FPC 0)", "0 (FPC 0) ", "99999999999999999999 (FPC 0)  Prsnt  a  b  1  Master\n1 (FPC 1) x", strings.Repeat("0 (FPC 0)  ", 1000),
		"*", "*1", "* 1 Master 0000.0000.0000", "Switch Ports Model SW Version\n", "NAME: \"Switch 1\"\nPID:\n"} {
		JunosMembers(s, s, s)
		IOSMembers(s, s, s)
		JunosMembers("0 (FPC 0) a b 1 Master\n1 (FPC 1) a b 1 Backup\n", s, s)
		IOSMembers(" 1 Master 0000.0000.0000 1 V01 Ready\n 2 Member 0000.0000.0001 1 V01 Ready\n", s, s)
	}
}
