package devconf

// 0.2.7: a scope's snmp block in the rendering. The labels number its
// community strings after the structured settings' in the order of the
// rendering, whatever order the device prints them in, and a trap group the
// block names is not a community.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// blockRendering is the snmp section of a scope with a block: tacctl's own
// community, then the block's community, trap group and trap options.
func blockRendering() devices.Section {
	return devices.Section{Name: SectionSNMP,
		Lines: []string{
			"set snmp client-list TACCTL-SNMP 192.0.2.10/32",
			"set snmp community lab-ro-community authorization read-only",
			"set snmp community lab-ro-community client-list-name TACCTL-SNMP",
			"set snmp community nms-ro authorization read-only",
			"set snmp community nms-ro clients 192.0.2.50/32",
			"set snmp trap-group nms-traps version v2",
			"set snmp trap-group nms-traps targets 198.51.100.7",
			"set snmp trap-options agent-address outgoing-interface",
		},
		Secret: []bool{false, true, true, true, true, true, true, false},
		Block:  []bool{false, false, false, true, true, true, true, true}}
}

func TestBlockLabelsFollowTheRendering(t *testing.T) {
	r := blockRendering()
	got, err := CommunityLabels(FamilyJunos, r.Lines)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"<secret:1>": "lab-ro-community", "<secret:2>": "nms-ro", "<secret:3>": "nms-traps"}
	if len(got) != len(want) {
		t.Fatalf("labels: %v", got)
	}
	for l, s := range want {
		if got[l] != s {
			t.Errorf("%s is %q, want %q", l, got[l], s)
		}
	}
	// a trap group named like a community is the same string: one label
	lines := append(slices.Clone(r.Lines), "set snmp trap-group nms-ro targets 198.51.100.8")
	got, _ = CommunityLabels(FamilyJunos, lines)
	if len(got) != 3 {
		t.Errorf("a trap group of a community's name has a label of its own: %v", got)
	}
}

// The device prints the block's community before tacctl's own and has
// others of its own between: every one is labelled by the rendering, so the
// block's statements still compare equal and nothing of the device's is
// taken for them.
func TestBlockLabelsMapWhateverTheDeviceOrder(t *testing.T) {
	text := strings.Join([]string{
		"set snmp community device-own authorization read-write",
		"set snmp community nms-ro clients 192.0.2.50/32",
		"set snmp community nms-ro authorization read-only",
		"set snmp trap-group nms-traps targets 198.51.100.7",
		"set snmp trap-group nms-traps version v2",
		"set snmp community lab-ro-community client-list-name TACCTL-SNMP",
		"set snmp community lab-ro-community authorization read-only",
		"set snmp client-list TACCTL-SNMP 192.0.2.10/32",
		"set snmp trap-options agent-address outgoing-interface",
		"set snmp trap-options source-address 192.0.2.250",
		"set snmp trap-group device-traps targets 198.51.100.9",
	}, "\n") + "\n"
	r := blockRendering()
	ex, err := Extract("juniper", text, r)
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Sections[SectionSNMP].Lines
	for _, want := range []string{
		"set snmp community <secret:1> authorization read-only", "set snmp community <secret:2> clients 192.0.2.50/32",
		"set snmp trap-group <secret:3> targets 198.51.100.7", "set snmp community <other:1> authorization read-write",
		"set snmp trap-group <other:2> targets 198.51.100.9",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("the extraction lacks %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
	for _, l := range got {
		if strings.Contains(l, "nms-") || strings.Contains(l, "lab-ro") || strings.Contains(l, "device-") {
			t.Errorf("the extraction holds a string: %q", l)
		}
	}
	res, err := Compare("juniper", r, ex.Sections[SectionSNMP], true)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateOK || res.Unmanaged != 3 {
		t.Errorf("%s, %d unmanaged:\n%v", res.State, res.Unmanaged, res.Lines)
	}
	for _, l := range res.Lines {
		if l.Op == OpMissing {
			t.Errorf("missing: %q", l.Text)
		}
	}
	// a leaf under a block's object that the block does not state is a
	// difference, one under the device's own is not
	more := ex.Sections[SectionSNMP]
	more.Lines = append(slices.Clone(more.Lines), "set snmp trap-group <secret:3> targets 203.0.113.9")
	res, _ = Compare("juniper", r, more, true)
	if res.State != StateDiffers {
		t.Errorf("an extra target of the block's trap group reads %s", res.State)
	}
	more.Lines = append(slices.Clone(ex.Sections[SectionSNMP].Lines), "set snmp trap-group <other:2> targets 203.0.113.9")
	res, _ = Compare("juniper", r, more, true)
	if res.State != StateOK || res.Unmanaged != 4 {
		t.Errorf("an extra target of the device's trap group reads %s (%d)", res.State, res.Unmanaged)
	}
	// and the planner types the real name for a label
	lb, _ := CommunityLabels(FamilyJunos, r.Lines)
	if lb["<secret:2>"] != "nms-ro" {
		t.Errorf("<secret:2> is %q", lb["<secret:2>"])
	}
}

// --- the IOS snmp block -----------------------------------------------------------

// iosBlockRendering is the snmp section of an IOS scope with a block:
// tacctl's own list and community, then the block's list, community, host and
// 'enable traps' lines.
func iosBlockRendering() devices.Section {
	return devices.Section{Name: SectionSNMP,
		Lines: []string{
			"ip access-list standard TACCTL-SNMP",
			"  permit host 192.0.2.10",
			"  deny   any",
			"snmp-server community lab-ro-community RO TACCTL-SNMP",
			"ip access-list standard NMS-POLLERS",
			"  permit host 192.0.2.50",
			"  permit 198.51.100.0 0.0.0.255",
			"snmp-server community nms-ro RO NMS-POLLERS",
			"snmp-server host 198.51.100.7 version 2c nms-traps udp-port 162 config",
			"snmp-server enable traps config",
			"snmp-server enable traps snmp linkdown",
		},
		Secret: []bool{false, false, false, true, false, false, false, true, true, false, false},
		Block:  []bool{false, false, false, false, true, true, true, true, true, true, true}}
}

// The device prints its lines in its own order, with its own communities and
// hosts between; every string is labelled by the rendering, the block's
// statements compare equal, a trap line that the device enables in another
// shape is satisfied, and what the device holds besides is its own.
func TestIOSBlockComparesAsRendered(t *testing.T) {
	r := iosBlockRendering()
	text := strings.Join([]string{
		"hostname rt1",
		"snmp-server community device-own RW DEVICE-OWN",
		"snmp-server community nms-ro RO NMS-POLLERS",
		"snmp-server community lab-ro-community RO TACCTL-SNMP",
		"snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart",
		"snmp-server enable traps config",
		"snmp-server enable traps tty",
		// the stored form: the default port is not printed
		"snmp-server host 198.51.100.7 version 2c nms-traps config",
		"snmp-server host 198.51.100.9 version 2c device-traps",
		"ip access-list standard TACCTL-SNMP",
		" permit 192.0.2.10",
		" deny any",
		"ip access-list standard NMS-POLLERS",
		" permit 198.51.100.0 0.0.0.255",
		" permit 192.0.2.50",
		"ip access-list standard DEVICE-OWN",
		" permit 203.0.113.1",
		"end",
	}, "\n") + "\n"
	ex, err := Extract("cisco", text, r)
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Sections[SectionSNMP].Lines
	for _, want := range []string{
		"snmp-server community <secret:2> RO NMS-POLLERS", "snmp-server community <other:1> RW DEVICE-OWN",
		"snmp-server host 198.51.100.7 version 2c <secret:3> config", "snmp-server host 198.51.100.9 version 2c <other:2>",
		"ip access-list standard NMS-POLLERS > permit 192.0.2.50",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("the extraction lacks %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
	for _, l := range got {
		for _, bad := range []string{"nms-ro", "nms-traps", "device-own", "device-traps", "lab-ro-community"} {
			if strings.Contains(l, bad) {
				t.Errorf("the extraction holds a string: %q", l)
			}
		}
	}
	res, err := Compare("cisco", r, ex.Sections[SectionSNMP], true)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range res.Lines {
		if l.Op == OpMissing {
			t.Errorf("missing: %q", l.Text)
		}
	}
	// the device's own: another community, its list and its list's entry, a
	// trap host of another community, 'enable traps tty', and the device's
	// own spelling of the trap line the rendering states shorter
	if res.State != StateOK || res.Unmanaged != 5 {
		t.Errorf("%s, %d unmanaged:\n%v", res.State, res.Unmanaged, res.Lines)
	}

	// an entry the block does not state in a list it defines is a difference
	more := ex.Sections[SectionSNMP]
	more.Lines = append(slices.Clone(more.Lines), "ip access-list standard NMS-POLLERS > permit 203.0.113.9")
	if res, _ = Compare("cisco", r, more, true); res.State != StateDiffers {
		t.Errorf("an extra entry of the block's list reads %s", res.State)
	}
	// an entry in the device's own list is not
	more.Lines = append(slices.Clone(ex.Sections[SectionSNMP].Lines), "ip access-list standard DEVICE-OWN > permit 203.0.113.9")
	if res, _ = Compare("cisco", r, more, true); res.State != StateOK {
		t.Errorf("an extra entry of the device's list reads %s", res.State)
	}
	// the block's host with other options on the device is a difference
	more.Lines = slices.Clone(ex.Sections[SectionSNMP].Lines)
	for i, l := range more.Lines {
		if strings.HasPrefix(l, "snmp-server host 198.51.100.7 ") {
			more.Lines[i] = "snmp-server host 198.51.100.7 version 2c <secret:3>"
		}
	}
	res, _ = Compare("cisco", r, more, true)
	if res.State != StateDiffers {
		t.Errorf("a block host with other options reads %s", res.State)
	}
	extra := false
	for _, l := range res.Lines {
		if l.Op == OpExtra && l.Text == "snmp-server host 198.51.100.7 version 2c <secret:3> (present, not compared)" && !l.Unmanaged {
			extra = true
		}
	}
	if !extra {
		t.Errorf("the device's line of the block's host is not a difference:\n%v", res.Lines)
	}
	// the community retyped with another access list is a difference too
	more.Lines = slices.Clone(ex.Sections[SectionSNMP].Lines)
	for i, l := range more.Lines {
		if l == "snmp-server community <secret:2> RO NMS-POLLERS" {
			more.Lines[i] = "snmp-server community <secret:2> RW NMS-POLLERS"
		}
	}
	if res, _ = Compare("cisco", r, more, true); res.State != StateDiffers {
		t.Errorf("a block community of another access reads %s", res.State)
	}
}

// 'snmp-server enable traps' with no type enables every type, which a device
// prints one by one: the statement is present once the device has any line of
// the family, and missing when it has none.
func TestIOSBlockBareTrapsLine(t *testing.T) {
	r := devices.Section{Name: SectionSNMP, Lines: []string{"snmp-server enable traps"}, Secret: []bool{false}, Block: []bool{true}}
	with := "hostname rt1\nsnmp-server enable traps snmp linkdown\nsnmp-server enable traps config\nend\n"
	ex, err := Extract("cisco", with, r)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := Compare("cisco", r, ex.Sections[SectionSNMP], true)
	if res.State != StateOK || res.Unmanaged != 2 {
		t.Errorf("with lines: %s (%d)\n%v", res.State, res.Unmanaged, res.Lines)
	}
	ex, _ = Extract("cisco", "hostname rt1\nend\n", r)
	res, _ = Compare("cisco", r, ex.Sections[SectionSNMP], true)
	if res.State != StateMissing {
		t.Errorf("without lines: %s\n%v", res.State, res.Lines)
	}
}
