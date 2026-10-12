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
