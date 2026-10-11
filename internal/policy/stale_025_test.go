package policy

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

// linesOfPrevious is a generation of previousDefaults as rule lines.
func linesOfPrevious(group string, gen int) []string {
	var out []string
	for _, r := range previousDefaults[group][gen] {
		out = append(out, r.name+"|"+r.action+"|"+strings.Join(r.match, ","))
	}
	return out
}

// The 0.2.3 shipped lists are what the table says: the operator's 14 rules
// and nine privileges, the viewer's nine rules.
func TestPreviousDefaultsAreWhat023Shipped(t *testing.T) {
	op := linesOfPrevious("operator", 1)
	if len(op) != 14 || op[0] != "show|deny|^(running-config view full)( .*)?$" || op[8] != "monitor|permit|^(capture)( .*)?$" {
		t.Errorf("operator 0.2.3: %q", op)
	}
	if ro := linesOfPrevious("readonly", 1); len(ro) != 9 {
		t.Errorf("readonly 0.2.3: %q", ro)
	}
	if n := len(previousPrivileges["operator"][0]); n != 9 {
		t.Errorf("operator privileges 0.2.3: %d entries", n)
	}
}

// An override equal to a list of 0.2.3 is not a choice and is dropped; a
// list that differs by one rule or one entry is left alone and named.
func TestDropPreviousDefaults(t *testing.T) {
	c, _ := newConf(t, "")
	for _, g := range []string{"operator", "readonly"} {
		if err := Write(c, g, linesOfPrevious(g, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := WritePrivileges(c, "operator", previousPrivileges["operator"][0]); err != nil {
		t.Fatal(err)
	}
	if got := StaleOperatorPolicy(c); len(got) != 3 {
		t.Fatalf("stale before: %v", got)
	}
	dropped, err := DropPreviousDefaults(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dropped, " ") != "commands.operator commands.readonly privileges.operator" {
		t.Errorf("dropped %v", dropped)
	}
	for _, g := range []string{"operator", "readonly"} {
		if HasOverride(c, g) || !SameLines(Lines(c, g), DefaultLines(g)) {
			t.Errorf("%s still overridden: %q", g, Lines(c, g))
		}
	}
	if c.HasOverride("privileges.operator") {
		t.Error("privileges.operator still overridden")
	}
	if got := StaleOperatorPolicy(c); len(got) != 0 {
		t.Errorf("stale after: %v", got)
	}
	again, err := DropPreviousDefaults(c)
	if err != nil || len(again) != 0 {
		t.Errorf("a second run: %v %v", again, err)
	}

	// One entry more, or fewer, is a choice.
	own := append(append([]string{}, previousPrivileges["operator"][0]...), "show version")
	if err := WritePrivileges(c, "operator", own); err != nil {
		t.Fatal(err)
	}
	opLines := append(linesOfPrevious("operator", 1)[:13:13], "debug|permit|", "*|deny|")
	if err := Write(c, "operator", opLines); err != nil {
		t.Fatal(err)
	}
	if dropped, _ := DropPreviousDefaults(c); len(dropped) != 0 {
		t.Errorf("customised lists dropped: %v", dropped)
	}
	got := StaleOperatorPolicy(c)
	if len(got) != 2 || got[0].Setting != "privileges.operator" || got[1].Setting != "commands.operator" {
		t.Fatalf("stale: %v", got)
	}
	if want := "privileges.operator (exec all: ping, exec all: traceroute, exec all: monitor capture, clear counters, clear line, clear ip arp, clear arp-cache, clear mac address-table dynamic)"; got[0].String() != want {
		t.Errorf("privileges: %q", got[0])
	}
	if got[1].String() != "commands.operator (clear, monitor, ping, traceroute)" {
		t.Errorf("commands: %q", got[1])
	}
	if got[0].Fix() != "tacctl group privilege reset operator" || got[1].Fix() != "tacctl group commands reset operator" ||
		got[0].Restores() != "the shipped value" || got[1].Restores() != "the shipped value" {
		t.Errorf("fixes: %q %q", got[0].Fix(), got[1].Fix())
	}
}

// The Junos sets the 0.2.3 preset wrote are named, the current ones and a
// customised one are not.
func TestStaleOperatorPolicyJunosSets(t *testing.T) {
	c, _ := newConf(t, "")
	if err := WriteJunosSet(c, "readonly", conf.JunosDenyCommands, []string{viewerDenyCommands023}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJunosSet(c, "operator", conf.JunosDenyCommands, []string{operatorDenyCommands023}); err != nil {
		t.Fatal(err)
	}
	got := StaleOperatorPolicy(c)
	if len(got) != 2 || got[0].String() != "junos readonly deny-commands" || got[1].Fix() != "tacctl group reset operator --preset --only junos" || got[1].Restores() != "the role preset's value" {
		t.Fatalf("0.2.3 sets: %v", got)
	}
	for _, r := range RolePreset() {
		if r.Group == "readonly" || r.Group == "operator" {
			if err := WriteJunosSet(c, r.Group, conf.JunosDenyCommands, r.Junos[conf.JunosDenyCommands]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := StaleOperatorPolicy(c); len(got) != 0 {
		t.Errorf("the current preset: %v", got)
	}
}

// The preset's rules are the shipped ones plus the show deny: neither
// carries anything retired.
func TestCurrentPresetIsNotStale(t *testing.T) {
	c, _ := newConf(t, "")
	for _, r := range RolePreset() {
		if r.Commands != nil {
			if err := Write(c, r.Group, r.Commands); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := WritePrivileges(c, "operator", DefaultPrivileges("operator")); err != nil {
		t.Fatal(err)
	}
	if got := StaleOperatorPolicy(c); len(got) != 0 {
		t.Errorf("stale: %v", got)
	}
}
