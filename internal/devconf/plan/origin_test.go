package plan

import (
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// A line tacctl renders from its structured settings is never taken for a
// block's, however many leading words it shares with a statement of a block
// of another section.
func TestOriginIsLookedUpInTheLinesOwnSection(t *testing.T) {
	f := systemFixture(t)
	sec := junosAbsentSection(t, "set system login message <<'EOF'\nNotice.\nEOF\nset system login password minimum-length 12\n")
	exp := withSystem(expectedSections(t, f.expected), sec)
	exp[indexOfSection(exp, "system")].Origin = make([]string, len(sec.Lines))
	for i := range exp[indexOfSection(exp, "system")].Origin {
		exp[indexOfSection(exp, "system")].Origin[i] = "scope block lab juniper system"
	}
	d, _ := planSystem(t, dropPrefix("system login class", "system login message"), exp, systemOpt)
	var roles, system int
	for _, l := range d.Lines {
		o := d.originOf(l)
		switch l.Section {
		case "roles":
			roles++
			if o != "" {
				t.Errorf("a login class of the structured settings is a block's: %q from %q", l.Text, o)
			}
		case "system":
			if l.Text != "" && o != "" {
				system++
			}
		}
	}
	if roles == 0 {
		t.Fatal("the plan has no roles line: the case tests nothing")
	}
	if system == 0 {
		t.Error("no line of the system block names its block")
	}
}

func indexOfSection(secs []devices.Section, name string) int {
	for i := range secs {
		if secs[i].Name == name {
			return i
		}
	}
	return -1
}
