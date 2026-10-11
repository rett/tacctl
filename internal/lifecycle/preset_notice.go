package lifecycle

import (
	"strings"

	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// presetNotice tells an install that ran 0.2.2's 'group preset roles' that
// the engineer rules it wrote are still in force: the preset's values are
// overrides, which an upgrade never touches, and the Cisco denies of 0.2.2
// did not hold (tacquito anchors a match at both ends, so a prefix form
// matched only the exact single-word argument). It prints nothing when
// engineer carries other values or none.
//
// The fix is the current preset, applied over the old values:
// 'tacctl group reset engineer' (docs/plans/0.2.3-plan.md D51) does that for
// the one group, with a diff and a confirmation.
func (h *Host) presetNotice() {
	stale := policy.Stale022Preset(h.Conf)
	if len(stale) == 0 {
		return
	}
	h.echo(ui.Red + "  The engineer group still carries the role preset of 0.2.2 (" + strings.Join(stale, ", ") + ")." + ui.NC)
	h.echo(ui.Red + "  Its Cisco denies did not hold: 'no aaa new-model', 'enable secret ...', 'ip ssh ...' and" + ui.NC)
	h.echo(ui.Red + "  'do reload in 5' were permitted, because tacquito matches the whole arguments string." + ui.NC)
	h.echo(ui.Red + "  An upgrade does not change these settings. Review the current preset and apply it:" + ui.NC)
	h.echo(ui.Red + "    tacctl group reset engineer --dry-run" + ui.NC)
	h.echo(ui.Red + "    tacctl group reset engineer" + ui.NC)
	h.echo("")
}

// operatorNotice tells an install whose stored settings still give the
// operator or the viewer what 0.2.5 removed (a command that clears a table
// or a line, captures traffic or floods; the Junos deny sets of the 0.2.3
// preset) that they are still in force: an upgrade drops only a list that
// is exactly what 0.2.3 shipped, and never changes a value somebody chose.
// It prints nothing for an install on the shipped values.
func (h *Host) operatorNotice() {
	stale := policy.StaleOperatorPolicy(h.Conf)
	if len(stale) == 0 {
		return
	}
	h.echo(ui.Red + "  An operator may no longer interrupt service, even briefly: the commands that clear a" + ui.NC)
	h.echo(ui.Red + "  table or a line, capture traffic, or send ping and traceroute at a rate are the engineer's." + ui.NC)
	h.echo(ui.Red + "  These stored settings still give them to the operator or the viewer, and an upgrade does" + ui.NC)
	h.echo(ui.Red + "  not change a value somebody set:" + ui.NC)
	fixes := map[string]bool{}
	var order []string
	for _, s := range stale {
		h.echo(ui.Red + "    " + s.String() + ui.NC)
		if f := s.Fix(); !fixes[f] {
			fixes[f] = true
			order = append(order, f)
		}
	}
	h.echo(ui.Red + "  Review each with '--dry-run' and take the shipped value:" + ui.NC)
	for _, f := range order {
		h.echo(ui.Red + "    " + f + ui.NC)
	}
	h.echo(ui.Red + "  A device configured earlier keeps its 'privilege exec level 7' lines until they are removed:" + ui.NC)
	h.echo(ui.Red + "  'tacctl device config plan <device>' prints the 'no privilege exec ...' lines." + ui.NC)
	h.echo("")
}
