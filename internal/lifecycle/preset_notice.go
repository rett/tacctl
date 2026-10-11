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
