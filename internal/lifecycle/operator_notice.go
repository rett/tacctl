package lifecycle

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// The operator audit of 0.2.5 (docs/plans/0.2.5-operator-audit.md): what
// the upgrade says about it. Two things need saying, and they are
// different: a stored setting that still gives the operator what was
// removed (named every upgrade while it stays), and the devices
// configured earlier, which keep the privilege lines they were given
// whatever tacctl.yaml holds (said once, by the first upgrade onto this
// release, and again with a stored setting).

// OperatorNoticeDone reports whether the upgrade has said what a device
// configured earlier keeps (the marker p.OperatorNoticeMarker). An empty
// path is always done: nothing records it.
func OperatorNoticeDone(p paths.Paths) bool {
	if p.OperatorNoticeMarker == "" {
		return true
	}
	_, err := os.Stat(p.OperatorNoticeMarker)
	return err == nil
}

// MarkOperatorNotice records that it was said (the marker, 0600, in
// VarLib). A fresh install writes it too: it has no device configured
// earlier.
func MarkOperatorNotice(p paths.Paths) error {
	if p.OperatorNoticeMarker == "" {
		return nil
	}
	if err := paths.MkVarLib(filepath.Dir(p.OperatorNoticeMarker)); err != nil {
		return err
	}
	return os.WriteFile(p.OperatorNoticeMarker, []byte("tacctl 0.2.5 told once, at an upgrade, that a device configured earlier keeps the operator privilege lines it was given. Delete this file only to be told again.\n"), 0o600)
}

// operatorNotice is the upgrade's say about the operator audit. It prints
// when a stored setting still carries what 0.2.5 removed (the commands
// that clear a table or a line, capture traffic, or take ping and
// traceroute past a bound; the Junos deny sets of the 0.2.3 preset), and
// on the first upgrade onto this release; an install on the shipped values
// that has already been told prints nothing.
//
// The stored settings are named with the command that replaces each
// (policy.Fixes); an upgrade drops only a list that is exactly what 0.2.3
// shipped, and never changes a value somebody chose. The devices are said
// whatever tacctl.yaml holds: a device configured by an earlier walkthrough
// keeps its 'privilege exec level 7' lines (and Junos its 'clear' bit),
// so its operators keep the old reach when the server does not answer
// and always over RADIUS, until the lines are removed.
func (h *Host) operatorNotice() {
	stale := policy.StaleOperatorPolicy(h.Conf)
	first := !OperatorNoticeDone(h.Paths)
	if len(stale) == 0 && !first {
		return
	}
	h.echo(ui.Red + "  An operator may no longer interrupt service, even briefly: the commands that clear a" + ui.NC)
	h.echo(ui.Red + "  table or a line, capture traffic, or send ping and traceroute with an unbounded count," + ui.NC)
	h.echo(ui.Red + "  timeout or size (or interactively) are the engineer's." + ui.NC)
	if len(stale) > 0 {
		h.echo(ui.Red + "  These stored settings still give them to the operator or the viewer, and an upgrade does" + ui.NC)
		h.echo(ui.Red + "  not change a value somebody set:" + ui.NC)
		for _, s := range stale {
			h.echo(ui.Red + "    " + s.String() + ui.NC)
		}
		h.echo(ui.Red + "  Review each with '--dry-run', then run it ('group privilege reset' and 'group commands" + ui.NC)
		h.echo(ui.Red + "  reset' put back the shipped value, 'group reset ... --preset' the role preset's):" + ui.NC)
		for _, f := range policy.Fixes(stale) {
			h.echo(ui.Red + "    " + f + ui.NC)
		}
	}
	h.echo(ui.Red + "  A device configured by an earlier walkthrough keeps the lines it was given: until they are" + ui.NC)
	h.echo(ui.Red + "  removed its operators keep the old reach whenever the server does not answer, and always" + ui.NC)
	h.echo(ui.Red + "  over RADIUS. On Cisco, in configuration mode:" + ui.NC)
	for _, l := range []string{
		"no privilege exec all level 7 ping",
		"no privilege exec all level 7 traceroute",
		"no privilege exec all level 7 monitor capture",
		"no privilege exec level 7 clear counters",
		"no privilege exec level 7 clear line",
		"no privilege exec level 7 clear ip arp",
		"no privilege exec level 7 clear arp-cache",
		"no privilege exec level 7 clear mac address-table dynamic",
	} {
		h.echo(ui.Red + "    " + l + ui.NC)
	}
	h.echo(ui.Red + "  On Junos, in configuration mode:" + ui.NC)
	h.echo(ui.Red + "    delete system login class OP-CLASS permissions clear" + ui.NC)
	h.echo(ui.Red + "  After 'tacctl device config pull <device>', 'tacctl device config plan <device>' prints" + ui.NC)
	h.echo(ui.Red + "  exactly the lines a given device needs, in the form its image stores them." + ui.NC)
	h.echo("")
	// An upgrade never creates VarLib (an install without one has seen no
	// device and pinned no key); it is told again until something does.
	if _, err := os.Stat(filepath.Dir(h.Paths.OperatorNoticeMarker)); first && err == nil {
		if err := MarkOperatorNotice(h.Paths); err != nil {
			h.Out.Warn("Could not record that this notice was shown in " + h.Paths.OperatorNoticeMarker + ": " + strings.TrimSpace(err.Error()))
		}
	}
}
