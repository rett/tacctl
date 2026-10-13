package plan

// The output of a WTI unit's plan (0.2.7; design W11-W13). The box, the
// report and the check line come first, then the checklist of menu steps
// between two banners, then the IP tables block between a second pair, then
// the check and the way back. Every line is a comment ('#') but the lines of
// the one <iptables> block: a copy of a whole output pastes nothing but that
// block (CheckRegion), and the block is the only text a person pastes.

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// ErrWTIPlain: a unit's plan has no statements to load from a file.
var ErrWTIPlain = errors.New("plan: a WTI unit has no plain form: its plan is menu steps and one IP tables block")

// UnitInfo is what the pull of a WTI unit saw beside its sections.
type UnitInfo struct {
	// Version is the command menu version, SiteID the Site ID the unit
	// printed ("" when it printed none).
	Version, SiteID string
	// OtherSessions is the number of other sessions the unit had.
	OtherSessions int
}

func wtiBanner(s string) string { return "##### " + s + " #####" }

// wtiRow is one line of a checklist.
type wtiRow struct {
	keys, label, enter, was string
}

// wtiRows formats rows as the comment lines of a checklist, the columns
// aligned within it, numbered from first.
func wtiRows(rows []wtiRow, first int) []string {
	kw, lw := 0, 0
	for i := range rows {
		rows[i].keys = strings.Join(strings.Fields(rows[i].keys), "  ")
		kw, lw = max(kw, len(rows[i].keys)), max(lw, len(rows[i].label))
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		s := fmt.Sprintf("#%3d. %-*s  %-*s  -> %s", first+i, kw, r.keys, lw, r.label, r.enter)
		if r.was != "" {
			s += "   was: " + r.was
		}
		out[i] = s
	}
	return out
}

// commentLines wraps a sentence into comment lines.
func commentLines(s string, width int) []string {
	var out []string
	for _, l := range wrapText(s, width) {
		out = append(out, "# "+l)
	}
	return out
}

// the legend at the head of a checklist.
func wtiLegend() []string {
	return []string{
		"# At the unit's prompt type /N and Enter. For each step type the item numbers of its second column,",
		"# one at a time with Enter after each, then what the arrow says. A pick: the number of the line",
		"# that reads as shown. ESC goes back one level. A value is live as soon as its Enter is accepted.",
	}
}

// wtiCheckStep is the check that follows the steps: the way the unit's AAA
// or SNMP is looked at from outside.
func wtiCheckStep(d Delta, h Header) string {
	switch {
	case d.WTI != nil && d.WTI.GuardedAAA:
		return "CHECK from a SECOND session (this one stays open): log in as a member of scope " + h.Scope +
			" and type /H; the help lists the commands of the level the server assigned (Step 8 of tacctl config wti). Go on only when it does."
	case d.WTI != nil && d.WTI.SNMPSteps:
		addr := h.Address
		if addr == "" {
			addr = "<unit-address>"
		}
		return "CHECK from the tacctl server: tacctl scope snmp " + h.Scope + " test " + addr
	}
	return ""
}

// wtiStepsRegion is the checklist's banner pair.
func wtiStepsRegion(d Delta, h Header) []RegionLine {
	if d.WTI == nil || len(d.WTI.Steps) == 0 {
		return nil
	}
	out := []RegionLine{{Text: wtiBanner("DO THESE STEPS ON: " + h.Device), Comment: true, Line: -1}}
	for _, l := range wtiLegend() {
		out = append(out, RegionLine{Text: l, Comment: true, Line: -1})
	}
	rows := make([]wtiRow, len(d.WTI.Steps))
	for i, s := range d.WTI.Steps {
		rows[i] = wtiRow{keys: s.Keys, label: s.Label, enter: s.Enter, was: s.Was}
	}
	for i, l := range wtiRows(rows, 1) {
		out = append(out, RegionLine{Text: l, Comment: true, Line: d.WTI.Steps[i].Line})
	}
	n := len(rows)
	save := fmt.Sprintf("#%3d. ESC ESC  leave /N: wait for \"Saving configuration to flash\"", n+1)
	out = append(out, RegionLine{Text: save, Comment: true, Line: -1})
	if c := wtiCheckStep(d, h); c != "" {
		lines := wrapText(c, 92)
		for i, l := range lines {
			pad := "#%3d. "
			text := fmt.Sprintf(pad, n+2) + l
			if i > 0 {
				text = "#      " + l
			}
			out = append(out, RegionLine{Text: text, Comment: true, Line: -1})
		}
	}
	out = append(out, RegionLine{Text: wtiBanner("END OF STEPS"), Comment: true, Line: -1})
	return out
}

// wtiBlockLines are the lines of an IP tables list as a block.
func wtiBlockLines(cmds []string) []string {
	return append(append([]string{"<iptables>"}, cmds...), "</iptables>")
}

// wtiIPTablesRegion is the block's banner pair, with the notes above it.
func wtiIPTablesRegion(d Delta, h Header) []RegionLine {
	if d.WTI == nil || d.WTI.Block == nil {
		return nil
	}
	b := d.WTI.Block
	li := b.Line
	out := []RegionLine{{Text: wtiBanner("IP TABLES (replaces every entry; see the notes): " + h.Device), Comment: true, Line: li}}
	first := "Do this "
	if d.WTI != nil && len(d.WTI.Steps) > 0 {
		first += "after the steps above and their check, "
	}
	for _, l := range commentLines(first+"from the serial session or one you can afford to lose: the list is the unit's firewall, and a wrong one cuts off every way in.", 96) {
		out = append(out, RegionLine{Text: l, Comment: true, Line: li})
	}
	for _, l := range commentLines("At the /N menu type 5 and Enter, then paste the block below as it stands (<iptables> to </iptables>, at the left margin) at the page's prompt. The unit answers \"Configuring iptables - Please wait...\".", 96) {
		out = append(out, RegionLine{Text: l, Comment: true, Line: li})
	}
	now := plural(len(b.Old), "entry", "entries")
	if len(b.Old) == 0 {
		now = "no entry"
	}
	text := fmt.Sprintf("The paste REPLACES every entry the unit holds (%s now) with %s", now, plural(len(b.Commands)+len(b.Tail), "entry", "entries"))
	if len(b.Tail) > 0 {
		text += fmt.Sprintf(": %d rendered by tacctl and the %d of the unit's own tail, kept as the pull showed them (the final DROP and the policies).", len(b.Commands), len(b.Tail))
	} else {
		text += ", all rendered by tacctl. The unit's list has no tail (no final DROP, no INPUT policy), so this list restricts nothing until the walkthrough's last step is pasted by you (Step 11: tacctl device config show " + h.Device + ")."
	}
	for _, l := range commentLines(text, 96) {
		out = append(out, RegionLine{Text: l, Comment: true, Line: li})
	}
	for _, l := range commentLines("It is live when the unit takes it; there is no commit-confirm. Leaving /N with ESC (any session that does) writes it to flash: wait for \"Saving configuration to flash\". Check at once from a second session, and from an address outside the list: it must be refused.", 96) {
		out = append(out, RegionLine{Text: l, Comment: true, Line: li})
	}
	for _, l := range commentLines("The way back is: tacctl device config plan "+h.Device+" --backout (the old list as a block, or the slots to clear).", 96) {
		out = append(out, RegionLine{Text: l, Comment: true, Line: li})
	}
	for _, l := range wtiBlockLines(append(append([]string{}, b.Commands...), b.Tail...)) {
		out = append(out, RegionLine{Text: l, Line: li})
	}
	out = append(out, RegionLine{Text: wtiBanner("END OF IP TABLES: " + h.Device), Comment: true, Line: li})
	return out
}

// wtiRegionLines are the lines of both banner pairs, in order.
func wtiRegionLines(d Delta, h Header) []RegionLine {
	return append(wtiStepsRegion(d, h), wtiIPTablesRegion(d, h)...)
}

// wtiAfter is the text after the regions: the check, the way back, what not
// to do. All comments.
func wtiAfter(d Delta, h Header) string {
	var b strings.Builder
	add := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString("# " + l + "\n")
		}
	}
	b.WriteString("#\n")
	add("Check now. The unit has no rollback: nothing undoes this by itself.")
	b.WriteString("#   From the tacctl server:   tacctl device config pull " + h.Device + " --diff     (" + joinAnd(d.Planned()) + ": ok)\n")
	if d.WTI != nil && d.WTI.GuardedAAA {
		b.WriteString("#   In a second session:      log in as a member of scope " + h.Scope + " and type /H (the help lists the commands of the assigned level), then /X\n")
	}
	if d.WTI != nil && d.WTI.Block != nil {
		b.WriteString("#   From an address outside the IP tables list: the unit must refuse it\n")
	}
	b.WriteString("#\n")
	if HasBackout(d) {
		what := "the steps with the values the pull showed"
		if d.WTI != nil && d.WTI.Block != nil {
			what += ", the old IP tables list as a block of its own"
		}
		add("To undo it: tacctl device config plan " + h.Device + " --backout     (" + what + "; tacctl keeps this plan's back-out until the next plan with changes).")
	} else {
		add("tacctl has no steps of its own to undo this plan.")
	}
	add("Do not: paste anything outside the banners; paste a block into another unit; leave /N with ESC before the last step of the list; keep this output in a file after the paste when it holds a secret.")
	b.WriteString(lockoutHelp(d, h))
	return b.String()
}

// wtiPreamble is what a unit's report says before its steps: the version
// check, and what to have ready.
func wtiPreamble(d Delta, h Header, add func(string), blank func(), b *strings.Builder) {
	add("The unit has no commit-confirm and no rollback: every value is live as soon as its Enter is accepted, and the configuration is written to flash when a top-level menu is left with ESC (any session that leaves one saves everything). tacctl types nothing: you do each step yourself.")
	sessions := ""
	if h.Unit != nil {
		switch h.Unit.OtherSessions {
		case 0:
			sessions = " (the pull saw none)"
		case 1:
			sessions = " (the pull saw 1 other session)"
		default:
			sessions = fmt.Sprintf(" (the pull saw %d other sessions)", h.Unit.OtherSessions)
		}
	}
	add("Before you start: keep the serial console, or a second session logged in as an Administrator, open until the check at the end passes; type /SN and make sure no other administrator is on the unit" + sessions + ".")
	way := "the old values"
	if d.WTI != nil && d.WTI.Block != nil {
		way = "the old values and the old IP tables list as a block (or the slots to clear)"
	}
	add("The way back is tacctl device config plan " + h.Device + " --backout: " + way + ".")
	blank()
	b.WriteString("# Type this first, on " + h.Device + ", and check the version:   /H\n")
	site := ""
	if h.Unit != nil && h.Unit.SiteID != "" {
		site = " /J shows the unit's Site ID: the pull read " + h.Unit.SiteID + "; another one means this is not the unit."
	}
	add(promptCheck(devconf.FamilyWTI) + site)
	blank()
}

// the shapes the paste check allows between the banners.
var reWTIBlockLine = regexp.MustCompile(`^iptables -[AP] [ -~]{1,250}$`)

// checkWTIRegion verifies the whole-paste invariant of a unit's output as an
// allowlist: every line is a comment, or a line of the one <iptables> block,
// and the block lies between the IP tables banners.
func checkWTIRegion(lines []string) error {
	state := 0 // 0 outside, 1 inside the IP tables banners before the block, 2 in the block, 3 after the block
	blocks := 0
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "#"):
			switch {
			case strings.HasPrefix(l, "##### IP TABLES") || strings.HasPrefix(l, "##### BACK-OUT, IP TABLES"):
				if state != 0 {
					return fmt.Errorf("line %d: an IP tables banner inside another", i+1)
				}
				state = 1
			case strings.HasPrefix(l, "##### END OF IP TABLES"):
				if state == 2 {
					return fmt.Errorf("line %d: the block is not closed", i+1)
				}
				state = 0
			}
		case l == "<iptables>":
			if state != 1 {
				return fmt.Errorf("line %d: a block outside the IP tables banners", i+1)
			}
			state = 2
			blocks++
		case l == "</iptables>":
			if state != 2 {
				return fmt.Errorf("line %d: a block that was not opened", i+1)
			}
			state = 3
		case state == 2 && reWTIBlockLine.MatchString(l):
		default:
			return fmt.Errorf("line %d, %q, is not a comment and not a line of the block", i+1, l)
		}
	}
	if state == 2 {
		return errors.New("the block is not closed")
	}
	if blocks > 1 {
		return errors.New("more than one block")
	}
	return nil
}

// --- the back-out -------------------------------------------------------------------------

// wtiBackoutRows are the back-out's steps: the plan's steps in reverse order
// with the values the pull showed as targets.
func wtiBackoutRows(d Delta) []wtiRow {
	var rows []wtiRow
	if d.WTI == nil {
		return rows
	}
	for i := len(d.WTI.Steps) - 1; i >= 0; i-- {
		s := d.WTI.Steps[i]
		enter := s.Back
		if enter == "" {
			enter = "(" + s.BackNote + ")"
		}
		rows = append(rows, wtiRow{keys: s.Keys, label: s.Label, enter: enter, was: s.EnterShown})
	}
	return rows
}

// wtiHasBackout reports a back-out of at least one line tacctl can say.
func wtiHasBackout(d Delta) bool {
	if d.WTI == nil {
		return false
	}
	for _, s := range d.WTI.Steps {
		if s.Back != "" {
			return true
		}
	}
	if b := d.WTI.Block; b != nil {
		return len(b.OldUnsafe) == 0
	}
	return false
}

// wtiBackoutLines are the lines of the back-out's banner pairs: the IP
// tables first (the change that can lock out is undone first), then the
// steps.
func wtiBackoutLines(d Delta, h Header) []RegionLine {
	var out []RegionLine
	cm := func(s string) { out = append(out, RegionLine{Text: s, Comment: true, Line: -1}) }
	if b := d.WTI.Block; b != nil {
		n := len(b.Commands) + len(b.Tail)
		switch {
		case len(b.OldUnsafe) > 0:
			cm(wtiBanner("BACK-OUT, IP TABLES BY HAND: " + h.Device))
			for _, l := range commentLines("The unit's list held entries the paste check does not allow, so tacctl does not make a block of it. Put them back by hand, one slot each, in this order:", 96) {
				cm(l)
			}
			for i, c := range b.Old {
				cm(fmt.Sprintf("#%3d. %s", i+1, c))
			}
			cm(wtiBanner("END OF IP TABLES: " + h.Device))
		case len(b.Old) == 0:
			cm(wtiBanner("BACK-OUT, IP TABLES (the unit's list was empty): " + h.Device))
			for _, l := range commentLines(fmt.Sprintf("The list held no entry at the pull. At /N, 5: for each slot from 1 to %d type the slot number and Enter, then <SPACE><CR> to clear it. Then leave /N with ESC and wait for \"Saving configuration to flash\".", n), 96) {
				cm(l)
			}
			cm(wtiBanner("END OF IP TABLES: " + h.Device))
		default:
			cm(wtiBanner("BACK-OUT, IP TABLES (replaces every entry; see the notes): " + h.Device))
			for _, l := range commentLines(fmt.Sprintf("The list of the pull, %s, in its order. At the /N menu type 5 and Enter, paste the block as it stands, then leave /N with ESC and wait for \"Saving configuration to flash\". It replaces the %d entries the plan pasted.",
				plural(len(b.Old), "entry", "entries"), n), 96) {
				cm(l)
			}
			for _, l := range wtiBlockLines(b.Old) {
				out = append(out, RegionLine{Text: l, Line: -1})
			}
			cm(wtiBanner("END OF IP TABLES: " + h.Device))
		}
	}
	rows := wtiBackoutRows(d)
	if len(rows) > 0 {
		cm(wtiBanner("UNDO THESE STEPS ON: " + h.Device))
		for _, l := range wtiLegend() {
			cm(l)
		}
		for _, l := range wtiRows(rows, 1) {
			cm(l)
		}
		cm(fmt.Sprintf("#%3d. ESC ESC  leave /N: wait for \"Saving configuration to flash\"", len(rows)+1))
		cm(wtiBanner("END OF STEPS"))
	}
	return out
}

// wtiBackout is the back-out as its own output.
func wtiBackout(d Delta, h Header) (string, error) {
	if d.Empty() || !wtiHasBackout(d) {
		return "", ErrNoBackout
	}
	var b strings.Builder
	add := func(s string) {
		for _, l := range wrapText(s, 100) {
			b.WriteString("# " + l + "\n")
		}
	}
	b.WriteString(boxLine(d, h) + "\n")
	add("BACK-OUT of the plan for " + h.Device + ": it puts back what the pull of " + fmtTime(h.Pulled) +
		" showed, for the settings the plan changed. Use it only after the plan was done and the check was not fine.")
	if w := wtiPlainBackoutWarning(d); w != "" {
		add("WARNING: " + w + ".")
	}
	add("The unit has no rollback: each value is live as soon as its Enter is accepted, and leaving /N with ESC saves it. Keep the serial session open, and a second one for the check.")
	b.WriteString("#\n")
	b.WriteString("# Type this first, on " + h.Device + ", and check the version:   /H\n")
	add(promptCheck(devconf.FamilyWTI))
	b.WriteString("#\n")
	for _, l := range wtiBackoutLines(d, h) {
		b.WriteString(l.Text + "\n")
	}
	b.WriteString("#\n")
	add("A value that tacctl does not hold (a secret, a community) is a line that says to re-enter the one you keep.")
	add("Check now: tacctl device config pull " + h.Device + " --diff     (the differences of the plan are back).")
	add("Do not: paste anything outside the banners; paste a block into another unit; leave /N with ESC before the last step of the list.")
	b.WriteString(lockoutHelp(d, h))
	return b.String(), nil
}

// --- the cleanup --------------------------------------------------------------------------

// wtiCleanupLines are the steps of the --converge region.
func wtiCleanupLines(d Delta, h Header) []RegionLine {
	if d.WTI == nil || len(d.WTI.CleanupSteps) == 0 {
		return nil
	}
	var out []RegionLine
	for _, l := range wtiLegend() {
		out = append(out, RegionLine{Text: l, Comment: true, Line: -1})
	}
	rows := make([]wtiRow, len(d.WTI.CleanupSteps))
	for i, s := range d.WTI.CleanupSteps {
		rows[i] = wtiRow{keys: s.Keys, label: s.Label, enter: s.Enter, was: s.Was}
	}
	for i, l := range wtiRows(rows, 1) {
		out = append(out, RegionLine{Text: l, Comment: true, Line: d.WTI.CleanupSteps[i].Line})
	}
	out = append(out, RegionLine{Text: fmt.Sprintf("#%3d. ESC ESC  leave /N: wait for \"Saving configuration to flash\"", len(rows)+1), Comment: true, Line: -1})
	return out
}

// wtiCleanupAfter is the text after the cleanup steps.
func wtiCleanupAfter(d Delta, h Header) string {
	var b strings.Builder
	add := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString("# " + l + "\n")
		}
	}
	b.WriteString("#\n")
	add("There is no other step for " + h.Device + ": its first checklist is empty. Check that the pull is current (tacctl device config pull " + h.Device +
		" --diff reads ok for aaa) and keep a second session logged in as yourself open.")
	add("Nothing rolls the cleanup back by itself. To put a value back: the read/write community is a string tacctl does not hold (re-enter the one you keep), and the other protocol's switch is Enable at its page 1 (/N 28 or /N 29).")
	b.WriteString(lockoutHelp(d, h))
	return b.String()
}
