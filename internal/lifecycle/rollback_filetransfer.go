package lifecycle

// The console's file transfer settings (0.2.28, settings.file_transfer in
// console.yaml) in a rollback. Every older release refuses the key, 0.2.27
// included: its console.yaml reader answers "settings: unknown key
// 'file_transfer'", so the console falls back to its defaults and every
// 'console' command that writes the file fails. So every target removes it
// (console.Keys0228), after the snapshot --apply takes first, and says what it
// held.
//
// The targets before 0.2.20 take it out with the other settings they remove
// (console.PlanRollbackSince0220 and console.PlanRollback read the file for
// them). The targets from 0.2.20 to 0.2.27 read the rest of the file as it is
// and have no plan of the file, so this addition plans it for them
// (console.PlanRollbackSince0228) and adds the step; it is one entry of
// rollbackAdditions.

import (
	"strings"

	"github.com/rett/tacctl/internal/console"
)

// fileTransferRelease is the release that made the change (its entry in
// rollbackAdditions).
const fileTransferRelease = "0.2.28"

// planConsoleFileTransfer plans console.yaml for the targets whose own plan
// does not read it. The earlier ones read it already, with the file transfer
// key among what they remove.
func (p *RollbackPlan) planConsoleFileTransfer() error {
	if p.console.Exists {
		return nil
	}
	cp, err := console.PlanRollbackSince0228(p.in.Paths.ConsoleFile)
	if err != nil {
		return err
	}
	p.console = cp
	p.consoleSince0228 = cp.Text != nil
	return nil
}

// addConsoleFileTransfer adds the step that takes the key out of console.yaml,
// for the targets planned above.
func (p *RollbackPlan) addConsoleFileTransfer() {
	if p.consoleSince0228 {
		p.addConsoleStep()
	}
}

// FileTransferRemoved reports whether the plan takes the file transfer
// settings out of console.yaml (they were set): the command then says that
// the commands that set them write them again until the upgrade.
func (p *RollbackPlan) FileTransferRemoved() bool {
	for _, r := range p.console.Remove {
		if strings.HasPrefix(r, "settings.file_transfer: ") {
			return true
		}
	}
	return false
}
