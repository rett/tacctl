package lifecycle

// The break-glass firewall (0.2.24) in a rollback. It is a setting and a set of
// files every older release lacks: breakglass.firewall in tacctl.yaml, which
// conf.Added0224 lists so that the key list of every target but 0.2.26, 0.2.25 and 0.2.24 removes
// it (a 0.2.23 binary refuses the key), the nftables table inet tacctl in the
// kernel, the rules file under the state directory and the boot unit
// tacctl-breakglass-firewall.service. Every target but 0.2.26, 0.2.25 and 0.2.24 (which have them)
// removes the last three, through RollbackInput.RemoveFirewall (the command's
// seam over the runner; nil lists the step and does nothing), and says so; the nftables package stays,
// and so does every hold: an older release that has holds (0.2.5 and later)
// takes them as they are, and its server completes the TCP handshake of a held
// address again, as 0.2.23 did. The step needs no snapshot: none of the three
// is part of one.

import (
	"os"
	"slices"
	"strings"
)

// planFirewall reads what the firewall left: the rules file and the boot unit
// (there is a table to remove when either is there) and the holds that stand
// (named in a note when there is).
func (p *RollbackPlan) planFirewall() error {
	pt := p.in.Paths
	for _, f := range []string{pt.FirewallRules, pt.FirewallUnit} {
		if _, err := os.Lstat(f); err == nil {
			p.firewallFiles = append(p.firewallFiles, f)
		}
	}
	for _, h := range p.in.Conf.Holds() {
		p.firewallHolds = append(p.firewallHolds, h.Device+" ("+h.Address+")")
	}
	p.firewallTodo = len(p.firewallFiles) > 0
	return nil
}

// FirewallTodo says --apply removes the table, the rules file and the boot
// unit.
func (p *RollbackPlan) FirewallTodo() bool { return p.firewallTodo }

// FirewallHolds are the holds that stand, as "name (address)": the table that
// refused their TCP connections goes with the rollback.
func (p *RollbackPlan) FirewallHolds() []string { return slices.Clone(p.firewallHolds) }

// addFirewall adds the step (before the one that lists what is left
// untouched; none when there is nothing to remove) and the note about the
// holds that stand.
func (p *RollbackPlan) addFirewall() {
	if !p.firewallTodo {
		return
	}
	pt := p.in.Paths
	s := RollbackStep{Title: "the break-glass firewall: remove the nftables table, its rules file and its boot unit", Todo: true,
		Lines: []string{
			"remove the table inet tacctl with nft (the rest of the ruleset is not touched)",
			"remove " + pt.FirewallRules + " and " + pt.FirewallUnit + " (disabled first)",
			"the nftables package stays; nftables.service is never touched",
		}}
	at := len(p.Steps)
	for i := range p.Steps {
		if p.Steps[i].Title == "leave every other file untouched" {
			at = i
			break
		}
	}
	p.Steps = slices.Insert(p.Steps, at, s)
	if len(p.firewallHolds) > 0 {
		p.Notes = append(p.Notes, "The break-glass hold of "+strings.Join(p.firewallHolds, ", ")+" stands, and "+p.target()+
			" takes it over as it is, without the firewall: its server completes the TCP handshake of the held address again, so a device that falls back to its local accounts only when the server is unreachable (WTI Transport Failure, Junos authentication-order [ tacplus password ]) will not. Release the hold before the rollback if that matters.")
	}
}

// applyFirewall removes the table, the file and the unit and returns the line
// that says so ("" when there was nothing).
func (p *RollbackPlan) applyFirewall() (string, error) {
	if !p.firewallTodo || p.in.RemoveFirewall == nil {
		return "", nil
	}
	removed, err := p.in.RemoveFirewall()
	if len(removed) == 0 {
		return "", err
	}
	return "break-glass firewall: removed " + strings.Join(removed, ", ") + "; the nftables package stays", err
}
