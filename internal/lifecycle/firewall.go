package lifecycle

// The break-glass firewall in install, upgrade and uninstall (0.2.24,
// internal/firewall): install and upgrade write the rules file and the boot
// unit and load the table for the holds and the setting that stand (an upgrade
// from 0.2.23 with holds standing is how those holds get the fix), uninstall
// takes the table, the file and the unit away. The nftables package is
// installed by EnsureDependencies; nftables.service is never touched.

import (
	"context"
	"strings"

	"github.com/rett/tacctl/internal/firewall"
)

// firewallEngine is the table's engine over the host.
func (h *Host) firewallEngine() *firewall.Engine {
	return &firewall.Engine{Runner: h.Runner, Paths: h.Paths, Conf: h.Conf}
}

// firewallStep loads the table the holds and the setting ask for, and says
// what it did. It never fails the command: a table that cannot be loaded
// while an address is held is a warning that names the fix, the way the
// report of a hold does.
func (h *Host) firewallStep(ctx context.Context) {
	out := h.Out
	res := h.firewallEngine().Apply(ctx)
	ports := firewall.PortList(res.Ports)
	switch {
	case res.State == firewall.Failed:
		fix := "Fix: " + firewall.InstallCommand + ", then " + firewall.FixCommand(res.Mode)
		if !res.NftMissing {
			fix = "Fix: remove the cause, then " + firewall.FixCommand(res.Mode)
		}
		if res.Enforces() {
			out.Warn("Break-glass firewall: NOT APPLIED (" + res.Why + "). The server still completes the TCP handshake on " + ports + " for " + strings.Join(res.Addrs, ", ") + ", so a held device that falls back to its local accounts only when the server is unreachable will not. " + fix + ".")
		} else {
			out.Warn("Break-glass firewall: NOT APPLIED (" + res.Why + "). " + fix + ".")
		}
	case res.State == firewall.Idle:
		// nft is not here and the table would refuse nothing: the package
		// warning said it.
	case res.State == firewall.Removed:
		out.Info("Break-glass firewall: off (breakglass.firewall); no table is loaded.")
	case len(res.Addrs) > 0:
		out.Info("Break-glass firewall: " + strings.Join(res.Addrs, ", ") + " refused on " + ports + " (" + res.Mode + "); " + firewall.UnitName + " loads the table at boot.")
	default:
		out.Info("Break-glass firewall: the table inet tacctl is loaded (" + res.Mode + " on " + ports + ", no address held); " + firewall.UnitName + " loads it at boot.")
	}
	if line := res.UnitLine(); line != "" {
		out.Warn("Break-glass firewall: " + line)
	}
}

// firewallRemove takes the table, the rules file and the boot unit away
// (uninstall); the package stays. A failure is a warning.
func (h *Host) firewallRemove(ctx context.Context) {
	removed, err := h.firewallEngine().Remove(ctx)
	if len(removed) > 0 {
		h.Out.Info("Break-glass firewall removed: " + strings.Join(removed, ", ") + ".")
	}
	if err != nil {
		h.Out.Warn("Break-glass firewall: " + err.Error() + ".")
	}
}
