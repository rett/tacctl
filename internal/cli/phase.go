package cli

// '_phase <backend> <install|upgrade|uninstall> <phase>[,<phase>...]
// [<tree>|--keep-logs]': one or more lifecycle phases of one backend, run
// on their own (docs/plans/go-rewrite.md 2.3 and 3.2, Decision 14). It is
// hidden, with the same low surface as _completion-names: not in the usage,
// not offered by completion, and for superusers only (it is not in the tier
// table). The container drivers and the lifecycle tests use it to drive a
// phase without the whole of install, upgrade or uninstall.
//
// Contract:
//
//   - <backend> is a registered id, enabled or not (an unknown one: exit 2).
//   - <phase> is one phase of that lifecycle (backend.InstallPhases,
//     UpgradePhases, UninstallPhases), or several separated by commas, run
//     in that order in one process: a phase that hands something to a later
//     one (RADIUS 'upgrade config' to 'upgrade finish') needs them together.
//     A phase the module has no work in does nothing.
//   - The last argument is the tree install and upgrade phases take shipped
//     files from (default: the binary's own tree, as for 'tacctl install'),
//     or for uninstall '--keep-logs' (the logs are archived before they are
//     removed).
//   - No preflight: a phase runs whatever state the machine is in, as it
//     does inside install, upgrade or uninstall.
//   - Output: each phase's own lines, as install, upgrade and uninstall
//     print them. Then what the phases left for the closing summaries:
//     'SUMMARY <note>' per upgrade summary note (UPGRADE_SUMMARY_NOTES) and
//     'SAVED <line>' per line of uninstall's "Removed:" list
//     (UNINSTALL_SAVED), on stdout.
//   - Exit status: 0; 1 when a phase failed, after
//     "[ERROR] Backend '<id>': <lifecycle> step '<phase>' failed (exit <n>)."
//     (the phases after it are not run); 2 for a usage error.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
)

const phaseUsage = "Usage: tacctl _phase <backend> <install|upgrade|uninstall> <phase>[,<phase>...] [<tree>|--keep-logs]"

// lifecyclePhases are the phases of each lifecycle command, in order.
var lifecyclePhases = map[string][]backend.Phase{
	"install":   backend.InstallPhases,
	"upgrade":   backend.UpgradePhases,
	"uninstall": backend.UninstallPhases,
}

// upgradeNoter is a backend that leaves notes for the closing summary of
// 'tacctl upgrade' (the RADIUS module).
type upgradeNoter interface{ UpgradeNotes() []string }

// uninstallSaver is a backend that leaves lines for the "Removed:" list of
// 'tacctl uninstall' (the RADIUS module).
type uninstallSaver interface{ UninstallSaved() []string }

func phaseCmd(inv *invocation) *cobra.Command {
	c := hidden("_phase")
	c.RunE = inv.native(noPreflight, inv.phase)
	return c
}

func (inv *invocation) phase(args []string) error {
	out := inv.app.Out
	usage := func() error {
		out.Error(phaseUsage)
		return exit(2)
	}
	if len(args) < 3 || len(args) > 4 {
		return usage()
	}
	id, verb := args[0], args[1]
	known, ok := lifecyclePhases[verb]
	if !ok {
		return usage()
	}
	var phases []backend.Phase
	for _, p := range strings.Split(args[2], ",") {
		if !slices.Contains(known, backend.Phase(p)) {
			var names []string
			for _, k := range known {
				names = append(names, string(k))
			}
			out.ErrorE("Unknown " + verb + " phase '" + p + "' (phases: " + strings.Join(names, " ") + ").")
			return exit(2)
		}
		phases = append(phases, backend.Phase(p))
	}
	tree, keepLogs := inv.app.Paths.Tree, false
	if len(args) == 4 {
		switch {
		case verb == "uninstall" && args[3] == "--keep-logs":
			keepLogs = true
		case verb != "uninstall" && args[3] != "" && !strings.HasPrefix(args[3], "-"):
			tree = args[3]
		default:
			return usage()
		}
	}
	b, err := inv.app.Backends().Get(id)
	if err != nil {
		return err // *backend.UnknownError: exit 2
	}
	for _, p := range phases {
		var err error
		switch verb {
		case "install":
			err = b.Install(inv.ctx, p, tree)
		case "upgrade":
			err = b.Upgrade(inv.ctx, p, tree)
		default:
			err = b.Uninstall(inv.ctx, p, keepLogs)
		}
		if err != nil {
			var code int
			if backend.Reported(err) {
				code = backend.ExitCode(err)
			} else {
				code = exitCode(err, out)
			}
			out.Error("Backend '" + id + "': " + verb + " step '" + string(p) + "' failed (exit " + strconv.Itoa(code) + ").")
			return exit(1)
		}
	}
	if n, ok := b.(upgradeNoter); ok && verb == "upgrade" {
		for _, note := range n.UpgradeNotes() {
			inv.echo("SUMMARY " + note)
		}
	}
	if s, ok := b.(uninstallSaver); ok && verb == "uninstall" {
		for _, line := range s.UninstallSaved() {
			inv.echo("SAVED " + line)
		}
	}
	return nil
}
