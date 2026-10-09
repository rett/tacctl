package lifecycle

// 'tacctl uninstall' (cmd_uninstall, lib/lifecycle.sh at 0.1.16).

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// Uninstall is 'tacctl uninstall [-y|--yes]' (cmd_uninstall): what will go
// and a confirmation, then every backend that is enabled or still
// installed is stopped; whether to keep the config backups and each
// backend's logs is asked (-y, new in 0.2.0, answers the confirmation
// "yes" and these "no": nothing is kept); then the installed command and
// each backend's program, the sudoers rules and the Linux host data, the
// completion, the man page, the state directory (the backups archived
// first under /root when asked), each backend's data (logs archived when
// asked), the deploy clone and its safe.directory entry, each backend's
// account; and the summary. Any other argument is refused before anything
// is done.
//
// Go, tacquito's source and the Go build cache stay.
func Uninstall(ctx context.Context, h *Host, args []string) error {
	yes := false
	if err := parseLifecycleArgs(h, args, nil, &yes, uninstallUsage); err != nil {
		return err
	}
	out, p := h.Out, h.Paths
	// Every backend that is enabled or still installed is removed.
	ids := h.Set.Present()

	h.echo("")
	h.echo(rule)
	h.echoE("  " + ui.Red + "tacctl Uninstaller" + ui.NC)
	h.echo(rule)
	h.echo("")
	h.echo("Backends: " + h.backendNames(ids))
	h.echo("")
	h.echo("This will remove:")
	h.echo("  - Management CLI (tacctl), its state directory (" + p.StateDir + ": store, tacctl.yaml, backups)")
	h.echo("  - Sudoers rules (" + p.SudoersFile + ", " + p.TierSudoersFile + ")")
	h.echo("  - Bash completion (" + p.Completion + ") and man page")
	h.echo("  - Linux host build data (" + p.LinuxDir + ") and the generated known_hosts (" + p.KnownHosts + ")")
	h.echo("  - Management repo (" + p.Deploy + ")")
	h.echo("  - TACACS+ (tacquito): service and units, binary, password hash generator (tacquito-hashgen),")
	h.echo("    configuration directory (/etc/tacquito), log directory (/var/log/tacquito), logrotate config,")
	h.echo("    service user (tacquito)")
	if slices.Contains(ids, backend.RADIUS) {
		h.echo("  - RADIUS (FreeRADIUS): tacctl's instance (its config files, unit drop-in, logs, logrotate config);")
		h.echo("    the FreeRADIUS package stays installed, with its own configuration as shipped")
	}
	h.echo("")
	h.echoE(ui.Yellow + "The tacquito source (/opt/tacquito-src) and Go installation")
	h.echoE("(/usr/local/go) will NOT be removed." + ui.NC)
	h.echo("")
	if !yes && !h.confirm("Are you sure you want to uninstall tacctl? [y/N]: ") {
		out.Info("Cancelled.")
		return nil
	}
	h.echo("")

	// Stop and disable the services.
	if err := h.phase(ids, func(b backend.Backend) error { return b.Uninstall(ctx, backend.PhaseStop, false) }); err != nil {
		return err
	}

	// What to keep (-y keeps nothing).
	h.echo("")
	keepBackups := !yes && h.confirm("Preserve config backups ("+p.BackupDir+")? [y/N]: ")
	keepLogs := map[string]bool{}
	for _, id := range ids {
		b, err := h.Set.Get(id)
		if err != nil {
			continue
		}
		logs := b.Describe().LogDir
		if logs == "" {
			continue
		}
		if !yes && h.confirm("Preserve accounting logs ("+logs+")? [y/N]: ") {
			keepLogs[id] = true
		}
	}
	h.echo("")

	// No account may keep the console as its shell once it is gone.
	h.removeConsole(ctx)

	out.Info("Removing binaries and symlinks...")
	if err := h.rmF(p.Command, p.ConsoleCommand); err != nil {
		return err
	}
	if err := h.phase(ids, func(b backend.Backend) error { return b.Uninstall(ctx, backend.PhaseProgram, false) }); err != nil {
		return err
	}

	out.Info("Removing sudoers rules and Linux host build data...")
	if err := h.removeAccess(); err != nil {
		return err
	}

	// (each backend removes its logrotate file with its data, below)
	out.Info("Removing logrotate config and bash completion...")
	if err := h.rmF(p.Completion); err != nil {
		return err
	}
	out.Info("Removing man page...")
	if err := h.rmF(p.ManPage); err != nil {
		return err
	}
	h.mandb(ctx)

	archive := ""
	if keepBackups {
		// Backups of a host that never ran the state migration are still
		// under the daemon's directory.
		parent := ""
		if isDir(filepath.Join(p.StateDir, "backups")) {
			parent = p.StateDir
		} else if d := filepath.Join(p.Etc, "backups"); isDir(d) && !isSymlink(d) {
			parent = p.Etc
		}
		if parent != "" {
			archive = p.ArchiveDir + "/tacquito-backups-" + h.now().Format("20060102_150405") + ".tar.gz"
			// 'tar czf ... 2>/dev/null || true'
			h.cmd(ctx, execx.Cmd{Name: "tar", Args: []string{"czf", archive, "-C", parent, "backups/"},
				Stdout: out.Stdout, Stderr: io.Discard})
			out.Info("Config backups saved to " + archive)
		}
	}
	out.Info("Removing configuration and state directories...")
	if err := h.rmRF(p.StateDir); err != nil {
		return err
	}

	// Each backend's config directory and logs.
	if err := h.phase(ids, func(b backend.Backend) error {
		return b.Uninstall(ctx, backend.PhaseData, keepLogs[b.ID()])
	}); err != nil {
		return err
	}

	out.Info("Removing management repo...")
	if err := h.rmRF(p.Deploy); err != nil {
		return err
	}
	// The system-wide safe.directory entry of the removed clone
	// (best effort).
	h.cmd(ctx, execx.Cmd{Name: "git", Args: []string{"config", "--system", "--unset-all", "safe.directory", "^" + p.Deploy + "$"},
		Stdout: out.Stdout, Stderr: io.Discard})

	// Each backend's source-checkout entry and service user.
	if err := h.phase(ids, func(b backend.Backend) error { return b.Uninstall(ctx, backend.PhaseAccount, false) }); err != nil {
		return err
	}

	h.echo("")
	h.echo(rule)
	h.echo("  Uninstall Complete")
	h.echo(rule)
	h.echo("")
	h.echo("  Removed:")
	h.echo("    - TACACS+ (tacquito) service and binary")
	h.echo("    - Management CLI and symlinks")
	h.echo("    - Configuration and systemd unit")
	h.echo("    - Logrotate config, sudoers rules, bash completion")
	h.echo("    - Service user")
	if archive != "" {
		h.echo("    - Config backups saved to: " + archive)
	}
	for _, id := range ids {
		if s, ok := h.summarizer(id); ok {
			for _, line := range s.UninstallSaved() {
				h.echo("    - " + line)
			}
		}
	}
	h.echo("")
	h.echo("  Not removed:")
	h.echo("    - Go installation (/usr/local/go)")
	h.echo("    - tacquito source (/opt/tacquito-src)")
	h.echo("    - Go build cache (/root/.cache/go-build)")
	h.echo("")
	return nil
}

// removeAccess is uninstall_remove_access: what grants or serves access
// through a tacctl about to be gone. Both sudoers drop-ins go (the tier
// rules allow commands of the removed binary to the tier groups, and must
// not outlive it), and so does the Linux host data (pam_tacplus source and
// prebuilt modules) the generated known_hosts (with its directory) and the tier-migration marker,
// with their parent directory when that leaves it empty.
func (h *Host) removeAccess() error {
	p := h.Paths
	if err := h.rmF(p.SudoersFile, p.TierSudoersFile); err != nil {
		return err
	}
	if err := h.rmRF(p.LinuxDir); err != nil {
		return err
	}
	// The marker of the one-time tier migration (a reinstall starts again).
	if err := h.rmF(p.TierPinMarker); err != nil {
		return err
	}
	if err := h.rmRF(filepath.Dir(p.KnownHosts)); err != nil {
		return err
	}
	// rmdir: only when empty.
	_ = os.Remove(p.VarLib)
	_ = os.Remove(filepath.Dir(p.LinuxDir))
	return nil
}

func isSymlink(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.Mode()&os.ModeSymlink != 0
}
