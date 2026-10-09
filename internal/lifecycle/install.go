package lifecycle

// 'tacctl install' (cmd_install, lib/lifecycle.sh at 0.1.16).

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// installPrereqs are the commands install needs before anything else (git
// for the clones, wget for the Go tarball); python3 left the list in 0.2.0
// (docs/plans/go-rewrite.md 3.9 item 6).
var installPrereqs = []string{"git", "wget"}

// Install is 'tacctl install [--branch <name>] [-y|--yes]' (cmd_install):
// the plan and a confirmation ([y/N]; -y answers it, new in 0.2.0), then
// in 0.1.16's order: every enabled backend's 'install build' (tacquito:
// Go checked, source, build), the deploy clone (cloned, or pulled), the
// installed command (built from the clone when it is not the clone's
// binary: the 0.2.0 counterpart of 0.1.16's symlink), the state migration,
// the device templates, the backends' 'install files', the completion and
// the man page, the packages, the backends' 'install account', the
// configuration (InstallSeed: an existing store or tacquito.yaml is kept),
// the backends' 'install start', and the summary (the new shared secret,
// shown once, on a fresh install).
//
// The files shipped with the tree (completion, man page; the backends'
// units, logrotate and README.md) come from paths.Tree, the checkout this
// binary belongs to, as 0.1.16 takes them from its own PROJECT_DIR.
func Install(ctx context.Context, h *Host, args []string) error {
	yes, branch := false, ""
	if err := parseLifecycleArgs(h, args, &branch, &yes, installUsage); err != nil {
		return err
	}
	out, p := h.Out, h.Paths
	for _, c := range installPrereqs {
		if !h.has(c) {
			out.Error("Required command '" + c + "' not found. Install it first.")
			return backend.ErrFailed
		}
	}
	tree := p.Tree

	h.echo("")
	h.echo(rule)
	h.echo("  tacctl Installer")
	h.echo(rule)
	h.echo("")
	h.echo("This will:")
	h.echo("  - Install tacctl (" + p.Deploy + ", " + p.Command + ") and its state directory (" + p.StateDir + ")")
	h.echo("  - Install the TACACS+ backend: Go " + paths.GoVersion + " (if not present), tacquito built from")
	h.echo("    source, a 'tacquito' service user, the service on port 49/tcp")
	h.echo("  - Seed the store: scope '" + DefaultScopeFresh + "' with a generated shared secret, built-in")
	h.echo("    users created disabled (an existing configuration is kept instead)")
	h.echo("")
	h.echo("RADIUS (FreeRADIUS) is not installed; add it later with: tacctl backend enable radius")
	h.echo("")
	if !yes && !h.confirm("Continue with installation? [y/N]: ") {
		out.Info("Cancelled.")
		return nil
	}
	h.echo("")

	// Each backend's daemon (for tacquito: Go, source, build).
	ids, err := h.enabled()
	if err != nil {
		return err
	}
	if err := h.install(ctx, ids, backend.PhaseBuild, tree); err != nil {
		return err
	}

	// The management repo, for future upgrades.
	if err := h.installDeploy(ctx, branch); err != nil {
		return err
	}

	// Create the state directory (and adopt any state from /etc/tacquito)
	// before anything writes to it; tacctl.yaml may have moved.
	if err := StateMigrate(StateOptionsFrom(p, out, h.Now, h.IsRoot)); err != nil {
		return backend.ErrFailed
	}
	repairVarLib(out, p.VarLib)
	h.Conf.Reload()
	// A fresh install has nothing for the one-time tier migration of
	// 'tacctl upgrade' (every group it creates records its tier), so the
	// marker is there from the start; an install over an existing store
	// leaves the migration to the first upgrade.
	if model.Mode(p.StoreFile) != "store" {
		if err := MarkTierPin(p); err != nil {
			out.Warn("Could not record the tier migration marker " + p.TierPinMarker + ": " + strings.TrimSpace(err.Error()))
		}
	}
	// The device config templates (a customised one already there is
	// kept).
	if _, err := h.TemplatesSync(ctx, tree); err != nil {
		out.Warn("Could not install every config template in " + p.Templates + "/.")
	} else {
		out.Info("Config templates installed: " + p.Templates + "/")
	}
	// Each backend's system files (logrotate config).
	if err := h.install(ctx, ids, backend.PhaseFiles, tree); err != nil {
		return err
	}
	if h.Completion != nil {
		script, err := h.Completion()
		if err != nil {
			return err
		}
		if err := h.writeFile(p.Completion, script, 0o644); err != nil {
			return err
		}
		out.Info("Bash completion installed: " + p.Completion)
	}
	if src := filepath.Join(tree, "man", "tacctl.1"); isRegular(src) {
		if err := h.installManPage(ctx, src); err != nil {
			return err
		}
		out.Info("Man page installed: " + p.ManPage)
	}
	out.Info("Management CLI installed:")
	out.Info("  tacctl — user, config, and system management")
	out.Info("  Deploy source: " + p.Deploy)

	// The packages.
	if h.has("apt-get") {
		if err := h.EnsureDependencies(ctx); err != nil {
			return err
		}
	}
	// Service users and directories.
	if err := h.install(ctx, ids, backend.PhaseAccount, tree); err != nil {
		return err
	}
	// Shared secret, store, configuration.
	seed, err := InstallSeed(ctx, h.Env)
	if err != nil {
		return err
	}
	// Install, start and verify each backend's service.
	if err := h.install(ctx, ids, backend.PhaseStart, tree); err != nil {
		return err
	}
	h.installSummary(seed)
	return nil
}

// installDeploy is the "Clone management repo" step: the deploy clone
// pulled (on --branch's branch when it names one) or cloned, readable by
// everyone and safe for git as any user, its entrypoint executable; then
// the installed command made the clone's binary. A clone of a bash-era
// release is refused before anything is built.
func (h *Host) installDeploy(ctx context.Context, branch string) error {
	out, p := h.Out, h.Paths
	deploy := p.Deploy
	if isDir(filepath.Join(deploy, ".git")) {
		out.Info("Management repo already cloned at " + deploy + ", pulling latest...")
		if branch != "" {
			h.gitQuiet(ctx, deploy, "checkout", branch)
		}
		h.gitQuietErr(ctx, deploy, "pull", "--quiet")
	} else {
		if lexists(deploy) {
			if err := h.rmRF(deploy); err != nil {
				return err
			}
		}
		args := []string{"clone", "--quiet"}
		if branch != "" {
			args = append(args, "--branch", branch)
		}
		if code := h.git(ctx, "", append(args, paths.ManageRepo, deploy)...); code != 0 {
			return &backend.Error{Code: code, Reason: "git clone"}
		}
		out.Info("Management repo cloned to " + deploy)
	}
	NormalizeDeployPerms(deploy)
	// Without a system-wide safe.directory entry, an unprivileged operator
	// running 'git -C /opt/tacctl log' hits "detected dubious ownership".
	h.ensureSafeDirectory(ctx, deploy)
	// 755 so non-root users can exec into sudo through it.
	if err := h.chmod(filepath.Join(deploy, "bin", "tacctl.sh"), 0o755); err != nil {
		return err
	}
	// A release of the bash era has no Go sources to build; its own
	// installer installs it (an install, unlike an upgrade, has nothing
	// to hand over).
	if !exists(filepath.Join(deploy, "go.mod")) && exists(filepath.Join(deploy, "lib", "core.sh")) {
		what := "The tree in " + deploy
		if branch != "" {
			what = "'" + branch + "'"
		}
		out.Error(what + " is a release of the bash era; install it with its own installer: sudo " +
			filepath.Join(deploy, "bin", "tacctl.sh") + " install")
		return backend.ErrFailed
	}
	return h.installCommand(ctx)
}

// installCommand makes the installed command the binary of the deploy
// clone's HEAD: when it is not a binary yet (missing, or 0.1.16's symlink)
// or this binary was not built from that commit, the clone's shim installs
// it (Build: the verified release binary, or one built from the clone).
// Run from the bootstrap shim, which did that a moment ago, it is already. 0.1.16 symlinked its entrypoint
// instead. The login console's symlink (paths.ConsoleCommand) is made
// either way.
func (h *Host) installCommand(ctx context.Context) error {
	p := h.Paths
	head, _ := h.gitOut(ctx, p.Deploy, "rev-parse", "HEAD")
	if st, err := os.Lstat(p.Command); err == nil && st.Mode().IsRegular() && head != "" && head == h.Commit {
		_, err := h.ensureConsoleLink()
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.Command), 0o755); err != nil {
		return h.failed("mkdir: cannot create directory '" + filepath.Dir(p.Command) + "': " + errno(err))
	}
	if err := h.Build(ctx, p.Deploy, p.Command); err != nil {
		return h.buildFailed(err, "")
	}
	_, err := h.ensureConsoleLink()
	return err
}

// installSummary is the closing summary of install.
func (h *Host) installSummary(seed SeedResult) {
	p := h.Paths
	h.echo("")
	h.echo(rule)
	h.echo("  Installation Complete")
	h.echo(rule)
	h.echo("")
	h.echo("  TACACS+:        tacquito.service (enabled, running)")
	h.echo("  Store:          " + p.StoreFile)
	h.echo("  Config:         " + p.Config + " (rendered from the store)")
	h.echo("  Accounting log: " + p.AcctLog)
	h.echo("")
	if seed.Mode != SeedFresh {
		// Existing data was kept: no new secret, no seeded users.
		switch seed.Mode {
		case SeedStore:
			h.echo("  Existing store kept: users, groups, scopes and shared secrets are unchanged.")
		case SeedFlipped:
			h.echo("  Existing tacquito.yaml kept and moved into the store: users, scopes and shared secrets are unchanged.")
		default:
			h.echoE("  " + ui.Yellow + "Existing tacquito.yaml kept, NOT moved into the store: legacy read-only mode (see the report above)." + ui.NC)
		}
		h.echo("  Show a scope's shared secret: tacctl scope secret <scope> show")
		h.echo("")
		return
	}
	h.echo("  Shared Secret:  " + seed.Secret)
	h.echo("")
	h.echoE("  " + ui.Red + "SAVE THE SHARED SECRET" + ui.NC + " (shown again by: tacctl scope secret " + DefaultScopeFresh + " show).")
	h.echoE("  " + ui.Yellow + "Clear your terminal after recording: history -c && clear" + ui.NC)
	h.echo("")
	h.echo("  Built-in users:")
	h.echo("    engineer (superuser)   — disabled; tacctl user passwd engineer")
	h.echo("    operator (operator)    — disabled; tacctl user passwd operator")
	h.echo("    viewer   (readonly)    — disabled; tacctl user passwd viewer")
	h.echo("    root     (readonly)    — permanent accounting-only sink (never authenticates)")
	h.echo("")
	h.echo("  Next steps:")
	h.echo("    1. Activate a built-in:    tacctl user passwd engineer")
	h.echo("       (or add your own:       tacctl user add <username> <group>)")
	h.echo("    2. Configure devices:      tacctl config cisco / tacctl config juniper")
	h.echo("    3. Narrow scope prefixes:  tacctl scope prefixes " + DefaultScopeFresh + " <your-subnets>")
	h.echo("    4. Add a prod scope:       tacctl scope add prod --prefixes <cidrs> --secret generate")
	h.echo("    5. Open port 49/tcp in your firewall if needed")
	h.echo("    6. RADIUS as well (optional): tacctl backend enable radius")
	h.echo("")
	h.echo("  Security hardening:")
	h.echo("    7. Bind to a specific IP:  tacctl config listen tcp <mgmt-ip>:49")
	h.echo("    8. Add connection ACL:     tacctl config allow add <cidr>")
	h.echo("    9. Review config:          tacctl config show")
	h.echo("")
}
