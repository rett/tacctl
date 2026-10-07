package tacacs

// install files|account|start and upgrade files|finish.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/lifecycle"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
)

// startWait is the 'sleep 2' after a start or restart, before the
// is-active check.
const startWait = 2 * time.Second

// --- install -------------------------------------------------------------------

// installFiles is _tacacs_install_files <tree>: the logrotate config.
func (b *Backend) installFiles(tree string) error {
	src := share(tree) + "/tacquito.logrotate"
	if !isRegular(src) {
		return nil
	}
	dst := b.logrotateFile()
	if err := cpFile(src, dst); err != nil {
		return b.fileError("cp", err)
	}
	b.out().InfoE("Log rotation installed: " + dst)
	return nil
}

// installAccount is _tacacs_install_account <tree>: the service user, the
// config and log directories, README.md.
func (b *Backend) installAccount(ctx context.Context, tree string) error {
	out, p := b.out(), b.env.Paths
	if b.shSilent(ctx, "", "id", User) != 0 {
		out.Info("Creating tacquito service user...")
		if code := b.sh(ctx, "", "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", User); code != 0 {
			return failed(code, "useradd")
		}
	} else {
		out.Info("Service user 'tacquito' already exists.")
	}
	for _, d := range []string{p.Etc, p.Log} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			return b.fileError("mkdir", err)
		}
	}
	if err := b.chownTacquito(p.Etc, p.Log); err != nil {
		return b.fileError("chown", err)
	}
	// The config directory is world-traversable so everyone can read
	// README.md; what is sensitive inside is 0640 by its own mode. The log
	// directory stays 0750.
	if err := os.Chmod(p.Etc, 0o755); err != nil {
		return b.fileError("chmod", err)
	}
	if err := os.Chmod(p.Log, 0o750); err != nil {
		return b.fileError("chmod", err)
	}
	if err := b.installReadme(tree); err != nil {
		b.stderrLine("cp: " + err.Error())
		out.WarnE("Could not install " + filepath.Join(p.Etc, "README.md") + ".")
	}
	return nil
}

// installReadme is install_readme <tree>/README.md: README.md in the
// config directory, readable by everyone. Nothing without the source.
func (b *Backend) installReadme(tree string) error {
	src := tree + "/README.md"
	if !isRegular(src) {
		return nil
	}
	dst := filepath.Join(b.env.Paths.Etc, "README.md")
	if err := cpFile(src, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o644)
}

// installStart is _tacacs_install_start <tree>, after the first render:
// the units, enable, start, check.
func (b *Backend) installStart(ctx context.Context, tree string) error {
	out, cfg := b.out(), b.env.Paths.Config
	if lifecycle.ConfigServiceAccess(&lifecycle.Env{Env: b.env, IsRoot: b.isRoot()}) != nil {
		out.ErrorE("Could not make " + cfg + " readable by the tacquito service user.")
		return failed(1, "config access")
	}

	// The unit, the template for further listeners and the drop-ins; over
	// an earlier install this is the same conversion as on upgrade.
	out.Info("Installing systemd service...")
	if !b.unitsInstall(ctx, tree) {
		out.Error("Could not install the systemd units (see above).")
		return failed(1, "units")
	}
	b.unitsKeepDiscard()
	if code := b.run(ctx, "daemon-reload"); code != 0 {
		return failed(code, "systemctl daemon-reload")
	}
	if code := b.run(ctx, "enable", rtacacs.UnitName); code != 0 {
		return failed(code, "systemctl enable")
	}

	out.Info("Starting tacquito...")
	// A start that fails is judged by the check below.
	b.run(ctx, "start", rtacacs.UnitName)
	b.sleep(ctx, startWait)
	if b.run(ctx, "is-active", "--quiet", rtacacs.UnitName) != 0 {
		out.Error("Tacquito failed to start. Check: journalctl -u tacquito")
		return failed(1, "start")
	}
	out.Info("Tacquito is running!")
	b.instancesSync(ctx)
	b.listenCheck(ctx)
	return nil
}

// --- upgrade files ---------------------------------------------------------------

// upgradeFiles is _tacacs_upgrade_files <tree>: the units, README.md in
// the config directory, logrotate; what it replaced is counted in
// UpgradeReport.FilesUpdated.
func (b *Backend) upgradeFiles(ctx context.Context, tree string) error {
	l, p := &b.life, b.env.Paths
	l.report.FilesUpdated, l.report.FilesNotes = 0, nil
	b.upgradeUnits(ctx, tree)

	readme := filepath.Join(p.Etc, "README.md")
	if err := b.updateIfChanged(tree+"/README.md", readme, "README.md"); err != nil {
		return err
	}
	// Installs from before the README fix have it 0600 root, or not at all.
	_ = os.Chmod(readme, 0o644)
	if err := b.updateIfChanged(share(tree)+"/tacquito.logrotate", b.logrotateFile(), "logrotate config"); err != nil {
		return err
	}
	// Older installs left the config directory at 0750, which keeps
	// non-root users from README.md.
	_ = os.Chmod(p.Etc, 0o755)
	return nil
}

// upgradeUnits is _tacacs_upgrade_units: unitsInstall (which also
// converts an install from before the listener model), reported and
// counted. 'finish' restarts when it changed something. A unit update
// that stops is not an upgrade failure: the files in place keep working.
func (b *Backend) upgradeUnits(ctx context.Context, tree string) {
	l := &b.life
	b.unitsInstall(ctx, tree)
	switch l.unitsState {
	case unitsChanged:
		for _, n := range l.unitsNotes {
			b.out().InfoE("  " + n)
		}
		l.report.FilesUpdated++
	case unitsStopped:
		l.report.FilesNotes = append(l.report.FilesNotes,
			"Units: NOT updated — the previous unit files are in place (see 'Unit update stopped' above)")
	default:
		b.out().Info("  Unchanged: tacquito.service")
	}
}

// --- upgrade finish ----------------------------------------------------------------

// upgradeFinish is _tacacs_upgrade_finish: the store gate, then one
// restart for everything this upgrade changed that the daemon reads, with
// the unit files and the binary rolled back if the daemon does not come
// up; then the headline and notes for the closing summary.
//
// The restart rule: tacquito restarts when the build phase left a binary
// it is not running yet (a rebuild, or one the run before a self-update
// re-exec built), the units or drop-ins changed, the store gate moved a
// legacy install into the store, or the config phase changed tacquito.yaml.
// A new README, logrotate file, template or completion is no reason to
// drop its sessions, and an upgrade with nothing new restarts nothing. A
// restart that fails falls through to the is-active check and the
// rollback.
func (b *Backend) upgradeFinish(ctx context.Context) error {
	l, out := &b.life, b.out()
	// A stop of the gate is not an upgrade failure: the code is installed
	// and the daemon keeps its config.
	storeFlip := b.UpgradeStoreFlip
	if l.flip != nil {
		storeFlip = l.flip
	}
	flip := storeFlip(ctx)
	l.report.Head, l.report.Notes, l.report.UpToDate = "", nil, ""

	newBinary := l.skipBuild == "false"
	restart := newBinary || l.unitsState == unitsChanged || flip == lifecycle.Flipped || l.configChanged
	if restart {
		out.Info("Restarting tacquito service...")
		b.run(ctx, "restart", rtacacs.UnitName)
		b.sleep(ctx, startWait)
		if b.run(ctx, "is-active", "--quiet", rtacacs.UnitName) == 0 {
			out.Info("Tacquito is running.")
			_ = os.Remove(b.tacquitoBin() + ".bak")
			b.unitsKeepDiscard()
			b.instancesSync(ctx)
		} else {
			return b.upgradeRollback(ctx, newBinary, flip)
		}
		b.listenCheck(ctx)
	} else {
		// Nothing to restart for; unit files (if any changed) count as
		// proven.
		b.unitsKeepDiscard()
	}

	switch {
	case newBinary && l.currentCommit != l.newCommit:
		l.report.Head = "Upgrade Complete: " + l.currentCommit + " -> " + l.newCommit
	case l.prebuilt:
		l.report.Head = "Upgrade Complete: now running the tacquito binary built at " + l.currentCommit
	case newBinary:
		l.report.Head = "Upgrade Complete: rebuilt at " + l.currentCommit + " (patch overlay refreshed)"
	default:
		l.report.Head = "Scripts Updated (source unchanged at " + l.currentCommit + ")"
		if !restart && l.report.FilesUpdated == 0 {
			l.report.UpToDate = "Already Up to Date (source unchanged at " + l.currentCommit + ")"
		}
	}
	if l.unitsState == unitsChanged {
		l.report.Notes = append(l.report.Notes,
			"Units: tacquito.service and its listener drop-in are current (settings in "+b.env.Paths.Overrides+")")
	}
	switch flip {
	case lifecycle.Flipped:
		l.report.Notes = append(l.report.Notes, "Store: migrated from tacquito.yaml ('tacctl store rollback' undoes it)")
	case lifecycle.FlipStopped:
		l.report.Notes = append(l.report.Notes, "Store: NOT migrated — legacy read-only mode (see 'Store migration stopped' above)")
	}
	return nil
}

// upgradeRollback is the way back of upgradeFinish when the daemon did not
// come up: everything this upgrade replaced under it goes back at once
// (unit files with their settings, and the binary) and one restart
// follows. The phase fails either way.
func (b *Backend) upgradeRollback(ctx context.Context, newBinary bool, flip lifecycle.FlipResult) error {
	out, cfg := b.out(), b.env.Paths.Config
	var rolled []string
	if b.unitsRollback(ctx) {
		out.Error("Tacquito failed to start after upgrade. The previous unit files and settings were restored.")
		rolled = append(rolled, "unit files")
	}
	if newBinary {
		out.Error("Tacquito failed to start after upgrade. Rolling back binary...")
		bin := b.tacquitoBin()
		if err := b.moveBack(bin+".bak", bin); err != nil {
			return err
		}
		rolled = append(rolled, "binary")
	}
	if len(rolled) == 0 {
		out.Error("Tacquito failed to start. Check: journalctl -u tacquito")
		lifecycle.FlipHint(out, cfg, flip)
		return failed(1, "restart")
	}
	b.run(ctx, "restart", rtacacs.UnitName)
	b.sleep(ctx, startWait)
	if b.run(ctx, "is-active", "--quiet", rtacacs.UnitName) == 0 {
		out.Warn("Rolled back to the previous " + strings.Join(rolled, " ") + ". Service is running.")
	} else {
		out.Error("Rollback failed. Check: journalctl -u tacquito")
	}
	lifecycle.FlipHint(out, cfg, flip)
	return failed(1, "restart")
}
