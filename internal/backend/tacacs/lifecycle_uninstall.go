package tacacs

// uninstall stop|program|data|account.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// defaultArchiveDir is where uninstall keeps the accounting logs it was
// asked to preserve (/root, as 0.1.16).
const defaultArchiveDir = "/root"

// instanceUnits is _tacacs_instance_units: the instance units this machine
// knows of, from the drop-in directories and from the links 'systemctl
// enable' made; sorted, each once.
func (b *Backend) instanceUnits() []string {
	dir := b.env.Paths.TacacsUnitDir
	seen := map[string]bool{}
	var out []string
	for _, pat := range []string{
		filepath.Join(dir, "tacquito@*.service.d"),
		filepath.Join(dir, "tacquito.service.wants", "tacquito@*.service"),
		filepath.Join(dir, "multi-user.target.wants", "tacquito@*.service"),
	} {
		for _, f := range globSorted(pat) {
			u := strings.TrimSuffix(filepath.Base(f), ".d")
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	sort.Strings(out)
	return out
}

// uninstallStop is _tacacs_uninstall_stop: every listener's unit. An
// install from before the listener model has only tacquito.service.
func (b *Backend) uninstallStop(ctx context.Context) error {
	out := b.out()
	for _, unit := range b.instanceUnits() {
		out.InfoE("Stopping " + unit + "...")
		b.quiet(ctx, "disable", "--quiet", "--now", unit)
	}
	if b.quiet(ctx, "is-active", "--quiet", Service) == 0 {
		out.Info("Stopping tacquito service...")
		if code := b.run(ctx, "stop", Service); code != 0 {
			return failed(code, "systemctl stop")
		}
	}
	if b.quiet(ctx, "is-enabled", "--quiet", Service) == 0 {
		b.quiet(ctx, "disable", Service)
	}
	return nil
}

// uninstallProgram is _tacacs_uninstall_program: the binaries (silently,
// under the generic step's message), then the units.
func (b *Backend) uninstallProgram(ctx context.Context) error {
	bin := b.tacquitoBin()
	if err := b.rmF(bin, bin+".bak", b.hashgenBin()); err != nil {
		return err
	}
	b.out().Info("Removing systemd unit...")
	return b.uninstallUnits(ctx)
}

// uninstallUnits is _tacacs_uninstall_units: every unit file, drop-in
// directory and enablement link of either layout (tacquito.service with
// the hand-managed drop-in, or with the rendered one plus the template and
// its instances).
func (b *Backend) uninstallUnits(ctx context.Context) error {
	p := b.env.Paths
	dir := p.TacacsUnitDir
	svc := b.serviceFile()
	files := []string{svc, svc + ".bak", b.templateFile()}
	trees := []string{p.OverrideDir, filepath.Join(dir, "tacquito.service.d"), filepath.Join(dir, "tacquito.service.wants")}
	trees = append(trees, globSorted(filepath.Join(dir, "tacquito@*.service.d"))...)
	links := globSorted(filepath.Join(dir, "multi-user.target.wants", "tacquito@*.service"))
	links = append(links, filepath.Join(dir, "multi-user.target.wants", "tacquito.service"))
	if err := b.rmF(files...); err != nil {
		return err
	}
	if err := b.rmRF(trees...); err != nil {
		return err
	}
	if err := b.rmF(links...); err != nil {
		return err
	}
	if code := b.run(ctx, "daemon-reload"); code != 0 {
		return failed(code, "systemctl daemon-reload")
	}
	return nil
}

// uninstallData is _tacacs_uninstall_data [--keep-logs]: the logrotate
// config, the config directory, the logs (kept as an archive first when
// asked).
func (b *Backend) uninstallData(ctx context.Context, keepLogs bool) error {
	p, out := b.env.Paths, b.out()
	if err := b.rmF(b.logrotateFile()); err != nil {
		return err
	}
	// Removing does not follow the compatibility symlinks left in the
	// config directory.
	if err := b.rmRF(p.Etc); err != nil {
		return err
	}
	logDir := filepath.Clean(p.Log)
	archive := ""
	if keepLogs && isDir(logDir) {
		dir := b.life.archiveDir
		if dir == "" {
			dir = b.env.Paths.ArchiveDir
		}
		if dir == "" {
			dir = defaultArchiveDir
		}
		archive = dir + "/tacquito-logs-" + b.now().Format("20060102_150405") + ".tar.gz"
		b.shQuiet(ctx, "", "tar", "czf", archive, "-C", filepath.Dir(logDir), filepath.Base(logDir)+"/")
		out.InfoE("Accounting logs saved to " + archive)
	}
	out.Info("Removing log directory...")
	if err := b.rmRF(logDir); err != nil {
		return err
	}
	if archive != "" {
		b.life.saved = append(b.life.saved, "Accounting logs saved to: "+archive)
	}
	return nil
}

// uninstallAccount is _tacacs_uninstall_account: the source checkout's
// safe.directory entry, the service user. Never fails.
func (b *Backend) uninstallAccount(ctx context.Context) {
	b.shQuiet(ctx, "", "git", "config", "--system", "--unset-all", "safe.directory", "^"+b.env.Paths.TacquitoSrc+"$")
	if b.shSilent(ctx, "", "id", User) == 0 {
		b.out().Info("Removing tacquito service user...")
		b.shQuiet(ctx, "", "userdel", User)
	}
}

// rmF is 'rm -f <path>...' under 'set -e': a path that is not there is
// fine, one that cannot be removed ends the phase.
func (b *Backend) rmF(paths ...string) error {
	for _, p := range paths {
		if err := unix.Unlink(p); err != nil && !errors.Is(err, unix.ENOENT) {
			return b.fileError("rm", &os.PathError{Op: "cannot remove", Path: p, Err: err})
		}
	}
	return nil
}

// rmRF is 'rm -rf <path>...' under 'set -e'.
func (b *Backend) rmRF(paths ...string) error {
	for _, p := range paths {
		if err := os.RemoveAll(p); err != nil {
			return b.fileError("rm", err)
		}
	}
	return nil
}
