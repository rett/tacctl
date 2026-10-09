package lifecycle

// The login console's pieces that come and go with tacctl itself
// (docs/plans/operator-console-wp-console.md 5.3): the symlink
// /usr/local/bin/tacctl-console, made by install and refreshed by every
// upgrade, and at uninstall the accounts whose login shell it is (they get
// /bin/bash back, so no account is left with a shell that is about to
// vanish), sshd's drop-in and the /etc/shells line. The accounts' shells,
// the group and the drop-in are otherwise 'host sync' of this server's
// business.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
)

// ensureConsoleLink makes paths.ConsoleCommand a symlink to
// paths.Command (a new link renamed over the old path, so the console never
// disappears for a login in between). It reports whether it changed
// anything.
func (h *Host) ensureConsoleLink() (bool, error) {
	p := h.Paths
	if target, err := os.Readlink(p.ConsoleCommand); err == nil && target == p.Command {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p.ConsoleCommand), 0o755); err != nil {
		return false, h.failed("mkdir: cannot create directory '" + filepath.Dir(p.ConsoleCommand) + "': " + errno(err))
	}
	tmp := p.ConsoleCommand + ".tacctl-link"
	_ = os.Remove(tmp)
	if err := os.Symlink(p.Command, tmp); err != nil {
		return false, h.failed("ln: failed to create symbolic link '" + p.ConsoleCommand + "': " + errno(err))
	}
	if err := os.Rename(tmp, p.ConsoleCommand); err != nil {
		_ = os.Remove(tmp)
		return false, h.failed("ln: failed to create symbolic link '" + p.ConsoleCommand + "': " + errno(err))
	}
	return true, nil
}

// consoleAccounts are the accounts of this machine whose login shell is
// the console ('getent passwd', field 7).
func (h *Host) consoleAccounts(ctx context.Context) []string {
	res := h.cmd(ctx, execx.Cmd{Name: "getent", Args: []string{"passwd"}})
	if res.Code != 0 {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		f := strings.Split(l, ":")
		if len(f) == 7 && f[6] == h.Paths.ConsoleCommand {
			out = append(out, f[0])
		}
	}
	return out
}

// removeConsole is the uninstall's part for the console: every account
// whose shell is the console gets /bin/bash ('usermod -s'; named), then
// sshd's drop-in goes (checked with 'sshd -t', sshd reloaded) and the
// /etc/shells line. The symlink itself goes with the binary. Failures are
// warnings: the uninstall goes on.
func (h *Host) removeConsole(ctx context.Context) {
	p, out := h.Paths, h.Out
	var restored, failed []string
	for _, name := range h.consoleAccounts(ctx) {
		res := h.cmd(ctx, execx.Cmd{Name: "usermod", Args: []string{"-s", console.SystemLoginShell, name}})
		if res.Code != 0 {
			failed = append(failed, name)
			continue
		}
		restored = append(restored, name)
	}
	if len(restored) > 0 {
		out.Info("Login shell " + console.SystemLoginShell + " restored for: " + strings.Join(restored, ", "))
	}
	if len(failed) > 0 {
		out.Warn("Could not give these accounts " + console.SystemLoginShell + " back (usermod -s failed); their shell " +
			p.ConsoleCommand + " is removed now, so they cannot log in until it is changed: " + strings.Join(failed, ", "))
	}
	for _, path := range []string{p.SSHDDropIn, p.SSHDEngineerDropIn, p.SSHDEngineerDropInOld} {
		d := console.DropInFile{Runner: h.Runner, Path: path}
		if ch, err := d.Remove(ctx); err != nil {
			out.Warn("sshd drop-in " + path + ": " + strings.Join(lines(err), " "))
		} else if ch == console.Removed {
			out.Info("Removed sshd drop-in " + path)
		}
	}
	if ch, err := console.RemoveShells(p.ShellsFile, p.ConsoleCommand); err != nil {
		out.Warn(strings.Join(lines(err), " "))
	} else if ch == console.Removed {
		out.Info("Removed " + p.ConsoleCommand + " from " + p.ShellsFile)
	}
}

// lines are an error's lines (names.Error and console's errors have them).
func lines(err error) []string {
	var l interface{ Lines() []string }
	if errors.As(err, &l) {
		return l.Lines()
	}
	return []string{err.Error()}
}

// updateConsoleDropIn is upgrade's refresh of sshd's drop-in for the
// console, on the model of updateTierSudoers: a drop-in that is installed
// and differs from this release's text (for console.yaml's settings) is
// rewritten, checked with 'sshd -t' (restored when sshd refuses it) and sshd
// reloaded: "Updated: sshd drop-in", else "Unchanged:". It is never
// created here ('host sync' of this server or 'console install' does).
func (h *Host) updateConsoleDropIn(ctx context.Context) int {
	p := h.Paths
	_, errC := os.Stat(p.SSHDDropIn)
	_, errE := os.Stat(p.SSHDEngineerDropIn)
	_, errO := os.Stat(p.SSHDEngineerDropInOld)
	if errC != nil && errE != nil && errO != nil {
		return 0
	}
	f, err := console.Load(p.ConsoleFile)
	if err != nil {
		h.Out.Warn("  Not updated: sshd drop-in (" + strings.Join(lines(err), " ") + ")")
		return 0
	}
	n := 0
	if errC == nil {
		n += h.updateDropIn(ctx, "sshd drop-in", p.SSHDDropIn, console.DropIn(p.ConsoleCommand, f.AgentForwarding, f.GatewayPorts, f.ForwardingTiers))
	}
	// The engineer tier's lockdown lived in the console's drop-in before it
	// had a file of its own: an install that has one gets the other. The
	// file also was named tacctl-engineer.conf, which sshd reads after the
	// console's, where a forwarding tier of the console beat it (S1): the
	// renamed file is written first, then the old one goes.
	n += h.updateDropIn(ctx, "sshd drop-in for the engineer tier", p.SSHDEngineerDropIn, console.EngineerDropIn(f.AgentForwarding))
	if errO == nil {
		if _, err := os.Stat(p.SSHDEngineerDropIn); err != nil {
			h.Out.Warn("  Not renamed: " + p.SSHDEngineerDropInOld + " stays until " + p.SSHDEngineerDropIn + " is written")
			return n
		}
		d := console.DropInFile{Runner: h.Runner, Path: p.SSHDEngineerDropInOld}
		if ch, err := d.Remove(ctx); err != nil && ch == console.Unchanged {
			h.Out.Warn("  Not removed: sshd drop-in " + p.SSHDEngineerDropInOld + " (" + strings.Join(lines(err), " ") + ")")
		} else {
			h.Out.Info("  Removed: sshd drop-in " + p.SSHDEngineerDropInOld + " (renamed to " + filepath.Base(p.SSHDEngineerDropIn) + ")")
			n++
		}
	}
	return n
}

// updateDropIn makes the drop-in at path hold text (see updateConsoleDropIn).
func (h *Host) updateDropIn(ctx context.Context, what, path, text string) int {
	out := h.Out
	d := console.DropInFile{Runner: h.Runner, Path: path}
	ch, err := d.Install(ctx, text)
	switch {
	case err != nil && ch == console.Unchanged:
		out.Warn("  Not updated: " + what + " (" + strings.Join(lines(err), " ") + "; " + path + " is unchanged)")
		return 0
	case err != nil:
		out.Warn("  Updated: " + what + ", but " + strings.Join(lines(err), " "))
		return 1
	case ch == console.Unchanged:
		out.Info("  Unchanged: " + what)
		return 0
	}
	out.Info("  Updated: " + what)
	return 1
}

// updateConsoleLink is upgrade's refresh of the console's symlink.
func (h *Host) updateConsoleLink() (int, error) {
	changed, err := h.ensureConsoleLink()
	if err != nil || !changed {
		return 0, err
	}
	h.Out.Info("  Updated: " + h.Paths.ConsoleCommand + " -> " + h.Paths.Command)
	return 1, nil
}
