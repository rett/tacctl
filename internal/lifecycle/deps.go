package lifecycle

// ensure_dependencies (lib/lifecycle.sh at 0.1.16): the distribution
// packages tacctl needs on the server.

import (
	"context"
	"io"
	"strings"

	"github.com/rett/tacctl/internal/execx"
)

// The packages tacctl needs (DEPS_CORE, DEPS_LINUX_HOSTS). The core set is
// required: git for the deploy clone and tacquito's source, wget for the Go
// tarball the bootstrap shim fetches. python3, python3-yaml and
// python3-bcrypt left it in 0.2.0 (docs/plans/go-rewrite.md 3.9 item 6):
// nothing runs python any more, and nothing is uninstalled. The rest serve
// 'tacctl host' (preparing the pam_tacplus source, building it in
// containers, reaching hosts over ssh), so failing to get them only warns.
var (
	DepsCore       = []string{"git", "wget"}
	DepsLinuxHosts = []string{"openssh-client", "autoconf", "automake", "libtool", "gnulib", "gcc", "make",
		"libpam0g-dev", "podman", "uidmap"}
)

// EnsureDependencies is ensure_dependencies: install whatever is missing
// from DepsCore and DepsLinuxHosts with apt (Debian and Ubuntu only, as in
// 0.1.16; elsewhere it warns with the list and succeeds). 'tacctl install'
// runs it, and every 'tacctl upgrade', so a release that needs a new
// package brings it along. A core package that cannot be installed is an
// error (printed; ErrFailed): the command stops.
func (h *Host) EnsureDependencies(ctx context.Context) error {
	out := h.Out
	if !h.has("apt-get") || !h.has("dpkg-query") {
		out.Warn("Not a Debian/Ubuntu system; make sure the equivalents of these are installed:")
		out.Warn("  " + strings.Join(DepsCore, " ") + " " + strings.Join(DepsLinuxHosts, " "))
		return nil
	}
	var core, extra []string
	for _, p := range DepsCore {
		if !h.pkgInstalled(ctx, p) {
			core = append(core, p)
		}
	}
	for _, p := range DepsLinuxHosts {
		if !h.pkgInstalled(ctx, p) {
			extra = append(extra, p)
		}
	}
	if len(core) == 0 && len(extra) == 0 {
		out.Info("Required packages: all present.")
		return nil
	}
	if len(core) > 0 {
		out.Info("Installing required packages: " + strings.Join(core, " "))
		if !h.aptInstall(ctx, core) {
			out.Error("Could not install: " + strings.Join(core, " ") + ". Install them and re-run.")
			return h.failed("")
		}
	}
	if len(extra) > 0 {
		out.Info("Installing packages for Linux host support: " + strings.Join(extra, " "))
		if !h.aptInstall(ctx, extra) {
			out.Warn("Could not install: " + strings.Join(extra, " ") + ". 'tacctl host' and 'tacctl config linux' need them; everything else works.")
		}
	}
	return nil
}

// pkgInstalled is _pkg_installed: dpkg-query -W -f='${Status}' <pkg>
// says 'install ok installed'.
func (h *Host) pkgInstalled(ctx context.Context, pkg string) bool {
	res := h.cmd(ctx, execx.Cmd{Name: "dpkg-query", Args: []string{"-W", "-f=${Status}", pkg}, Stderr: io.Discard})
	return strings.Contains(string(res.Stdout), "install ok installed")
}

// aptInstall is _apt_install: 'DEBIAN_FRONTEND=noninteractive apt-get
// install -y -qq <pkgs> >/dev/null', and when that fails (a stale package
// index is the usual cause) 'apt-get update -qq' once and the install
// again. apt's complaints go to stderr.
func (h *Host) aptInstall(ctx context.Context, pkgs []string) bool {
	env := withEnv(h.Environ.Environ(), []string{"DEBIAN_FRONTEND=noninteractive"})
	install := func() bool {
		return h.cmd(ctx, execx.Cmd{Name: "apt-get", Args: append([]string{"install", "-y", "-qq"}, pkgs...),
			Env: env, Stdout: io.Discard, Stderr: h.Out.Stderr}).Code == 0
	}
	if install() {
		return true
	}
	h.cmd(ctx, execx.Cmd{Name: "apt-get", Args: []string{"update", "-qq"}, Stdout: io.Discard, Stderr: h.Out.Stderr})
	return install()
}
