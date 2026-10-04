package tacacs

// The tacquito checkout and binaries: the patch overlay, 'install build',
// 'upgrade preflight' and 'upgrade build'.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// --- the patch overlay (patches/README.md) ---------------------------------
//
// tacquito is built from an upstream checkout; behaviours tacctl depends on
// that are not upstream live as git-apply diffs in the patch directory
// (paths.PatchDir: TACCTL_PATCH_DIR, else <tree>/patches) and are applied
// again after every upstream pull.

// patchFiles are the *.patch files of the patch directory, in glob order.
func (b *Backend) patchFiles() []string {
	return globSorted(filepath.Join(b.env.Paths.PatchDir, "*.patch"))
}

// patchesApplied is tacquito_patches_applied: every patch is applied to
// the working tree (reverse check). No patches at all counts as applied.
func (b *Backend) patchesApplied(ctx context.Context) bool {
	src := b.env.Paths.TacquitoSrc
	for _, p := range b.patchFiles() {
		if b.shQuiet(ctx, "", "git", "-C", src, "apply", "--reverse", "--check", p) != 0 {
			return false
		}
	}
	return true
}

// applyPatches is apply_tacquito_patches: apply every patch not applied
// yet onto the checkout (pristine upstream, since the callers ran 'git
// checkout -- .' before the pull). It reports whether it applied any. A
// patch that will not apply (upstream drift) ends the phase rather than
// letting an unpatched binary be built.
func (b *Backend) applyPatches(ctx context.Context) (bool, error) {
	if !isDir(b.env.Paths.PatchDir) {
		return false, nil
	}
	src := b.env.Paths.TacquitoSrc
	applied := 0
	for _, p := range b.patchFiles() {
		if b.shQuiet(ctx, "", "git", "-C", src, "apply", "--reverse", "--check", p) == 0 {
			continue // already applied
		}
		if b.shQuiet(ctx, "", "git", "-C", src, "apply", "--check", p) != 0 {
			b.out().ErrorE("tacquito patch will not apply cleanly: " + filepath.Base(p) + ".")
			b.out().Error("Upstream likely changed the patched file; refresh the diff in patches/.")
			return false, failed(1, "patch")
		}
		// 0.1.16 runs this with errexit off (the caller's '|| true').
		b.sh(ctx, "", "git", "-C", src, "apply", p)
		b.out().InfoE("Applied tacquito patch: " + filepath.Base(p))
		applied++
	}
	return applied > 0, nil
}

// --- install build -------------------------------------------------------------

// installBuild is _tacacs_install_build: the Go toolchain, the tacquito
// checkout with the patch overlay, the binaries. Go itself is the
// bootstrap shim's to install; this checks it is there.
func (b *Backend) installBuild(ctx context.Context) error {
	out := b.out()
	goBin := b.goBin()
	if !executable(goBin) {
		out.ErrorE("Go not found at " + goBin + ". Install Go first.")
		return failed(1, "go")
	}
	ver, _ := b.shOut(ctx, "", goBin, "version")
	if f := strings.Fields(ver); len(f) > 2 {
		ver = strings.TrimPrefix(f[2], "go")
	} else {
		ver = ""
	}
	out.InfoE("Go " + ver + " already installed, skipping.")

	src := b.env.Paths.TacquitoSrc
	if isDir(src) {
		out.InfoE("Tacquito source already exists at " + src + ", pulling latest...")
		// Drop the patches applied last time so the pull stays clean.
		b.shQuiet(ctx, src, "git", "checkout", "--", ".")
		if code := b.sh(ctx, src, "git", "pull", "--quiet"); code != 0 {
			return failed(code, "git pull")
		}
	} else {
		out.Info("Cloning tacquito...")
		if code := b.sh(ctx, "", "git", "clone", "--quiet", TacquitoRepo, src); code != 0 {
			return failed(code, "git clone")
		}
	}
	if _, err := b.applyPatches(ctx); err != nil {
		return err
	}

	bin, hashgen, goProg := b.tacquitoBin(), b.hashgenBin(), b.goProgram()
	out.Info("Building tacquito server...")
	if code := b.sh(ctx, src+"/cmds/server", goProg, "build", "-o", bin, "."); code != 0 {
		return failed(code, "go build")
	}
	out.Info("Building password hash generator...")
	if code := b.sh(ctx, src+"/cmds/server/config/authenticators/bcrypt/generator", goProg, "build", "-o", hashgen, "."); code != 0 {
		return failed(code, "go build")
	}
	// go build honours the umask (077 under tacctl): systemd's
	// User=tacquito must be able to exec the binary.
	for _, f := range []string{bin, hashgen} {
		if err := os.Chmod(f, 0o755); err != nil {
			return b.fileError("chmod", err)
		}
	}
	out.Info("Binaries installed:")
	out.InfoE("  Server:  " + bin)
	out.InfoE("  Hashgen: " + hashgen)
	b.ensureSafeDirectory(ctx, src)
	return nil
}

// --- upgrade preflight and build ---------------------------------------------

// upgradePreflight is _tacacs_upgrade_preflight: nothing is touched when
// the build cannot run.
func (b *Backend) upgradePreflight(ctx context.Context) error {
	src := b.env.Paths.TacquitoSrc
	if !isDir(src) {
		b.out().ErrorE("Tacquito source not found at " + src + ". Run 'tacctl install' first.")
		return failed(1, "preflight")
	}
	if goBin := b.goBin(); !executable(goBin) {
		b.out().ErrorE("Go not found at " + goBin + ". Install Go first.")
		return failed(1, "preflight")
	}
	b.ensureSafeDirectory(ctx, src)
	return nil
}

// upgradeBuild is _tacacs_upgrade_build: pull tacquito, rebuild when
// upstream or the patch overlay moved or the binary is missing.
//
// The build runs before tacctl pulls itself, and a tacctl that changed
// re-executes the upgrade, whose own build then finds the source current:
// the binary the first run built is in place, but the daemon has not been
// restarted on it. The first run's tacquito.bak (removed only once the
// daemon came up on the new binary, or put back when it did not) says so,
// and this run takes over its restart and rollback. The commit the first
// run started from comes in UpgradeFromEnv (SetUpgradeFrom), for the
// summary.
func (b *Backend) upgradeBuild(ctx context.Context) error {
	l, out := &b.life, b.out()
	l.prebuilt = false
	src := b.env.Paths.TacquitoSrc
	cur, code := b.shOut(ctx, src, "git", "rev-parse", "--short", "HEAD")
	if code != 0 {
		return failed(code, "git rev-parse")
	}
	l.currentCommit = cur
	out.InfoE("Current commit: " + cur)

	out.Info("Pulling latest source...")
	if code := b.sh(ctx, src, "git", "fetch", "--quiet"); code != 0 {
		return failed(code, "git fetch")
	}
	// The summary is defined even when a rebuild is driven by the patch
	// overlay rather than an upstream pull.
	l.newCommit = cur
	local, code := b.shOut(ctx, src, "git", "rev-parse", "HEAD")
	if code != 0 {
		return failed(code, "git rev-parse")
	}
	remote, code := b.shOut(ctx, src, "git", "rev-parse", "@{u}")
	if code != 0 {
		return failed(code, "git rev-parse")
	}

	bin, hashgen := b.tacquitoBin(), b.hashgenBin()
	bak := bin + ".bak"
	if local == remote && b.patchesApplied(ctx) && isRegular(bin) {
		if isRegular(bak) {
			out.InfoE("Tacquito source already up to date (" + cur + "); patches applied. The binary built from it is not running yet.")
			l.skipBuild = "false"
			l.prebuilt = true
			if l.from != "" {
				l.currentCommit = l.from
			}
			nc, code := b.shOut(ctx, src, "git", "rev-parse", "--short", "HEAD")
			if code != 0 {
				return failed(code, "git rev-parse")
			}
			l.newCommit = nc
			return nil
		}
		out.InfoE("Tacquito source already up to date (" + cur + "); patches applied.")
		l.skipBuild = "true"
		return nil
	}

	l.skipBuild = "false"
	// A .bak already there is the binary from before a build the daemon
	// was not restarted on (above): the one to go back to, so it stays.
	if isRegular(bin) && !isRegular(bak) {
		// cp -p: keep the binary's mode. Under tacctl's umask 077 a plain
		// cp made a 0700 root copy that the tacquito user could not
		// execute once it was moved back (fixed in 0.1.17 too).
		if err := copyPreserve(bin, bak); err != nil {
			return b.fileError("cp", err)
		}
		out.InfoE("Backed up current binary to " + bak)
	}
	if l.from == "" {
		l.from = cur
	}

	// Drop the patches applied last time so the pull is clean, then build
	// from pristine upstream plus the overlay.
	b.shQuiet(ctx, src, "git", "checkout", "--", ".")
	if local != remote {
		if code := b.sh(ctx, src, "git", "pull", "--quiet"); code != 0 {
			return failed(code, "git pull")
		}
		nc, code := b.shOut(ctx, src, "git", "rev-parse", "--short", "HEAD")
		if code != 0 {
			return failed(code, "git rev-parse")
		}
		l.newCommit = nc
		out.InfoE("Updated: " + cur + " -> " + nc)
		writeString(out.Stdout, "\n")
		out.Info("Changes:")
		log, _ := b.shOut(ctx, src, "git", "log", "--oneline", cur+".."+nc)
		if log != "" {
			lines := strings.Split(log, "\n")
			writeString(out.Stdout, strings.Join(lines[:min(len(lines), 20)], "\n")+"\n")
		}
		writeString(out.Stdout, "\n")
	}
	if _, err := b.applyPatches(ctx); err != nil {
		return err
	}

	goProg := b.goProgram()
	out.Info("Building tacquito server...")
	if b.sh(ctx, src+"/cmds/server", goProg, "build", "-o", bin, ".") != 0 {
		out.Error("Build failed. Restoring previous binary.")
		if err := b.moveBack(bak, bin); err != nil {
			return err
		}
		return failed(1, "go build")
	}
	out.Info("Building password hash generator...")
	if b.sh(ctx, src+"/cmds/server/config/authenticators/bcrypt/generator", goProg, "build", "-o", hashgen, ".") != 0 {
		out.Warn("Hashgen build failed (non-critical).")
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		return b.fileError("chmod", err)
	}
	if !executable(hashgen) {
		// 0.1.16 ends the phase with '[[ -x hashgen ]] && chmod ...', whose
		// status is the phase's: with no hash generator at all, the
		// upgrade stops here, silently.
		return failed(1, "hashgen")
	}
	if err := os.Chmod(hashgen, 0o755); err != nil {
		return b.fileError("chmod", err)
	}
	return nil
}
