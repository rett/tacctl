package hosts

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// buildTools are the programs 'config linux build' needs, in the order it
// checks them.
var buildTools = []string{"git", "gnulib-tool", "autoreconf", "libtoolize", "make", "gcc"}

// gnulibModules are the gnulib modules pam_tacplus 1.7.0 imports.
var gnulibModules = []string{
	"fcntl", "crypto/md5", "array-list", "list", "xlist", "getrandom", "realloc-posix",
	"explicit_bzero", "xalloc", "getopt-gnu",
}

// BuildTarball is cmd_config_linux_build: the pinned pam_tacplus tag is
// cloned (and checked against its commit), prepared with gnulib and
// autotools, and its 'make dist' tarball installed as PAM_TACPLUS_TARBALL.
// Failures are printed; the error is then ErrFailed.
func (e *Env) BuildTarball(ctx context.Context) error {
	for _, t := range buildTools {
		if _, err := e.Runner.LookPath(t); err != nil {
			e.Out.Error("'" + t + "' not found. Install the build tools first:")
			e.Out.Error("  apt install autoconf automake libtool gnulib libpam0g-dev build-essential git")
			return ErrFailed
		}
	}
	work, err := TempDir()
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	src := work + "/src"
	e.Out.Info("Fetching pam_tacplus " + PamTacplusTag + "...")
	res, err := e.Runner.Run(ctx, execx.Cmd{Name: "git", Args: []string{
		"clone", "--quiet", "--depth", "1", "--branch", PamTacplusTag, PamTacplusRepo, src}})
	if interrupted(ctx) {
		return ui.ErrInterrupted
	}
	if err != nil || res.Code != 0 {
		e.Out.Error("Could not clone " + PamTacplusRepo + ".")
		return ErrFailed
	}
	res, _ = e.Runner.Run(ctx, execx.Cmd{Name: "git", Args: []string{"-C", src, "rev-parse", "HEAD"}, Stderr: e.Out.Stderr})
	if got := strings.TrimRight(string(res.Stdout), "\n"); got != PamTacplusCommit {
		e.Out.ErrorE("Tag " + PamTacplusTag + " resolved to " + got + ", expected " + PamTacplusCommit + ". Refusing to build.")
		return ErrFailed
	}

	e.Out.Info("Preparing source tarball...")
	log, err := os.Create(work + "/build.log")
	if err != nil {
		return err
	}
	// Current gnulib no longer defines this macro; glibc provides
	// explicit_bzero, so the branch that used it is never taken.
	dropLine(src+"/configure.ac", "  gl_PREREQ_EXPLICIT_BZERO")
	// The steps run as one subshell whose status is the last one's: 0.1.16
	// ran them under 'if ! ( ... )', where a failing step does not stop the
	// next.
	steps := [][]string{
		append([]string{"gnulib-tool", "--makefile-name=Makefile.gnulib", "--libtool", "--import"}, gnulibModules...),
		{"autoreconf", "-f", "-i"},
		{"./configure"},
		{"make", "dist"},
	}
	code := 0
	for _, s := range steps {
		res, err := e.Runner.Run(ctx, execx.Cmd{Name: s[0], Args: s[1:], Dir: src, Stdout: log, Stderr: log})
		if interrupted(ctx) {
			_ = log.Close()
			return ui.ErrInterrupted
		}
		code = res.Code
		if err != nil && code == 0 {
			code = 127
		}
	}
	_ = log.Close()
	if code != 0 {
		data, _ := os.ReadFile(work + "/build.log")
		_, _ = e.Out.Stderr.Write(lastLines(data, 20))
		e.Out.Error("Preparing the pam_tacplus tarball failed.")
		return ErrFailed
	}
	if err := e.Paths.mkDir(); err != nil {
		return err
	}
	if err := os.Chmod(e.Paths.Dir, 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(src + "/" + tarballName)
	if err != nil {
		// 'install' of a tarball 'make dist' did not leave, under errexit.
		_, _ = io.WriteString(e.Out.Stderr, "install: cannot stat '"+src+"/"+tarballName+"': "+strerror(err)+"\n")
		return ErrFailed
	}
	if err := replaceFile(e.Paths.Tarball(), data, 0o644); err != nil {
		return err
	}
	e.Out.InfoE("Wrote " + e.Paths.Tarball() + " (sha256 " + fileSHA256(e.Paths.Tarball()) + ").")
	return nil
}

// dropLine is "sed -i '/^<line>$/d' <file>": every line equal to line
// removed (nothing happens when the file cannot be read).
func dropLine(path, line string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	var kept []string
	text := string(data)
	trail := strings.HasSuffix(text, "\n")
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if l != line {
			kept = append(kept, l)
		}
	}
	out := strings.Join(kept, "\n")
	if trail && len(kept) > 0 {
		out += "\n"
	}
	_ = replaceFile(path, []byte(out), st.Mode().Perm())
}
