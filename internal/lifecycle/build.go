package lifecycle

// The tacctl binary: obtained by the deploy clone's bootstrap shim (the
// verified release binary, or built with the one recipe the Makefile and
// the shim use), and the man page.

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

// Build makes dst the tacctl binary of tree with tree's own bootstrap shim,
// '<tree>/bin/tacctl.sh --install-binary <dst>': the verified release
// binary when tree is at a release tag, otherwise (or when it cannot be
// verified, which the shim says in one line) the binary built with the
// recipe of docs/plans/go-rewrite.md 5.1 (vendored, no network, -trimpath,
// the version stamped from git). The shim prints what it does ('Installing
// the <tag> release binary …' or 'Building <dst> from <tree>...'). A tree
// whose shim predates --install-binary (0.2.0) is built with its
// '--build <dst>', and the 'Building' line is printed here. Either way
// <dst>.new is written and renamed over dst, so dst is replaced atomically
// or not at all, and the shim's output is passed through. On failure
// <dst>.new is removed (a build that was cancelled is killed before its own
// cleanup can run), dst is as it was, and the error says so: ErrFailed, or
// exit status 130 when ctx was cancelled (Ctrl-C).
func (h *Host) Build(ctx context.Context, tree, dst string) error {
	recipe := filepath.Join(tree, "bin", "tacctl.sh")
	args := []string{"--install-binary", dst}
	if !shimInstallsBinaries(recipe) {
		h.Out.Info("Building " + dst + " from " + tree + "...")
		args = []string{"--build", dst}
	}
	res, err := h.Runner.Run(ctx, execx.Cmd{Name: recipe, Args: args,
		Stdout: h.Out.Stdout, Stderr: h.Out.Stderr})
	if err == nil && res.Code == 0 {
		return nil
	}
	_ = os.Remove(dst + ".new")
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return &backend.Error{Code: 130, Reason: "build interrupted"}
	}
	return backend.ErrFailed
}

// shimInstallsBinaries: the shim at path has the '--install-binary' mode
// (0.2.1 and later). An unreadable shim is taken for one that has not.
func shimInstallsBinaries(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && bytes.Contains(data, []byte("--install-binary"))
}

// buildFailed prints Decision 20's text after a failed Build of the
// installed command: what happened, and the way back to the code the
// installed command was built from (start, the deploy clone's commit
// before this run moved it). It returns err.
func (h *Host) buildFailed(err error, start string) error {
	out, p := h.Out, h.Paths
	out.Error("tacctl could not be built (see above). The installed command is unchanged.")
	if start != "" {
		out.Error("Fix the cause and run 'sudo tacctl upgrade' again; or, to go back to the code the installed command was built from:")
		out.Error("  sudo git -C " + p.Deploy + " checkout " + start)
	} else {
		out.Error("Fix the cause and run 'sudo tacctl install' again.")
	}
	return err
}

// installManPage is install_man_page <src>: the man page gzipped to
// paths.ManPage (0644), then 'mandb -q' (best effort). No source: nothing,
// so an older checkout keeps working.
func (h *Host) installManPage(ctx context.Context, src string) error {
	data, err := os.ReadFile(src)
	if err != nil || !isRegular(src) {
		return nil
	}
	dst := h.Paths.ManPage
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return h.failed("mkdir: cannot create directory '" + filepath.Dir(dst) + "': " + errno(err))
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	zw.Name = filepath.Base(src)
	if _, err := zw.Write(data); err != nil {
		return h.failed("gzip: " + err.Error())
	}
	if err := zw.Close(); err != nil {
		return h.failed("gzip: " + err.Error())
	}
	if err := writeKeepMode(dst, buf.Bytes(), 0o600); err != nil {
		return h.failed("cannot create " + dst + ": " + errno(err))
	}
	if err := h.chmod(dst, 0o644); err != nil {
		return err
	}
	h.mandb(ctx)
	return nil
}

// mandb is 'mandb -q 2>/dev/null || true'.
func (h *Host) mandb(ctx context.Context) {
	h.cmd(ctx, execx.Cmd{Name: "mandb", Args: []string{"-q"}, Stdout: h.Out.Stdout})
}
