package cli

// Delegation to the bash implementation, for the duration of the rewrite
// (docs/plans/go-rewrite.md 4): every command the Go binary does not own yet
// is handed to bin/tacctl.sh of a bash tree, by exec (not as a child), with
// the original arguments and the unmodified environment, so stdin, the
// terminal, signals and the exit status are bash's own. No preflight and no
// tier gate run here: bash runs both itself. WP4.1 deletes this file.

import (
	"os"
	"path/filepath"

	"github.com/rett/tacctl/internal/app"
)

// delegate execs the bash implementation with a.Args.
func delegate(a *app.App) error {
	impl := a.Paths.BashImpl
	if !isBashImpl(impl, a.Exe) {
		a.Out.Error("command not available in this build")
		a.Out.Error("No bash implementation of tacctl at " + impl + " (TACCTL_BASH_IMPL names one).")
		return &ExitError{Code: 1}
	}
	argv := append([]string{impl}, a.Args...)
	if err := a.Runner.Exec(impl, argv, a.Env.Environ()); err != nil {
		a.Out.Error("Cannot run " + impl + ": " + err.Error())
		return &ExitError{Code: 126}
	}
	return nil
}

// isBashImpl reports whether impl is the entrypoint of a bash release tree:
// the file exists, its tree has lib/core.sh (a 0.2.0 tree's bin/tacctl.sh is
// the bootstrap shim, which would only come back here), and it is not this
// executable.
func isBashImpl(impl, self string) bool {
	st, err := os.Stat(impl)
	if err != nil || st.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(impl), "..", "lib", "core.sh")); err != nil {
		return false
	}
	if self != "" {
		if me, err := os.Stat(self); err == nil && os.SameFile(st, me) {
			return false
		}
	}
	return true
}
