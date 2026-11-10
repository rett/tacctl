package cli

// The rule for a path the caller names to write (--out, --output): tacctl
// writes only inside the caller's home, and never expands '~' or variables.
// A shell does that before tacctl sees the argument; a path that reaches
// tacctl still starting with '~' (a quoted argument, a script that did not
// expand it) would otherwise name a directory called '~' in the current
// directory. The checks are one place so that every command that writes a
// named path applies the same rule.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// outPathHint ends every refusal: what to do instead.
const outPathHint = "tacctl does not expand ~ or variables; name a path inside your home, relative to the current directory"

// callerHome is the home directory of the person who ran sudo (SUDO_UID), else
// of this process's own user, from the account database, with symbolic links
// resolved; a home that is the root directory is refused. It is never $HOME. A test build's TACCTL_TEST_HOME replaces the
// look-up (app.Knobs.Home), a test of this package replaces it with
// hooks.homeOfUID.
func (inv *invocation) callerHome() (string, error) {
	home := inv.app.Knobs.Home()
	if home == "" {
		uid := inv.hooks.euid()
		if id, _, ok := inv.callerIDs(); ok && uid == 0 {
			uid = id
		}
		h, err := inv.hooks.homeOf(uid)
		if err != nil || h == "" || !filepath.IsAbs(h) {
			return "", errors.New("cannot find your home directory in the account database, so there is no place tacctl may write")
		}
		home = h
	}
	r, err := filepath.EvalSymlinks(filepath.Clean(home))
	if err != nil {
		return "", errors.New("your home directory " + home + " cannot be used: " + cfgErrno(err))
	}
	if r == "/" {
		// every absolute path is inside it, so nothing would be refused
		return "", errors.New("your home directory " + home + " cannot be used: it is the root of the file system, which holds every path")
	}
	return r, nil
}

// outPath checks a path the caller named for flag and returns the absolute
// path to write: relative ones are taken from the current directory, '..' is
// resolved, and the directory part has its symbolic links resolved (the last
// component is left as named, so a write that replaces or refuses an existing
// name keeps doing what it did). The error is one sentence that says what to
// do. An empty path, a NUL, a first component that starts with '~', a '$' or
// a backtick, and a path that, with the symbolic links of its longest existing
// part resolved, is not strictly inside the caller's home are refused.
//
// The refusals about the spelling of the path end with outPathHint; one that
// is about what the file system says ("cannot be resolved") gives the cause
// and the path and no hint, since it is not a matter of '~' or variables.
//
// The file-system calls run as this process, which is root under sudo. A
// command that then writes as the caller (asCaller) uses outPathAsCaller
// instead, so that the check sees what the write will see: on an NFS home
// with root_squash that others cannot search, root cannot stat the path and
// the caller can. A command that writes as root keeps outPath: the check
// must fail where its write would.
func (inv *invocation) outPath(flag, p string) (string, error) {
	return inv.checkOutPath(flag, p, func(fn func() error) error { return fn() })
}

// outPathAsCaller is outPath with the file-system calls of the check run with
// the identity of the person who ran sudo (inv.callerRun), for a command that
// writes the file as that person.
func (inv *invocation) outPathAsCaller(flag, p string) (string, error) {
	return inv.checkOutPath(flag, p, inv.callerRun)
}

// callerRun runs fn as the person who ran sudo: asCaller, or the hook that
// replaces it in a test (the identity switch itself needs root).
func (inv *invocation) callerRun(fn func() error) error {
	if h := inv.hooks; h != nil && h.asCallerRun != nil {
		return h.asCallerRun(fn)
	}
	return inv.asCaller(fn)
}

// checkOutPath is the one place of the rules; run runs the calls that touch
// the file system (the symbolic links of the path and of its directory).
func (inv *invocation) checkOutPath(flag, p string, run func(func() error) error) (string, error) {
	refuse := func(why string) (string, error) {
		return "", errors.New(flag + " " + why + ": " + outPathHint + ".")
	}
	// what the file system says is told as it is, with the path
	unresolved := func(err error) (string, error) {
		return "", errors.New(flag + " '" + p + "' cannot be resolved (" + cfgErrno(err) + ").")
	}
	switch {
	case p == "":
		return refuse("takes a path, and none was given")
	case strings.ContainsRune(p, 0):
		return refuse("holds a NUL character")
	case strings.ContainsAny(p, "$`"):
		return refuse("'" + p + "' holds a '$' or a backtick, which tacctl does not expand")
	}
	if first, _, _ := strings.Cut(p, "/"); strings.HasPrefix(first, "~") {
		return refuse("'" + p + "' starts with '~', which tacctl does not expand")
	}
	home, err := inv.callerHome()
	if err != nil {
		return "", errors.New(flag + ": " + err.Error() + ".")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return unresolved(err)
	}
	outside := func() (string, error) {
		return refuse("'" + p + "' is not inside your home (" + home + "), the only place tacctl writes")
	}
	// the path itself, a symbolic link in it followed (it must lead inside),
	// and what is written: its directory resolved, the name as given
	var full, dir string
	if err := run(func() (err error) {
		if full, err = resolveExisting(abs); err != nil {
			return err
		}
		if !strictlyInside(home, full) {
			return nil // refused below, as outside
		}
		dir, err = resolveExisting(filepath.Dir(abs))
		return err
	}); err != nil {
		return unresolved(err)
	}
	if !strictlyInside(home, full) {
		return outside()
	}
	out := filepath.Join(dir, filepath.Base(abs))
	if !strictlyInside(home, out) {
		return outside()
	}
	return out, nil
}

// strictlyInside reports whether path is below dir (not dir itself); both are
// absolute and clean.
func strictlyInside(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveExisting resolves the symbolic links of the longest existing part of
// the absolute, clean path and appends the rest, which does not exist. A link
// that does not lead anywhere is an error.
func resolveExisting(path string) (string, error) {
	var rest []string
	cur := path
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		rest = append([]string{filepath.Base(cur)}, rest...)
		cur = parent
	}
	r, err := filepath.EvalSymlinks(cur)
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{r}, rest...)...), nil
}
