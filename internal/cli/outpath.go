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
// resolved. It is never $HOME. A test build's TACCTL_TEST_HOME replaces the
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
func (inv *invocation) outPath(flag, p string) (string, error) {
	refuse := func(why string) (string, error) {
		return "", errors.New(flag + " " + why + ": " + outPathHint + ".")
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
		return refuse("'" + p + "' cannot be resolved (" + err.Error() + ")")
	}
	outside := func() (string, error) {
		return refuse("'" + p + "' is not inside your home (" + home + "), the only place tacctl writes")
	}
	// the path itself, a symbolic link in it followed (it must lead inside)
	full, err := resolveExisting(abs)
	if err != nil {
		return refuse("'" + p + "' cannot be resolved (" + cfgErrno(err) + ")")
	}
	if !strictlyInside(home, full) {
		return outside()
	}
	// what is written: its directory resolved, the name as given
	dir, err := resolveExisting(filepath.Dir(abs))
	if err != nil {
		return refuse("'" + p + "' cannot be resolved (" + cfgErrno(err) + ")")
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
