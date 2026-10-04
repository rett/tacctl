// Package lifecycle holds what tacctl install and upgrade do to tacctl's
// own state and to the TACACS+ configuration (lib/lifecycle.sh and the
// legacy-mode half of lib/backends/tacacs.sh at the 0.1.16 tag):
//
//   - StateMigrate (state.go): tacctl-owned state moves from the daemon's
//     directory into the state directory, with compatibility symlinks;
//   - InstallSeed (seed.go): the configuration of a fresh install, or the
//     existing one kept;
//   - the in-place migrations of a legacy tacquito.yaml, BackupConfig,
//     RenderApply and ConfigSyncExisting (legacy.go);
//   - UpgradeStoreFlip, the gate that moves a legacy install into the
//     store, and StoreUnflip, its way back (flip.go).
//
// The orchestration of install, upgrade and uninstall and the backends'
// phases call these; they are not commands. Messages are the 0.1.16 ones,
// byte for byte: info and warn lines on Stdout, errors on Stderr.
//
// This package must not import internal/backend/tacacs: the TACACS+ module
// calls into it (its 'upgrade config' and 'upgrade finish' phases), and
// reaches it through the backend contract and the Smoker interface.
package lifecycle

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// StateItems are STATE_MIGRATE_ITEMS: what moves from TACCTL_ETC to
// TACCTL_STATE_DIR, in this order (backups first, so backups/legacy exists
// in the new location before anything is displaced).
var StateItems = []string{"backups", "templates", "tacctl.yaml", "linux-hosts", "linux-uids"}

// StateOptions are the inputs of StateMigrate.
type StateOptions struct {
	Etc      string // TACCTL_ETC: the old location (the daemon's directory)
	StateDir string // TACCTL_STATE_DIR: the new one
	Out      ui.Output
	// Now names displaced copies (nil: time.Now).
	Now func() time.Time
	// IsRoot: the state directory is given to root:root (bash: EUID 0).
	IsRoot bool
}

// StateOptionsFrom are the StateOptions of resolved paths.
func StateOptionsFrom(p paths.Paths, out ui.Output, now func() time.Time, isRoot bool) StateOptions {
	return StateOptions{Etc: p.Etc, StateDir: p.StateDir, Out: out, Now: now, IsRoot: isRoot}
}

func (o StateOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// StateMigrate is state_migrate: bring tacctl-owned state (StateItems)
// from the daemon's directory into the state directory, leaving a symlink
// at each old path so the previous release still finds its files after a
// rollback. It is idempotent and runs on every install and upgrade: a
// regular file at an old path (older code replaces files by rename) that is
// newer than the one at the new path wins, the displaced copy is kept under
// backups/legacy/, and the symlink is restored. Symlinks are never followed
// when deciding what to move, and nothing moves into itself.
//
// A state directory that is the daemon's directory (also through a
// symlink) is left alone. Otherwise it is created 0700 (root:root when
// IsRoot). Every item is tried; a failed one is reported ('State migration
// failed for <item>') and the result is ui.ErrReported, everything printed.
//
// Call it before anything reads tacctl.yaml (or Reload the Config after):
// it may move the file the Config reads.
func StateMigrate(o StateOptions) error {
	if r := readlinkF(o.StateDir); r != "" && r == readlinkF(o.Etc) {
		return nil
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		stderrLine(o.Out, "mkdir: "+err.Error())
		return ui.ErrReported
	}
	if st, err := os.Stat(o.StateDir); err != nil || st.Mode().Perm() != 0o700 {
		if err := os.Chmod(o.StateDir, 0o700); err != nil {
			stderrLine(o.Out, "chmod: "+err.Error())
			return ui.ErrReported
		}
	}
	if o.IsRoot {
		if err := os.Chown(o.StateDir, 0, 0); err != nil {
			stderrLine(o.Out, "chown: "+err.Error())
			return ui.ErrReported
		}
	}
	var failed error
	for _, item := range StateItems {
		if err := o.migrateItem(item); err != nil {
			stderrLine(o.Out, err.Error())
			o.Out.ErrorE("State migration failed for " + item)
			failed = ui.ErrReported
		}
	}
	return failed
}

// legacyPath is _state_legacy_path: an unused name for a displaced item
// under backups/legacy (created on demand):
// <label>.<YYYYmmdd-HHMMSS>[.<n>].
func (o StateOptions) legacyPath(label string) (string, error) {
	dir := filepath.Join(o.StateDir, "backups", "legacy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	ts := o.now().Format("20060102-150405")
	dest := filepath.Join(dir, label+"."+ts)
	for n := 1; lexists(dest); n++ {
		dest = filepath.Join(dir, label+"."+ts+"."+strconv.Itoa(n))
	}
	return dest, nil
}

// errNotEmpty is _state_merge_dir's failure to empty its source.
var errNotEmpty = errors.New("not fully merged")

// mergeDir is _state_merge_dir: merge the entries of the real directory
// src into the real directory dst. Missing entries move over; directories
// present in both recurse; for a file present in both the newer one stays
// and the other goes to backups/legacy. Anything else (symlinks, mixed
// types) is left in place with a warning. It succeeds only when src ends up
// empty (and is removed).
func (o StateOptions) mergeDir(src, dst, rel string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		entry, target := filepath.Join(src, name), filepath.Join(dst, name)
		es, err := os.Lstat(entry)
		if err != nil {
			return err
		}
		ts, terr := os.Lstat(target)
		switch {
		case terr != nil:
			if err := move(entry, target); err != nil {
				return err
			}
		case es.Mode()&fs.ModeSymlink != 0 || ts.Mode()&fs.ModeSymlink != 0:
			o.Out.WarnE("State migration: not merging symlink " + entry)
		case es.IsDir() && ts.IsDir():
			_ = o.mergeDir(entry, target, rel+"_"+name)
		case es.Mode().IsRegular() && ts.Mode().IsRegular():
			legacy, err := o.legacyPath(rel + "_" + name)
			if err != nil {
				return err
			}
			if es.ModTime().After(ts.ModTime()) {
				if err := copyPreserve(target, legacy); err != nil {
					return err
				}
				if err := move(entry, target); err != nil {
					return err
				}
			} else if err := move(entry, legacy); err != nil {
				return err
			}
		default:
			o.Out.WarnE("State migration: type mismatch, left in place: " + entry)
		}
	}
	if err := syscall.Rmdir(src); err != nil {
		return errNotEmpty
	}
	return nil
}

// migrateItem is _state_migrate_item: bring one item up to date
// (old = <Etc>/<name>, new = <StateDir>/<name>). A non-nil error is a
// failure of a file operation (the item failed).
func (o StateOptions) migrateItem(name string) error {
	old, nw := filepath.Join(o.Etc, name), filepath.Join(o.StateDir, name)
	oldReal, newReal := readlinkF(old), readlinkF(nw)

	// Never move something into itself.
	if strings.HasPrefix(newReal+"/", oldReal+"/") || strings.HasPrefix(oldReal+"/", newReal+"/") {
		return nil
	}

	ost, oerr := os.Lstat(old)
	if oerr == nil && ost.Mode()&fs.ModeSymlink != 0 {
		// A link to the new path is the settled state (caught above). Any
		// other link is the operator's; leave it.
		o.Out.WarnE("State migration: " + old + " is a symlink elsewhere; left alone")
		return nil
	}

	if !exists(old) {
		// Interrupted run, or state created fresh in the new location:
		// restore the compatibility link, but only on hosts that have an
		// old directory.
		if lexists(nw) && isDir(o.Etc) {
			return os.Symlink(nw, old)
		}
		return nil
	}

	if !lexists(nw) {
		if err := move(old, nw); err != nil {
			return err
		}
		if err := os.Symlink(nw, old); err != nil {
			return err
		}
		o.Out.InfoE("State migrated: " + old + " -> " + nw)
		return nil
	}

	// Both exist (old is a real file or directory, never a symlink here).
	nst, _ := os.Lstat(nw)
	switch {
	case nst != nil && nst.Mode()&fs.ModeSymlink != 0:
		o.Out.WarnE("State migration: " + nw + " is a symlink; " + old + " left alone")
		return nil
	case isDir(old) && isDir(nw):
		if err := o.mergeDir(old, nw, name); err != nil {
			o.Out.WarnE("State migration: " + old + " not fully merged into " + nw + "; left in place")
			return nil
		}
	case isRegular(old) && isRegular(nw):
		if sameBytes(old, nw) {
			if err := os.Remove(old); err != nil {
				return err
			}
		} else {
			legacy, err := o.legacyPath(name)
			if err != nil {
				return err
			}
			if newer(old, nw) {
				// Rolled-back code wrote the old path: its content is newer.
				if err := copyPreserve(nw, legacy); err != nil {
					return err
				}
				if err := move(old, nw); err != nil {
					return err
				}
			} else if err := move(old, legacy); err != nil {
				return err
			}
			o.Out.WarnE("State migration: " + name + " existed in both places; the displaced copy is " + legacy)
		}
	default:
		o.Out.WarnE("State migration: " + old + " and " + nw + " are different kinds of file; left alone")
		return nil
	}
	if err := os.Symlink(nw, old); err != nil {
		return err
	}
	o.Out.InfoE("State migrated: " + old + " -> " + nw)
	return nil
}

// --- file helpers (bash tests and coreutils) ---------------------------------

// readlinkF is 'readlink -f': every symlink resolved, the last component
// allowed not to exist; "" when a directory on the way does not exist.
func readlinkF(p string) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return ""
		}
		p = filepath.Join(wd, p)
	}
	p = filepath.Clean(p)
	for range 64 {
		if p == "/" {
			return p
		}
		dir, base := filepath.Split(p)
		rdir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return ""
		}
		full := filepath.Join(rdir, base)
		st, err := os.Lstat(full)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return full
			}
			return ""
		}
		if st.Mode()&fs.ModeSymlink == 0 {
			return full
		}
		target, err := os.Readlink(full)
		if err != nil {
			return ""
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(rdir, target)
		}
		p = filepath.Clean(target)
	}
	return ""
}

// exists is bash's -e (symlinks followed).
func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// lexists is '-e p || -L p'.
func lexists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// isDir is bash's -d.
func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// isRegular is bash's -f.
func isRegular(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// newer is 'a -nt b': a's modification time is later, or a exists and b
// does not.
func newer(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)
	if err != nil {
		return true
	}
	return sa.ModTime().After(sb.ModTime())
}

// sameBytes is 'cmp -s a b'.
func sameBytes(a, b string) bool {
	da, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	db, err := os.ReadFile(b)
	return err == nil && string(da) == string(db)
}

// move is mv: a rename, or across file systems a copy that keeps modes,
// times and (as root) owners, then the removal of the source.
func move(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyTree(src, dst); err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	return os.RemoveAll(src)
}

// copyTree is 'cp -a src dst'.
func copyTree(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case st.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)
	case st.IsDir():
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, n := range names {
			if err := copyTree(filepath.Join(src, n), filepath.Join(dst, n)); err != nil {
				return err
			}
		}
		return keepAttrs(st, dst)
	}
	return copyPreserve(src, dst)
}

// copyPreserve is 'cp -p src dst' for a regular file: content, mode,
// times and (as root) owner.
func copyPreserve(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return keepAttrs(st, dst)
}

// keepAttrs gives dst the mode, times and (best effort) owner of st.
func keepAttrs(st fs.FileInfo, dst string) error {
	if err := os.Chmod(dst, st.Mode().Perm()); err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(dst, int(sys.Uid), int(sys.Gid))
		atime := time.Unix(sys.Atim.Sec, sys.Atim.Nsec)
		return os.Chtimes(dst, atime, st.ModTime())
	}
	return os.Chtimes(dst, st.ModTime(), st.ModTime())
}

// stderrLine is 'echo "<s>" >&2' (a failing program's own message).
func stderrLine(out ui.Output, s string) {
	if out.Stderr != nil {
		_, _ = io.WriteString(out.Stderr, s+"\n")
	}
}

// repairVarLib brings an existing VarLib (/var/lib/tacctl) to
// paths.VarLibMode: users' ssh reaches the generated known_hosts through
// it, and older builds created it 0700. A missing VarLib is left to the
// first write under it; a symlink is left alone.
func repairVarLib(o ui.Output, dir string) {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() == paths.VarLibMode {
		return
	}
	if err := paths.MkVarLib(dir); err != nil {
		o.Warn("Could not set the mode of " + dir + " to 0711: " + err.Error())
	}
}
