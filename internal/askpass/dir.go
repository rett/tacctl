package askpass

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// runUserRoot is the parent of the per-user runtime directories (a test
// points it elsewhere).
var runUserRoot = "/run/user"

// SocketDir is the directory the agent of user uid puts its socket in, in
// this order:
//
//  1. $XDG_RUNTIME_DIR/tacctl, when XDG_RUNTIME_DIR is an absolute path of
//     a directory owned by the user (a login session's runtime directory,
//     tmpfs, removed at logout);
//  2. /run/user/<uid>/tacctl, when that runtime directory exists and is
//     the user's (the console scrubs the environment and a login without
//     pam_systemd sets no XDG_RUNTIME_DIR, but the directory may be there);
//  3. $HOME/.local/state/tacctl/run, for a user without a runtime
//     directory (next to the shell history).
//
// The directory itself is created 0700 by Agent.Listen. Without any of the
// three the error is ErrNoDir and the shell runs without a cache.
func SocketDir(getenv func(string) string, uid int) (string, error) {
	if x := getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) && ownedDir(x, uid) {
		return filepath.Join(x, "tacctl"), nil
	}
	if r := filepath.Join(runUserRoot, strconv.Itoa(uid)); ownedDir(r, uid) {
		return filepath.Join(r, "tacctl"), nil
	}
	if h := getenv("HOME"); filepath.IsAbs(h) && ownedDir(h, uid) {
		return filepath.Join(h, ".local", "state", "tacctl", "run"), nil
	}
	return "", ErrNoDir
}

// ownedDir reports whether p is a directory (not a link) of uid.
func ownedDir(p string, uid int) bool {
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}

// resolveExisting is p with its symbolic links resolved as far as p exists;
// the part that does not exist is appended unresolved.
func resolveExisting(p string) (string, error) {
	rest := ""
	for cur := p; ; cur = filepath.Dir(cur) {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		} else if !errors.Is(err, os.ErrNotExist) || cur == filepath.Dir(cur) {
			return "", err
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

// checkParent refuses a parent directory in which another user could
// replace the socket directory: it must be a directory of root or of the
// current user, and one that group or others can write to must have the
// sticky bit.
func checkParent(parent string) error {
	fi, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoDir, unwrapOp(err))
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok {
		return fmt.Errorf("%w: %s is not a directory", ErrNoDir, parent)
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%w: %s belongs to another user", ErrNoDir, parent)
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%w: %s is writable by others", ErrNoDir, parent)
	}
	return nil
}

// openPrivateDir makes dir a directory of the current user, mode 0700,
// creating it (and missing parents, 0700) when it does not exist, and
// returns an open descriptor of it and its path with the links of the
// parents resolved. dir itself must not be a link: it is opened with
// O_NOFOLLOW and what is checked and changed (owner, mode) is the open
// directory, not a path that could be swapped.
func openPrivateDir(dir string) (fd int, real string, err error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return -1, "", fmt.Errorf("%w: %q is not an absolute, clean path", ErrNoDir, dir)
	}
	parent, err := resolveExisting(filepath.Dir(dir))
	if err != nil {
		return -1, "", fmt.Errorf("%w: %v", ErrNoDir, unwrapOp(err))
	}
	// A parent that exists is checked before anything is created in it;
	// the ones created here are the user's, 0700.
	if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return -1, "", fmt.Errorf("%w: %v", ErrNoDir, unwrapOp(err))
		}
	} else if err != nil {
		return -1, "", fmt.Errorf("%w: %v", ErrNoDir, unwrapOp(err))
	}
	if err := checkParent(parent); err != nil {
		return -1, "", err
	}
	real = filepath.Join(parent, filepath.Base(dir))
	if err := os.Mkdir(real, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return -1, "", fmt.Errorf("%w: %v", ErrNoDir, unwrapOp(err))
	}
	fd, err = unix.Open(real, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("%w: %s is not a directory of the current user", ErrNoDir, dir)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || int(st.Uid) != os.Geteuid() {
		_ = unix.Close(fd)
		return -1, "", fmt.Errorf("%w: %s is not a directory of the current user", ErrNoDir, dir)
	}
	if st.Mode&0o777 != 0o700 {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			_ = unix.Close(fd)
			return -1, "", fmt.Errorf("%w: %v", ErrNoDir, err)
		}
	}
	return fd, real, nil
}

// hostTag is this host's name as it appears in socket names: lower case,
// [a-z0-9.], anything else '_', at most 24 characters. A home directory
// may be shared between hosts (NFS); a socket of another host cannot be
// probed, so cleanup touches only the sockets of this one.
func hostTag() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "host"
	}
	b := []byte(strings.ToLower(h))
	for i, c := range b {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' {
			b[i] = '_'
		}
	}
	if len(b) > 24 {
		b = b[:24]
	}
	return string(b)
}

// removeStale removes the sockets of shells of this host that no longer
// run: files ap-<host>-<pid>-<random>.sock of the current user, sockets,
// that refuse a connection. (The pid is no proof of life: pids are not
// shared across namespaces.)
func removeStale(dir, host string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		name := e.Name()
		rest, ok := strings.CutPrefix(name, "ap-")
		if !ok {
			continue
		}
		rest, ok = strings.CutSuffix(rest, ".sock")
		if !ok {
			continue
		}
		f := strings.Split(rest, "-")
		if len(f) != 3 || f[0] != host {
			continue
		}
		p := filepath.Join(dir, name)
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSocket == 0 {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
			continue
		}
		c, err := net.DialTimeout("unix", p, 250*time.Millisecond)
		if err == nil {
			_ = c.Close()
			continue
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			_ = os.Remove(p)
		}
	}
}
