package sftpd

import (
	"errors"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// How the home is reached
//
// The home is held open as a directory descriptor, and every client path is
// resolved against it one component at a time with openat(2), each
// directory component opened with O_NOFOLLOW|O_DIRECTORY. The last
// component is then used with the *at calls of its parent descriptor
// (openat with O_NOFOLLOW, mkdirat, unlinkat, renameat2, fstatat with
// AT_SYMLINK_NOFOLLOW); a change of attributes pins the entry with an O_PATH
// descriptor and goes through /proc/self/fd (see pinned).
//
// This is os.Root's confinement without its symbolic-link following: an
// os.Root resolves links inside the root, so a link that points at .ssh
// would be followed, and a check made before the call (Lstat, then Open)
// could lose a race to a rename that puts a link where the directory was.
// Here no call resolves a name through a link at all: each kernel lookup is
// a single component, and a link in that position makes the call fail
// (ELOOP, or ENOTDIR with O_DIRECTORY), whatever happened between our last
// look and the call. A descriptor that is held cannot be redirected by a
// rename of its name. ".." never reaches the kernel (parsePath removes it
// lexically, and a component that is a link is never entered), so a path
// cannot climb out of the home, and neither can a link.

// dirFlags opens a directory component without following a link.
const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// home is the home directory, held open.
type home struct{ fd int }

// openHome opens the home. The home path itself may be reached through a
// link (it is the caller's configuration, not the client's).
func openHome(dir string) (*home, error) {
	if dir == "" {
		return nil, errors.New("sftpd: no home directory")
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return &home{fd: fd}, nil
}

func (h *home) close() { _ = unix.Close(h.fd) }

// target is a resolved client path: the open directory that holds the last
// component, and that component's name. For the home itself the directory
// is the home and the name ".".
type target struct {
	v    vpath
	dir  int
	name string
	own  bool // dir is ours to close
}

func (t *target) close() {
	if t.own {
		_ = unix.Close(t.dir)
	}
}

// resolve opens the directories above the last component of v, without
// following a link at any step, and returns the target.
func (h *home) resolve(v vpath) (*target, error) {
	if v.isRoot() {
		return &target{v: v, dir: h.fd, name: "."}, nil
	}
	fd := h.fd
	for _, c := range v.parent() {
		next, err := unix.Openat(fd, c, dirFlags, 0)
		if err != nil {
			err = classify(fd, c, err, "open", v)
			if fd != h.fd {
				_ = unix.Close(fd)
			}
			return nil, err
		}
		if fd != h.fd {
			_ = unix.Close(fd)
		}
		fd = next
	}
	return &target{v: v, dir: fd, name: v.name(), own: fd != h.fd}, nil
}

// classify turns the errno of a failed *at call on dir/name into the error
// for the client: a refusal when a symbolic link stopped it (the lookup
// said ELOOP or, with O_DIRECTORY, ENOTDIR, and the entry is a link), else
// a path error with the virtual path. The lstat here only names the cause
// of a failure that already happened; it decides nothing.
func classify(dir int, name string, err error, op string, v vpath) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		var st unix.Stat_t
		if unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return errSymlink()
		}
	}
	return &os.PathError{Op: op, Path: v.String(), Err: err}
}

// pathErr wraps an errno of a call on t.
func (t *target) pathErr(op string, err error) error {
	if err == nil {
		return nil
	}
	return classify(t.dir, t.name, err, op, t.v)
}

// lstat is fstatat without following a link.
func (t *target) lstat() (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(t.dir, t.name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, t.pathErr("stat", err)
}

// open opens the last component, never following a link.
func (t *target) open(flags int, mode uint32) (int, error) {
	fd, err := unix.Openat(t.dir, t.name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return -1, t.pathErr("open", err)
	}
	return fd, nil
}

// openDir opens the last component, which must be a directory.
func (t *target) openDir() (int, error) {
	fd, err := unix.Openat(t.dir, t.name, dirFlags, 0)
	if err != nil {
		return -1, t.pathErr("open", err)
	}
	return fd, nil
}

// fileInfo is a directory entry or a stat, as the library wants it.
type fileInfo struct {
	name string
	st   unix.Stat_t
}

func (f *fileInfo) Name() string       { return f.name }
func (f *fileInfo) Size() int64        { return f.st.Size }
func (f *fileInfo) Mode() os.FileMode  { return modeOf(f.st.Mode) }
func (f *fileInfo) IsDir() bool        { return f.st.Mode&unix.S_IFMT == unix.S_IFDIR }
func (f *fileInfo) ModTime() time.Time { return time.Unix(f.st.Mtim.Unix()) }

// Sys gives the library the owner for the long listing.
func (f *fileInfo) Sys() any { return &syscall.Stat_t{Uid: f.st.Uid, Gid: f.st.Gid} }

func modeOf(m uint32) os.FileMode {
	fm := os.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		fm |= os.ModeDir
	case unix.S_IFLNK:
		fm |= os.ModeSymlink
	case unix.S_IFIFO:
		fm |= os.ModeNamedPipe
	case unix.S_IFSOCK:
		fm |= os.ModeSocket
	case unix.S_IFBLK:
		fm |= os.ModeDevice
	case unix.S_IFCHR:
		fm |= os.ModeDevice | os.ModeCharDevice
	}
	if m&unix.S_ISUID != 0 {
		fm |= os.ModeSetuid
	}
	if m&unix.S_ISGID != 0 {
		fm |= os.ModeSetgid
	}
	if m&unix.S_ISVTX != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

// pinned is an entry held by an O_PATH descriptor: the inode that was found
// under the name at the time of the open, whatever the name is later made to
// mean. Its attributes are read from the descriptor (st) and changed through
// /proc/self/fd, which names that inode and nothing else.
type pinned struct {
	fd int
	t  *target
	st unix.Stat_t
}

// pin opens the last component without following a link (O_NOFOLLOW with
// O_PATH gives the link itself, which the caller refuses) and reads its
// attributes from the descriptor.
func (t *target) pin(op string) (*pinned, error) {
	fd, err := unix.Openat(t.dir, t.name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, t.pathErr(op, err)
	}
	p := &pinned{fd: fd, t: t}
	if err := unix.Fstat(fd, &p.st); err != nil {
		p.close()
		return nil, t.pathErr(op, err)
	}
	return p, nil
}

func (p *pinned) close() { _ = unix.Close(p.fd) }

// proc is the path that names the pinned inode.
func (p *pinned) proc() string { return "/proc/self/fd/" + strconv.Itoa(p.fd) }

// chmod sets the permission bits of the pinned inode.
func (p *pinned) chmod(mode uint32) error {
	return p.t.pathErr("chmod", unix.Chmod(p.proc(), mode))
}

// utimes sets the access and modification times (seconds) of the pinned
// inode.
func (p *pinned) utimes(atime, mtime uint32) error {
	ts := []unix.Timespec{{Sec: int64(atime)}, {Sec: int64(mtime)}}
	return p.t.pathErr("chtimes", unix.UtimesNano(p.proc(), ts))
}
