package sftpd

import (
	"errors"
	"io"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

// server holds one session's state and implements the library's handler
// interfaces. The library calls the handlers from several goroutines at
// once: the fields below are read-only after Serve builds them, and what a
// handler changes is held by the file it works on or guarded by its own
// lock.
type server struct {
	home *home
	cfg  Config
}

var (
	_ sftp.FileReader           = (*server)(nil)
	_ sftp.OpenFileWriter       = (*server)(nil)
	_ sftp.PosixRenameFileCmder = (*server)(nil)
	_ sftp.LstatFileLister      = (*server)(nil)
	_ sftp.RealPathFileLister   = (*server)(nil)
	_ sftp.ReadlinkFileLister   = (*server)(nil)
)

func (s *server) audit(e Event) {
	if s.cfg.Audit != nil {
		s.cfg.Audit(e)
	}
}

// display is a client path for an event: cleaned when it can be, else cut.
func display(p string) string {
	if v, err := parsePath(p); err == nil {
		return v.String()
	}
	if len(p) > maxName {
		p = p[:maxName] + "..."
	}
	return p
}

// noteRefusal audits err when it is a refusal.
func (s *server) noteRefusal(err error, path, to string) {
	reason := reasonOf(err)
	if reason == "" {
		return
	}
	e := Event{Op: "refused", Path: display(path), Err: errors.New(reason)}
	if to != "" {
		e.To = display(to)
	}
	s.audit(e)
}

// guard is deferred by every handler: a panic (the input is hostile)
// becomes a failure status, and a refusal is audited.
func (s *server) guard(err *error, r *sftp.Request) {
	if p := recover(); p != nil {
		*err = &statusError{code: sftp.ErrSSHFxFailure, msg: "internal error"}
	}
	s.noteRefusal(*err, r.Filepath, r.Target)
}

// path is a client path for an operation: cleaned, and refused when it is
// .ssh or under it.
func (s *server) path(p string) (vpath, error) {
	v, err := parsePath(p)
	if err != nil {
		return nil, err
	}
	if v.inSSH() {
		return nil, errSSH()
	}
	return v, nil
}

// changePath is path for an operation that changes the entry: the home
// itself is not one that can be removed, renamed or created.
func (s *server) changePath(p string) (vpath, error) {
	v, err := s.path(p)
	if err != nil {
		return nil, err
	}
	if v.isRoot() {
		return nil, errOutside()
	}
	return v, nil
}

// RealPath answers realpath without touching the file system: the cleaned
// virtual path ("." is "/"). Links are not resolved, as none is followed.
func (s *server) RealPath(p string) (string, error) {
	v, err := parsePath(p)
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

// Readlink is refused: a link is never followed, and its target is not
// shown.
func (s *server) Readlink(string) (string, error) {
	return "", errSymlink()
}

// listerAt serves a snapshot of entries to the library.
type listerAt []os.FileInfo

func (l listerAt) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[off:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

// Filelist serves list, stat and readlink.
func (s *server) Filelist(r *sftp.Request) (la sftp.ListerAt, err error) {
	defer s.guard(&err, r)
	switch r.Method {
	case "List":
		return s.list(r)
	case "Stat":
		return s.stat(r, true)
	default:
		return nil, errUnsupported(r.Method)
	}
}

// Lstat is stat without following a link.
func (s *server) Lstat(r *sftp.Request) (la sftp.ListerAt, err error) {
	defer s.guard(&err, r)
	return s.stat(r, false)
}

func (s *server) list(r *sftp.Request) (sftp.ListerAt, error) {
	v, err := s.path(r.Filepath)
	if err != nil {
		return nil, err
	}
	t, err := s.home.resolve(v)
	if err != nil {
		return nil, err
	}
	defer t.close()
	infos, err := s.home.readDir(t)
	if err != nil {
		return nil, err
	}
	return listerAt(infos), nil
}

// stat answers stat (follow) and lstat. A link is lstat'ed as a link; stat
// of a link would follow it, so it is refused.
func (s *server) stat(r *sftp.Request, follow bool) (sftp.ListerAt, error) {
	v, err := s.path(r.Filepath)
	if err != nil {
		return nil, err
	}
	t, err := s.home.resolve(v)
	if err != nil {
		return nil, err
	}
	defer t.close()
	st, err := t.lstat()
	if err != nil {
		return nil, err
	}
	if follow && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, errSymlink()
	}
	name := "/"
	if !v.isRoot() {
		name = v.name()
	}
	return listerAt{&fileInfo{name: name, st: st}}, nil
}

// Filecmd serves the requests that change something.
func (s *server) Filecmd(r *sftp.Request) (err error) {
	defer s.guard(&err, r)
	switch r.Method {
	case "Setstat":
		return s.setstat(r)
	case "Rename":
		return s.rename(r, false)
	case "Rmdir":
		return s.remove(r, true)
	case "Remove":
		return s.remove(r, false)
	case "Mkdir":
		return s.mkdir(r)
	case "Symlink":
		return errSymlink()
	case "Link":
		return errUnsupported("hard link")
	default:
		return errUnsupported(r.Method)
	}
}

// PosixRename is rename that replaces an existing target.
func (s *server) PosixRename(r *sftp.Request) (err error) {
	defer s.guard(&err, r)
	return s.rename(r, true)
}

func (s *server) mkdir(r *sftp.Request) (err error) {
	v, err := s.changePath(r.Filepath)
	if err != nil {
		return err
	}
	defer func() { s.audit(Event{Op: "mkdir", Path: v.String(), Err: err}) }()
	t, err := s.home.resolve(v)
	if err != nil {
		return err
	}
	defer t.close()
	mode := uint32(0o755)
	if r.AttrFlags().Permissions {
		if a := r.Attributes(); a != nil {
			mode = a.Mode & 0o777
		}
	}
	return t.pathErr("mkdir", unix.Mkdirat(t.dir, t.name, mode))
}

// remove deletes a file or link (the entry itself, never what a link points
// at) or, with dir, an empty directory.
func (s *server) remove(r *sftp.Request, dir bool) (err error) {
	v, err := s.changePath(r.Filepath)
	if err != nil {
		return err
	}
	defer func() { s.audit(Event{Op: "delete", Path: v.String(), Err: err}) }()
	t, err := s.home.resolve(v)
	if err != nil {
		return err
	}
	defer t.close()
	flags := 0
	op := "remove"
	if dir {
		flags = unix.AT_REMOVEDIR
		op = "rmdir"
	}
	return t.pathErr(op, unix.Unlinkat(t.dir, t.name, flags))
}

// rename moves an entry; a link is moved as the link it is. Plain rename
// fails when the target exists (as OpenSSH's server does), posix-rename
// replaces it.
func (s *server) rename(r *sftp.Request, replace bool) (err error) {
	src, err := s.changePath(r.Filepath)
	if err != nil {
		return err
	}
	dst, err := s.changePath(r.Target)
	if err != nil {
		return err
	}
	defer func() { s.audit(Event{Op: "rename", Path: src.String(), To: dst.String(), Err: err}) }()
	ts, err := s.home.resolve(src)
	if err != nil {
		return err
	}
	defer ts.close()
	td, err := s.home.resolve(dst)
	if err != nil {
		return err
	}
	defer td.close()
	return ts.pathErr("rename", renameat(ts, td, replace))
}

func renameat(ts, td *target, replace bool) error {
	if replace {
		return unix.Renameat2(ts.dir, ts.name, td.dir, td.name, 0)
	}
	err := unix.Renameat2(ts.dir, ts.name, td.dir, td.name, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		// A file system without RENAME_NOREPLACE: look, then rename.
		var st unix.Stat_t
		if unix.Fstatat(td.dir, td.name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
			return unix.EEXIST
		}
		return unix.Renameat2(ts.dir, ts.name, td.dir, td.name, 0)
	}
	return err
}

// setstat changes the permission bits and the times, nothing else.
func (s *server) setstat(r *sftp.Request) (err error) {
	v, err := s.changePath(r.Filepath)
	if err != nil {
		return err
	}
	fl := r.AttrFlags()
	if fl.Size {
		return errUnsupported("changing the size")
	}
	if fl.UidGid {
		return errUnsupported("changing the owner")
	}
	a := r.Attributes()
	if a == nil {
		return errBadPath("malformed attributes")
	}
	defer func() { s.audit(Event{Op: "setstat", Path: v.String(), Err: err}) }()
	t, err := s.home.resolve(v)
	if err != nil {
		return err
	}
	defer t.close()
	st, err := t.lstat()
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return errSymlink()
	}
	if fl.Permissions {
		if err := t.chmod(a.Mode & 0o777); err != nil {
			return err
		}
	}
	if fl.Acmodtime {
		if err := t.utimes(a.Atime, a.Mtime); err != nil {
			return err
		}
	}
	return nil
}

// Fileread opens a file for download.
func (s *server) Fileread(r *sftp.Request) (ra io.ReaderAt, err error) {
	defer s.guard(&err, r)
	f, err := s.openFile(r, false)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Filewrite opens a file for upload.
func (s *server) Filewrite(r *sftp.Request) (wa io.WriterAt, err error) {
	defer s.guard(&err, r)
	f, err := s.openFile(r, true)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// OpenFile opens a file for reading and writing on one handle.
func (s *server) OpenFile(r *sftp.Request) (rw sftp.WriterAtReaderAt, err error) {
	defer s.guard(&err, r)
	f, err := s.openFile(r, true)
	if err != nil {
		return nil, err
	}
	return f, nil
}
