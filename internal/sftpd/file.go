package sftpd

import (
	"os"
	"sync"
	"sync/atomic"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

// file is an open regular file of a client: the handle behind a download,
// an upload or a read-write open. The library calls ReadAt and WriteAt from
// several goroutines and Close once the client closes the handle (or the
// session ends).
type file struct {
	s      *server
	f      *os.File
	key    inode // the file on the disk, for the quota's book of open files
	v      vpath
	write  bool // opened for upload
	append bool
	quota  *quota  // nil when there is no quota
	rate   *bucket // nil when there is no rate limit

	quotaNoted atomic.Bool

	read, written atomic.Int64

	mu     sync.Mutex
	xferr  error // the error that ended the session with the handle open
	closed sync.Once
}

// openFile opens the file of r. write says the open is for an upload (the
// handle can write); otherwise it is a download.
func (s *server) openFile(r *sftp.Request, write bool) (*file, error) {
	v, err := s.path(r.Filepath)
	if err != nil {
		return nil, err
	}
	t, err := s.home.resolve(v)
	if err != nil {
		return nil, err
	}
	defer t.close()
	pf := r.Pflags()

	// O_NONBLOCK so that opening a FIFO neither blocks the session nor
	// waits for a peer; the type is checked before anything is read or
	// written, and the flag is cleared for a regular file. The file is
	// not truncated by the open: the size it had is needed, and a FIFO or
	// device must not be touched.
	if write && s.quota != nil {
		s.quota.refresh()
	}
	flags := unix.O_NONBLOCK
	mode := uint32(0o644) // the attributes of an open are not parsed: the client sets the mode with setstat
	if write {
		flags |= unix.O_WRONLY
		if pf.Read {
			flags = flags&^unix.O_WRONLY | unix.O_RDWR
		}
		if pf.Creat {
			flags |= unix.O_CREAT
		}
		if pf.Excl {
			flags |= unix.O_EXCL
		}
		if pf.Append {
			flags |= unix.O_APPEND
		}
	} else {
		flags |= unix.O_RDONLY
	}
	fd, err := t.open(flags, mode)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, t.pathErr("stat", err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFDIR:
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: v.String(), Err: unix.EISDIR}
	default:
		_ = unix.Close(fd)
		return nil, &statusError{reason: reasonUnsupported, code: sftp.ErrSSHFxOpUnsupported, msg: "not a regular file"}
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, t.pathErr("open", err)
	}
	if write && pf.Trunc {
		if err := unix.Ftruncate(fd, 0); err != nil {
			_ = unix.Close(fd)
			return nil, t.pathErr("truncate", err)
		}
		s.quotaRelease(st.Size)
	}
	f := &file{
		s:      s,
		f:      os.NewFile(uintptr(fd), v.String()),
		key:    inode{u64(st.Dev), u64(st.Ino)},
		v:      v,
		write:  write,
		append: write && pf.Append,
		quota:  s.quota,
		rate:   s.rate,
	}
	if f.quota != nil {
		f.quota.hold(f)
	}
	return f, nil
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.f.ReadAt(p, off)
	f.read.Add(int64(n))
	f.rate.take(int64(n))
	return n, err
}

func (f *file) WriteAt(p []byte, off int64) (int, error) {
	w := func() (int, error) {
		if f.append {
			// The file is open with O_APPEND, which the kernel honours for
			// every write and Go's WriteAt refuses; the offset is ignored,
			// as it is for the OpenSSH server.
			return f.f.Write(p)
		}
		return f.f.WriteAt(p, off)
	}
	var n int
	var err error
	if f.quota != nil {
		n, err = f.quota.write(f.f, len(p), off, f.append, w)
		if reasonOf(err) == reasonQuota && f.quotaNoted.CompareAndSwap(false, true) {
			f.s.noteRefusal(err, f.v.String(), "") // once per handle, not once per packet
		}
	} else {
		n, err = w()
	}
	f.written.Add(int64(n))
	f.rate.take(int64(n)) // what was written, after it: a refused write costs nothing
	return n, err
}

// TransferError is called by the library when the session ends with the
// handle still open.
func (f *file) TransferError(err error) {
	f.mu.Lock()
	f.xferr = err
	f.mu.Unlock()
}

// Close closes the file and audits the transfer: an upload for a handle
// opened to write (with the bytes written), a download for one that was
// read from (with the bytes read). It is safe to call twice.
func (f *file) Close() error {
	var cerr error
	f.closed.Do(func() {
		if f.quota != nil {
			f.quota.unhold(f) // while the descriptor is still open
		}
		cerr = f.f.Close()
		f.mu.Lock()
		err := f.xferr
		f.mu.Unlock()
		if cerr != nil {
			err = cerr
		}
		if f.write {
			f.s.audit(Event{Op: "upload", Path: f.v.String(), Bytes: f.written.Load(), Err: err})
		}
		if !f.write || f.read.Load() > 0 {
			f.s.audit(Event{Op: "download", Path: f.v.String(), Bytes: f.read.Load(), Err: err})
		}
	})
	return cerr
}
