package sftpd

import (
	"encoding/binary"
	"errors"
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
	wonly  bool // opened for upload and not for reading: no READ request may reach WriteAt
	append bool
	quota  *quota  // nil when there is no quota
	rate   *bucket // nil when there is no rate limit

	quotaNoted atomic.Bool
	readNoted  atomic.Bool

	read, written atomic.Int64

	// restore, with restoring, is the mode the file gets when the handle
	// closes: the open created it, for a mode without the owner's write bit,
	// owner-writable (see openNew). Set before the handle is handed out, and
	// not changed.
	restore   uint32
	restoring bool

	mu     sync.Mutex
	xferr  error // the error that ended the session with the handle open
	closed sync.Once
}

// freshModes is the files of the session that the open created owner-writable
// and that wait for their mode to be set when the handle closes. A setstat of
// the permissions of such a file takes it out: the client has said what it
// wants, and that is not undone at the close.
type freshModes struct {
	mu sync.Mutex
	m  map[inode]*file
}

func (b *freshModes) add(f *file) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[inode]*file{}
	}
	b.m[f.key] = f
}

// take reports whether f is still waiting, and stops it from waiting.
func (b *freshModes) take(f *file) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m[f.key] != f {
		return false
	}
	delete(b.m, f.key)
	return true
}

// forget drops the file on disk k: its permissions were set by the client.
func (b *freshModes) forget(k inode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, k)
}

// defaultFileMode is the mode of a new file when the client's open request
// does not carry one (the umask of the console still applies).
const defaultFileMode = 0o644

// permBits is the part of a mode a client may set: the permission bits. The
// set-user-ID, set-group-ID and sticky bits, and any file type bits, are
// dropped. Setstat and open take their mode through it (a mkdir takes none:
// see mkdir).
func permBits(m uint32) uint32 { return m & 0o777 }

// openMode is the mode the client asks for in the open request r, and whether
// it asked. The library hands the handlers the attribute block of an open as
// raw bytes and drops the attribute flags that say which fields it holds
// (Request.Flags of an open is the open flags, so AttrFlags and Attributes
// would read the wrong thing). A block of exactly four bytes is read as the
// permissions: it is what the OpenSSH sftp and scp clients send, without a
// size, owner or times. It is not always so: a version 3 block that holds only
// the flag of the extended attributes and a count of none is four bytes of
// zero too, and would read as the mode 0000. A value of zero is therefore
// read as asking for nothing (a client that really asks for 0000 gets the
// default, and can set the mode afterwards). Any other length could be the
// permissions together with a size, an owner or times, in an order that
// cannot be told apart, so it asks for nothing and the new file gets the
// default mode, as before.
func openMode(r *sftp.Request) (uint32, bool) {
	if len(r.Attrs) != 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.Attrs)
	if v == 0 {
		return 0, false
	}
	return permBits(v), true
}

// openFile opens the file of r. write says the open is for an upload (the
// handle can write); otherwise it is a download.
func (s *server) openFile(r *sftp.Request, write bool) (*file, error) {
	if err := s.handles.acquire(); err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			s.handles.release() // an open that failed (or panicked) holds no place
		}
	}()
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
	mode := uint32(defaultFileMode)
	readOnlyNew := false // a create for a mode without the owner's write bit
	if write {
		flags |= unix.O_WRONLY
		if pf.Read {
			flags = flags&^unix.O_WRONLY | unix.O_RDWR
		}
		if pf.Creat {
			flags |= unix.O_CREAT
			if m, ok := openMode(r); ok {
				mode = m // only a file the open creates gets it; an existing one keeps its mode
				readOnlyNew = m&0o200 == 0
			}
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
	var fd int
	created := false
	if readOnlyNew {
		fd, created, err = t.openNew(flags, mode|0o200)
	} else {
		fd, err = t.open(flags, mode)
	}
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
		// Judged on the open file, so that nothing between a look and the
		// open can change what it is. Nothing has been truncated yet.
		if st.Nlink > 1 {
			_ = unix.Close(fd)
			return nil, errLink()
		}
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
		if s.beforeTruncate != nil {
			s.beforeTruncate()
		}
		if err := s.truncate(fd, t); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}
	f := &file{
		s:      s,
		f:      os.NewFile(uintptr(fd), v.String()),
		key:    inode{u64(st.Dev), u64(st.Ino)},
		v:      v,
		write:  write,
		wonly:  write && !pf.Read,
		append: write && pf.Append,
		quota:  s.quota,
		rate:   s.rate,
	}
	if created {
		// st.Mode is what the kernel made of the mode and the umask, with the
		// owner's write bit that openNew added; the mode the client asked for
		// is that without it, exactly what open(2) would have made, whatever
		// the umask is. (A umask that clears the owner's write bit leaves the
		// file as the kernel made it, and nothing is restored.)
		if st.Mode&0o200 != 0 {
			f.restore, f.restoring = st.Mode&0o777&^0o200, true
			s.fresh.add(f)
		}
	}
	if f.quota != nil {
		f.quota.hold(f)
	}
	opened = true
	return f, nil
}

// openNew is the open of a file that may be created, for a client that asked
// for a mode without the owner's write bit (0444 for a read-only source file).
// The file is created with mode, which the caller gives the owner's write bit:
// the client's next steps on the handle are its own (an upload ends with a
// size step, a truncate by path, which the kernel refuses on a file its owner
// cannot write), and the mode it asked for is set when the handle closes (see
// Close). A client that never closes the handle cleanly leaves the file
// owner-writable; it is the owner's own file, and the session ending closes
// the handles it left open.
//
// An existing file is never touched: only a file this open creates is changed
// at the close, and the open that creates it is the one whose O_CREAT|O_EXCL
// succeeds. When the client did not ask for O_EXCL, the create is tried with it
// first, and an existing file is then opened without O_CREAT (it can be
// removed between the two calls: the create is tried again, a few times).
// Whether the file was created is the kernel's answer, not a look at the file
// afterwards.
func (t *target) openNew(flags int, mode uint32) (fd int, created bool, err error) {
	if flags&unix.O_EXCL != 0 {
		fd, err = t.open(flags, mode)
		return fd, err == nil, err
	}
	for range 3 {
		fd, err = t.open(flags|unix.O_EXCL, mode)
		if err == nil {
			return fd, true, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return -1, false, err
		}
		fd, err = t.open(flags&^unix.O_CREAT, 0)
		if err == nil {
			return fd, false, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, false, err
		}
	}
	return -1, false, err
}

// truncate empties the open file fd and takes the size it had off the usage.
// With a quota the size is read, the file cut and the usage lowered as one step
// under the quota's lock, like a write: a write on another handle of the same
// file has either finished before (its growth is in the size read here) or
// starts after (it sees the empty file), and the usage never lags the disk.
func (s *server) truncate(fd int, t *target) error {
	cut := func() (int64, error) {
		var cur unix.Stat_t
		if err := unix.Fstat(fd, &cur); err != nil {
			return 0, t.pathErr("stat", err)
		}
		if err := unix.Ftruncate(fd, 0); err != nil {
			return 0, t.pathErr("truncate", err)
		}
		return cur.Size, nil
	}
	if s.quota == nil {
		_, err := cut()
		return err
	}
	return s.quota.truncating(cut)
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.f.ReadAt(p, off)
	f.read.Add(int64(n))
	f.rate.take(int64(n))
	return n, err
}

// readSlack is the room the library leaves behind the data of a READ
// request (the header of the reply: its dataHeaderLen); the data of a WRITE
// request is cut from the packet that came in and has none unless the client
// sent bytes after it.
const readSlack = 4 + 1 + 4 + 4

// isReadRequest reports whether the buffer p that the library hands to WriteAt
// is the buffer of a READ request, not the data of a WRITE.
//
// For a handle opened only for writing the library has one entry for both
// kinds of request, and calls WriteAt with a buffer of zeros for a READ: the
// request would write zeros at the offset it asks for. WriteAt is given no
// other sign of the request, so the buffer is told by its capacity (the
// library allocates a READ's buffer with room for the reply header). A client
// cannot make a READ look like a WRITE; a WRITE followed by exactly readSlack
// bytes of padding looks like a READ and is refused, which hurts only the
// client that sent it. TestReadOnWriteOnlyHandleWritesNothing pins this to the
// vendored library: a change of its allocation fails that test.
func isReadRequest(p []byte) bool { return cap(p)-len(p) == readSlack }

func (f *file) WriteAt(p []byte, off int64) (int, error) {
	if f.wonly && isReadRequest(p) {
		err := errUnsupported("read of a handle opened only for writing")
		if f.readNoted.CompareAndSwap(false, true) {
			f.s.noteRefusal(err, f.v.String(), "") // once per handle
		}
		return 0, err
	}
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
		var merr error
		if f.restoring && f.s.fresh.take(f) {
			// The mode the client asked for, on the descriptor (the name may
			// have gone elsewhere), before it is closed.
			merr = f.f.Chmod(os.FileMode(f.restore))
		}
		cerr = f.f.Close()
		if cerr == nil {
			cerr = merr
		}
		f.s.handles.release()
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
