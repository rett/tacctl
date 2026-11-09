package sftpd

import (
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// maxHandles is how many handles a session may have open at once, files and
// directory listings together. Each holds a descriptor, and the client picks
// how many to open: without a bound it is a way to exhaust the descriptors of
// the process that serves it.
const maxHandles = 256

// handleCount counts the open handles of a session against a limit.
type handleCount struct {
	max int

	mu sync.Mutex
	n  int
}

// acquire takes a place, or says there is none.
func (c *handleCount) acquire() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n >= c.max {
		return errTooMany()
	}
	c.n++
	return nil
}

// release gives a place back.
func (c *handleCount) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n > 0 {
		c.n--
	}
}

// listBatch is how many names a directory listing reads at a time when the
// library asks for fewer (it asks for MaxFilelist, 100): the memory of a
// listing is a batch, whatever the size of the directory.
const listBatch = 100

// dirLister serves a directory listing to the library, one batch at a time.
// The directory is held open for as long as the handle is, and read as the
// client asks for entries. The library asks for entries at the offset of the
// ones it has been given, so a listing is a sequential read; a request for an
// earlier offset starts the directory again from its beginning, and one for a
// later offset skips ahead. Entries come in the order the file system gives
// them, not sorted (a client sorts a listing itself when it wants it so).
//
// It is an io.Closer: the library closes it with the handle.
type dirLister struct {
	s    *server
	v    vpath
	root bool // the home: .ssh is left out

	mu  sync.Mutex
	fd  int      // the directory; f owns it
	f   *os.File // nil once closed
	pos int64    // entries given out so far
}

// list opens the directory of v for a listing and takes a place for it.
func (s *server) list(v vpath) (*dirLister, error) {
	if err := s.handles.acquire(); err != nil {
		return nil, err
	}
	t, err := s.home.resolve(v)
	if err != nil {
		s.handles.release()
		return nil, err
	}
	defer t.close()
	fd, err := t.openDir()
	if err != nil {
		s.handles.release()
		return nil, err
	}
	return &dirLister{s: s, v: v, root: v.isRoot(), fd: fd, f: os.NewFile(uintptr(fd), v.String())}, nil
}

// ListAt gives the entries from offset off on.
func (l *dirLister) ListAt(ls []os.FileInfo, off int64) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if off < 0 {
		return 0, io.EOF
	}
	if off < l.pos {
		if err := l.rewind(); err != nil {
			return 0, err
		}
	}
	for l.pos < off {
		if _, err := l.next(int(min(off-l.pos, listBatch))); err != nil {
			return 0, err
		}
	}
	n := 0
	for n < len(ls) {
		got, err := l.next(min(len(ls)-n, listBatch))
		n += copy(ls[n:], got)
		if err != nil {
			return n, err // io.EOF at the end of the directory
		}
	}
	return n, nil
}

// rewind starts the directory again from its first entry, on a new
// description of the same directory.
func (l *dirLister) rewind() error {
	fd, err := unix.Openat(l.fd, ".", dirFlags, 0)
	if err != nil {
		return &os.PathError{Op: "readdir", Path: l.v.String(), Err: err}
	}
	_ = l.f.Close()
	l.fd, l.f, l.pos = fd, os.NewFile(uintptr(fd), l.v.String()), 0
	return nil
}

// next reads up to want entries (at least one, unless the directory is at
// its end, then io.EOF), each lstat'ed through the open directory (a link is
// listed as a link). A name that is gone since it was read is left out.
func (l *dirLister) next(want int) ([]os.FileInfo, error) {
	var out []os.FileInfo
	for len(out) == 0 {
		names, err := l.f.Readdirnames(want)
		if len(names) == 0 {
			if err == nil {
				err = io.EOF
			}
			if err != io.EOF {
				err = &os.PathError{Op: "readdir", Path: l.v.String(), Err: err}
			}
			return nil, err
		}
		for _, n := range names {
			if l.root && n == sshDir {
				continue
			}
			fi := &fileInfo{name: n}
			if err := unix.Fstatat(l.fd, n, &fi.st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				continue
			}
			out = append(out, fi)
		}
	}
	l.pos += int64(len(out))
	return out, nil
}

// Close closes the directory and gives the place back. It is safe to call
// twice.
func (l *dirLister) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	l.s.handles.release()
	return err
}
