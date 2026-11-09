package sftpd

import (
	"errors"
	"math"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// remeasureAfter is how old the last measure of the home may be when a file
// is opened for writing before the whole home is measured again, so that a
// second session, or a file tacctl itself wrote, is noticed.
const remeasureAfter = 5 * time.Second

// maxMeasureDepth bounds the walk of the home. A path is at most maxPath
// bytes, so a tree made of paths has at most maxPath/2 levels; a tree that
// was made deeper by moving subtrees under each other is not walked below
// this depth, and the walk then says it was not complete.
const maxMeasureDepth = maxPath

// quota keeps the usage of the home: the sum of the sizes of its regular
// files, no link followed, each inode once, .ssh counted. It is measured
// when the session starts and when a file is opened for writing and the last
// measure is older than remeasureAfter, and is kept current in between from
// what the session does itself (writes, deletes, truncations and renames).
// The overshoot between two sessions that write at once is accepted.
//
// A walk that could not see all of the home (a directory it may not list or
// search, a failed open, no descriptor left, the depth cap) is incomplete,
// and then the home counts as full: the usage is taken as at least the
// limit, so that nothing that makes the home bigger is accepted, until a later
// walk is complete. Reading, deleting and writes that do not grow the home
// go on.
//
// One lock covers the usage and, for a write, the check and the write that
// follows it, so that two writes of the same session cannot both fit in the
// room of one.
type quota struct {
	limit int64
	home  *home
	now   func() time.Time
	depth int // the depth the walk goes to

	mu         sync.Mutex
	used       int64
	incomplete bool // the last walk did not see all of the home
	measuredAt time.Time
	held       map[inode]map[*file]struct{} // the files this session has open, by inode
}

// inode names a file on its device.
type inode [2]uint64

// newQuota measures the home; depth is how far the walk goes (0 is
// maxMeasureDepth).
func newQuota(h *home, limit int64, now func() time.Time, depth int) *quota {
	if depth <= 0 {
		depth = maxMeasureDepth
	}
	q := &quota{limit: limit, home: h, now: now, depth: depth, held: map[inode]map[*file]struct{}{}}
	q.remeasure()
	return q
}

// remeasure walks the home. The caller holds q.mu (or is the constructor).
func (q *quota) remeasure() {
	used, complete := measure(q.home, q.depth)
	// A file whose last name is gone while a handle of this session is open
	// still holds its data: it is not in the walk, and it counts.
	for _, set := range q.held {
		for f := range set {
			if fi, err := f.f.Stat(); err == nil && nlinkOf(fi) == 0 {
				used += fi.Size()
			}
			break // the files of one inode have one size
		}
	}
	q.used, q.incomplete = used, !complete
	q.measuredAt = q.now()
}

// nlinkOf is the link count of a stat result (1 when it cannot be told).
func nlinkOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return u64(st.Nlink)
	}
	return 1
}

// usedLocked is the usage the checks go by: the limit at least when the
// measure was incomplete. The caller holds q.mu.
func (q *quota) usedLocked() int64 {
	if q.incomplete {
		return max(q.used, q.limit)
	}
	return q.used
}

// refresh measures the home again when the last measure is stale. It is
// called when a file is opened for writing.
func (q *quota) refresh() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.now().Sub(q.measuredAt) > remeasureAfter {
		q.remeasure()
	}
}

// usage is the current usage.
func (q *quota) usage() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.usedLocked()
}

// release takes the size of a file that went away (or was cut) off the
// usage.
func (q *quota) release(n int64) {
	if n <= 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.used = max(0, q.used-n)
}

// hold notes that f is open. A file that lost its last name between its
// open and now (a remove that did not know of the handle) took its room off
// the usage: it is put back.
func (q *quota) hold(f *file) {
	q.mu.Lock()
	defer q.mu.Unlock()
	set := q.held[f.key]
	if set == nil {
		set = map[*file]struct{}{}
		q.held[f.key] = set
		if fi, err := f.f.Stat(); err == nil && nlinkOf(fi) == 0 {
			q.used += fi.Size()
		}
	}
	set[f] = struct{}{}
}

// unhold notes that f is about to be closed. The last handle on a file with
// no name left gives its room back: its data goes with the handle.
func (q *quota) unhold(f *file) {
	q.mu.Lock()
	defer q.mu.Unlock()
	set := q.held[f.key]
	delete(set, f)
	if len(set) > 0 {
		return
	}
	delete(q.held, f.key)
	if fi, err := f.f.Stat(); err == nil && nlinkOf(fi) == 0 {
		q.used = max(0, q.used-fi.Size())
	}
}

// unlinking runs op, which removes the entry t names or replaces it, and
// takes the size of the file off the usage when this was its last name and no
// handle of the session is open on it (else the data stays until the last
// handle closes). The look at the entry, op and the accounting are one step
// under the lock, so a handle opened meanwhile is either seen here or finds
// the name gone in hold.
func (q *quota) unlinking(t *target, op func() error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	var freed int64
	var st unix.Stat_t
	if unix.Fstatat(t.dir, t.name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink <= 1 &&
		len(q.held[inode{u64(st.Dev), u64(st.Ino)}]) == 0 {
		freed = st.Size
	}
	if err := op(); err != nil {
		return err
	}
	q.used = max(0, q.used-freed)
	return nil
}

// write does the write w with the check that it fits: a write that would take
// the measured usage over the limit is refused whole (see doc.go for what that
// does and does not guarantee). w writes at the offset (or at the end, for a file open with
// O_APPEND) and returns the count.
func (q *quota) write(f *os.File, n int, off int64, appending bool, w func() (int, error)) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	before := fi.Size()
	if appending {
		off = before
	}
	if off < 0 {
		return 0, &os.PathError{Op: "write", Path: f.Name(), Err: unix.EINVAL}
	}
	var grow int64
	switch {
	case off > math.MaxInt64-int64(n):
		return 0, errQuota() // off+n does not even fit in a size
	case off+int64(n) > before:
		grow = off + int64(n) - before
	}
	if grow > 0 && grow > q.limit-q.usedLocked() {
		return 0, errQuota()
	}
	wn, werr := w()
	if grow > 0 {
		if fi, err := f.Stat(); err == nil && fi.Size() > before {
			q.used += fi.Size() - before
		}
	}
	return wn, werr
}

// measure sums the sizes of the regular files below the home and says
// whether it saw all of them: false when a directory could not be listed,
// searched or opened (a mode the client set, a descriptor limit), or lies
// deeper than depth, and then the sum is a lower bound only. It lists the
// home through a descriptor of its own: a directory read moves the offset
// of the open file, and the home's descriptor is shared.
func measure(h *home, depth int) (int64, bool) {
	fd, err := unix.Openat(h.fd, ".", dirFlags, 0)
	if err != nil {
		return 0, false
	}
	w := &walk{depth: depth, seen: map[[2]uint64]bool{}, complete: true}
	return w.dir(fd, 0), w.complete
}

// walk is one measure: the inodes seen, and whether anything escaped it.
type walk struct {
	depth    int
	seen     map[[2]uint64]bool
	complete bool
}

// dir sums the directory fd and below, and closes fd. An entry that is gone
// since the listing (ENOENT) is not a failure; any other error is.
func (w *walk) dir(fd, depth int) int64 {
	f := os.NewFile(uintptr(fd), "")
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		w.complete = false
	}
	var total int64
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				w.complete = false
			}
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			key := [2]uint64{u64(st.Dev), u64(st.Ino)}
			if !w.seen[key] {
				w.seen[key] = true
				total += st.Size
			}
		case unix.S_IFDIR:
			if depth >= w.depth {
				w.complete = false
				continue
			}
			sub, err := unix.Openat(fd, n, dirFlags, 0)
			if err != nil {
				if !errors.Is(err, unix.ENOENT) {
					w.complete = false
				}
				continue
			}
			total += w.dir(sub, depth+1)
		}
	}
	return total
}

// u64 widens the integer types the stat structures use, which differ by
// architecture.
func u64[T ~int32 | ~int64 | ~uint32 | ~uint64](v T) uint64 { return uint64(v) }
