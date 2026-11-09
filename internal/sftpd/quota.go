package sftpd

import (
	"math"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// remeasureAfter is how old the last measure of the home may be when a file
// is opened for writing before the whole home is measured again, so that a
// second session, or a file tacctl itself wrote, is noticed.
const remeasureAfter = 5 * time.Second

// maxMeasureDepth bounds the walk of the home. A path is at most maxPath
// bytes, so a tree made of paths has at most maxPath/2 levels; a tree that
// was made deeper by moving subtrees under each other is not counted below
// this depth.
const maxMeasureDepth = maxPath

// quota keeps the usage of the home: the sum of the sizes of its regular
// files, no link followed, each inode once, .ssh counted. It is measured
// when the session starts and when a file is opened for writing and the last
// measure is older than remeasureAfter, and is kept current in between from
// what the session does itself (writes, deletes, truncations and renames).
// The overshoot between two sessions that write at once is accepted.
//
// One lock covers the usage and, for a write, the check and the write that
// follows it, so that two writes of the same session cannot both fit in the
// room of one.
type quota struct {
	limit int64
	home  *home
	now   func() time.Time

	mu         sync.Mutex
	used       int64
	measuredAt time.Time
}

func newQuota(h *home, limit int64, now func() time.Time) *quota {
	q := &quota{limit: limit, home: h, now: now}
	q.remeasure()
	return q
}

// remeasure walks the home. The caller holds q.mu (or is the constructor).
func (q *quota) remeasure() {
	q.used = measure(q.home)
	q.measuredAt = q.now()
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
	return q.used
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

// write does the write w with the check that it fits: a write that would take
// the usage over the limit is refused whole, so nothing is written past the
// limit. w writes at the offset (or at the end, for a file open with
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
	if grow > 0 && grow > q.limit-q.used {
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

// measure sums the sizes of the regular files below the home. It lists the
// home through a descriptor of its own: a directory read moves the offset
// of the open file, and the home's descriptor is shared.
func measure(h *home) int64 {
	fd, err := unix.Openat(h.fd, ".", dirFlags, 0)
	if err != nil {
		return 0
	}
	return measureDir(fd, 0, map[[2]uint64]bool{})
}

// measureDir sums the directory fd and below, and closes fd.
func measureDir(fd, depth int, seen map[[2]uint64]bool) int64 {
	f := os.NewFile(uintptr(fd), "")
	defer func() { _ = f.Close() }()
	names, _ := f.Readdirnames(-1)
	var total int64
	for _, n := range names {
		var st unix.Stat_t
		if unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			key := [2]uint64{u64(st.Dev), u64(st.Ino)}
			if !seen[key] {
				seen[key] = true
				total += st.Size
			}
		case unix.S_IFDIR:
			if depth >= maxMeasureDepth {
				continue
			}
			if sub, err := unix.Openat(fd, n, dirFlags, 0); err == nil {
				total += measureDir(sub, depth+1, seen)
			}
		}
	}
	return total
}

// u64 widens the integer types the stat structures use, which differ by
// architecture.
func u64[T ~int32 | ~int64 | ~uint32 | ~uint64](v T) uint64 { return uint64(v) }
