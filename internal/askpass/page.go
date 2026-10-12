package askpass

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// The layout of the locked page: the secret's slot, then a staging slot a
// store is received into (so the live secret is replaced only by a
// complete, valid one, and the socket is never read while the agent's
// lock is held).
const (
	slotSecret = 0
	slotStage  = MaxSecret
	pageNeeded = 2 * MaxSecret
)

// page is an anonymous private mapping, locked in RAM, excluded from core
// dumps and not inherited by a forked child.
type page struct {
	b []byte
}

// newPage maps and locks the page. A failed mlock is an error: a password
// that can be swapped out is not what D70 promises.
func newPage() (*page, error) {
	size := max(os.Getpagesize(), pageNeeded)
	b, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("%w: mmap: %v", ErrNoLock, err)
	}
	if err := unix.Mlock(b); err != nil {
		_ = unix.Munmap(b)
		return nil, fmt.Errorf("%w: mlock: %v", ErrNoLock, err)
	}
	// Best effort: older kernels lack these. MADV_WIPEONFORK does nothing
	// for Go's own exec path (clone with CLONE_VM|CLONE_VFORK shares the
	// address space and nothing is copied); it covers a fork(2) made by
	// other code in the process, and is harmless otherwise.
	_ = unix.Madvise(b, unix.MADV_DONTDUMP)
	_ = unix.Madvise(b, unix.MADV_WIPEONFORK)
	return &page{b: b}, nil
}

func (p *page) secret() []byte { return p.b[slotSecret : slotSecret+MaxSecret] }
func (p *page) stage() []byte  { return p.b[slotStage : slotStage+MaxSecret] }

// wipe zeroes the whole page.
func (p *page) wipe() { Zero(p.b) }

// release zeroes, unlocks and unmaps the page; p is unusable afterwards.
func (p *page) release() {
	p.wipe()
	_ = unix.Munlock(p.b)
	_ = unix.Munmap(p.b)
	p.b = nil
}

// harden marks the process not dumpable (no core file, no ptrace or
// /proc/<pid>/mem by the same uid without CAP_SYS_PTRACE). The flag is
// reset by execve, so commands the shell starts are not affected.
func harden() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// MarkNotDumpable is harden for callers outside the package: the root-side
// pull marks itself, since a password it prompted for lives in its memory.
func MarkNotDumpable() error { return harden() }
