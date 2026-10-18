package hosts

// The lock of 'host provisioner': one command at a time per host on the
// tacctl server, held from the first check to the last step. Two operators
// rotating the same host would otherwise create, prove and remove each
// other's accounts and rewrite each other's registry line.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ErrRotationBusy is returned by LockHost when another command holds the
// host's lock.
var ErrRotationBusy = errors.New("another rotation is running")

// LockHost takes the exclusive lock of host name under dir
// (<dir>/host-provisioner-<name>.lock, made 0700/0600 when missing) without
// waiting, and returns the function that releases it. The lock goes with
// the process, so a command that dies leaves none behind. name must be an
// enrolled host's (the registry's names have no path separators).
func LockHost(dir, name string) (unlock func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "host-provisioner-"+name+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrRotationBusy
		}
		return nil, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}

// lockRecords takes the exclusive lock on the records (a file of its own
// beside the records directory), waiting for it: a record is changed by 'host sync', 'host
// enroll' and 'host provisioner', which can run at once.
func (rs Records) lockRecords() (unlock func(), err error) {
	if err := os.MkdirAll(filepath.Dir(rs.Dir), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(rs.Dir), ".hosts.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}

// ErrRegistryBusy is returned by the registry's writes when another command
// kept the registry's lock for longer than registryLockWait.
var ErrRegistryBusy = errors.New("the host registry is locked by another tacctl command; try again in a moment")

// registryLockWait is how long a write of the registry waits for the lock
// (the commands that hold it write one file and let go); a variable for the
// tests.
var registryLockWait = 30 * time.Second

// registryLockPoll is the pause between two tries of the lock.
const registryLockPoll = 20 * time.Millisecond

// lock takes the lock of the registry's writes: the same file as the
// records' (.hosts.lock, beside the registry), so that a record and the
// registry are never changed at once. It waits up to registryLockWait for
// it, and the lock goes with the process.
func (r *Registry) lock() (unlock func(), err error) {
	dir := filepath.Dir(r.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".hosts.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(registryLockWait)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("%w (waited %s)", ErrRegistryBusy, registryLockWait)
		}
		time.Sleep(registryLockPoll)
	}
}

// Lock takes the lock the registry's writes take (and the records'), waiting
// for it as they do, and returns the function that lets go. While it is held,
// a write of the registry or of the records (which take it too) waits, and
// this process must not call one: the lock is not reentrant. 'backup restore'
// holds it from before it changes anything until the host files are back.
func (r *Registry) Lock() (unlock func(), err error) { return r.lock() }

// WithLock runs fn holding the registry's lock (see Lock). fn must not call a
// write of the registry or of the records.
func (r *Registry) WithLock(fn func() error) error {
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// SetLockWait changes how long the registry's lock is waited for and returns
// the function that puts it back. It is the seam of the tests that hold the
// lock; no command calls it.
func SetLockWait(d time.Duration) (restore func()) {
	old := registryLockWait
	registryLockWait = d
	return func() { registryLockWait = old }
}
