package hosts

// The lock of 'host provisioner': one command at a time per host on the
// tacctl server, held from the first check to the last step. Two operators
// rotating the same host would otherwise create, prove and remove each
// other's accounts and rewrite each other's registry line.

import (
	"errors"
	"os"
	"path/filepath"

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
