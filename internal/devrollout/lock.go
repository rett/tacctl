package devrollout

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrBusy is a device whose lock another rollout holds.
var ErrBusy = errors.New("another rollout is running on the device")

// Lock is the per-device lock of a transaction (D138): 'flock' on
// '<dir>/<name>.lock'. Two rollouts of different devices run side by side;
// the same device is refused.
type Lock struct {
	f *os.File
}

// LockDevice takes the device's lock without waiting: ErrBusy when another
// process (or another job of this one) holds it. dir is created 0700.
func LockDevice(dir, name string) (*Lock, error) {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return nil, fmt.Errorf("devrollout: a device name %q cannot name a lock file", name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, name+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrBusy, name)
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Unlock releases the lock; a second call is a no-op. The file stays (its
// removal would race with a waiter that opened it).
func (l *Lock) Unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
