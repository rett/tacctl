package hosts

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The bash writes its files with 'install -m <mode> <tmp> <dest>' (a fresh
// inode with that mode) and makes its scratch files with mktemp. These are
// the native forms (docs/plans/go-rewrite.md 3.9 item 2).

// replaceFile writes data to path as a new file with mode: what
// 'install -m <mode> <tmp> <path>' leaves.
func replaceFile(path string, data []byte, mode os.FileMode) error {
	if err := syscall.Unlink(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// InstallError is a failed 'install' of a file the operator named: Msg is
// the line GNU install prints on stderr.
type InstallError struct {
	Msg string
	Err error
}

func (e *InstallError) Error() string { return e.Msg }
func (e *InstallError) Unwrap() error { return e.Err }

// installAs is 'install -m <mode> <src> <dest>' for an operator-named dest,
// src being a file called srcName holding data: a dest that is a directory
// receives <dest>/<basename of srcName>. It returns the path written.
func installAs(srcName string, data []byte, dest string, mode os.FileMode) (string, error) {
	target := dest
	if st, err := os.Stat(dest); err == nil && st.IsDir() {
		target = filepath.Join(dest, filepath.Base(srcName))
	}
	if err := syscall.Unlink(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return target, &InstallError{Msg: "install: cannot remove '" + target + "': " + strerror(err), Err: err}
	}
	if err := replaceFile(target, data, mode); err != nil {
		return target, &InstallError{Msg: "install: cannot create regular file '" + target + "': " + strerror(err), Err: err}
	}
	return target, nil
}

// strerror is the C library's text for the errno under err.
func strerror(err error) string {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return err.Error()
	}
	s := en.Error()
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

const tempChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// tempName is a mktemp name in dir: tmp.XXXXXXXXXX.
func tempName(dir string) string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = tempChars[int(b[i])%len(tempChars)]
	}
	return filepath.Join(dir, "tmp."+string(b))
}

// TempFile is 'mktemp': an empty file, mode 0600, in TMPDIR.
func TempFile() (string, error) {
	for range 100 {
		p := tempName(os.TempDir())
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		return p, f.Close()
	}
	return "", errors.New("mktemp: too many attempts")
}

// TempDir is 'mktemp -d': a directory, mode 0700, in TMPDIR.
func TempDir() (string, error) {
	for range 100 {
		p := tempName(os.TempDir())
		err := os.Mkdir(p, 0o700)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		return p, nil
	}
	return "", errors.New("mktemp: too many attempts")
}
