package backend

import (
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

// isRegular is bash's -f (symlinks followed).
func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func itoa(n int) string { return strconv.Itoa(n) }

// copyPreserve is 'cp -p src dst': the content, then the owner (best
// effort: an unprivileged caller keeps its own, as cp does silently), the
// mode (with the setuid, setgid and sticky bits) and the access and
// modification times. An existing dst is truncated and rewritten in place.
func copyPreserve(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	var atime time.Time
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = out.Chown(int(sys.Uid), int(sys.Gid))
		atime = time.Unix(sys.Atim.Sec, sys.Atim.Nsec)
	}
	mode := st.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if err := out.Chmod(mode); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if atime.IsZero() {
		atime = st.ModTime()
	}
	return os.Chtimes(dst, atime, st.ModTime())
}
