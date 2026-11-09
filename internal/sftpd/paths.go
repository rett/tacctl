package sftpd

import (
	"strings"
)

const (
	// maxName and maxPath are the Linux limits (NAME_MAX, PATH_MAX); a
	// client path over them is a bad request, answered with a status
	// before the kernel is asked.
	maxName = 255
	maxPath = 4096

	// sshDir is the entry of the home the client must never reach.
	sshDir = ".ssh"
)

// vpath is a client path as the server sees it: the components of the
// cleaned absolute path under the virtual root "/", which is the home.
// The root is the empty list.
type vpath []string

// parsePath cleans a client path lexically, as a Unix shell would after
// "cd /": empty and "." components go, ".." removes the component before it
// and, at the root, does nothing (so ".." can never leave the home), and a
// relative path is taken from the root. The cleaning is only a lexical
// step: it is sound because the resolution never follows a symbolic link
// (see resolve), so a name always means what it says.
//
// A path with a NUL, one over maxPath or a component over maxName is a bad
// request.
func parsePath(p string) (vpath, error) {
	if len(p) > maxPath {
		return nil, errBadPath("path too long")
	}
	if strings.IndexByte(p, 0) >= 0 {
		return nil, errBadPath("path contains a NUL")
	}
	var out vpath
	for _, c := range strings.Split(p, "/") {
		switch c {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			if len(c) > maxName {
				return nil, errBadPath("file name too long")
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// String is the virtual path: "/" for the root, else "/a/b".
func (v vpath) String() string {
	return "/" + strings.Join(v, "/")
}

// isRoot reports whether v is the home itself.
func (v vpath) isRoot() bool { return len(v) == 0 }

// inSSH reports whether v is the .ssh entry of the home or anything under
// it. The name is compared as written (case-sensitive) on the cleaned path,
// so ".ssh/../.ssh/x", "//.ssh" and "a/../.ssh" are all caught.
func (v vpath) inSSH() bool { return len(v) > 0 && v[0] == sshDir }

// parent is the directory that holds v (v must not be the root) and name
// the last component.
func (v vpath) parent() vpath { return v[:len(v)-1] }
func (v vpath) name() string  { return v[len(v)-1] }
