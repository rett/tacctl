package sftpd

import (
	"errors"
	"io"
	"strings"

	"github.com/pkg/sftp"
)

// Event is one audited thing a client did. Path and To are the virtual
// paths the client used, cleaned (the home is "/"); they hold what the
// client sent, so the caller sanitises them before it logs them.
type Event struct {
	// Op is "upload" or "download" (at close, Bytes the total moved),
	// "delete", "rename", "mkdir", "setstat", or "refused".
	Op string
	// Path is the file the Op is about; To is the new name of a rename.
	Path, To string
	// Bytes is the size of a transfer.
	Bytes int64
	// Err is why an Op failed. For Op "refused" it names the reason the
	// request was refused: ".ssh", "outside the home", "symlink", "quota",
	// "unsupported" or "bad path".
	Err error
}

// Config is what a session needs.
type Config struct {
	// Home is the directory that is "/" for the client.
	Home string
	// Audit, when set, is called once per upload, download, delete, rename,
	// mkdir and setstat, and once per refusal. It is called from the
	// goroutines that serve the requests, never with a lock held, and it
	// must not block for long.
	Audit func(Event)
}

// Serve runs the SFTP protocol on rw until the client ends it, and closes
// rw. A client that ends the session cleanly gives nil. It never writes to
// standard output or error.
func Serve(rw io.ReadWriteCloser, cfg Config) error {
	defer func() { _ = rw.Close() }()
	h, err := openHome(cfg.Home)
	if err != nil {
		return err
	}
	defer h.close()
	s := &server{home: h, cfg: cfg}
	rs := sftp.NewRequestServer(rw, sftp.Handlers{FileGet: s, FilePut: s, FileCmd: s, FileList: s})
	err = rs.Serve()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// subsystemNames are the programs sshd's Subsystem line names for sftp:
// the OpenSSH server binary and the built-in.
var subsystemNames = [...]string{"sftp-server", "internal-sftp"}

// IsSubsystemCommand reports whether cmd is what sshd passes for the sftp
// subsystem: the base name of its first word is sftp-server or
// internal-sftp ("/usr/lib/openssh/sftp-server", "internal-sftp",
// "sftp-server -l INFO"); the arguments are ignored. A command with a shell
// metacharacter (";", "&", "|", "$", a backtick, a parenthesis, a redirection,
// a newline or a NUL) is not one, and neither is a program that only has
// spaces in its path: the first word is cut at the first blank.
func IsSubsystemCommand(cmd string) bool {
	if strings.ContainsAny(cmd, ";&|`$()<>\n\r\x00") {
		return false
	}
	w := strings.Fields(cmd)
	if len(w) == 0 {
		return false
	}
	base := w[0]
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	for _, n := range subsystemNames {
		if base == n {
			return true
		}
	}
	return false
}
