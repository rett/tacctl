package sftpd

import (
	"cmp"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// Event is one audited thing a client did. Path and To are the virtual
// paths the client used, cleaned (the home is "/"); they hold what the
// client sent, so the caller sanitises them before it logs them.
type Event struct {
	// Op is "upload" or "download" (at close, Bytes the total moved; an open
	// that failed in the kernel gives the same Op at once, with Err set),
	// "delete", "rename", "mkdir", "setstat", or "refused".
	Op string
	// Path is the file the Op is about; To is the new name of a rename.
	Path, To string
	// Bytes is the size of a transfer.
	Bytes int64
	// Err is why an Op failed. For Op "refused" it names the reason the
	// request was refused: ".ssh", "outside the home", "symlink", "link",
	// "quota", "unsupported", "bad path" or "too many open files".
	Err error
}

// Config is what a session needs.
type Config struct {
	// Home is the directory that is "/" for the client.
	Home string
	// Quota is the size in bytes the files of the home may add up to; 0
	// means no limit, and then the home is not measured. What it guarantees
	// is in the package comment: a write is refused when it would take the
	// usage the session measured over the limit, and no more than that.
	Quota int64
	// Rate is the bytes per second the session may move, reads and writes
	// together, with a burst of one second; 0 means no limit.
	Rate int64
	// Audit, when set, is called once per upload, download, delete, rename,
	// mkdir and setstat (with Err set when it failed), and once per refusal.
	// It is called from the goroutines that serve the requests. No lock of
	// this package is held, but the library may hold one of its own: the
	// upload and download events fire when a handle is closed, which the
	// library does under the lock of its set of open handles. The callback
	// must not block, and must not call into the session.
	Audit func(Event)
}

// Serve runs the SFTP protocol on rw until the client ends it, and closes
// rw. A client that ends the session cleanly gives nil. It never writes to
// standard output or error.
func Serve(rw io.ReadWriteCloser, cfg Config) error {
	return serve(rw, cfg, seams{})
}

// seams are what a test replaces: the clock, and the sleep of the rate
// limit (the default sleeps until the time is up or the session has ended).
type seams struct {
	now   func() time.Time
	sleep func(time.Duration)

	measureDepth int // the depth of the quota walk, 0 for the default
	maxHandles   int // the open handles a session may have, 0 for the default

	// beforeTruncate, when set, runs in an open that truncates, after the
	// file is open and judged and before it is cut.
	beforeTruncate func()
	// afterPin, when set, runs in a setstat after the entry is pinned and
	// judged and before it is changed.
	afterPin func()
}

func serve(rw io.ReadWriteCloser, cfg Config, sm seams) error {
	n := newEndNotifier(rw)
	rw = n
	defer func() { _ = rw.Close() }()
	if sm.now == nil {
		sm.now = time.Now
	}
	if sm.sleep == nil {
		sm.sleep = func(d time.Duration) { sleepUntil(n.done, d) }
	}
	h, err := openHome(cfg.Home)
	if err != nil {
		return err
	}
	defer h.close()
	s := newServer(h, cfg, sm)
	rs := sftp.NewRequestServer(rw, sftp.Handlers{FileGet: s, FilePut: s, FileCmd: s, FileList: s})
	err = rs.Serve()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// newServer builds the state of one session. The home is measured here when
// there is a quota, and not at all when there is none.
func newServer(h *home, cfg Config, sm seams) *server {
	s := &server{home: h, cfg: cfg, handles: handleCount{max: cmp.Or(sm.maxHandles, maxHandles)}, beforeTruncate: sm.beforeTruncate, afterPin: sm.afterPin}
	if cfg.Quota > 0 {
		s.quota = newQuota(h, cfg.Quota, sm.now, sm.measureDepth)
	}
	s.rate = newBucket(cfg.Rate, sm.now, sm.sleep)
	return s
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
