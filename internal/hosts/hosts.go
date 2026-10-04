// Package hosts is tacctl's side of Linux-host login (lib/linux_hosts.sh at
// 0.1.16): the enrolled-host registry, the UID file, the per-scope installer
// that wraps config/linux/client-install.sh, the ssh protocol that pushes a
// script to a host and runs it there, the container build of pam_tacplus
// and 'config linux build'. The command flows ('host enroll', 'config linux
// script', ...) live in internal/cli, which reads the model and the backends
// and hands this package plain values.
//
// Messages are 0.1.16's, written through the injected ui.Output where the
// bash function printed them; every info/warn/error line goes through the
// E variants (echo -e), as lib/core.sh's helpers do.
package hosts

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// UIDBase..UIDMax is the range tacctl assigns UIDs (and the matching
// primary GIDs) from: it never gives out a number outside it, and the
// client script never touches an account whose UID is outside it.
const (
	UIDBase = 20000
	UIDMax  = 29999
)

// UIDRange is the range in words ("20000-29999").
var UIDRange = strconv.Itoa(UIDBase) + "-" + strconv.Itoa(UIDMax)

// UIDInRange reports whether uid is a decimal number from UIDBase to UIDMax
// written without leading zeros.
func UIDInRange(uid string) bool {
	if uid == "" || uid[0] == '0' || strings.Trim(uid, "0123456789") != "" || len(uid) > 9 {
		return false
	}
	n, _ := strconv.Atoi(uid)
	return n >= UIDBase && n <= UIDMax
}

// The pinned pam_tacplus (LINUX_* and PAM_TACPLUS_* of lib/linux_hosts.sh).
const (
	PamTacplusRepo   = "https://github.com/kravietz/pam_tacplus.git"
	PamTacplusTag    = "v1.7.0"
	PamTacplusCommit = "b1b7f5351eca07f1bf2f6184602bdfb73d10a155"
	tarballName      = "pam_tacplus-1.7.0.tar.gz"
)

// The two methods a host can be enrolled with (LINUX_METHODS).
const (
	Tacplus = "tacplus"
	Radius  = "radius"
)

// Methods are the methods, in LINUX_METHODS order.
var Methods = []string{Tacplus, Radius}

// MethodList is "tacplus, radius" (${LINUX_METHODS// /, }).
func MethodList() string { return strings.Join(Methods, ", ") }

// MethodBackend is linux_method_backend: the backend (and protocol) that
// serves a method; ok is false for an unknown one.
func MethodBackend(method string) (string, bool) {
	switch method {
	case Tacplus:
		return "tacacs", true
	case Radius:
		return "radius", true
	}
	return "", false
}

// MethodLabel is linux_method_label: RADIUS for radius, TACACS+ for
// anything else.
func MethodLabel(method string) string {
	if method == Radius {
		return "RADIUS"
	}
	return "TACACS+"
}

// Paths are the files of Linux-host login.
type Paths struct {
	Dir    string // LINUX_DIR (TACCTL_LINUX_DIR, /var/lib/tacctl/linux)
	UIDs   string // LINUX_UID_FILE
	Hosts  string // LINUX_HOSTS_FILE
	VarLib string // paths.VarLib: made 0711 first when Dir is under it (mkDir)
}

// Tarball is PAM_TACPLUS_TARBALL.
func (p Paths) Tarball() string { return p.Dir + "/" + tarballName }

// Builds is LINUX_BUILDS_DIR.
func (p Paths) Builds() string { return p.Dir + "/builds" }

// Env is what the package works with in one invocation.
type Env struct {
	Paths  Paths
	Runner execx.Runner
	Out    ui.Output
	// Stdin is tacctl's standard input: what a script run on a host reads
	// from (a terminal lets the remote sudo ask for a password).
	Stdin io.Reader
	// AsUser is the user ssh and podman run as: SUDO_USER when tacctl runs
	// as root for someone else ("" runs them as tacctl's own user).
	AsUser string
	// AuthSock is SSH_AUTH_SOCK, passed to ssh run as AsUser.
	AuthSock string
	// Now is the clock (the knob clock in tests).
	Now func() time.Time
	// TTY reports whether a terminal can be opened (': > /dev/tty');
	// StdinTTY whether stdin is one ('[[ -t 0 ]]'); Machine is 'uname -m'.
	// Nil means the real checks.
	TTY      func() bool
	StdinTTY func() bool
	Machine  func() string
	// PinHostKeys pins an enrolled host's ssh keys (pin.go); nil pins
	// nothing.
	PinHostKeys KeyPinner
	// ReadKeys makes RunScript read the host's public keys over its
	// connection after a successful run (ReadKeysCommand), for PinKeys:
	// 'host enroll' and 'host sync' set it.
	ReadKeys bool

	sessionKeys []byte
	sessionErr  error
}

// ErrFailed is a failure whose messages have been printed: the bash
// function's 'return 1'.
var ErrFailed = errors.New("hosts: failed (reported)")

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) tty() bool {
	if e.TTY != nil {
		return e.TTY()
	}
	f, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func (e *Env) stdinTTY() bool {
	if e.StdinTTY != nil {
		return e.StdinTTY()
	}
	f, ok := e.Stdin.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// machine is 'uname -m'.
func (e *Env) machine() string {
	if e.Machine != nil {
		return e.Machine()
	}
	return Machine()
}

// Machine is the kernel's machine name, as 'uname -m' prints it.
func Machine() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Machine[:])
}

// stderrOut is an Output whose info/warn lines go to stderr ('warn ... >&2').
func (e *Env) stderrOut() ui.Output { return ui.Output{Stdout: e.Out.Stderr, Stderr: e.Out.Stderr} }

// interrupted reports whether ctx was cancelled by a signal: the command
// stops there, as bash dies with its foreground child.
func interrupted(ctx context.Context) bool { return ctx.Err() != nil }

var reLinuxName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// LinuxName reports whether a tacctl user name can be a Linux account
// (lowercase letters, digits, _ and -, starting with a letter or _, at most
// 32) and is not root.
func LinuxName(name string) bool { return name != "root" && reLinuxName.MatchString(name) }

// TierOf is tier_for_privlvl.
func TierOf(privlvl string) string { return string(tier.ForPrivLvl(privlvl)) }

// splitRow is "IFS='|' read -r username privlvl" of a linux-users row.
func splitRow(row string) (name, privlvl string) {
	name, privlvl, _ = strings.Cut(row, "|")
	return name, privlvl
}

// UserCount is linux_scope_user_count: the rows of the linux-users view
// that would get an account, counted (no UIDs are assigned).
func UserCount(rows []string) int {
	n := 0
	for _, r := range rows {
		if name, _ := splitRow(r); LinuxName(name) {
			n++
		}
	}
	return n
}

// ScopeUsers is linux_scope_users: "name:tier:uid" lines for the rows of
// the linux-users view that can be Linux accounts, a UID of UIDBase..UIDMax
// assigned to each on first use, joined by newlines ('$(...)': no trailing
// one). Names useradd would reject are skipped with a warning on stderr.
// Users whose group has no priv-lvl, and users whose UID file entry is
// outside the range (set by hand before 0.2.1), are skipped with a warning
// too and returned in keep: they are still users of the scope, so a host
// expires their accounts rather than deleting them. No UID left in the
// range is printed and ErrFailed.
func (e *Env) ScopeUsers(rows []string) (users string, keep []string, err error) {
	uids := UIDs{Path: e.Paths.UIDs}
	var out []string
	for _, r := range rows {
		name, privlvl := splitRow(r)
		if name == "" || name == "root" {
			continue
		}
		if !reLinuxName.MatchString(name) {
			e.stderrOut().WarnE("Skipping '" + name + "': not a valid Linux account name (lowercase letters, digits, _ and - only).")
			continue
		}
		t := TierOf(privlvl)
		if t == string(tier.None) {
			e.stderrOut().WarnE("Skipping '" + name + "': its group has no priv-lvl.")
			keep = append(keep, name)
			continue
		}
		uid, err := uids.For(name)
		if errors.Is(err, ErrUIDRangeFull) {
			e.Out.ErrorE("No UID left for '" + name + "': every number of " + UIDRange + " has been given out (UIDs are never reused).")
			e.Out.ErrorE("Give it a free number of the range by hand: tacctl config linux uid " + name + " <uid>")
			return "", nil, ErrFailed
		}
		if err != nil {
			return "", nil, err
		}
		if !UIDInRange(uid) {
			e.stderrOut().WarnE("Skipping '" + name + "': its UID " + uid + " is outside " + UIDRange + ", so no host gets an account for it. Assign one in the range: tacctl config linux uid " + name + " <uid>")
			keep = append(keep, name)
			continue
		}
		out = append(out, name+":"+t+":"+uid)
	}
	return strings.Join(out, "\n"), keep, nil
}

// CountLines is "awk -F: 'NF { n++ } END { print n + 0 }'": the lines of
// s that are not empty.
func CountLines(s string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if l != "" {
			n++
		}
	}
	return n
}

// mkDir creates Dir: its parent VarLib (when Dir is under it) with
// paths.VarLibMode first, so creating Dir never leaves /var/lib/tacctl
// unreadable to the users' ssh (VarLib/ssh/known_hosts).
func (p Paths) mkDir() error {
	if p.VarLib != "" && strings.HasPrefix(p.Dir, p.VarLib+"/") {
		if err := paths.MkVarLib(p.VarLib); err != nil {
			return err
		}
	}
	return os.MkdirAll(p.Dir, 0o700)
}
