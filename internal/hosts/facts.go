package hosts

// What 'host enroll' and 'host sync' learn about a host over the
// enrolment session, read-only, after the script has run (FactsCommand):
// the address the ssh connection reached, which tacctl records as the
// host's address in the device registry, and the local useradd UID range
// of /etc/login.defs, which is warned about when it overlaps tacctl's own
// range: a local account created by hand could then be given a
// UID tacctl has handed out. tacctl never edits login.defs. The same read
// gives what 'host show' prints as the host's facts (SystemFactsCommand):
// its OS, sshd's version and the PAM modules it has; those are only shown.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
)

// FactsCommand is the read-only remote command that prints the facts:
// sshd's SSH_CONNECTION ('client port server port': the third field is the
// host's own address the connection reached) and the UID_MIN/UID_MAX lines
// of /etc/login.defs, after a 'login_defs=present' marker when the file is
// readable.
const FactsCommand = `printf 'ssh_connection=%s\n' "$SSH_CONNECTION"; ` +
	`if [ -r /etc/login.defs ]; then echo login_defs=present; grep -E '^[[:space:]]*UID_(MIN|MAX)[[:space:]]' /etc/login.defs; fi; ` +
	SystemFactsCommand

// SystemFactsCommand is the part of FactsCommand that 'host show' only
// shows (and that a host enrolled with --local runs here): the NAME,
// VERSION_ID and PRETTY_NAME lines of /etc/os-release, sshd's version (an
// sshd without -V names its version in the complaint), and each of the
// two PAM modules found in the usual module directories with its version
// (pam_radius_auth's from the package manager, pam_tacplus's from the
// module itself). Every part is read without root.
const SystemFactsCommand = `if [ -r /etc/os-release ]; then grep -E '^(NAME|VERSION_ID|PRETTY_NAME)=' /etc/os-release | sed 's/^/os_/'; fi; ` +
	`s=$(command -v sshd || echo /usr/sbin/sshd); printf 'sshd=%s\n' "$("$s" -V 2>&1 | grep -o 'OpenSSH_[^ ,]*' | head -n 1)"; ` +
	`for m in pam_tacplus pam_radius_auth; do ` +
	`f=$(ls /lib/security/$m.so /lib64/security/$m.so /usr/lib/security/$m.so /usr/lib64/security/$m.so /lib/*-linux-gnu*/security/$m.so /usr/lib/*-linux-gnu*/security/$m.so 2>/dev/null | head -n 1); ` +
	`[ -n "$f" ] || continue; ` +
	`if [ $m = pam_tacplus ]; then v=$(grep -aoE 'pam_tacplus [0-9]+(\.[0-9]+)+' "$f" 2>/dev/null | head -n 1 | cut -d' ' -f2); ` +
	`else v=$(dpkg-query -W -f '${Version}' libpam-radius-auth 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' pam_radius 2>/dev/null | grep -v 'not installed'); fi; ` +
	`printf 'pam=%s %s %s\n' "$m" "$f" "$v"; done; true`

// useradd's own UID_MIN and UID_MAX when login.defs does not set them
// (shadow-utils).
const (
	defaultUIDMin = 1000
	defaultUIDMax = 60000
)

// Facts is what FactsCommand printed (or, for a host enrolled with
// --local, what this server's own login.defs says).
type Facts struct {
	// Address is the host's address the session reached ("" when sshd did
	// not report one).
	Address string
	// LoginDefs: login.defs was read; UIDMin..UIDMax is useradd's range
	// (the shadow-utils defaults for a setting it does not hold).
	LoginDefs      bool
	UIDMin, UIDMax int

	// What SystemFactsCommand printed: os-release's NAME, VERSION_ID and
	// PRETTY_NAME, sshd's version ('OpenSSH_9.6p1') and the PAM modules
	// found ("" when not reported).
	OSName, OSVersion, OSPretty string
	SSHD                        string
	PAM                         []PAMModule
}

// PAMModule is a PAM module found on a host: its name (pam_tacplus or
// pam_radius_auth), the file and its version ("" when not reported).
type PAMModule struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
}

// OS is the host's OS as os-release names it: PRETTY_NAME, else NAME and
// VERSION_ID ("" when not reported).
func (f Facts) OS() string {
	if f.OSPretty != "" {
		return f.OSPretty
	}
	return strings.TrimSpace(f.OSName + " " + f.OSVersion)
}

// Module is the PAM module name among those found (nil when it was not).
func (f Facts) Module(name string) *PAMModule {
	for i := range f.PAM {
		if f.PAM[i].Name == name {
			return &f.PAM[i]
		}
	}
	return nil
}

// ModuleOf is the PAM module a host enrolled with method logs in through.
func ModuleOf(method string) string {
	if method == Radius {
		return "pam_radius_auth"
	}
	return "pam_tacplus"
}

// ParseFacts reads FactsCommand's output.
func ParseFacts(out []byte) Facts {
	f := Facts{UIDMin: defaultUIDMin, UIDMax: defaultUIDMax}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "ssh_connection="); ok {
			if fl := strings.Fields(v); len(fl) == 4 {
				if a, err := netip.ParseAddr(fl[2]); err == nil {
					f.Address = a.Unmap().WithZone("").String()
				}
			}
			continue
		}
		if line == "login_defs=present" {
			f.LoginDefs = true
			continue
		}
		if f.systemLine(line) {
			continue
		}
		f.loginDefsLine(line)
	}
	return f
}

// systemLine takes a line of SystemFactsCommand; false for any other.
func (f *Facts) systemLine(line string) bool {
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return false
	}
	unquote := func(s string) string {
		if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
			return s[1 : len(s)-1]
		}
		return s
	}
	switch k {
	case "os_NAME":
		f.OSName = unquote(v)
	case "os_VERSION_ID":
		f.OSVersion = unquote(v)
	case "os_PRETTY_NAME":
		f.OSPretty = unquote(v)
	case "sshd":
		f.SSHD = v
	case "pam":
		fl := strings.Fields(v)
		if len(fl) < 2 || f.Module(fl[0]) != nil {
			return true
		}
		m := PAMModule{Name: fl[0], Path: fl[1]}
		if len(fl) > 2 {
			m.Version = strings.Join(fl[2:], " ")
		}
		f.PAM = append(f.PAM, m)
	default:
		return false
	}
	return true
}

// loginDefsLine takes a UID_MIN or UID_MAX line of login.defs.
func (f *Facts) loginDefsLine(line string) {
	fl := strings.Fields(line)
	if len(fl) < 2 {
		return
	}
	n, err := strconv.Atoi(fl[1])
	if err != nil || n < 0 {
		return
	}
	switch fl[0] {
	case "UID_MIN":
		f.UIDMin = n
	case "UID_MAX":
		f.UIDMax = n
	}
}

// LocalFacts are this server's own facts for a host enrolled with --local:
// its logins reach the backends from 127.0.0.1, and its login.defs is
// path ("" or unreadable: not read).
func LocalFacts(path string) Facts {
	f := Facts{Address: "127.0.0.1", UIDMin: defaultUIDMin, UIDMax: defaultUIDMax}
	data, err := os.ReadFile(path)
	if path == "" || err != nil {
		return f
	}
	f.LoginDefs = true
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f.loginDefsLine(strings.TrimSpace(sc.Text()))
	}
	return f
}

// UIDOverlap reports whether local useradd can hand out a UID of r on the
// host.
func (f Facts) UIDOverlap(r Range) bool {
	return f.LoginDefs && f.UIDMin <= r.Max && f.UIDMax >= r.Min && f.UIDMin <= f.UIDMax
}

// UIDWarning is the warning for a host whose useradd range overlaps r
// (nil when it does not).
func (f Facts) UIDWarning(name string, r Range) []string {
	if !f.UIDOverlap(r) {
		return nil
	}
	fix := "  Keep UID_MIN-UID_MAX in /etc/login.defs on " + name + " clear of " + r.String() + " (tacctl does not change it)."
	if r.Min > defaultUIDMax {
		fix = "  Keep UID_MAX below " + strconv.Itoa(r.Min) + " in /etc/login.defs on " + name + " (the default is 60000; tacctl does not change it)."
	}
	return []string{
		name + ": local useradd there gives out UIDs " + strconv.Itoa(f.UIDMin) + "-" + strconv.Itoa(f.UIDMax) +
			" (/etc/login.defs UID_MIN/UID_MAX), which overlaps tacctl's " + r.String() + ":",
		"  an account created there by hand could take a UID tacctl has given out (and a home tacctl kept).",
		fix,
	}
}

// readFacts runs FactsCommand on target over the connection s shares with
// the script run, before it is closed.
func (env *Env) readFacts(ctx context.Context, s SSH, target string) {
	c := s.Cmd("-T", target, FactsCommand)
	c.Stderr = io.Discard
	res, err := env.Runner.Run(ctx, c)
	if err != nil {
		return
	}
	f := ParseFacts(res.Stdout)
	env.Facts = &f
}

// readLocalSystem adds this server's own SystemFactsCommand facts to f
// (a host enrolled with --local); nothing when it cannot be run.
func (env *Env) readLocalSystem(ctx context.Context, f *Facts) {
	res, err := env.Runner.Run(ctx, execx.Cmd{Name: "sh", Args: []string{"-c", SystemFactsCommand}, Stderr: io.Discard})
	if err != nil {
		return
	}
	sys := ParseFacts(res.Stdout)
	f.OSName, f.OSVersion, f.OSPretty, f.SSHD, f.PAM = sys.OSName, sys.OSVersion, sys.OSPretty, sys.SSHD, sys.PAM
}
