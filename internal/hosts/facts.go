package hosts

// What 'host enroll' and 'host sync' learn about a host over the
// enrolment session, read-only, after the script has run (FactsCommand):
// the address the ssh connection reached, which tacctl records as the
// host's address in the device registry, and the local useradd UID range
// of /etc/login.defs, which is warned about when it overlaps tacctl's own
// range: a local account created by hand could then be given a
// UID tacctl has handed out. tacctl never edits login.defs.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// FactsCommand is the read-only remote command that prints the facts:
// sshd's SSH_CONNECTION ('client port server port': the third field is the
// host's own address the connection reached) and the UID_MIN/UID_MAX lines
// of /etc/login.defs, after a 'login_defs=present' marker when the file is
// readable.
const FactsCommand = `printf 'ssh_connection=%s\n' "$SSH_CONNECTION"; ` +
	`if [ -r /etc/login.defs ]; then echo login_defs=present; grep -E '^[[:space:]]*UID_(MIN|MAX)[[:space:]]' /etc/login.defs; fi; true`

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
		f.loginDefsLine(line)
	}
	return f
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
