package hosts

// 'host show --check': a read-only look at an enrolled host as root, over
// the same kind of login 'host enroll' and 'host sync' use (the invoking
// user's ssh; sudo, with a terminal for its password), so the command line
// can compare it with what tacctl would make it. Nothing is copied to the
// host: the check is one command line (CheckScript) run through 'bash -c'.
// It reads the tac groups and their GIDs, the accounts named, the PAM files
// tacctl writes (with the checksums the client script recorded when it
// wrote them), the client script protocol it recorded, and the host's
// public keys.

import (
	"context"
	"io"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// TacGroups are tacctl's groups on a host in the order of their fixed GIDs
// (the client script's group_gid): the first number of the UID range, the
// next, and so on.
var TacGroups = []string{"tac-users", "tac-console", "tac-superuser", "tac-operator", "tac-readonly"}

// HostGroups are the groups a host has: every one on the tacctl server
// itself (local), tac-users and tac-superuser elsewhere.
func HostGroups(local bool) []string {
	if local {
		return append([]string(nil), TacGroups...)
	}
	return []string{"tac-users", "tac-superuser"}
}

// GroupGID is the fixed GID of one of tacctl's groups in r (0 for another
// group).
func GroupGID(group string, r Range) int {
	for i, g := range TacGroups {
		if g == group {
			return r.Min + i
		}
	}
	return 0
}

// PAMFiles are the PAM files the client script writes, in /etc/pam.d.
var PAMFiles = []string{"tacctl-auth", "tacctl-account", "tacctl-session"}

// checkPrefix starts every line CheckScript prints for tacctl.
const checkPrefix = "tacctl-check "

// CheckScript is the read-only script of 'host show --check' for the
// accounts names (Linux account names, LinuxName): one line per fact,
// each starting with checkPrefix. The client script's own locations can be
// moved as for the client script (TACCTL_CLIENT_STATE,
// TACCTL_CLIENT_PAM_DIR), and the ssh keys' (TACCTL_CLIENT_SSH_DIR), for
// tests.
func CheckScript(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = remoteWord(n)
	}
	return `STATE_DIR="${TACCTL_CLIENT_STATE:-/var/lib/tacctl-client}"
PAM_DIR="${TACCTL_CLIENT_PAM_DIR:-/etc/pam.d}"
SSH_DIR="${TACCTL_CLIENT_SSH_DIR:-/etc/ssh}"
say() { printf '` + checkPrefix + `%s\n' "$*"; }
for g in ` + strings.Join(TacGroups, " ") + `; do
    line=$(getent group "$g") && say "group $g $(echo "$line" | cut -d: -f3)"
done
for n in ` + strings.Join(q, " ") + `; do
    line=$(getent passwd "$n") || { say "account $n"; continue; }
    home=$(echo "$line" | cut -d: -f6)
    mode=-
    if [ -n "$home" ] && [ -d "$home" ] && [ ! -L "$home" ]; then mode=$(stat -c %a "$home"); fi
    say "account $n $(echo "$line" | cut -d: -f3) $(echo "$line" | cut -d: -f4) $mode $home"
done
for f in ` + strings.Join(PAMFiles, " ") + `; do
    if [ -f "$PAM_DIR/$f" ]; then say "pam $f $(sha256sum < "$PAM_DIR/$f" | cut -d' ' -f1)"; else say "pam $f -"; fi
done
if [ -r "$STATE_DIR/pam.sha256" ]; then
    while read -r sum f; do say "pam-written ${f##*/} $sum"; done < "$STATE_DIR/pam.sha256"
fi
say "protocol $(cat "$STATE_DIR/protocol" 2>/dev/null)"
for k in "$SSH_DIR"/ssh_host_*_key.pub; do
    if [ -r "$k" ]; then say "key $(cat "$k")"; fi
done
true
`
}

// AccountState is an account as the check found it.
type AccountState struct {
	// Exists: the host has an account of that name.
	Exists bool
	// UID and GID are its numbers; HomeMode is its home directory's mode
	// in octal ("-" when it is not a directory), Home the directory.
	UID, GID, HomeMode, Home string
}

// HostState is what the check read.
type HostState struct {
	// Groups are the GIDs of tacctl's groups that exist, by name.
	Groups map[string]string
	// Accounts are the accounts asked about, by name.
	Accounts map[string]AccountState
	// PAM are the checksums (sha256) of the PAM files, by file ("" when
	// the file is missing); PAMWritten the ones the client script recorded
	// when it wrote them (empty when it recorded none: before 0.2.2).
	PAM, PAMWritten map[string]string
	// Protocol is the client script protocol the host recorded ("" before
	// 0.2.2).
	Protocol string
	// Keys are the host's public keys (ssh_host_*_key.pub lines).
	Keys []byte
}

// ParseCheck reads the lines CheckScript printed (without checkPrefix).
func ParseCheck(lines []string) HostState {
	s := HostState{Groups: map[string]string{}, Accounts: map[string]AccountState{}, PAM: map[string]string{}, PAMWritten: map[string]string{}}
	var keys strings.Builder
	for _, l := range lines {
		kind, rest, _ := strings.Cut(l, " ")
		f := strings.Fields(rest)
		switch kind {
		case "group":
			if len(f) == 2 {
				s.Groups[f[0]] = f[1]
			}
		case "account":
			switch {
			case len(f) == 1:
				s.Accounts[f[0]] = AccountState{}
			case len(f) >= 4:
				a := AccountState{Exists: true, UID: f[1], GID: f[2], HomeMode: f[3]}
				if len(f) > 4 {
					// The home is the rest of the line, spaces and all.
					a.Home = strings.SplitN(rest, " ", 5)[4]
				}
				s.Accounts[f[0]] = a
			}
		case "pam":
			if len(f) == 2 {
				s.PAM[f[0]] = strings.TrimPrefix(f[1], "-")
			}
		case "pam-written":
			if len(f) == 2 {
				s.PAMWritten[f[0]] = f[1]
			}
		case "protocol":
			s.Protocol = strings.TrimSpace(rest)
		case "key":
			keys.WriteString(rest + "\n")
		}
	}
	if keys.Len() > 0 {
		s.Keys = []byte(keys.String())
	}
	return s
}

// checkWriter passes everything to w as it comes except the lines that
// start with checkPrefix, which it keeps: a partial line is held back only
// while it could still be one of those (a sudo prompt, which ends in no
// newline, goes through at once).
type checkWriter struct {
	w     io.Writer
	held  []byte
	lines []string
	// passing: the current line is not one of ours (it went through).
	passing bool
}

func (c *checkWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if c.passing {
			if _, err := c.w.Write([]byte{b}); err != nil {
				return 0, err
			}
			if b == '\n' {
				c.passing = false
			}
			continue
		}
		if b == '\n' {
			line := strings.TrimSuffix(string(c.held), "\r")
			if rest, ok := strings.CutPrefix(line, checkPrefix); ok {
				c.lines = append(c.lines, rest)
			} else if _, err := c.w.Write(append(c.held, b)); err != nil {
				return 0, err
			}
			c.held = c.held[:0]
			continue
		}
		c.held = append(c.held, b)
		if n := len(c.held); n <= len(checkPrefix) && string(c.held) != checkPrefix[:n] {
			if _, err := c.w.Write(c.held); err != nil {
				return 0, err
			}
			c.held, c.passing = c.held[:0], true
		}
	}
	return len(p), nil
}

// flush passes on a last line without a newline.
func (c *checkWriter) flush() {
	if len(c.held) > 0 {
		_, _ = c.w.Write(c.held)
		c.held = c.held[:0]
	}
}

// Check runs CheckScript for names on target (here for 'local') as root,
// over one ssh connection it closes at the end, and reads what it printed.
// Everything else the host prints (ssh's and sudo's messages, a sudo
// prompt) goes through. code is the remote command's exit status: 0 when
// the check ran; with a password sudo and no terminal it is 1 after the
// message 'host sync' gives. A signal ends the command: ui.ErrInterrupted.
func (e *Env) Check(ctx context.Context, target, port, identity string, names []string) (HostState, int, error) {
	cw := &checkWriter{w: e.Out.Stdout}
	out := ui.Output{Stdout: cw, Stderr: e.Out.Stderr}
	script := CheckScript(names)
	var c execx.Cmd
	var s SSH
	if target == Local {
		c = execx.Cmd{Name: "bash", Args: []string{"-c", script}}
	} else {
		s = e.ssh(port, identity)
		tty := e.stdinTTY()
		args := []string{"-T"}
		if tty {
			args = []string{"-o", "LogLevel=ERROR", "-t"}
		}
		c = s.Cmd(append(args, target, "s="+remoteWord(script)+"; "+asRoot(`bash -c "$s"`, tty))...)
	}
	code, intr, err := Attached(ctx, e.Runner, c, e.Stdin, out)
	cw.flush()
	if target != Local {
		closer := s.Cmd("-O", "exit", target)
		closer.Stdout, closer.Stderr = io.Discard, io.Discard
		_, _ = e.Runner.Run(context.WithoutCancel(ctx), closer)
	}
	if intr {
		return HostState{}, code, ui.ErrInterrupted
	}
	if err != nil && code == 0 {
		code = 1
	}
	return ParseCheck(cw.lines), code, nil
}
