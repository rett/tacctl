package hosts

import (
	"context"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// DefaultSSHOptions are the options every ssh of 'tacctl host' carries
// (_host_ssh): a connect timeout, and one shared connection per host for
// the whole command (the probe, the copy and the run), so a login that
// needs a password or a key passphrase asks once. The socket sits in the
// ssh user's own ~/.ssh (ssh expands the path itself); RunScript closes it,
// and it goes away by itself a minute after the last use.
var DefaultSSHOptions = []string{
	"-o", "ConnectTimeout=10",
	"-o", "ControlMaster=auto", "-o", "ControlPath=~/.ssh/tacctl-%C", "-o", "ControlPersist=60",
}

// SSH builds ssh commands the way _host_ssh does: run as AsUser through
// 'sudo -u <user> -H [env SSH_AUTH_SOCK=...]' when set, Options first, then
// BatchMode=yes when no terminal can answer a prompt, then -p and -i.
type SSH struct {
	// AsUser and AuthSock: the invoking user and their agent socket.
	AsUser, AuthSock string
	// Options is the option vector (DefaultSSHOptions for 'tacctl host').
	Options []string
	// Batch adds '-o BatchMode=yes' (no terminal: fail instead of waiting
	// on a password or host-key prompt nobody can answer).
	Batch bool
	// Port and Identity, when set, are -p and -i.
	Port, Identity string
}

// Cmd is the ssh command with args after the options.
func (s SSH) Cmd(args ...string) execx.Cmd {
	argv := append([]string(nil), s.Options...)
	if s.Batch {
		argv = append(argv, "-o", "BatchMode=yes")
	}
	if s.Port != "" {
		argv = append(argv, "-p", s.Port)
	}
	if s.Identity != "" {
		argv = append(argv, "-i", s.Identity)
	}
	c := execx.Cmd{Name: "ssh", Args: append(argv, args...)}
	if s.AsUser != "" {
		c.AsUser = s.AsUser
		if s.AuthSock != "" {
			c.UserEnv = []string{"SSH_AUTH_SOCK=" + s.AuthSock}
		}
	}
	return c
}

// ssh is the SSH of this invocation for a host.
func (e *Env) ssh(port, identity string) SSH {
	return SSH{
		AsUser: e.AsUser, AuthSock: e.AuthSock, Options: DefaultSSHOptions,
		Batch: !e.tty(), Port: port, Identity: identity,
	}
}

// Attached runs c with the terminal (execx.Attached, shared with 'tacctl
// shell'): a remote 'trap ... exit 130' comes back as 130, and interrupted
// reports whether ctx was cancelled meanwhile.
func Attached(ctx context.Context, r execx.Runner, c execx.Cmd, stdin io.Reader, out ui.Output) (code int, interrupted bool, err error) {
	return execx.Attached(ctx, r, c, stdin, out.Stdout, out.Stderr)
}

// remoteWord quotes a script argument for the remote shell: as it is when
// it holds only characters no shell treats specially, else in single
// quotes. The arguments tacctl passes (--accounts-only, --allow-uid-mismatch,
// ...) are validated to the first kind, so the command reads as 0.1.16's.
func remoteWord(w string) string {
	if w != "" && strings.Trim(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./,:=+@%-") == "" {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}

// RemoteCommand is the command host_run_script runs on the host for the
// copy at remote: the copy is removed however the shell ends, a hang-up or
// interrupt ends it with 130, and the script runs as root (directly, or
// through sudo). With a terminal sudo may ask for a password (the prompt
// names the host, since 'host sync --all' asks once per host); without one
// only passwordless sudo or a root login can work, so it says so instead
// of failing on sudo's own message.
func RemoteCommand(remote string, args []string, tty bool) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = remoteWord(a)
	}
	run := "bash " + remote + " " + strings.Join(q, " ")
	inner := ""
	if tty {
		inner = "sudo -p '[sudo] password for %u on %H: ' " + run
	} else {
		inner = "if sudo -n true 2>/dev/null; then sudo -n " + run + "; else echo '[ERROR] sudo on this host needs a password and there is no terminal to ask on. Run tacctl host from a terminal, allow passwordless sudo for this login, or log in as root.' >&2; false; fi"
	}
	return "trap 'rm -f " + remote + "' EXIT; trap 'exit 130' HUP INT TERM; if [ \"$(id -u)\" = 0 ]; then " + run + "; else " + inner + "; fi"
}

// copyCommand makes a private temp file on the host, fills it from stdin
// and prints its name.
const copyCommand = `umask 077; f=$(mktemp /tmp/tacctl.XXXXXXXX) && cat > "$f" && echo "$f"`

var reRemoteCopy = regexp.MustCompile(`^/tmp/tacctl\.[A-Za-z0-9]+$`)

// RunScript is host_run_script: it copies script to the host and runs it
// as root there with args, over one ssh connection that it closes at the
// end; the copy is deleted afterwards (an install script holds the scope
// secret). For target 'local' it runs the script here. It returns the
// script's exit status (a failed copy is 1, its error printed). A signal
// during the run ends the command: ui.ErrInterrupted.
func (e *Env) RunScript(ctx context.Context, target, port, identity, script string, args []string) (int, error) {
	// The script's output goes through as it comes; its account summary is
	// kept for the caller.
	e.Summary = nil
	sw := &summaryWriter{w: e.Out.Stdout}
	out := ui.Output{Stdout: sw, Stderr: e.Out.Stderr}
	defer func() { e.Summary = sw.sum }()
	if target == Local {
		code, intr, err := Attached(ctx, e.Runner, execx.Cmd{Name: "bash", Args: append([]string{script}, args...)}, e.Stdin, out)
		if intr {
			return code, ui.ErrInterrupted
		}
		if err != nil {
			return code, err
		}
		return code, nil
	}
	e.sessionKeys, e.sessionErr = nil, nil
	s := e.ssh(port, identity)
	f, err := os.Open(script)
	if err != nil {
		return 1, err
	}
	c := s.Cmd(target, copyCommand)
	c.Stdin, c.Stderr = f, e.Out.Stderr
	res, err := e.Runner.Run(ctx, c)
	_ = f.Close()
	if interrupted(ctx) {
		return 130, ui.ErrInterrupted
	}
	if err != nil || res.Code != 0 {
		e.Out.ErrorE("Could not copy the script to " + target + " (ssh failed).")
		return 1, nil
	}
	remote := strings.TrimRight(string(res.Stdout), "\n")
	if !reRemoteCopy.MatchString(remote) {
		e.Out.ErrorE("Unexpected reply from " + target + " while copying the script.")
		return 1, nil
	}
	tty := e.stdinTTY()
	flag := "-T"
	if tty {
		flag = "-t"
	}
	code, intr, startErr := Attached(ctx, e.Runner, s.Cmd(flag, target, RemoteCommand(remote, args, tty)), e.Stdin, out)
	if startErr != nil && code == 0 {
		code = 1
	}
	// The host's own public keys, read over this connection for PinKeys.
	if e.ReadKeys && code == 0 && !intr {
		e.readKeys(ctx, s, target)
	}
	closer := s.Cmd("-O", "exit", target)
	closer.Stdout, closer.Stderr = io.Discard, io.Discard
	_, _ = e.Runner.Run(context.WithoutCancel(ctx), closer)
	if intr {
		return code, ui.ErrInterrupted
	}
	return code, nil
}
