package cli

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/app"
)

// noSudo are the first words that run as the invoking user: 'hash' as in
// bash (bin/tacctl.sh), and the completion entry points, which must never
// prompt for a password or read /etc/tacctl (docs/plans/go-rewrite.md 3.2).
var noSudo = map[string]bool{
	"hash":             true,
	"completion":       true,
	"__complete":       true,
	"__completeNoDesc": true,
}

// needsSudo is bin/tacctl.sh's re-exec condition: not root, not
// TACCTL_SKIP_SUDO=1, and a command that needs root.
func needsSudo(a *app.App) bool {
	if a.EUID == 0 || a.Paths.SkipSudo {
		return false
	}
	first := ""
	if len(a.Args) > 0 {
		first = a.Args[0]
	}
	return !noSudo[first]
}

// sudoArgv is the argv of the re-exec: 'sudo <exe> <args>', and for 'host'
// with an agent socket 'sudo SSH_AUTH_SOCK=<sock> <exe> <args>' (sudo's
// env_reset would drop it; ssh runs as the invoking user and needs it).
func sudoArgv(exe string, args []string, sshAuthSock string) []string {
	argv := []string{"sudo"}
	if len(args) > 0 && args[0] == "host" && sshAuthSock != "" {
		argv = append(argv, "SSH_AUTH_SOCK="+sshAuthSock)
	}
	argv = append(argv, exe)
	return append(argv, args...)
}

// reexec replaces tacctl with itself under sudo, environment unchanged
// (sudo applies its own policy to it).
func reexec(a *app.App) error {
	sudo, err := a.Runner.LookPath("sudo")
	if err != nil {
		return &ExitError{Code: 127, Err: fmt.Errorf("sudo not found (%v): run tacctl as root", err)}
	}
	exe := a.Exe
	if exe == "" || !strings.HasPrefix(exe, "/") {
		return &ExitError{Code: 1, Err: fmt.Errorf("cannot locate the tacctl executable to re-run it under sudo")}
	}
	argv := sudoArgv(exe, a.Args, a.Env.Get("SSH_AUTH_SOCK"))
	if err := a.Runner.Exec(sudo, argv, a.Env.Environ()); err != nil {
		return &ExitError{Code: 126, Err: fmt.Errorf("cannot run %s: %v", sudo, err)}
	}
	return nil
}
