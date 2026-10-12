package cli

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/app"
)

// noSudo are the first words that run as the invoking user: 'hash' as in
// bash (bin/tacctl.sh), and the completion entry points, which must never
// prompt for a password or read /etc/tacctl (docs/plans/go-rewrite.md 3.2).
// A new such word is one entry.
var noSudo = map[string]bool{
	"hash":             true,
	"completion":       true,
	"__complete":       true,
	"__completeNoDesc": true,
	// The interactive shell (0.2.1) runs as the user and re-enters tacctl
	// under sudo for each line it executes.
	"shell": true,
	// ssh runs the helper of the password cache as the user it was run as
	// (SSH_ASKPASS, askpass_cmd.go): no sudo, no tier gate, no preflight.
	"_askpass": true,
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

// keepEnv are the first words whose re-exec carries variables of the
// invoker across sudo's env_reset, as command-line assignments: 'host'
// runs ssh as the invoking user to enrol and sync hosts with their agent
// (bin/tacctl.sh). 'tacctl ssh' does not: its sessions log in by password,
// never with the agent. sudo accepts 'SSH_AUTH_SOCK=...' without a SETENV
// tag because both tacctl drop-ins keep it ('Defaults!<tacctl> env_keep +=
// "SSH_AUTH_SOCK"', tier.EnvKeep); a rule that matches ALL (a superuser's
// own sudoers line, with or without the drop-ins) allows it anyway. The
// assignment, rather than env_keep alone, is what carries the socket for
// the latter, where tacctl's Defaults line may not be installed. A later
// word that needs the same is one entry; it must be in tier.EnvKeep too.
var keepEnv = map[string][]string{
	"host": {"SSH_AUTH_SOCK"},
}

// sudoArgv is the argv of the re-exec: 'sudo <exe> <args>', with
// 'NAME=<value>' before <exe> for each keepEnv variable of the first word
// that is set and not empty in env.
func sudoArgv(exe string, args []string, env func(string) string) []string {
	argv := []string{"sudo"}
	if len(args) > 0 {
		for _, name := range keepEnv[args[0]] {
			if v := env(name); v != "" {
				argv = append(argv, name+"="+v)
			}
		}
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
	argv := sudoArgv(exe, a.Args, a.Env.Get)
	if err := a.Runner.Exec(sudo, argv, a.Env.Environ()); err != nil {
		return &ExitError{Code: 126, Err: fmt.Errorf("cannot run %s: %v", sudo, err)}
	}
	return nil
}
