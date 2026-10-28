package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/app"
)

// noSudo are the first words that run as the invoking user: 'hash' as in
// bash (bin/tacctl.sh), and the completion entry points, which must never
// prompt for a password or read /etc/tacctl (docs/plans/go-rewrite.md 3.2).
// A new such word is one entry.
var noSudo = map[string]bool{
	"hash":       true,
	"completion": true,
	// The manual page in a pager (man_cmd.go): for every tier and for the
	// console, whose users have no man command of their own.
	"man":              true,
	"__complete":       true,
	"__completeNoDesc": true,
	// The help of the words, for the bash help key (help_request.go).
	"__help": true,
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
// The caller's NO_COLOR and TACCTL_COLOR are not here: env_keep carries a
// variable of the caller's environment through sudo by itself, with no
// assignment on the command line (the colour decision of the root process,
// app.New, reads them).
var keepEnv = map[string][]string{
	"host": {"SSH_AUTH_SOCK"},
}

// editorVarNames are the variables the lines that open an editor carry
// across sudo (editorLine): the caller's VISUAL and EDITOR.
var editorVarNames = []string{"VISUAL", "EDITOR"}

// editorLine reports whether args is one of the four command lines that open
// the caller's editor: 'scope block <scope> juniper edit|adopt ...' and
// 'device block <name> edit|adopt ...' (the lines tier.EditorKeep keeps the
// editor's variables for). Only those lines carry them: a sudoers rule that
// does not keep a variable for a line refuses it on the command line.
func editorLine(args []string) bool {
	switch {
	case len(args) >= 5 && args[0] == "scope" && args[1] == "block":
		return args[4] == "edit" || args[4] == "adopt"
	case len(args) >= 4 && args[0] == "device" && args[1] == "block":
		return args[3] == "edit" || args[3] == "adopt"
	}
	return false
}

// sudoArgv is the argv of the re-exec: 'sudo <exe> <args>', with
// 'NAME=<value>' before <exe> for each keepEnv variable of the first word
// that is set and not empty in env, and the editor's variables on the lines
// that open one.
func sudoArgv(exe string, args []string, env func(string) string) []string {
	argv := []string{"sudo"}
	if len(args) > 0 {
		names := keepEnv[args[0]]
		if editorLine(args) {
			names = append(slices.Clone(names), editorVarNames...)
		}
		for _, name := range names {
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
	_ = a.Close() // what the colour sink holds goes out before the image is replaced
	if err := a.Runner.Exec(sudo, argv, a.Env.Environ()); err != nil {
		return &ExitError{Code: 126, Err: fmt.Errorf("cannot run %s: %v", sudo, err)}
	}
	return nil
}
