// Package gitx is how tacctl runs a git command that talks to a remote
// (clone, fetch, pull): the tacquito source and tacctl's own deploy clone
// share it, so both are guarded the same way.
package gitx

import (
	"context"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/execx"
)

// Net returns c, a git command that talks to the remote (Name "git"), run so
// that it cannot wait for an operator who is not there: tacctl's stdin is
// the null device, but git asks on the terminal (/dev/tty) for a user name,
// a password or a key passphrase, and a stalled transfer waits for ever.
//
// It is run through env(1), so that the environment is not read here (only
// internal/paths reads it): GIT_TERMINAL_PROMPT=0 and a GIT_ASKPASS that
// fails end the prompt, SSH_ASKPASS is unset, the remote shell runs with
// BatchMode=yes (after the core.sshCommand of the clone, or of git's
// configuration for a clone not made yet; a GIT_SSH_COMMAND of the operator
// is replaced), and an http transfer slower than 1000 bytes per second for
// 60 seconds is dropped. The other fields of c (Dir, Stdout, Stderr, ...)
// are kept. The leading '-C <dir>' of c, when it has one, is also where
// core.sshCommand is read; a command with neither '-C' nor a Dir (the clone
// not made yet) reads it from "/", not from tacctl's working directory, so
// that the repository the operator stands in does not leak its local
// configuration into the clone: only the global and system configuration
// apply, as for a plain 'git clone'.
func Net(ctx context.Context, r execx.Runner, c execx.Cmd) execx.Cmd {
	remoteShell := "ssh"
	lookup := execx.Cmd{Name: "git", Dir: c.Dir}
	if len(c.Args) >= 2 && c.Args[0] == "-C" {
		lookup.Args = append(lookup.Args, c.Args[:2]...)
	} else if c.Dir == "" {
		lookup.Dir = "/"
	}
	lookup.Args = append(lookup.Args, "config", "--get", "core.sshCommand")
	if res, err := r.Run(ctx, lookup); err == nil && res.Code == 0 {
		if cfg := strings.TrimSpace(string(res.Stdout)); cfg != "" {
			remoteShell = cfg
		}
	}
	args := []string{"-u", "SSH_ASKPASS", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=false",
		"GIT_SSH_COMMAND=" + remoteShell + " -o BatchMode=yes",
		c.Name, "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=60"}
	c.Args = append(args, c.Args...)
	c.Name = "env"
	return c
}

// Unwrap is the git command behind a Net command: the 'env ... git -c ...
// <args>' it runs becomes 'git <args>'; any other command is as it is. It is
// for tests that look at what a guarded command does.
func Unwrap(c execx.Cmd) execx.Cmd {
	if c.Name != "env" {
		return c
	}
	i := slices.Index(c.Args, "git")
	if i < 0 {
		return c
	}
	rest := c.Args[i+1:]
	for len(rest) >= 2 && rest[0] == "-c" {
		rest = rest[2:]
	}
	c.Name, c.Args = "git", rest
	return c
}
