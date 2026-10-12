package cli

// '_askpass <prompt>': the program ssh runs as SSH_ASKPASS when 'tacctl ssh'
// has a cached password (D70, ssh.go). It runs as the user, on ssh's
// request, with TACCTL_ASKPASS in its environment: it answers a prompt that
// is a password prompt (askpass.IsPasswordPrompt: never a host-key
// question, a passphrase or a one-time code) with what the session's
// agent hands it, once, and exits 1 with no output for anything else.
//
// ssh gives its askpass program no arguments of its own, so SSH_ASKPASS is
// the tacctl binary and the marker askpass.HelperEnv in the environment
// turns 'tacctl <prompt>' into this verb (askpassHelperArgs, Main).

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/askpass"
)

func init() { registerFamily(askpassHelperCmd) }

func askpassHelperCmd(inv *invocation) *cobra.Command {
	c := hidden("_askpass")
	// No gate, no preflight, no warnings: the helper runs as the user, is
	// not run through sudo, and writes the password and nothing else.
	c.RunE = func(_ *cobra.Command, args []string) error { return inv.askpassHelper(args) }
	return c
}

// askpassHelperArgs rewrites the command line of an ssh askpass call (one
// argument, the prompt, and the helper marker in the environment) into the
// helper verb.
func askpassHelperArgs(environ, args []string) []string {
	if len(args) == 1 && slices.Contains(environ, askpass.HelperEnv+"=1") {
		return []string{"_askpass", args[0]}
	}
	return args
}

func (inv *invocation) askpassHelper(args []string) error {
	a := inv.app
	if len(args) == 0 {
		return exit(1)
	}
	if err := askpass.RunHelper(inv.ctx, inv.askpassValue(), strings.Join(args, " "), a.Out.Stdout); err != nil {
		return exit(1)
	}
	return nil
}
