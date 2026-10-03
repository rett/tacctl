package cli

import "github.com/spf13/cobra"

// versionCmd is 'version', '--version' and '-v' (bin/tacctl.sh): the first
// command the Go binary owns. Extra arguments are ignored, as in bash, except
// '--long'.
func versionCmd(inv *invocation) *cobra.Command {
	c := verb("version", "Print tacctl version")
	c.Aliases = []string{"--version", "-v"}
	c.RunE = func(_ *cobra.Command, args []string) error {
		if tierManaged(inv.ctx, inv.app) {
			return delegate(inv.app)
		}
		writeVersion(inv.app.Out.Stdout, inv.build, len(args) > 0 && args[0] == "--long")
		return nil
	}
	return c
}
