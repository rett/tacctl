package cli

import "github.com/spf13/cobra"

// versionCmd is 'version', '--version' and '-v' (bin/tacctl.sh): the first
// command the Go binary owns, behind the tier gate like every native one.
// Extra arguments are ignored, as in bash, except '--long'.
func versionCmd(inv *invocation) *cobra.Command {
	c := verb("version [--long]", "Print tacctl version")
	c.Aliases = []string{"--version", "-v"}
	c.RunE = inv.native(noPreflight, func(args []string) error {
		writeVersion(inv.app.Out.Stdout, inv.build, len(args) > 0 && args[0] == "--long")
		return nil
	})
	return c
}
