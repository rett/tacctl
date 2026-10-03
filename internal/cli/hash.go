package cli

import "github.com/spf13/cobra"

// The 'hash' family (lib/users.sh cmd_hash at 0.1.16): runs as the invoking
// user, never under sudo (reexec.go). Delegated until WP2.4a.
func hashCmd() *cobra.Command {
	return verb("hash", "Bcrypt helper (generate, commands — runs as invoking user, no sudo)",
		verb("generate", "Prompt for a password and print its bcrypt hash"),
		verb("commands", "Show OS-specific one-liners for offline generation"),
	)
}
