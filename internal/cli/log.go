package cli

import "github.com/spf13/cobra"

// The 'log' family (lib/service.sh cmd_log at 0.1.16). Delegated until WP2.4d.
func logCmd() *cobra.Command {
	return verb("log", "Log viewer (tail, search, failures, accounting; --backend <id>)",
		verb("tail", "Show the last N log entries"),
		verb("search", "Search the logs for a username or keyword"),
		verb("failures", "Show auth failures from the last 24 hours"),
		verb("accounting", "Show last N accounting log entries"),
		verb("clear", "Purge each backend's logs (confirms)"),
	)
}
