package cli

import "github.com/spf13/cobra"

// The 'backend' family (lib/backend.sh cmd_backend at 0.1.16). Delegated
// until WP2.4d (enable|disable: WP3.3c).
func backendCmd() *cobra.Command {
	return verb("backend", "Auth backends: list, status, enable <id>, disable <id>",
		verb("list", "Every backend: protocol, implementation, installed, enabled, service"),
		verb("status", "Service and listener state of every backend (or one)"),
		verb("enable", "Install the backend if needed, enable it, render its config, start it"),
		verb("disable", "Stop and disable it, take it out of backends.enabled (confirms)"),
	)
}
