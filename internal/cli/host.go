package cli

import "github.com/spf13/cobra"

// The 'host' family (lib/linux_hosts.sh cmd_host at 0.1.16). Delegated until WP3.2.
func hostCmd() *cobra.Command {
	return verb("host", "Linux hosts: enroll, sync, unenroll TACACS+ or RADIUS login over SSH",
		verb("list", "Show enrolled hosts"),
		verb("enroll", "Install TACACS+ or RADIUS login on a host over SSH and register it"),
		verb("sync", "Push account adds, removals and tier changes"),
		verb("unenroll", "Remove the login method from the host"),
		verb("default-method", "Show or set the method for hosts enrolled without --method"),
	)
}
