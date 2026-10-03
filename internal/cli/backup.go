package cli

import "github.com/spf13/cobra"

// The 'backup' family (lib/service.sh cmd_backup at 0.1.16). Delegated until WP2.4d.
func backupCmd() *cobra.Command {
	return verb("backup", "Backup management (list, diff, restore)",
		verb("list", "Show snapshots, then old-style backups"),
		verb("diff", "Diff store.yaml and tacctl.yaml against a snapshot"),
		verb("restore", "Restore a snapshot (with confirmation)"),
	)
}
