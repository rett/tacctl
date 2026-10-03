package cli

import "github.com/spf13/cobra"

// The top-level verbs outside the families (bin/tacctl.sh's dispatch at
// 0.1.16): install, upgrade, uninstall (lib/lifecycle.sh), status
// (lib/service.sh) and passwd (lib/users.sh). All delegated until Phase 3
// (status: WP2.4d, passwd: WP2.4a).
func lifecycleCmds() []*cobra.Command {
	return []*cobra.Command{
		verb("install", "Install tacctl and the TACACS+ backend (tacquito) from scratch"),
		verb("upgrade", "Pull latest source, rebuild, update scripts and every enabled backend"),
		verb("uninstall", "Remove tacctl, its backends' services and all associated files"),
		verb("status", "Show service health, stats, and recent errors (per backend)"),
		verb("passwd", "Change your own password (asks for the current one)"),
	}
}
