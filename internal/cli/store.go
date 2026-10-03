package cli

import "github.com/spf13/cobra"

// The 'store' family (lib/store.sh cmd_store at 0.1.16). Delegated until
// WP2.4d (rollback: Phase 3).
func storeCmd() *cobra.Command {
	return verb("store", "The canonical store: show, import, rollback",
		verb("show", "Print the model (YAML by default)"),
		verb("import", "Import a legacy tacquito.yaml (default: the live one)"),
		verb("rollback", "Undo the import: restore the pre-store tacquito.yaml"),
	)
}
