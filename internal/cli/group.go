package cli

import "github.com/spf13/cobra"

// The 'group' family (lib/groups.sh cmd_group at 0.1.16). Delegated until WP2.4a.
func groupCmd() *cobra.Command {
	return verb("group", "Group management (list, add, edit, remove)",
		verb("list", "List all groups"),
		verb("add", "Add a new group"),
		verb("remove", "Remove a custom group"),
		verb("edit", "Change a group's priv-lvl or juniper-class"),
		verb("commands", "Per-group authorized commands",
			verb("list", "Show rules + default action"),
			verb("default", "Set default action (catchall)"),
			verb("add", "Add a rule"),
			verb("remove", "Drop a rule"),
			verb("clear", "Drop overrides — revert to shipped defaults (confirms)"),
			verb("seed", "Re-apply legacy seed set (recovery tool)"),
		),
		verb("privilege", "Per-group Cisco priv-exec mappings",
			verb("list", "Show mappings (explicit or default)"),
			verb("add", "Move one or more commands to the priv-lvl"),
			verb("remove", "Remove mapping(s)"),
			verb("clear", "Wipe explicit mappings (revert to defaults)"),
			verb("seed", "Populate built-ins with safe defaults"),
		),
	)
}
