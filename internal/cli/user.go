package cli

import "github.com/spf13/cobra"

// The 'user' family (lib/users.sh cmd_user at 0.1.16). Delegated until WP2.4a.
func userCmd() *cobra.Command {
	return verb("user", "User management (list, add, remove, passwd, scope, ...)",
		verb("list", "List all users (name, group, status, pw age, scopes)"),
		verb("show", "Show user details incl. scope membership"),
		verb("add", "Add a new user; lands in default scope"),
		verb("remove", "Remove a user"),
		verb("passwd", "Change a user's password"),
		verb("disable", "Disable a user (preserves hash)"),
		verb("enable", "Re-enable a disabled user"),
		verb("rename", "Rename a user"),
		verb("move", "Move user to a different group"),
		verb("verify", "Verify password and show user details"),
		// user scope <user> {list|add|remove|replace} [csv] | remove --all
		verb("scope", "Manage which scopes the user can auth from"),
	)
}
