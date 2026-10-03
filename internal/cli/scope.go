package cli

import "github.com/spf13/cobra"

// The 'scope' family (lib/scopes.sh cmd_scope at 0.1.16). The sub-families
// take the scope name before their verb (scope prefixes <scope> add ...), so
// their verbs are arguments, not sub-commands. Delegated until WP2.4b.
func scopeCmd() *cobra.Command {
	return verb("scope", "Scope management (named CIDR + shared-secret bundles)",
		verb("list", "One row per scope (aggregated prefix list)"),
		verb("routing", "One row per (scope, prefix) — first-match order"),
		verb("show", "Detailed view"),
		verb("add", "Create a new scope"),
		verb("remove", "Delete a scope (confirms)"),
		verb("rename", "Rename (updates user references)"),
		verb("default", "Show or set the default scope"),
		verb("lookup", "Show which scope owns an address"),
		verb("prefixes", "Manage a scope's CIDR list"),
		verb("secret", "Manage a scope's shared secret"),
		verb("protocols", "Limit a scope to some protocols (tacacs, radius); default: all"),
		verb("vendor-attrs", "RADIUS: vendor privilege attributes sent to the scope's devices"),
		verb("devices", "RADIUS: tag an address of the scope with its vendor"),
		verb("aaa-order", "AAA method-list order in this scope's rendered device configs"),
		verb("exec-timeout", "Per-scope idle-session timeout in rendered device configs"),
		verb("tacacs-group", "Per-scope Cisco aaa-group-server label"),
		verb("radius-group", "Per-scope Cisco aaa-group-server label for RADIUS"),
		verb("auth-method", "Protocol this scope's device configs and host enrollments use"),
		verb("mgmt-acl", "Per-scope permit list and ACL / filter names"),
	)
}
