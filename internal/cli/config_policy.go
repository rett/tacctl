package cli

// 'config allow|deny' (lib/scopes.sh cmd_config_prefix_filter) and 'config
// mgmt-acl' (lib/render_devices.sh cmd_config_mgmt_acl) at 0.1.16, native
// since WP2.4b. The rest of 'config' belongs to WP2.4c (config.go): these
// families are built here and handed to config.go's tree through its
// registerConfigVerb hook (config_policy_register.go). bin/tacctl.sh runs
// preflight before every 'config' verb but 'render' with a store, so these
// run it.

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// configPolicySpecs are the arguments of each verb, for completion
// (args.go): the filter verbs (allow and deny alike) and mgmt-acl's.
var configPolicySpecs = map[string]Spec{
	"list":         {},
	"add":          {MinArgs: 1, MaxArgs: 1, Args: []string{""}},
	"remove":       {MinArgs: 1, MaxArgs: 1, Args: []string{""}},
	"clear":        {},
	"cisco-name":   {MaxArgs: 1, Args: []string{""}},
	"juniper-name": {MaxArgs: 1, Args: []string{""}},
}

// configPolicyFamilySpecs are the specs of the three family words, as
// config.go's registerConfigVerb takes them (config_policy_register.go).
var configPolicyFamilySpecs = map[string]Spec{
	"allow":    {MaxArgs: 2, Args: []string{"list|add|remove|clear", ""}},
	"deny":     {MaxArgs: 2, Args: []string{"list|add|remove|clear", ""}},
	"mgmt-acl": {MaxArgs: 2, Args: []string{"list|add|remove|clear|cisco-name|juniper-name", ""}},
}

// configAllowCmd, configDenyCmd and configMgmtACLCmd build the three
// families, native: the family word runs its dispatcher with the
// arguments, and each verb runs it with the verb put back in front, so
// 'config allow add x' and the family given 'add x' are the same call.
// config.go replaces its declared words of these names with them
// (registerConfigVerb, config_policy_register.go).
func configAllowCmd(inv *invocation) *cobra.Command {
	return configPolicyFamily(inv, "allow", "Manage connection allow list",
		func(args []string) error { return inv.configFilter("allow", args) }, configFilterVerbs)
}

func configDenyCmd(inv *invocation) *cobra.Command {
	return configPolicyFamily(inv, "deny", "Manage connection deny list",
		func(args []string) error { return inv.configFilter("deny", args) }, configFilterVerbs)
}

func configMgmtACLCmd(inv *invocation) *cobra.Command {
	return configPolicyFamily(inv, "mgmt-acl", "Manage Cisco VTY-ACL + Juniper lo0-filter permits", inv.configMgmtACL, [][2]string{
		{"list", "Show current permits"},
		{"add <cidr>[,<cidr>...]", "Add one or more CIDRs"},
		{"remove <cidr>[,<cidr>...]", "Remove one or more CIDRs"},
		{"clear", "Wipe all permits (confirms)"},
		{"cisco-name [name]", "Show or set the Cisco ACL name"},
		{"juniper-name [name]", "Show or set the Juniper filter name"},
	})
}

// configFilterVerbs are the verbs of allow and deny ({Use, Short}).
var configFilterVerbs = [][2]string{
	{"list", "Show the list"},
	{"add <cidr>[,<cidr>...]", "Add one or more CIDRs"},
	{"remove <cidr>[,<cidr>...]", "Remove one or more CIDRs"},
	{"clear", "Wipe all (confirms)"},
}

func configPolicyFamily(inv *invocation, name, short string, run func([]string) error, verbs [][2]string) *cobra.Command {
	c := verb(name+" <subcommand>", short)
	c.RunE = inv.native(withPreflight, run)
	for _, v := range verbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return run(append([]string{word}, args...))
		})))
	}
	return c
}

// configFilterUsage is the help of 'config allow|deny' (label), with the
// number of entries.
func configFilterUsage(label string, entries int) string {
	return Usage("config-filter", UsageVars{"label": label, "current": fmt.Sprintf("Current entries: %d", entries)})
}

// configMgmtACLUsage is the help of 'config mgmt-acl', with the names in
// effect and the number of permits.
func configMgmtACLUsage(cisco, juniper string, entries int) string {
	return Usage("config-mgmt-acl", UsageVars{"current": fmt.Sprintf("         cisco=%s  juniper=%s\nCurrent entries: %d", cisco, juniper, entries)})
}

// --- allow / deny -----------------------------------------------------------

// configFilter is cmd_config_prefix_filter for label allow or deny; args
// are what follows 'config <label>'.
func (inv *invocation) configFilter(label string, args []string) error {
	a := inv.app
	sub, value := arg(args, 0), arg(args, 1)
	switch sub {
	case "add", "remove", "clear":
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	current := m.Filters.Allow
	if label == "deny" {
		current = m.Filters.Deny
	}
	current = append([]string(nil), current...)

	switch sub {
	case "", "-h", "--help", "help":
		inv.write(configFilterUsage(label, countNonEmpty(current)))
	case "list":
		inv.echo("")
		inv.echoE(ui.Bold + "Connection " + label + " list" + ui.NC)
		inv.echo("--------------------------------------------")
		switch {
		case captured(current) != "":
			for _, e := range strings.Split(captured(current), "\n") {
				inv.echo("  - " + e)
			}
		case label == "allow":
			inv.echo("  (empty — all connections allowed)")
		default:
			inv.echo("  (empty — no connections denied)")
		}
		inv.echo("")
		inv.echoE("  " + ui.Cyan + "Note: deny takes precedence over allow." + ui.NC)
		inv.echo("")
	case "add", "remove":
		if value == "" {
			return inv.usageErr("Usage: tacctl config " + label + " " + sub + " <cidr>[,<cidr>...]")
		}
		requested, err := inv.parseCIDRList(value)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			return inv.usageErr("No valid CIDRs provided.")
		}
		var changed, skipped []string
		for _, c := range requested {
			has := contains(current, c)
			switch {
			case sub == "add" && !has:
				changed = append(changed, c)
				current = append(current, c)
			case sub == "remove" && has:
				changed = append(changed, c)
				current = without(current, c)
			default:
				skipped = append(skipped, c)
			}
		}
		if len(changed) == 0 {
			if sub == "add" {
				a.Out.Info("No new CIDRs to add to " + label + " list (already present: " + strings.Join(skipped, " ") + ").")
				inv.echo("")
			} else {
				a.Out.Warn("Nothing to remove from " + label + " list (not present: " + strings.Join(skipped, " ") + ").")
			}
			return nil
		}
		csv := joinNonEmpty(current, ",")
		if err := inv.applyStore(func(s *store.Store) error { return s.FiltersSet(label, csv) }); err != nil {
			return err
		}
		if sub == "add" {
			a.Out.Info(fmt.Sprintf("Added %d to %s list: %s", len(changed), label, strings.Join(changed, " ")))
			if len(skipped) > 0 {
				a.Out.Info("(Already present, unchanged: " + strings.Join(skipped, " ") + ")")
			}
		} else {
			a.Out.Info(fmt.Sprintf("Removed %d from %s list: %s", len(changed), label, strings.Join(changed, " ")))
			if len(skipped) > 0 {
				a.Out.Info("(Not present, skipped: " + strings.Join(skipped, " ") + ")")
			}
		}
		inv.echo("")
	case "clear":
		if captured(current) == "" {
			a.Out.Info(label + " list is already empty.")
			return nil
		}
		n := len(strings.Split(captured(current), "\n"))
		// Clearing either list removes a restriction: say what the
		// resulting posture is.
		if label == "allow" {
			a.Out.Warn("Clearing the allow list fails open: all source IPs become eligible")
			a.Out.Warn("to connect (subject to 'deny' and the secret-provider prefixes).")
		} else {
			a.Out.Warn("Clearing the deny list removes all per-IP deny overrides;")
			a.Out.Warn("any source matching 'allow' (or all, if allow is empty) can connect.")
		}
		entries := "entr" + plural(n, "y", "ies")
		if !a.Prompter().ConfirmPrefix(fmt.Sprintf("  Clear all %d %s-list %s? [y/N]: ", n, label, entries)) {
			a.Out.Info("Aborted.")
			return nil
		}
		if err := inv.applyStore(func(s *store.Store) error { return s.FiltersSet(label, "") }); err != nil {
			return err
		}
		a.Out.Info(fmt.Sprintf("Cleared %s list (%d %s removed).", label, n, entries))
		inv.echo("")
	default:
		inv.echo("")
		inv.echo("Usage: tacctl config " + label + " <list|add|remove|clear> [cidr[,cidr...]]")
		inv.echo("")
		return exit(1)
	}
	return nil
}

// --- mgmt-acl ---------------------------------------------------------------

// configMgmtACL is cmd_config_mgmt_acl: the global permit list and ACL /
// filter names in tacctl.yaml (mgmt_acl.*). tacquito never reads them, so
// nothing is rendered or restarted.
func (inv *invocation) configMgmtACL(args []string) error {
	a := inv.app
	sub, value := arg(args, 0), arg(args, 1)
	switch sub {
	case "", "-h", "--help", "help":
		inv.write(configMgmtACLUsage(inv.readMgmtACLName("cisco", ""), inv.readMgmtACLName("juniper", ""), len(inv.readMgmtACLCIDRs(""))))
	case "list":
		inv.echo("")
		inv.echoE(ui.Bold + "Management ACL (shared Cisco VTY-ACL + Juniper lo0 filter source)" + ui.NC)
		inv.echo("--------------------------------------------")
		if entries := inv.readMgmtACLCIDRs(""); len(entries) == 0 {
			inv.echo("  (empty)")
			inv.echo("")
			inv.echo("  Add with: tacctl config mgmt-acl add <cidr>")
			inv.echo("  Cisco/Juniper output uses a scaffold/comment until populated.")
		} else {
			for _, e := range entries {
				inv.echo("  - " + e)
			}
		}
		inv.echo("")
	case "add", "remove":
		if value == "" {
			return inv.usageErr("Usage: tacctl config mgmt-acl " + sub + " <cidr>[,<cidr>...]")
		}
		requested, err := inv.parseCIDRList(value)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			return inv.usageErr("No valid CIDRs provided.")
		}
		current := inv.readMgmtACLCIDRs("")
		if sub == "remove" && len(current) == 0 {
			a.Out.Warn("Nothing to remove — mgmt-acl permit list is empty.")
			return nil
		}
		var changed, skipped []string
		for _, c := range requested {
			has := contains(current, c)
			switch {
			case sub == "add" && !has:
				changed = append(changed, c)
				current = append(current, c)
			case sub == "remove" && has:
				changed = append(changed, c)
				current = without(current, c)
			default:
				skipped = append(skipped, c)
			}
		}
		if len(changed) == 0 {
			if sub == "add" {
				a.Out.Info("No new CIDRs to add (already present: " + strings.Join(skipped, " ") + ").")
				inv.echo("")
			} else {
				a.Out.Warn("Nothing to remove (not present: " + strings.Join(skipped, " ") + ").")
			}
			return nil
		}
		if err := inv.writeMgmtACLCIDRs(current, ""); err != nil {
			return err
		}
		if sub == "add" {
			a.Out.Info(fmt.Sprintf("Added %d to mgmt-acl: %s", len(changed), strings.Join(changed, " ")))
			if len(skipped) > 0 {
				a.Out.Info("(Already present, unchanged: " + strings.Join(skipped, " ") + ")")
			}
			a.Out.Info("Re-run 'tacctl config cisco' / 'tacctl config juniper' to see the new output.")
		} else {
			a.Out.Info(fmt.Sprintf("Removed %d from mgmt-acl: %s", len(changed), strings.Join(changed, " ")))
			if len(skipped) > 0 {
				a.Out.Info("(Not present, skipped: " + strings.Join(skipped, " ") + ")")
			}
		}
		inv.echo("")
	case "clear":
		if len(inv.readMgmtACLCIDRs("")) == 0 {
			a.Out.Info("Already empty.")
			inv.echo("")
			return nil
		}
		if !a.Prompter().ConfirmPrefix("  Clear all mgmt-acl entries? [y/N]: ") {
			a.Out.Info("Aborted.")
			return nil
		}
		if err := a.Conf().Unset("mgmt_acl.permits"); err != nil {
			return err
		}
		a.Out.Info("mgmt-acl cleared.")
		inv.echo("")
	case "cisco-name", "juniper-name":
		which := strings.TrimSuffix(sub, "-name")
		def := ciscoACLNameDefault
		if which == "juniper" {
			def = juniperACLNameDefault
		}
		current := inv.readMgmtACLName(which, "")
		if value == "" {
			inv.echo("")
			inv.echo("  " + which + "-name: " + current)
			if current == def {
				inv.echo("  (default — override with 'tacctl config mgmt-acl " + sub + " <name>')")
			} else {
				inv.echo("  (override in tacctl.yaml: mgmt_acl.names." + which + ")")
			}
			inv.echo("")
			return nil
		}
		if err := names.ValidateACLName(value); err != nil {
			return inv.validated(err)
		}
		if value == current {
			a.Out.Info(which + "-name already '" + value + "'; no change.")
			inv.echo("")
			return nil
		}
		if err := a.Conf().Set("mgmt_acl.names."+which, value); err != nil {
			return err
		}
		a.Out.Info("Set " + which + "-name = '" + value + "'.")
		a.Out.Info("Re-run 'tacctl config " + which + "' to see the new name in the output.")
		inv.echo("")
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", "Run 'tacctl config mgmt-acl' with no arguments for help.")
	}
	return nil
}
