package devices

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// The variables each Cisco template may use (cmd_config_cisco's envsubst
// whitelists); anything else in a template is left as written.
var (
	ciscoTacacsVars = []string{"SERVER_IP", "SECRET", "PRIVILEGE_COMMANDS", "GROUP_SUMMARY", "VTY_ACL_BLOCK",
		"VTY_ACCESS_CLASS", "AUTHZ_COMMANDS_BLOCK", "ACCT_COMMANDS_BLOCK", "AUTHN_METHODS", "AUTHZ_EXEC_METHODS",
		"EXEC_TIMEOUT", "TACACS_GROUP", "SNMP_BLOCK", "NETCONF_BLOCK"}
	ciscoRadiusVars = []string{"SERVER_IP", "SECRET", "AUTH_PORT", "ACCT_PORT", "RADIUS_GROUP", "PRIVILEGE_COMMANDS",
		"GROUP_SUMMARY", "VTY_ACL_BLOCK", "VTY_ACCESS_CLASS", "AUTHN_METHODS", "AUTHZ_EXEC_METHODS", "EXEC_TIMEOUT",
		"SNMP_BLOCK", "NETCONF_BLOCK"}
)

// CiscoTemplate is the template a Cisco config renders: cisco,
// cisco-legacy (IOS 12.x) or cisco-radius.
func CiscoTemplate(legacy bool, protocol string) string {
	switch {
	case protocol == RADIUS:
		return "cisco-radius"
	case legacy:
		return "cisco-legacy"
	}
	return "cisco"
}

// CiscoVars are the template variables of a Cisco config (the values
// cmd_config_cisco exports to envsubst), and the group summary under it.
func CiscoVars(req Request, d Data) map[string]string {
	c, scope := d.Conf, req.Scope
	groups := privGroups(d.Model)

	// The privilege block: per group below priv-lvl 15 (level 1 too: a
	// monitoring group lowers show running-config to it), its mappings
	// ('tacctl group privilege') or the shipped default, each (level,
	// mode, command) once across groups. An entry may name its mode
	// (exec, exec all, configure, configure all); none is exec.
	var privilege strings.Builder
	seen := map[string]bool{}
	for _, g := range groups {
		if g.priv == "15" {
			continue
		}
		cmds := lines(policy.Privileges(c, g.name))
		if len(cmds) == 0 {
			cmds = lines(policy.DefaultPrivileges(g.name))
		}
		if len(cmds) == 0 {
			continue
		}
		block := "! --- " + g.name + " — Privilege Level " + g.priv + " Commands ---\n"
		emitted := false
		for _, entry := range cmds {
			if entry == "" {
				continue
			}
			mode, cmd, _ := names.SplitPrivEntry(entry)
			pair := g.priv + "|" + mode + "|" + cmd
			if seen[pair] {
				continue
			}
			seen[pair] = true
			block += "privilege " + mode + " level " + g.priv + " " + cmd + "\n"
			emitted = true
		}
		if emitted {
			privilege.WriteString(block + "!\n")
		}
	}

	var summary strings.Builder
	for _, g := range groups {
		summary.WriteString("  " + g.name + ": priv-lvl " + g.priv + "\n")
	}

	tacacsGroup := confGet(c, "tacacs_group."+scope, "TACACS-GROUP")
	radiusGroup := confGet(c, "radius_group."+scope, "RADIUS-GROUP")
	aaaGroup := tacacsGroup
	if req.Protocol == RADIUS {
		aaaGroup = radiusGroup
	}
	authn := "group " + aaaGroup + " local"
	authzExec := "group " + aaaGroup + " local if-authenticated"
	authzCmd := "group " + aaaGroup + " local"
	if localFirst(c, scope) {
		authn = "local group " + aaaGroup
		authzExec = "local group " + aaaGroup + " if-authenticated"
		authzCmd = "local group " + aaaGroup
	}

	levels := ciscoLevels(groups)
	authzCommands := "! Per-command authorization not enabled.\n! To restrict commands per group, use 'tacctl group commands'."
	if anyGroupHasCommands(c) {
		authzCommands = ciscoAuthzBlock(c, groups, levels, authzCmd)
	}
	// Command accounting: one line per level in use, whether or not any
	// group has rules.
	acct := make([]string, 0, len(levels))
	for _, l := range levels {
		acct = append(acct, "aaa accounting commands "+strconv.Itoa(l)+" default start-stop group "+tacacsGroup)
	}

	// The VTY ACL from the management ACL; IPv6 entries are skipped (they
	// would need an 'ipv6 access-list'). An empty list emits comments only,
	// so the output stays safe to paste.
	aclName := d.ACL.Name
	var entries strings.Builder
	for _, e := range d.mgmtPermits() {
		if wc := cidr.CiscoWildcard(e); wc != "" {
			entries.WriteString("  permit " + wc + "\n")
		}
	}
	var aclBlock, accessClass string
	if entries.Len() > 0 {
		aclBlock = "ip access-list standard " + aclName + "\n" +
			"  remark Managed by tacctl — edit with 'tacctl config mgmt-acl'\n" +
			entries.String() + "  deny   any log"
		accessClass = "  access-class " + aclName + " in"
	} else {
		flag := ""
		if req.Protocol == RADIUS {
			flag = " --protocol radius"
		}
		aclBlock = "! " + aclName + " not emitted — mgmt-acl list is empty.\n" +
			"! Populate it on the tacctl server with\n" +
			"!   tacctl config mgmt-acl add <cidr>\n" +
			"! then re-run 'tacctl config cisco" + flag + "' to get the access-list block."
		accessClass = "! access-class " + aclName + " in   ! uncomment after populating mgmt-acl"
	}

	vars := map[string]string{
		"SERVER_IP":            d.authIP(""),
		"SECRET":               scopeSecret(d, scope),
		"PRIVILEGE_COMMANDS":   privilege.String(),
		"GROUP_SUMMARY":        summary.String(),
		"VTY_ACL_BLOCK":        aclBlock,
		"VTY_ACCESS_CLASS":     accessClass,
		"AUTHZ_COMMANDS_BLOCK": authzCommands,
		"ACCT_COMMANDS_BLOCK":  strings.Join(acct, "\n"),
		"AUTHN_METHODS":        authn,
		"AUTHZ_EXEC_METHODS":   authzExec,
		"EXEC_TIMEOUT":         execTimeout(c, scope),
		"TACACS_GROUP":         tacacsGroup,
		"RADIUS_GROUP":         radiusGroup,
		"SNMP_BLOCK":           CiscoSNMP(d.snmpInput(scope)).Text,
		"NETCONF_BLOCK":        CiscoNetconf(NetconfInput{Restricted: d.Restricted, Legacy: req.Legacy}),
	}
	if r := d.Radius; req.Protocol == RADIUS && r != nil {
		vars["SECRET"] = r.Secret
		vars["AUTH_PORT"], vars["ACCT_PORT"] = r.AuthPort, r.AcctPort
		vars["SERVER_IP"] = d.authIP(r.ServerAddr)
	}
	return vars
}

// ciscoLevels are the privilege levels in use: the distinct priv-lvls of
// the groups, ascending.
func ciscoLevels(groups []group) []int {
	var out []int
	for _, g := range groups {
		if n, err := strconv.Atoi(strings.TrimSpace(g.priv)); err == nil && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// ciscoAuthzBlock is the per-command authorization block (D5, D16): one
// 'aaa authorization commands <L>' per level in use, except a level where
// a group has no command rules (the server would deny that group every
// command), which gets a commented line naming the group(s) and the fix;
// then 'aaa authorization config-commands' and the commented console line.
func ciscoAuthzBlock(c *conf.Config, groups []group, levels []int, methods string) string {
	var b strings.Builder
	b.WriteString("! Per-command authorization (managed by 'tacctl group commands'): one line per\n" +
		"! privilege level in use; the server decides each command, including configuration\n" +
		"! commands, which IOS sends as ordinary commands.\n")
	for _, l := range levels {
		lvl := strconv.Itoa(l)
		var bare []string
		for _, g := range groups {
			if strings.TrimSpace(g.priv) == lvl && len(policy.Lines(c, g.name)) == 0 {
				bare = append(bare, g.name)
			}
		}
		line := "aaa authorization commands " + lvl + " default " + methods
		switch len(bare) {
		case 0:
			b.WriteString(line + "\n")
		case 1:
			b.WriteString("! " + line + "   ! NOT emitted: group '" + bare[0] + "' has no command rules and would be denied every command;" +
				" run 'tacctl group commands default " + bare[0] + " permit'\n")
		default:
			b.WriteString("! " + line + "   ! NOT emitted: groups '" + strings.Join(bare, "', '") + "' have no command rules and would be denied every command;" +
				" run 'tacctl group commands default <group> permit' for each\n")
		}
	}
	b.WriteString("aaa authorization config-commands\n")
	b.WriteString("! aaa authorization console   ! uncomment to have the console line ask the server too")
	return b.String()
}

// scopeSecret is "$(model_scope <scope> secret)".
func scopeSecret(d Data, scope string) string {
	if s := d.Model.Scope(scope); s != nil {
		return strings.TrimRight(s.Secret, "\n")
	}
	return ""
}

// renderCisco is cmd_config_cisco after its checks.
func renderCisco(o *out, req Request, d Data) error {
	t, err := ResolveTemplate(d.TemplateDir, CiscoTemplate(req.Legacy, req.Protocol))
	if err != nil {
		return err
	}
	vars := CiscoVars(req, d)
	allowed := ciscoTacacsVars
	if req.Protocol == RADIUS {
		allowed = ciscoRadiusVars
	}
	bg := BreakGlassFor(req, d)
	vars[breakGlassVar] = ciscoBreakGlass(bg)
	allowed = withBreakGlassVar(allowed)
	aclName := d.ACL.Name
	snmp := CiscoSNMP(d.snmpInput(req.Scope))

	o.header("Cisco IOS / IOS-XE Configuration", req.Scope, protocolNote(req.Protocol, req.Source),
		otherScopes(d.Model, req.Scope), "Copy and paste into the device:")
	o.addressRoles(d, req.Protocol)
	// Blank lines left by multi-line values are dropped ('awk NF'); the
	// '!' separators stay.
	o.write(DropBlank(Expand(t.Text, allowed, vars)))
	o.rule()
	o.heading(ui.Yellow, "Group → Privilege Level Mapping:")
	o.write(vars["GROUP_SUMMARY"])
	o.echo("")
	if req.Protocol == RADIUS {
		o.summaryLimits("cisco", req.Scope, d.Radius)
		o.echo("")
		o.heading(ui.Yellow, "Notes:")
		o.echo("  - The 'local' fallback ensures access if the RADIUS server is unreachable;")
		o.echo("    a reject from the server does not fall through to local")
		o.echo("  - Ensure a local admin account exists as a backup")
		o.echo("  - Uncomment 'ip radius source-interface ...' to pin the RADIUS client source")
		o.echo("  - " + aclName + " permits are managed with 'tacctl config mgmt-acl add <cidr>'")
		o.echo("  - For Type 6 (AES) key encryption, run on the device first:")
		o.echo("      conf t ; key config-key password-encrypt <master-key>")
		o.echo("      password encryption aes")
		o.echo("    then re-enter the radius key. (Type 7 is trivially reversible.)")
		o.echo("  - Manage 'privilege exec level' mappings with 'tacctl group privilege add ...'")
		o.echo("    (defaults move only the verified priv-15 commands DOWN; nothing is moved UP)")
		o.echo("  - Using template: " + t.Origin())
		o.echo("")
		o.unfilledBreakGlass(bg)
		o.unfilled(t.snmpGaps(snmp))
		return nil
	}
	o.heading(ui.Yellow, "Notes:")
	o.echo("  - The 'local' fallback ensures access if TACACS+ is unreachable")
	o.echo("  - Ensure a local admin account exists as a backup")
	o.echo("  - Uncomment 'ip tacacs source-interface ...' to pin the TACACS+ client source")
	o.echo("  - " + aclName + " permits are managed with 'tacctl config mgmt-acl add <cidr>'")
	if req.Legacy {
		o.echo("  - Type 6 (AES) key encryption is NOT available on IOS 12.x;")
		o.echo("    'service password-encryption' stores the key as Type 7.")
	} else {
		o.echo("  - For Type 6 (AES) key encryption, run on the device first:")
		o.echo("      conf t ; key config-key password-encrypt <master-key>")
		o.echo("      password encryption aes")
		o.echo("    then re-enter the tacacs key. (Type 7 is trivially reversible.)")
	}
	o.echo("  - Manage 'privilege exec level' mappings with 'tacctl group privilege add ...'")
	o.echo("    (defaults move only the verified priv-15 commands DOWN; nothing is moved UP)")
	if anyGroupHasCommands(d.Conf) {
		o.echo("  - A group at priv-lvl 15 is kept apart from the superusers only by the server's")
		o.echo("    rules: with the server unreachable, the 'local' fallback lets it run everything")
		o.echo("  - Commands typed on the console line are not sent to the server for authorization")
		o.echo("    unless 'aaa authorization console' is uncommented")
	}
	o.echo("  - Using template: " + t.Origin())
	o.echo("")
	o.unfilledBreakGlass(bg)
	o.unfilled(t.snmpGaps(snmp))
	return nil
}
