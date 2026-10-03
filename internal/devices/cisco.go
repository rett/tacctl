package devices

import (
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// The variables each Cisco template may use (cmd_config_cisco's envsubst
// whitelists); anything else in a template is left as written.
var (
	ciscoTacacsVars = []string{"SERVER_IP", "SECRET", "PRIVILEGE_COMMANDS", "GROUP_SUMMARY", "VTY_ACL_BLOCK",
		"VTY_ACCESS_CLASS", "AUTHZ_COMMANDS_BLOCK", "AUTHN_METHODS", "AUTHZ_EXEC_METHODS", "EXEC_TIMEOUT", "TACACS_GROUP"}
	ciscoRadiusVars = []string{"SERVER_IP", "SECRET", "AUTH_PORT", "ACCT_PORT", "RADIUS_GROUP", "PRIVILEGE_COMMANDS",
		"GROUP_SUMMARY", "VTY_ACL_BLOCK", "VTY_ACCESS_CLASS", "AUTHN_METHODS", "AUTHZ_EXEC_METHODS", "EXEC_TIMEOUT"}
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

	// The privilege-exec block: per group at priv-lvl 2-14, its mappings
	// ('tacctl group privilege') or the shipped default, each (level,
	// command) once across groups.
	var privilege strings.Builder
	seen := map[string]bool{}
	for _, g := range groups {
		if g.priv == "1" || g.priv == "15" {
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
		for _, cmd := range cmds {
			if cmd == "" {
				continue
			}
			pair := g.priv + "|" + cmd
			if seen[pair] {
				continue
			}
			seen[pair] = true
			block += "privilege exec level " + g.priv + " " + cmd + "\n"
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

	authzCommands := "! Per-command authorization not enabled.\n! To restrict commands per group, use 'tacctl group commands'."
	if anyGroupHasCommands(c) {
		authzCommands = "! Per-command authorization (managed by 'tacctl group commands').\n" +
			"aaa authorization commands 1 default " + authzCmd + "\n" +
			"aaa authorization commands 7 default " + authzCmd + "\n" +
			"aaa authorization commands 15 default " + authzCmd
	}

	// The VTY ACL from the management ACL; IPv6 entries are skipped (they
	// would need an 'ipv6 access-list'). An empty list emits comments only,
	// so the output stays safe to paste.
	aclName := d.ACL.Name
	var entries strings.Builder
	for _, e := range d.ACL.CIDRs {
		if e == "" {
			continue
		}
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
		"SERVER_IP":            d.ServerIP,
		"SECRET":               scopeSecret(d, scope),
		"PRIVILEGE_COMMANDS":   privilege.String(),
		"GROUP_SUMMARY":        summary.String(),
		"VTY_ACL_BLOCK":        aclBlock,
		"VTY_ACCESS_CLASS":     accessClass,
		"AUTHZ_COMMANDS_BLOCK": authzCommands,
		"AUTHN_METHODS":        authn,
		"AUTHZ_EXEC_METHODS":   authzExec,
		"EXEC_TIMEOUT":         execTimeout(c, scope),
		"TACACS_GROUP":         tacacsGroup,
		"RADIUS_GROUP":         radiusGroup,
	}
	if r := d.Radius; req.Protocol == RADIUS && r != nil {
		vars["SECRET"] = r.Secret
		vars["AUTH_PORT"], vars["ACCT_PORT"] = r.AuthPort, r.AcctPort
		if r.ServerAddr != "" {
			vars["SERVER_IP"] = r.ServerAddr
		}
	}
	return vars
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
	aclName := d.ACL.Name

	o.header("Cisco IOS / IOS-XE Configuration", req.Scope, protocolNote(req.Protocol, req.Source),
		otherScopes(d.Model, req.Scope), "Copy and paste into the device:")
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
	o.echo("  - Using template: " + t.Origin())
	o.echo("")
	return nil
}
