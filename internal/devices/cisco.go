package devices

import (
	"fmt"
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
		"EXEC_TIMEOUT", "TACACS_GROUP", "SNMP_BLOCK", "NETCONF_BLOCK", "SOURCE_INTERFACE_BLOCK", "HARDENING_BLOCK",
		"TACACS_PORT_LINE", "TACACS_HOST_PORT"}
	ciscoRadiusVars = []string{"SERVER_IP", "SECRET", "AUTH_PORT", "ACCT_PORT", "RADIUS_GROUP", "PRIVILEGE_COMMANDS",
		"GROUP_SUMMARY", "VTY_ACL_BLOCK", "VTY_ACCESS_CLASS", "AUTHN_METHODS", "AUTHZ_EXEC_METHODS", "EXEC_TIMEOUT",
		"SNMP_BLOCK", "NETCONF_BLOCK", "SOURCE_INTERFACE_BLOCK", "HARDENING_BLOCK"}
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
		block := "! --- " + g.name + " - Privilege Level " + g.priv + " Commands ---\n"
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
	// An entry with services that do not include ssh is not listed (a
	// standard access list matches the source only), with a comment that
	// says so above the list.
	var skipped strings.Builder
	for _, n := range d.mgmtSkipped("the VTY access list " + aclName + " (a standard access list matches the source only)") {
		skipped.WriteString("! " + n + "\n")
	}
	var aclBlock, accessClass string
	if entries.Len() > 0 {
		aclBlock = skipped.String() + "ip access-list standard " + aclName + "\n" +
			"  remark Managed by tacctl - edit with 'tacctl config mgmt-acl'\n" +
			entries.String() + "  deny   any log"
		accessClass = "  access-class " + aclName + " in"
	} else {
		flag := ""
		if req.Protocol == RADIUS {
			flag = " --protocol radius"
		}
		why := "mgmt-acl list is empty."
		if skipped.Len() > 0 {
			why = "no entry of the mgmt-acl list permits ssh (tcp/22)."
		}
		aclBlock = skipped.String() + "! " + aclName + " not emitted - " + why + "\n" +
			"! Populate it on the tacctl server with\n" +
			"!   tacctl config mgmt-acl add <cidr>\n" +
			"! then re-run 'tacctl config cisco" + flag + "' to get the access-list block."
		accessClass = "! access-class " + aclName + " in   ! uncomment after populating mgmt-acl"
	}

	// The scope's system block follows the SNMP step as the trailing lines of
	// its block (the template's own steps keep their numbers): the same
	// statements are the managed system section, so the walkthrough and a
	// pull's compare cannot drift. SNMP_STEP is the step alone, SYSTEM_BLOCK
	// the system lines, and neither is a template variable.
	snmpStep := CiscoSNMP(d.snmpInputFor(scope, "cisco")).Text
	system := d.Blocks.ciscoSystemLines(scope, dialectOf(req.Legacy))
	snmpBlock := snmpStep
	if len(system) > 0 {
		snmpBlock += "\n" + strings.Join(system, "\n")
	}
	if absent := d.Blocks.absentLines(scope); len(absent) > 0 {
		snmpBlock += "\n" + strings.Join(absent, "\n")
	}

	vars := map[string]string{
		"SERVER_IP":              d.authIP(""),
		"SECRET":                 scopeSecret(d, scope),
		"PRIVILEGE_COMMANDS":     privilege.String(),
		"GROUP_SUMMARY":          summary.String(),
		"VTY_ACL_BLOCK":          aclBlock,
		"VTY_ACCESS_CLASS":       accessClass,
		"AUTHZ_COMMANDS_BLOCK":   authzCommands,
		"ACCT_COMMANDS_BLOCK":    strings.Join(acct, "\n"),
		"AUTHN_METHODS":          authn,
		"AUTHZ_EXEC_METHODS":     authzExec,
		"EXEC_TIMEOUT":           execTimeout(c, scope),
		"TACACS_GROUP":           tacacsGroup,
		"RADIUS_GROUP":           radiusGroup,
		"SNMP_BLOCK":             snmpBlock,
		"SNMP_STEP":              snmpStep,
		"SYSTEM_BLOCK":           strings.Join(system, "\n"),
		"NETCONF_BLOCK":          CiscoNetconf(NetconfInput{Restricted: d.Restricted, Legacy: req.Legacy}),
		"SOURCE_INTERFACE_BLOCK": ciscoSourceInterfaceBlock(req, d),
		"HARDENING_BLOCK":        ciscoHardening(req, d),
	}
	// The TACACS+ port, written only when the listener is not on 49 (what
	// IOS uses when none is given): the block's own leaf, and the word of
	// the legacy host line, which goes after single-connection.
	if port := d.tacacsPortSet(); port != "" {
		vars["TACACS_PORT_LINE"] = "  port " + port
		vars["TACACS_HOST_PORT"] = " port " + port
	}
	if r := d.Radius; req.Protocol == RADIUS && r != nil {
		vars["SECRET"] = r.Secret
		vars["AUTH_PORT"], vars["ACCT_PORT"] = r.AuthPort, r.AcctPort
		vars["SERVER_IP"] = d.authIP(r.ServerAddr)
	}
	return vars
}

// The names of the standard block (D117): the plain ones tacctl has always
// rendered, and the console's login list. Nothing renames them and no
// setting changes them (the group has tacacs_group.<scope> of its own).
const (
	// ciscoTacacsServer and ciscoRadiusServer are the named server blocks.
	ciscoTacacsServer = "TACACS"
	ciscoRadiusServer = "RADIUS"
	// ciscoConsoleList is the console's login list: local only, so a local
	// user can log in on the console whatever the server says.
	ciscoConsoleList = "CONSOLE"
)

// ciscoSourceInterface is the interface the scope's devices source their
// server requests from (D119); "" when the scope sets none.
func ciscoSourceInterface(c *conf.Config, scope string) string {
	return confGet(c, "cisco.source_interface."+scope, "")
}

// ciscoSourceCommand is the statement that sets it, up to the interface.
func ciscoSourceCommand(protocol string) string {
	if protocol == RADIUS {
		return "ip radius source-interface"
	}
	return "ip tacacs source-interface"
}

// ciscoSourceInterfaceBlock is ${SOURCE_INTERFACE_BLOCK}: the statement when
// the scope sets an interface, and otherwise commented text that names the
// command and holds nothing a paste could take (D119: a statement is never
// rendered with a placeholder where its value goes).
func ciscoSourceInterfaceBlock(req Request, d Data) string {
	cmd := ciscoSourceCommand(req.Protocol)
	if ifc := ciscoSourceInterface(d.Conf, req.Scope); ifc != "" {
		return cmd + " " + ifc
	}
	return "! Source interface not set for scope " + req.Scope + ": the server matches this device by its source\n" +
		"! address, so a stable management interface is worth setting. Once, for the scope:\n" +
		"!   tacctl config cisco source-interface " + req.Scope + " <interface>\n" +
		"! then render this again to get the line:  " + cmd + " <interface>"
}

// PolicyGaps are the policy values the standard needs that the scope has
// not set, each as the sentence a plan's report carries (D119): a warning,
// not an irregularity. The statement they would give is left out of the
// managed sections. Only a Cisco request has any.
func PolicyGaps(req Request, d Data) []string {
	if req.Vendor != "cisco" || d.Conf == nil || ciscoSourceInterface(d.Conf, req.Scope) != "" {
		return nil
	}
	return []string{"policy value not set: source interface (tacctl config cisco source-interface " + req.Scope +
		" <interface>); the server matches this device by its source address"}
}

// ciscoHardening is ${HARDENING_BLOCK}, the walkthrough's Step 0 (D116 (B)):
// the site-policy lines of a device's hardening and its local enable
// secret, as comments. They are not compared, not planned and never in a
// region: nothing of the managed sections is rendered from this text.
func ciscoHardening(req Request, d Data) string {
	host := d.SNMP.DeviceName
	if host == "" {
		host, _, _ = strings.Cut(d.SNMP.SysName, ".")
	}
	if host == "" {
		host = "<HOSTNAME>"
	}
	enable := "enable algorithm-type scrypt secret <PASSWORD>"
	if req.Legacy && req.Protocol != RADIUS {
		enable = "enable secret <PASSWORD>"
	}
	note := func(line, where string) string { return fmt.Sprintf("  %-48s %s", line, where) }
	// A scope whose system block states the domain name types it in its own
	// step: the line says so in place of the placeholder.
	domain := "  ip domain name <DOMAIN>"
	if b := d.Blocks.CiscoSystem; b != nil && b.DomainName != nil {
		domain = note("ip domain name "+b.DomainName.Text, "(below, the system block of the scope)")
	}
	var b strings.Builder
	lines := []string{
		"--- Step 0: hardening checklist and the local enable secret ---",
		"Site policy, as comments: tacctl does not compare or plan these lines and keeps no value for them.",
		"Type what your site uses before the steps below; a line marked (below) is typed there.",
		"Global:",
		"  hostname " + host,
		domain,
		"  no ip domain lookup",
		note("service password-encryption", "(below, with the server block)"),
		"  service timestamps debug datetime msec localtime",
		"  service timestamps log datetime msec localtime",
		"  no service pad",
		"  no ip source-route",
		"  no ip http server",
		"  no ip http secure-server",
		"  ip ssh version 2",
		"  ip ssh time-out 60",
		"  ip ssh authentication-retries 3",
		"On line con 0 and line vty 0 15:",
		note("transport input ssh", "(below, the vty lines)"),
		note("exec-timeout "+execTimeout(d.Conf, req.Scope)+" 0", "(below)"),
		"  logging synchronous",
	}
	lines = append(lines,
		"The local enable secret. 'enable' uses it and nothing else: the standard has no enable list (with an 'enable'",
		"list that asks the server, anyone the server knows reaches level 15 with their own password). Set it before AAA:")
	lines = append(lines, "  no enable password", "  "+enable)
	for _, l := range lines {
		b.WriteString("! " + l + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
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
	// D118 (12): command authorization is its own step, after a check from a
	// new session: the session that pastes is a local user the server does
	// not know, and a server that answers FAIL never falls through.
	b.WriteString("! --- Check: before Step 2, from a NEW session ---\n" +
		"! Open a new session to this device with your own TACACS+ account (not the one you pasted\n" +
		"! from: that is a local user the server does not know) and run:  show privilege\n" +
		"! It must say the level the server gives your group (15 for a superuser). If the login is\n" +
		"! refused or the level is wrong, stop: put the server path right first (the key, the address,\n" +
		"! the source interface, the user's group) and leave Step 2 for later.\n" +
		"!\n" +
		"! --- Step 2: command authorization ---\n" +
		"! Typed only after the check. The session that pastes is a local user the server does not\n" +
		"! know: from the first line below every command of every session is asked of the server,\n" +
		"! which answers 'fail' for such a name and never falls through to 'local' (a break-glass\n" +
		"! local user is refused the same way while a server answers). Type these lines as the user\n" +
		"! of the new session, and keep a second session logged in.\n")
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
	b.WriteString("! Do NOT set 'aaa authorization console': the console would be authorized by the default lists,\n" +
		"! server first, which defeats the CONSOLE list.")
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
	if err := d.blockProblem(req); err != nil {
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
	snmp := CiscoSNMP(d.snmpInputFor(req.Scope, "cisco"))

	// a Cisco walkthrough is pasted from: every byte of it is ASCII
	o.ascii = true
	o.header("Cisco IOS / IOS-XE Configuration", req.Scope, strings.ReplaceAll(protocolNote(req.Protocol, req.Source), " \u2014 ", " - "),
		otherScopes(d.Model, req.Scope), "Copy and paste into the device:")
	o.addressRoles(d, req.Protocol)
	// Blank lines left by multi-line values are dropped ('awk NF'); the
	// '!' separators stay.
	o.write(DropBlank(Expand(t.Text, allowed, vars)))
	o.rule()
	o.heading(ui.Yellow, "Group -> Privilege Level Mapping:")
	o.write(vars["GROUP_SUMMARY"])
	o.echo("")
	if req.Protocol == RADIUS {
		o.summaryLimits("cisco", req.Scope, d.Radius, d.tacacsPort())
		o.echo("")
		o.heading(ui.Yellow, "Notes:")
		o.echo("  - The 'local' fallback ensures access if the RADIUS server is unreachable;")
		o.echo("    a reject from the server does not fall through to local")
		o.echo("  - Ensure a local admin account exists as a backup (Step 0)")
		o.echo("  - The console has its own login list, CONSOLE (local only): a local user can log in there")
		o.echo("    whatever the server says, and lands at privilege 1 ('aaa authorization console' is not")
		o.echo("    set, and must not be: it would put the console under the default lists, server first)")
		o.echo("  - 'enable' uses the local enable secret (Step 0) and nothing else: there is no enable list.")
		o.echo("    A RADIUS user lands at the level the server gives and needs no 'enable'")
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
	o.echo("  - Ensure a local admin account exists as a backup (Step 0)")
	o.echo("  - The console has its own login list, CONSOLE (local only): a local user can log in there")
	o.echo("    whatever the server says, and lands at privilege 1 ('aaa authorization console' is not")
	o.echo("    set, and must not be: it would put the console under the default lists, server first)")
	o.echo("  - 'enable' uses the local enable secret (Step 0) and nothing else: there is no enable list.")
	o.echo("    A TACACS+ user lands at the level the server gives and needs no 'enable'")
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
		o.echo("  - Step 2 (command authorization) is typed after the check, from a new session with your own")
		o.echo("    account: the session that pastes is a local user the server does not know, and the server's")
		o.echo("    'fail' is final, so that session (and a break-glass local user) is refused every command")
		o.echo("    while a server answers")
		o.echo("  - A group at priv-lvl 15 is kept apart from the superusers only by the server's")
		o.echo("    rules: with the server unreachable, the 'local' fallback lets it run everything")
		o.echo("  - Commands typed on the console line are not sent to the server for authorization")
		o.echo("    ('aaa authorization console' is not set)")
	}
	o.echo("  - Using template: " + t.Origin())
	o.echo("")
	o.unfilledBreakGlass(bg)
	o.unfilled(t.snmpGaps(snmp))
	return nil
}
