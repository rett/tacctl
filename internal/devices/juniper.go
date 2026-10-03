package devices

import (
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// The variables each Juniper template may use (cmd_config_juniper's
// envsubst whitelists).
var (
	juniperTacacsVars = []string{"SERVER_IP", "SECRET", "TEMPLATE_USERS", "TACPLUS_CONFIG", "MGMT_ACL_BLOCK",
		"CLASS_COMMAND_RULES", "VERIFY_COMMANDS", "GROUP_SUMMARY"}
	juniperRadiusVars = []string{"SERVER_IP", "SECRET", "TEMPLATE_USERS", "RADIUS_CONFIG", "MGMT_ACL_BLOCK",
		"CLASS_COMMAND_RULES", "VERIFY_COMMANDS", "GROUP_SUMMARY"}
)

// JuniperTemplate is the template a Juniper config renders.
func JuniperTemplate(protocol string) string {
	if protocol == RADIUS {
		return "juniper-radius"
	}
	return "juniper"
}

var (
	reSuperAdmin = regexp.MustCompile(`super|admin`)
	reRead       = regexp.MustCompile(`read`)
)

// juniperGroup is one group with a Juniper class, and the Junos login class
// suggested from its name.
type juniperGroup struct{ name, class, junos string }

// juniperGroups is the awk over model_group_info: the groups with a
// Juniper class, the login class 'super-user' for a name with super or
// admin in it, 'read-only' for one with read, else 'operator'.
func juniperGroups(d Data) []juniperGroup {
	var out []juniperGroup
	for _, g := range groupInfo(d.Model) {
		if g.class == "" || g.name == "" {
			continue
		}
		cls := "operator"
		if reSuperAdmin.MatchString(g.name) {
			cls = "super-user"
		} else if reRead.MatchString(g.name) {
			cls = "read-only"
		}
		out = append(out, juniperGroup{g.name, g.class, cls})
	}
	return out
}

// juniperAuthnOrder is the authentication-order of the scope's aaa-order
// for the method (tacplus or radius).
func juniperAuthnOrder(d Data, scope, method string) string {
	if localFirst(d.Conf, scope) {
		return "[ password " + method + " ]"
	}
	return method
}

// JuniperVars are the template variables of a Juniper config (the values
// cmd_config_juniper exports to envsubst).
func JuniperVars(req Request, d Data) map[string]string {
	c, scope := d.Conf, req.Scope
	groups := juniperGroups(d)
	serverIP, secret := d.ServerIP, scopeSecret(d, scope)
	if r := d.Radius; req.Protocol == RADIUS && r != nil {
		secret = r.Secret
		if r.ServerAddr != "" {
			serverIP = r.ServerAddr
		}
	}

	// Each template user is bound to a LOCAL class of its own name (Junos
	// refuses permissions on its predefined classes).
	var users strings.Builder
	for _, g := range groups {
		j := g.class
		switch g.junos {
		case "read-only":
			users.WriteString("set system login class " + j + " permissions view\n")
			users.WriteString("set system login class " + j + " permissions view-configuration\n")
		case "operator":
			for _, p := range []string{"clear", "network", "reset", "trace", "view", "view-configuration"} {
				users.WriteString("set system login class " + j + " permissions " + p + "\n")
			}
		case "super-user":
			users.WriteString("set system login class " + j + " permissions all\n")
		default:
			users.WriteString("set system login user " + j + " class " + g.junos + "\n")
			continue
		}
		users.WriteString("set system login user " + j + " class " + j + "\n")
	}
	templateUsers := strings.TrimSuffix(users.String(), "\n")

	method := "tacplus"
	if req.Protocol == RADIUS {
		method = "radius"
	}
	order := juniperAuthnOrder(d, scope, method)
	idle := execTimeout(c, scope)

	tacplus := "delete system authentication-order\n" +
		"set system authentication-order " + order + "\n" +
		"set system login idle-timeout " + idle + "\n" +
		"set system tacplus-server " + serverIP + " secret " + secret + "\n" +
		"set system tacplus-server " + serverIP + " single-connection\n" +
		"# Optional: pin client source IP for prefix-ACL matching on tacquito.\n" +
		"# Replace 10.0.0.1 with the device's management interface address, e.g.:\n" +
		"#   set system tacplus-server " + serverIP + " source-address 10.0.0.1\n" +
		"# Accounting events: login + change-log only. 'interactive-commands' is\n" +
		"# intentionally excluded because Junos internal daemons (mgd, jsd,\n" +
		"# health-probe op scripts, etc.) run non-tty CLI commands as root and\n" +
		"# generate a continuous stream of per-command accounting that is pure\n" +
		"# noise on the tacquito side. The login + change-log events still\n" +
		"# capture who logged in and who changed config.\n" +
		"set system accounting events [ login change-log ]\n" +
		"set system accounting destination tacplus"
	radius := ""
	if req.Protocol == RADIUS && d.Radius != nil {
		radius = "delete system authentication-order\n" +
			"set system authentication-order " + order + "\n" +
			"set system login idle-timeout " + idle + "\n" +
			"set system radius-server " + serverIP + " port " + d.Radius.AuthPort + "\n" +
			"set system radius-server " + serverIP + " accounting-port " + d.Radius.AcctPort + "\n" +
			"set system radius-server " + serverIP + " secret " + secret + "\n" +
			"# Optional: pin client source IP for prefix-ACL matching on the server (it\n" +
			"# answers only devices whose source address is inside a prefix of the scope).\n" +
			"# Replace 10.0.0.1 with the device's management interface address, e.g.:\n" +
			"#   set system radius-server " + serverIP + " source-address 10.0.0.1\n" +
			"# Accounting events: login + change-log only.\n" +
			"set system accounting events [ login change-log ]\n" +
			"set system accounting destination radius"
	}

	// The lo0 filter from the management ACL: defined live, applied only
	// in a comment (a misapplied lo0 filter can cut the routing protocols
	// off the RE). IPv6 entries are skipped (family inet only).
	acl := d.ACL.Name
	var terms strings.Builder
	for _, e := range d.ACL.CIDRs {
		if e == "" || strings.Contains(e, ":") {
			continue
		}
		terms.WriteString("set firewall family inet filter " + acl + " term permit-mgmt from source-address " + e + "\n")
	}
	mgmt := "# mgmt-acl empty — configure with 'tacctl config mgmt-acl add <cidr>' on the tacctl server\n" +
		"# to emit a source-restricted lo0 firewall filter here."
	if terms.Len() > 0 {
		f := "set firewall family inet filter " + acl + " term "
		mgmt = "# Restrict SSH / NETCONF to the configured mgmt subnets.\n" +
			"# These 'set firewall' lines define the filter in the candidate config.\n" +
			"# Activate it by uncommenting the 'set interfaces lo0 …' line below\n" +
			"# after reviewing — a misapplied lo0 filter can blackhole BGP / OSPF /\n" +
			"# IS-IS to the RE.\n" +
			terms.String() +
			f + "permit-mgmt from protocol tcp\n" +
			f + "permit-mgmt from destination-port [ ssh 830 ]\n" +
			f + "permit-mgmt then accept\n" +
			f + "deny-mgmt from protocol tcp\n" +
			f + "deny-mgmt from destination-port [ ssh 830 ]\n" +
			f + "deny-mgmt then { log; discard; }\n" +
			f + "default-accept then accept\n" +
			"#\n" +
			"# Apply (review first):\n" +
			"# set interfaces lo0 unit 0 family inet filter input " + acl
	}

	verify := "  show configuration system tacplus-server\n  show configuration system authentication-order"
	if req.Protocol == RADIUS {
		verify = "  show configuration system radius-server\n  show configuration system authentication-order\n" +
			"  show configuration system accounting"
	}
	for _, g := range groups {
		verify += "\n  show configuration system login user " + g.class
	}

	var summary strings.Builder
	for _, g := range groups {
		desc := g.junos
		switch g.junos {
		case "read-only":
			desc = "local: view + view-configuration"
		case "operator":
			desc = "local: clear/network/reset/trace/view + view-configuration"
		case "super-user":
			desc = "local: all"
		}
		summary.WriteString("  " + g.name + ": " + g.class + " (" + desc + ")\n")
	}

	// The command rules as the class's allow-commands / deny-commands,
	// enforced by Junos itself: each rule's name joins an alternation (its
	// match regexes are not carried over).
	var rules strings.Builder
	if anyGroupHasCommands(c) {
		if req.Protocol == RADIUS {
			rules.WriteString("# Per-command rules (enforced LOCALLY by Junos on the class, not by the RADIUS server).\n" +
				"# Push these on every device after 'tacctl group commands' changes.\n")
		} else {
			rules.WriteString("# Per-command authorization (enforced LOCALLY by Junos, not via TACACS+).\n" +
				"# Push these on every device after 'tacctl group commands' changes.\n")
		}
		for _, g := range groups {
			ls := lines(policy.Lines(c, g.name))
			if len(ls) == 0 {
				continue
			}
			def := policy.DefaultAction(c, g.name)
			var permit, deny []string
			for _, l := range ls {
				f := strings.SplitN(l, "|", 3)
				name, action := f[0], ""
				if len(f) > 1 {
					action = f[1]
				}
				if name == "" || name == "*" {
					continue
				}
				if action == "permit" {
					permit = append(permit, name)
				} else {
					deny = append(deny, name)
				}
			}
			rules.WriteString("# class '" + g.class + "' (group '" + g.name + "', default " + def + ")\n")
			if len(permit) > 0 {
				rules.WriteString("set system login class " + g.class + ` allow-commands "^(` + strings.Join(permit, "|") + `)( .*)?$"` + "\n")
			}
			if len(deny) > 0 {
				rules.WriteString("set system login class " + g.class + ` deny-commands "^(` + strings.Join(deny, "|") + `)( .*)?$"` + "\n")
			}
			if def == "deny" && len(permit) == 0 {
				rules.WriteString("# Default action is 'deny' but no allow-commands set —\n")
				rules.WriteString("# this class will be unable to run anything. Add explicit\n")
				rules.WriteString("# permits with 'tacctl group commands add " + g.name + " <name> --action permit'.\n")
			}
		}
	}
	classRules := strings.TrimSuffix(rules.String(), "\n")
	if !anyGroupHasCommands(c) {
		classRules = "# Per-command authorization not configured.\n" +
			"# To restrict commands per group, use 'tacctl group commands' on the tacctl server."
	}

	return map[string]string{
		"SERVER_IP":           serverIP,
		"SECRET":              secret,
		"TEMPLATE_USERS":      templateUsers,
		"TACPLUS_CONFIG":      tacplus,
		"RADIUS_CONFIG":       radius,
		"MGMT_ACL_BLOCK":      mgmt,
		"CLASS_COMMAND_RULES": classRules,
		"VERIFY_COMMANDS":     verify,
		"GROUP_SUMMARY":       summary.String(),
		// Not a template variable: the authentication-order the notes name.
		"authn_order": order,
	}
}

// renderJuniper is cmd_config_juniper after its checks.
func renderJuniper(o *out, req Request, d Data) error {
	t, err := ResolveTemplate(d.TemplateDir, JuniperTemplate(req.Protocol))
	if err != nil {
		return err
	}
	vars := JuniperVars(req, d)
	allowed := juniperTacacsVars
	if req.Protocol == RADIUS {
		allowed = juniperRadiusVars
	}
	o.header("Juniper Junos Configuration", req.Scope, protocolNote(req.Protocol, req.Source),
		otherScopes(d.Model, req.Scope), "Copy and paste into the device (configure mode):")
	o.write(Expand(t.Text, allowed, vars))
	o.rule()
	o.heading(ui.Yellow, "Group → Juniper Class Mapping:")
	o.write(vars["GROUP_SUMMARY"])
	o.echo("")
	if req.Protocol == RADIUS {
		o.summaryLimits("juniper", req.Scope, d.Radius)
		o.echo("")
		o.heading(ui.Yellow, "Notes:")
		o.echo("  - Template users MUST exist before RADIUS logins will work: the server names")
		o.echo("    one in Juniper-Local-User-Name and Junos logs the user in as that local user")
		o.echo("  - With authentication-order '" + vars["authn_order"] + "', Junos falls back to the local")
		o.echo("    password when no RADIUS server answers; test with the server unreachable")
		o.echo("    before relying on it. A reject from the server does not fall through to local")
		o.echo("  - If a login fails silently, the template user is likely missing")
		o.echo("  - Each template-user is bound to a LOCAL class of the same name;")
		o.echo("    edit its 'permissions' to fit your policy (Junos refuses to set")
		o.echo("    permissions on the predefined read-only/operator/super-user names)")
		o.echo("  - Uncomment and edit the source-address line to pin the client")
		o.echo("    source IP; the server matches it against the scope's prefixes")
		o.echo("  - Junos replaces the plaintext 'secret' with '$9$...' on commit,")
		o.echo("    but it sits in the candidate config until then — commit promptly")
		o.echo("    and protect the commit archive (/config/rescue.conf, juniper.conf.*).")
		o.echo("  - Using template: " + t.Origin())
		o.echo("")
		o.echoE(ui.Bold + "Verify after commit:" + ui.NC)
		o.echo(vars["VERIFY_COMMANDS"])
		o.echo("")
		return nil
	}
	o.heading(ui.Yellow, "Notes:")
	o.echo("  - Template users MUST exist before TACACS+ logins will work")
	o.echo("  - With authentication-order 'tacplus', Junos auto-falls-back to")
	o.echo("    local password ONLY when the tacplus server is unreachable —")
	o.echo("    a tacplus reject does not fall through to local")
	o.echo("  - If a login fails silently, the template user is likely missing")
	o.echo("  - Each template-user is bound to a LOCAL class of the same name;")
	o.echo("    edit its 'permissions' to fit your policy (Junos refuses to set")
	o.echo("    permissions on the predefined read-only/operator/super-user names)")
	o.echo("  - Uncomment and edit the source-address line to pin the client")
	o.echo("    source IP for prefix-ACL matching on tacquito")
	o.echo("  - Junos replaces the plaintext 'secret' with '$9$...' on commit,")
	o.echo("    but it sits in the candidate config until then — commit promptly")
	o.echo("    and protect the commit archive (/config/rescue.conf, juniper.conf.*).")
	o.echo("  - Using template: " + t.Origin())
	o.echo("")
	o.echoE(ui.Bold + "Verify after commit:" + ui.NC)
	o.echo(vars["VERIFY_COMMANDS"])
	o.echo("")
	return nil
}
