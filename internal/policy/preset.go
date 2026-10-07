package policy

// The role preset (docs/plans/0.2.2-plan.md D11, D19-D21, D27): starting
// values for four roles, viewer (the built-in readonly), operator,
// engineer and superuser. It is only a table; 'group preset roles' writes
// it through the same setters as 'group edit', 'group junos' and 'group
// commands', and never overwrites a value without --force. Nothing here
// names a site: the management filter of engineer's deny-configuration
// comes from --mgmt-filter.

import (
	"strings"

	"github.com/rett/tacctl/internal/conf"
)

// Role is one group of the preset.
type Role struct {
	Group   string // the tacctl group
	Label   string // the role's name, when not the group's
	PrivLvl int    // a group the preset creates gets this priv-lvl
	Class   string // ... and this Juniper class
	WTI     string // WTI level
	Tier    string // tacctl tier ("" leaves the priv-lvl band)
	// Junos are the deny sets by tacctl.yaml attribute (deny_commands, ...).
	Junos map[string][]string
	// Commands are Cisco command rules ('name|action|match' lines, the
	// catch-all last); nil leaves the group's rules alone.
	Commands []string
}

// EngineerClass is the Junos class of the preset's engineer group (D20):
// its template user is created by 'tacctl config juniper'.
const EngineerClass = "ENG-CLASS"

// engineerDenyConfiguration is engineer's deny-configuration, with the
// management filter's clause when one is given (D21).
func engineerDenyConfiguration(mgmtFilter string) string {
	filter := ""
	if mgmtFilter != "" {
		filter = "firewall .*" + mgmtFilter + "|"
	}
	return `^(groups [^ ]+ )?(system (login|root-auth|authentication|tacplus|radius|accounting|services|scripts|archival|master|ports)|snmp|event-options|security (ike|ipsec|ssh|cert|pki)|` +
		filter + `interfaces (fxp0|em0|me0|vme))`
}

// engineerCommands are engineer's Cisco rules: everything permitted but
// the device's trust boundary and lifecycle (AAA, users, lines, keys,
// SNMP, boot, software, reload, file deletion, scripting engines); 'no',
// 'default' and 'do' repeat the denies. Regexes match the arguments only.
var engineerCommands = []string{
	"reload|deny|",
	`copy|permit|^(running-config|startup-config|system:running-config) (startup-config|nvram:startup-config|(tftp|ftp|scp|sftp|http|https):|(flash|bootflash|usbflash\d*|harddisk):\S*\.(cfg|txt|conf))`,
	`copy|permit|^(flash|bootflash|crashinfo|core|harddisk|usbflash\d*|system):\S* (tftp|ftp|scp|sftp|http|https):`,
	"copy|deny|",
	"write|deny|^erase",
	"delete|deny|", "erase|deny|", "format|deny|", "fsck|deny|", "rename|deny|",
	"request|deny|", "install|deny|", "software|deny|", "upgrade|deny|", "archive|deny|",
	`configure|permit|^terminal\b`,
	"configure|deny|",
	"boot|deny|", "license|deny|", "crypto|deny|", "aaa|deny|", "username|deny|",
	`enable|deny|^(secret|password|algorithm-type|view)\b`,
	"tacacs|deny|", "tacacs-server|deny|", "radius|deny|", "radius-server|deny|", "snmp-server|deny|",
	"line|deny|", "login|deny|", "password|deny|", "privilege|deny|", "transport|deny|", "access-class|deny|",
	"authentication|deny|", "authorization|deny|", "accounting|deny|",
	`service|deny|^(password-encryption|password-recovery)\b`,
	"key|deny|^config-key",
	`ip|deny|^(http|ssh|scp|ftp|tftp|tacacs|radius|access-list( \S+)? VTY-ACL\b)`,
	"event|deny|", "kron|deny|", "tclsh|deny|", "scripting|deny|", "guestshell|deny|", "app-hosting|deny|", "iox|deny|",
	"hw-module|deny|", "redundancy|deny|", "switch|deny|", "issu|deny|",
	"test|deny|^aaa",
	`debug|deny|^all\b`,
	"clear|deny|^(crypto|aaa|configuration)",
	"no|deny|" + trustBoundary,
	"default|deny|" + trustBoundary,
	`do|deny|^(reload|copy|delete|erase|format|write erase|request|install|archive|crypto|tclsh|license|configure|hw-module|redundancy|switch)\b`,
	Catchall + "|permit|",
}

// trustBoundary is what 'no' and 'default' may not undo.
const trustBoundary = `^(aaa|username|enable (secret|password)|tacacs|tacacs-server|radius|radius-server|snmp-server|crypto|line|login|privilege|archive|boot|license|service (password-encryption|password-recovery)|key config-key|password|event|kron|ip (http|ssh|scp|ftp|tftp|tacacs|radius|access-list( \S+)? VTY-ACL\b))`

// RolePreset is the preset, in the order it is shown. mgmtFilter is the
// Junos firewall filter that guards the management interface ("" leaves
// its clause out).
func RolePreset(mgmtFilter string) []Role {
	return []Role{
		{Group: "readonly", Label: "viewer", PrivLvl: 1, WTI: "viewonly", Junos: map[string][]string{
			conf.JunosDenyCommands: {`^((ssh|telnet|file|request|restart|start|load|op|test|monitor|configure|edit)( .*)?|show (system (login|rollback|commit)|security (ike|ipsec).*|configuration .*(root-auth|login|tacplus|radius|secret|key|password).*))$`},
		}},
		{Group: "operator", PrivLvl: 7, WTI: "user", Junos: map[string][]string{
			conf.JunosDenyCommands: {`^(file (delete|rename|copy|archive)|request|start|load|op|test|configure|edit|clear (system|security|network-access)|monitor traffic .*write-file|show (system (login|rollback)|configuration .*(root-auth|login|tacplus|radius).*))( .*)?$`},
		}},
		{Group: "engineer", PrivLvl: 15, Class: EngineerClass, WTI: "superuser", Tier: "engineer", Junos: map[string][]string{
			conf.JunosDenyCommands:      {`^(request (system (reboot|halt|power-off|zeroize|software|snapshot|storage|scripts)|chassis routing-engine|vmhost|security)|start|load|op|file (copy|delete|rename|archive|show)|clear system login|restart (chassis|management).*)( .*)?$`},
			conf.JunosDenyConfiguration: {engineerDenyConfiguration(mgmtFilter)},
		}, Commands: engineerCommands},
		{Group: "superuser", PrivLvl: 15, WTI: "administrator"},
	}
}

// SameLines reports whether a group's rule lines are want, ignoring
// blank lines.
func SameLines(have, want []string) bool {
	return strings.Join(nonBlank(have), "\n") == strings.Join(nonBlank(want), "\n")
}
