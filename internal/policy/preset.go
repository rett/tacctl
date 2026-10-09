package policy

// The role preset (docs/plans/0.2.2-plan.md D11, D19-D21, D27; the content
// is docs/plans/0.2.3-baseline-design.md, D52): starting values for four
// roles, viewer (the built-in readonly), operator, engineer and superuser.
// It is only a table; 'group preset roles' writes it through the same
// setters as 'group edit', 'group junos' and 'group commands', and never
// overwrites a value without --force. Nothing here names a site.
//
// What the roles are: viewer is a monitoring and backup account (it reads
// the configuration and changes nothing), operator troubleshoots without
// changing anything, engineer provisions and configures (on Cisco limited
// by the few command rules below, which tacquito cannot tell apart in
// configuration mode, and on Junos only by its class),
// superuser can do everything. The roles nest: what a role may do, the one
// above it may do too (TestRolesNest).
//
// Every Cisco match is written ^(...)$ in full: tacquito appends a '$' to
// a regex that does not end in one, so a prefix form has to say
// '( .*)?$' itself (pfx), and tacctl wraps every stored regex as
// ^(?:...)$ when it renders, so a top-level alternation cannot be
// mis-anchored. Junos values are POSIX ERE: no \S, \d, \b or '(?'.

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
	// Junos are the deny sets by tacctl.yaml attribute (deny_commands, ...);
	// an attribute with no items clears the set.
	Junos map[string][]string
	// Commands are Cisco command rules ('name|action|match' lines, the
	// catch-all last); nil leaves the group's rules alone.
	Commands []string
}

// EngineerClass is the Junos class of the preset's engineer group (D20):
// its template user is created by 'tacctl config juniper'. Together with
// store.BuiltinGroups' classes it is the one place a class name lives
// (D54).
const EngineerClass = "EN-CLASS"

// pfx is a prefix match written in full: the alternatives, optionally
// followed by more arguments.
func pfx(alts string) string { return "^(" + alts + ")( .*)?$" }

// --- Junos (POSIX ERE; sizes with the '( )' wrapper, limits 241 / 236) ---

const (
	// viewerDenyCommands: 112 of 241 bytes.
	viewerDenyCommands = `^(ssh|telnet|file|request|restart|start|load|op|test|monitor|configure|edit|clear|show system rollback)( .*)?$`
	// operatorDenyCommands: 226 of 241 bytes. The hard protocol clears are
	// denied; 'clear interfaces statistics', 'clear arp', 'clear
	// ethernet-switching table' and 'clear firewall' stay.
	operatorDenyCommands = `^(file|request|restart|start|load|op|test|configure|edit|clear (bgp|ospf|ospf3|isis|ldp|rsvp|mpls|pim|igmp|msdp|bfd|vrrp|lacp|system|security|network-access|log|dhcp)|monitor traffic .*write-file|show system rollback)( .*)?$`
	// engineerDenyCommands: 192 of 241 bytes. 'request system ...' is
	// denied as a whole ('request support information' stays allowed);
	// 'load' only with a third word that does not begin with 't', so
	// 'load set terminal' passes and 'load set /var/tmp/x.set' does not.
	engineerDenyCommands = `^(request (system|chassis routing-engine|vmhost|security)|start|load [^ ]+ [^t][^ ]*|op|file (copy|delete|rename|archive|show)|clear (system login|log)|restart (chassis|management).*)( .*)?$`
)

// EngineerHardeningDenyConfiguration is an OPT-IN example, not canonical
// and never applied by the preset or by 'group reset': the paths an
// engineer's deny-configuration could hide, for a site that wants a trust
// boundary on Junos (it is also what stops the engineer from reading those
// paths, which the viewer and operator can read; see README, Default
// Groups). The management filter's clause is left out when mgmtFilter is
// "". 206 of 236 bytes without a filter.
func EngineerHardeningDenyConfiguration(mgmtFilter string) string {
	filter := ""
	if mgmtFilter != "" {
		filter = "firewall .*" + mgmtFilter + "|"
	}
	return `^(groups [^ ]+ )?(system (login|root-auth|auth|tacplus|radius|accounting|services|scripts|archival|master|ports)|snmp|event-options|security (ike|ipsec|ssh|pki)|` +
		filter + `interfaces (lo0 .*filter|fxp0|em0|me0|vme))`
}

// --- Cisco -----------------------------------------------------------------

// Secret-bearing sub-trees of 'show' that the preset keeps from viewer and
// operator (the level-filtered running-config stays readable).
const (
	viewerShowDeny   = `running-config view full|tech-support|startup-config|derived-config|key chain|snmp (community|user)|crypto|archive log`
	operatorShowDeny = `running-config view full|startup-config|derived-config|key chain|snmp (community|user)|crypto (isakmp key|key)|archive log`
)

// viewerCommands are the preset's rules of the viewer (readonly): the
// secret-bearing 'show' sub-trees denied (a deny that misses falls through
// to the shipped permits), then what the group ships with.
func viewerCommands() []string {
	return append([]string{"show|deny|" + pfx(viewerShowDeny)}, DefaultLines("readonly")...)
}

// operatorCommands are the preset's rules of the operator.
func operatorCommands() []string {
	return append([]string{"show|deny|" + pfx(operatorShowDeny)}, DefaultLines("operator")...)
}

// engineerCommands are engineer's Cisco rules: everything is permitted
// except the exec-level lifecycle (reload, software, file deletion), the
// shell escapes (tclsh, guestshell, app-hosting, iox, scripting), the
// copies that would load a configuration or write flash, the AAA debug
// and test commands, and the 'do' forms of those. Configuration mode is
// NOT restricted as a mode: an engineer may change AAA, TACACS+/RADIUS
// servers and keys, lines, privileges and the management ACL (so that
// tacctl's push can run with the engineer's own login, 0.2.5), and so can
// lock a device out. But tacquito sees a command as its first word and its
// arguments and cannot tell exec from configuration mode, so a deny stops
// the same word typed in configuration mode too: 'archive' (other than
// 'archive config'), 'switch', 'redundancy', 'hw-module', 'iox',
// 'app-hosting', 'scripting', 'software' and a bare 'configure' (inside
// configuration mode an engineer cannot run them, nor 'do' forms of the
// exec ones). A site that wants a trust boundary adds rules with 'group
// commands add'. Regexes match the arguments only.
func engineerCommands() []string {
	local := `(flash|bootflash|harddisk|disk\d|usbflash\d*):\S*`
	remote := `(tftp|ftp|scp|sftp|http|https):\S*`
	return []string{
		"reload|deny|",
		"copy|permit|" + pfx(`(running-config|startup-config|system:running-config|nvram:startup-config) (startup-config|nvram:startup-config|`+local+`|`+remote+`)`),
		"copy|permit|" + pfx(local+` `+remote),
		"copy|deny|",
		"write|deny|" + pfx("erase"),
		"delete|deny|", "erase|deny|", "format|deny|", "fsck|deny|", "rename|deny|", "mkdir|deny|", "rmdir|deny|",
		"request|deny|", "install|deny|", "software|deny|", "upgrade|deny|", "issu|deny|",
		"archive|permit|" + pfx("config"),
		"archive|deny|",
		"configure|permit|" + pfx(`terminal|confirm|revert|replace (nvram|archive|flash|bootflash|harddisk|disk\d|usbflash\d*):\S*`),
		"configure|deny|",
		"tclsh|deny|", "scripting|deny|", "guestshell|deny|", "app-hosting|deny|", "iox|deny|",
		"hw-module|deny|", "redundancy|deny|", "switch|deny|",
		"test|deny|" + pfx("aaa"),
		"debug|deny|" + pfx("all|aaa|tacacs|radius"),
		"clear|deny|" + pfx("aaa|logging|archive"),
		"do|deny|" + pfx(`reload|copy|delete|erase|format|fsck|rename|mkdir|rmdir|write erase|request|install|software|upgrade|issu|archive|configure|clear (aaa|logging|archive)|debug (all|aaa|tacacs|radius)|test aaa|tclsh|guestshell|app-hosting|iox|scripting|hw-module|redundancy|switch`),
		Catchall + "|permit|",
	}
}

// RolePreset is the preset, in the order it is shown.
func RolePreset() []Role {
	return []Role{
		{Group: "readonly", Label: "viewer", PrivLvl: 1, WTI: "viewonly", Junos: map[string][]string{
			conf.JunosDenyCommands: {viewerDenyCommands},
		}, Commands: viewerCommands()},
		{Group: "operator", PrivLvl: 7, WTI: "user", Junos: map[string][]string{
			conf.JunosDenyCommands: {operatorDenyCommands},
		}, Commands: operatorCommands()},
		{Group: "engineer", PrivLvl: 15, Class: EngineerClass, WTI: "superuser", Tier: "engineer", Junos: map[string][]string{
			conf.JunosDenyCommands: {engineerDenyCommands},
			// Nothing is hidden from reading (a viewer and an operator see
			// the whole configuration, secrets redacted by the class), so
			// the engineer's deny-configuration is empty; the preset sets
			// it empty (--force clears the 0.2.2 set).
			conf.JunosDenyConfiguration: nil,
		}, Commands: engineerCommands()},
		{Group: "superuser", PrivLvl: 15, WTI: "administrator"},
	}
}

// SameLines reports whether a group's rule lines are want, ignoring
// blank lines.
func SameLines(have, want []string) bool {
	return strings.Join(nonBlank(have), "\n") == strings.Join(nonBlank(want), "\n")
}
