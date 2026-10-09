package policy

// The 0.2.2 role preset's engineer text, kept only to recognise it. An
// install that ran 'group preset roles' on 0.2.2 carries these values as
// overrides, which an upgrade never touches; the Cisco rules do not hold
// (tacquito anchors every regex at both ends, so the prefix forms below
// matched only the exact single-word argument: 'no aaa new-model', 'enable
// secret ...', 'ip ssh ...', 'do reload in 5' and more were permitted) and
// the Junos sets changed in 0.2.3 (docs/plans/0.2.3-baseline-design.md).
// 'tacctl upgrade' compares them with the stored values and, when
// identical, tells the operator to apply the current preset.

import (
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/conf"
)

// Engineer022Commands is commands.engineer as 0.2.2's preset wrote it.
var engineerCommands022 = []string{
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
	"no|deny|" + trustBoundary022,
	"default|deny|" + trustBoundary022,
	`do|deny|^(reload|copy|delete|erase|format|write erase|request|install|archive|crypto|tclsh|license|configure|hw-module|redundancy|switch)\b`,
	Catchall + "|permit|",
}

// Engineer022Commands is that list (a copy), for the tests.
func Engineer022Commands() []string { return append([]string(nil), engineerCommands022...) }

const trustBoundary022 = `^(aaa|username|enable (secret|password)|tacacs|tacacs-server|radius|radius-server|snmp-server|crypto|line|login|privilege|archive|boot|license|service (password-encryption|password-recovery)|key config-key|password|event|kron|ip (http|ssh|scp|ftp|tftp|tacacs|radius|access-list( \S+)? VTY-ACL\b))`

const (
	engineerDenyCommands022 = `^(request (system (reboot|halt|power-off|zeroize|software|snapshot|storage|scripts)|chassis routing-engine|vmhost|security)|start|load|op|file (copy|delete|rename|archive|show)|clear system login|restart (chassis|management).*)( .*)?$`
	// engineerDenyConfiguration022 is the 0.2.2 set; --mgmt-filter put
	// 'firewall .*<name>|' in front of 'interfaces'.
	engineerDenyConfigurationHead022 = `^(groups [^ ]+ )?(system (login|root-auth|authentication|tacplus|radius|accounting|services|scripts|archival|master|ports)|snmp|event-options|security (ike|ipsec|ssh|cert|pki)|`
	engineerDenyConfigurationTail022 = `interfaces (fxp0|em0|me0|vme))`
)

// Engineer022Junos are the two Junos sets as 0.2.2's preset wrote them
// (filter is the --mgmt-filter name, "" for none), for the tests.
func Engineer022Junos(filter string) (denyCommands, denyConfiguration string) {
	if filter != "" {
		filter = "firewall .*" + filter + "|"
	}
	return engineerDenyCommands022, engineerDenyConfigurationHead022 + filter + engineerDenyConfigurationTail022
}

// reFilterClause022 is the optional management-filter clause.
var reFilterClause022 = regexp.MustCompile(`^(firewall \.\*[A-Za-z0-9_.-]+\|)?$`)

// Stale022Preset names the engineer settings in c that are exactly what
// 0.2.2's preset wrote (and so carry its failures): "commands.engineer"
// (the Cisco rules, which did not hold), "junos engineer deny-commands"
// and "junos engineer deny-configuration" (replaced in 0.2.3). Nothing
// when the group has other values or none.
func Stale022Preset(c *conf.Config) []string {
	var out []string
	if HasOverride(c, "engineer") && SameLines(Lines(c, "engineer"), engineerCommands022) {
		out = append(out, "commands.engineer")
	}
	if v := JunosSet(c, "engineer", conf.JunosDenyCommands); len(v) == 1 && v[0] == engineerDenyCommands022 {
		out = append(out, "junos engineer deny-commands")
	}
	if v := JunosSet(c, "engineer", conf.JunosDenyConfiguration); len(v) == 1 &&
		strings.HasPrefix(v[0], engineerDenyConfigurationHead022) && strings.HasSuffix(v[0], engineerDenyConfigurationTail022) &&
		reFilterClause022.MatchString(strings.TrimSuffix(strings.TrimPrefix(v[0], engineerDenyConfigurationHead022), engineerDenyConfigurationTail022)) {
		out = append(out, "junos engineer deny-configuration")
	}
	return out
}
