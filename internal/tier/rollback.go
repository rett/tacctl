package tier

import "strings"

// The text of the sudoers drop-ins as tacctl 0.2.3 wrote them, kept so that
// 'tacctl rollback 0.2.3' (docs/plans/0.2.4-plan.md D73) can put them back:
// 0.2.4's per-tier drop-in has the rows of 'device config pull|diff|list',
// 'device snmp' and 'console forget' and the Cmnd_Alias and env_keep line of
// the password cache (AskpassKeep). Sudo accepts both, and 0.2.3 ignores the
// extra rows (the verbs it lacks answer 'unknown'), but 0.2.3's upgrade
// compares the file with its own text, and a host that goes back should have
// the file the release it runs would write. The texts are frozen: they are
// the output of the 0.2.3 tag (testdata/sudoers.tiers.0.2.3 is its golden
// file, and a test reads the tag where it is available), not of the rules
// above, which move on.

// Sudoers023 is the per-tier drop-in 0.2.3 wrote.
func Sudoers023() string { return sudoers023 }

// Sudoers028 is the per-tier drop-in 0.2.8 wrote: this release's rules with
// the password cache's alias as 0.2.8 had it (without the 0.2.9 families
// 'device config apply', 'device onboard' and 'device collect', D141/D143)
// and the
// env_keep line as 0.2.8 had it. 'tacctl rollback 0.2.8' puts it back, and
// the upgrade's refresh knows it as an older text. The rows of the table are
// the same in the two releases, so it is derived from them (a rule that
// moves on again makes its own frozen copy); the two lines that did move are
// frozen below, and a test reads the 0.2.8 tag's golden file where the tag
// is available.
func Sudoers028() string {
	t := strings.Replace(Sudoers(), AskpassKeep(AskpassAlias), askpassKeep028(AskpassAlias), 1)
	return strings.Replace(t, EnvKeep, envKeep028, 1)
}

// GroupSudoers028 is the drop-in 'config sudoers install <group>' wrote in
// 0.2.8: 0.2.7's, with the colour variables on the env_keep line. 'tacctl
// rollback 0.2.8' puts it back over this release's. Frozen.
func GroupSudoers028(group string) string {
	return "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		groupAskpass027 + groupEditor027 + envKeep028 +
		"%" + group + " ALL=(ALL) NOPASSWD: " + Binary + "\n"
}

// envKeep028 is the env_keep line of the drop-ins of 0.2.8, frozen: the
// line that release wrote, not EnvKeep, which moves on.
const envKeep028 = "Defaults!" + Binary + " env_keep += \"" + envKeepNames027 + " NO_COLOR TACCTL_COLOR\"\n"

// askpassKeep028 is the password cache's alias and its 'Defaults!' line as
// the per-tier drop-in of 0.2.7 and 0.2.8 carries them (the lines of 'device
// config', 'ssh' and 'block adopt'), before 0.2.9 added the 'device config
// apply', 'device onboard' and 'device collect' lines. Frozen: not AskpassKeep.
func askpassKeep028(alias string) string {
	return "Cmnd_Alias " + alias + " = " +
		Binary + " device config pull *, " + Binary + " device config diff *, " + Binary + " device config plan *, \\\n" +
		"    " + Binary + " ssh *, " + Binary + " device ssh *, \\\n" +
		"    " + Binary + " scope block * adopt *, " + Binary + " device block * adopt *\n" +
		"Defaults!" + alias + " env_keep += \"" + AskpassVar + "\"\n"
}

// Sudoers027 is the per-tier drop-in 0.2.4 to 0.2.7 wrote: 0.2.8's text
// without the 'version --long' item and with the env_keep line that has not
// the colour variables. It is the text 'tacctl rollback' and the upgrade's
// refresh know as an older one; it is derived (a rule that moves on again
// makes its own frozen copy).
func Sudoers027() string {
	t := strings.Replace(Sudoers028(), envKeep028, envKeep027, 1)
	// 0.2.8 lists 'version --long' beside 'version'; 0.2.7 did not.
	return strings.Replace(t, ", "+Binary+" version --long", "", 1)
}

const sudoers023 = `# Managed by tacctl. Per-tier access for tacctl users with local accounts.
# Remove with: tacctl config sudoers tiers remove
Cmnd_Alias TACCTL_RO = /usr/local/bin/tacctl "", /usr/local/bin/tacctl passwd, /usr/local/bin/tacctl status, /usr/local/bin/tacctl version, \
    /usr/local/bin/tacctl help, /usr/local/bin/tacctl -h, /usr/local/bin/tacctl --help, \
    /usr/local/bin/tacctl user list, /usr/local/bin/tacctl user show *, /usr/local/bin/tacctl group list, /usr/local/bin/tacctl group show *, /usr/local/bin/tacctl scope list, \
    /usr/local/bin/tacctl backend list, /usr/local/bin/tacctl backend status, /usr/local/bin/tacctl backend status *, \
    /usr/local/bin/tacctl ssh *, /usr/local/bin/tacctl device list, /usr/local/bin/tacctl device list *, /usr/local/bin/tacctl device show *, /usr/local/bin/tacctl device notices, /usr/local/bin/tacctl device notices *, /usr/local/bin/tacctl device ssh *, /usr/local/bin/tacctl device ssh-config, \
    /usr/local/bin/tacctl _completion-names *, /usr/local/bin/tacctl _console-policy
Cmnd_Alias TACCTL_OP = /usr/local/bin/tacctl log tail, /usr/local/bin/tacctl log tail *, /usr/local/bin/tacctl log search *, \
    /usr/local/bin/tacctl log failures, /usr/local/bin/tacctl log accounting, /usr/local/bin/tacctl log accounting *, \
    /usr/local/bin/tacctl config validate, /usr/local/bin/tacctl backup list, \
    /usr/local/bin/tacctl device check *, /usr/local/bin/tacctl device scan, /usr/local/bin/tacctl device scan *, /usr/local/bin/tacctl device discover, /usr/local/bin/tacctl device discover *, /usr/local/bin/tacctl device export, /usr/local/bin/tacctl device export *, \
    /usr/local/bin/tacctl console show, /usr/local/bin/tacctl console check
Cmnd_Alias TACCTL_EN = /usr/local/bin/tacctl device add *, /usr/local/bin/tacctl device remove *, /usr/local/bin/tacctl device rename *, \
    /usr/local/bin/tacctl device address *, /usr/local/bin/tacctl device hostname *, /usr/local/bin/tacctl device vendor *, /usr/local/bin/tacctl device port *, \
    /usr/local/bin/tacctl device description *, /usr/local/bin/tacctl device location *, /usr/local/bin/tacctl device legacy-ssh *, /usr/local/bin/tacctl device hostkey *, /usr/local/bin/tacctl device import -, /usr/local/bin/tacctl device import - *, \
    /usr/local/bin/tacctl scope devices *, \
    /usr/local/bin/tacctl device config, /usr/local/bin/tacctl device config show *, /usr/local/bin/tacctl config cisco, /usr/local/bin/tacctl config cisco *, /usr/local/bin/tacctl config juniper, /usr/local/bin/tacctl config juniper *, /usr/local/bin/tacctl config wti, /usr/local/bin/tacctl config wti *, \
    /usr/local/bin/tacctl host list, /usr/local/bin/tacctl host show *, \
    /usr/local/bin/tacctl scope staging, /usr/local/bin/tacctl scope staging list, /usr/local/bin/tacctl scope secret *, /usr/local/bin/tacctl scope snmp *, /usr/local/bin/tacctl scope show *

Defaults!/usr/local/bin/tacctl env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"
%tac-superuser ALL=(ALL:ALL) ALL
%tac-superuser ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP, TACCTL_EN
%tac-engineer ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP, TACCTL_EN
%tac-operator ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP
%tac-readonly ALL=(root) NOPASSWD: TACCTL_RO
`

// GroupSudoers023 is the drop-in 'config sudoers install <group>' wrote in
// 0.2.1 to 0.2.3: the header, the env_keep line of the agent socket, the
// console's marker and the display, and the rule.
func GroupSudoers023(group string) string {
	return "# Managed by tacctl. Grants passwordless sudo on /usr/local/bin/tacctl\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		"Defaults!/usr/local/bin/tacctl env_keep += \"SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY\"\n" +
		"%" + group + " ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl\n"
}
