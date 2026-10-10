package tier

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
