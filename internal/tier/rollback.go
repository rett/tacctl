package tier

import (
	"slices"
	"strings"
)

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

// rules0222 are the rules 0.2.20 to 0.2.22 had: this release's without the
// engineer's row of 'device clone' (0.2.23).
func rules0222() []Rule {
	return slices.DeleteFunc(slices.Clone(Rules), func(r Rule) bool {
		return r.Tier == Engineer && r.Cmd == "device" && r.Sub == "clone"
	})
}

// Sudoers0222 is the per-tier drop-in 0.2.20 to 0.2.22 wrote: this release's
// rules without the engineer's row of 'device clone' (0.2.23). It is an older
// text of this tool's: every target that rewrites the drop-in recognises it,
// as it does this release's, and puts back its own. It is derived (a rule that
// moves on again makes its own frozen copy).
func Sudoers0222() string { return sudoersFrom(rules0222()) }

// rules0219 are the rules 0.2.19 had: this release's without the engineer's
// rows of 'device clone' (0.2.23) and 'scope mgmt-acl' and the operator's rows
// of 'console system-shell' and 'console password-cache' (0.2.20).
func rules0219() []Rule {
	return slices.DeleteFunc(rules0222(), func(r Rule) bool {
		return (r.Tier == Engineer && r.Cmd == "scope" && r.Sub == "mgmt-acl") ||
			(r.Tier == Operator && r.Cmd == "console" && (r.Sub == "system-shell" || r.Sub == "password-cache"))
	})
}

// Sudoers0219 is the per-tier drop-in 0.2.19 wrote: this release's rules
// without the engineer's row of 'scope mgmt-acl * mode' and the operator's
// rows of 'console system-shell' and 'console password-cache' (0.2.20). A rollback
// to 0.2.18 and 0.2.17 recognises it as an older text. It is derived (a rule
// that moves on again makes its own frozen copy).
func Sudoers0219() string { return sudoersFrom(rules0219()) }

// Sudoers0218 is the per-tier drop-in 0.2.18 wrote: 0.2.19's rules
// without the engineer's rows of 'device config apply', 'device enroll',
// 'device collect', 'device onboard' and 'device sync' (0.2.19). 'tacctl
// rollback 0.2.18' puts it back, and the upgrade's refresh knows it as an
// older text. It is derived (a rule that moves on again makes its own frozen
// copy).
func Sudoers0218() string {
	added := map[string]bool{"enroll": true, "collect": true, "onboard": true, "sync": true, "support-bundle": true}
	var rules []Rule
	for _, r := range rules0219() {
		switch {
		case r.Tier == Engineer && r.Cmd == "device" && added[r.Sub]:
			continue
		case r.Tier == Engineer && r.Cmd == "device" && r.Sub == "config":
			r.Sudoers = slices.DeleteFunc(slices.Clone(r.Sudoers), func(p string) bool { return p == "device config apply *" })
		}
		rules = append(rules, r)
	}
	return sudoersFrom(rules)
}

// Sudoers0217 is the per-tier drop-in 0.2.17 wrote: 0.2.18's rules
// with 0.2.17's names of the verbs 0.2.18 renamed and dropped the old names
// of (D273 to D275): the engineer's 'device config-syntax *' for 'device
// ios-syntax *', and the read-only 'device notices' and 'device notices *'
// for 'device notice list' and 'device notice list *', 'device ssh-config'
// for 'device client-config'. 'tacctl rollback 0.2.17' puts it back, so the
// old names run through sudo again under 0.2.17; the rollback to 0.2.3
// recognises it as an older text. It is derived (a rule that moves on again
// makes its own frozen copy).
func Sudoers0217() string {
	return strings.NewReplacer(
		Binary+" device ios-syntax *, ", Binary+" device config-syntax *, ",
		Binary+" device notice list, "+Binary+" device notice list *, ", Binary+" device notices, "+Binary+" device notices *, ",
		Binary+" device client-config, ", Binary+" device ssh-config, ",
	).Replace(Sudoers0218())
}

// Sudoers0216 is the per-tier drop-in 0.2.15 and 0.2.16 wrote: 0.2.17's
// rules with the password cache's alias as 0.2.9 to 0.2.16 had it (before
// 'device enroll' joined its lines, 0.2.17 D269). The rollback to 0.2.3
// recognises it as an older text; it is derived from the rules, with the
// alias frozen (askpassKeep0216).
func Sudoers0216() string {
	return strings.Replace(Sudoers0217(), AskpassKeep(AskpassAlias), askpassKeep0216(AskpassAlias), 1)
}

// Sudoers0214 is the per-tier drop-in 0.2.14 wrote: 0.2.16's rules
// without the operator's 'config validate --json' item (0.2.15). The rollback
// to 0.2.3 recognises it as an older text; it is derived (a rule that moves
// on again makes its own frozen copy).
func Sudoers0214() string {
	return strings.Replace(Sudoers0216(), ", "+Binary+" config validate --json", "", 1)
}

// Sudoers0213 is the per-tier drop-in 0.2.9 to 0.2.13 wrote: 0.2.14's rules
// without the engineer's 'host list --json' item (0.2.14). The rollback to
// 0.2.3 recognises it as an older text; it is derived like Sudoers0214.
func Sudoers0213() string {
	return strings.Replace(Sudoers0214(), ", "+Binary+" host list --json", "", 1)
}

// Sudoers028 is the per-tier drop-in 0.2.8 wrote: 0.2.13's rules with
// the password cache's alias as 0.2.8 had it (without the 0.2.9 families
// 'device config apply', 'device onboard' and 'device collect', D141/D143)
// and the
// env_keep line as 0.2.8 had it. The rollback to 0.2.3 recognises it as an
// older text, and the upgrade's refresh knows it as one. The rows of the table are
// the same in the two releases, so it is derived from them (a rule that
// moves on again makes its own frozen copy); the two lines that did move are
// frozen below, and a test reads the 0.2.8 tag's golden file where the tag
// is available.
func Sudoers028() string {
	t := strings.Replace(Sudoers0213(), askpassKeep0216(AskpassAlias), askpassKeep028(AskpassAlias), 1)
	return strings.Replace(t, EnvKeep, envKeep028, 1)
}

// GroupSudoers028 is the drop-in 'config sudoers install <group>' wrote in
// 0.2.8: 0.2.7's, with the colour variables on the env_keep line. The
// rollback to 0.2.3 recognises it as an older text. Frozen.
func GroupSudoers028(group string) string {
	return "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		groupAskpass027 + groupEditor027 + envKeep028 +
		"%" + group + " ALL=(ALL) NOPASSWD: " + Binary + "\n"
}

// envKeep028 is the env_keep line of the drop-ins of 0.2.8, frozen: the
// line that release wrote, not EnvKeep, which moves on.
const envKeep028 = "Defaults!" + Binary + " env_keep += \"" + envKeepNames027 + " NO_COLOR TACCTL_COLOR\"\n"

// askpassKeep0216 is the password cache's alias and its 'Defaults!' line as
// the drop-ins of 0.2.9 to 0.2.16 carry them (with the 'device config apply',
// 'device onboard' and 'device collect' lines), before 0.2.17 added 'device
// enroll'. Frozen: not AskpassKeep.
func askpassKeep0216(alias string) string {
	return "Cmnd_Alias " + alias + " = " +
		Binary + " device config pull *, " + Binary + " device config diff *, " + Binary + " device config plan *, \\\n" +
		"    " + Binary + " ssh *, " + Binary + " device ssh *, \\\n" +
		"    " + Binary + " scope block * adopt *, " + Binary + " device block * adopt *, \\\n" +
		"    " + Binary + " device config apply *, " + Binary + " device onboard *, " + Binary + " device collect *\n" +
		"Defaults!" + alias + " env_keep += \"" + AskpassVar + "\"\n"
}

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
