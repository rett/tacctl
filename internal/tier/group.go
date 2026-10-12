package tier

import (
	"regexp"
	"strings"
)

// GroupSudoers is the drop-in 'config sudoers install <group>' writes:
// passwordless tacctl for the members of group, with the environment the
// tiers drop-in keeps (EnvKeep, and the password cache's variable for the
// four command lines that use it). Upgrade writes it again from the
// group's name (GroupOfSudoers), so a release that changes it reaches a
// host that installed it.
func GroupSudoers(group string) string {
	return "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		AskpassKeep(AskpassGroupAlias) + EnvKeep +
		"%" + group + " ALL=(ALL) NOPASSWD: " + Binary + "\n"
}

var reGroupSudoersHeader = regexp.MustCompile(`^# to members of group '([a-zA-Z_][a-zA-Z0-9_-]*)'\. Remove with: tacctl config sudoers remove$`)

// GroupOfSudoers is the group a drop-in's header names, in the form
// 'config sudoers install' writes it, and false for a file whose first
// lines are not that (not tacctl's). It says nothing about the body.
func GroupOfSudoers(text string) (string, bool) {
	lines := strings.SplitN(text, "\n", 3)
	if len(lines) < 3 || lines[0] != "# Managed by tacctl. Grants passwordless sudo on "+Binary {
		return "", false
	}
	m := reGroupSudoersHeader.FindStringSubmatch(lines[1])
	if m == nil {
		return "", false
	}
	return m[1], true
}

// groupSudoersEarlier are the texts earlier releases wrote for group: the
// 0.1.x and 0.2.0 drop-in (the rule alone) and the 0.2.1 to 0.2.3 one (with
// the env_keep line for the agent socket, the console's marker and the
// display). Only a file that is exactly one of these (or the current text)
// is a file tacctl wrote and nobody has touched.
func groupSudoersEarlier(group string) []string {
	head := "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n"
	rule := "%" + group + " ALL=(ALL) NOPASSWD: " + Binary + "\n"
	return []string{
		head + rule,
		head + EnvKeep + rule,
	}
}

// GroupFile says what a sudoers file is to the upgrade's refresh.
type GroupFile int

// The kinds of drop-in ClassifyGroupSudoers tells apart.
const (
	// GroupForeign: not written by 'config sudoers install' (no header of
	// its form): left alone and not mentioned.
	GroupForeign GroupFile = iota
	// GroupCurrent: this release's text for the group.
	GroupCurrent
	// GroupOlder: exactly a text an earlier release wrote for the group:
	// replaced by this release's.
	GroupOlder
	// GroupUnrecognised: it says tacctl wrote it ('# Managed by tacctl')
	// but not for a group this release knows ('config sudoers install'
	// accepts [a-zA-Z_][a-zA-Z0-9_-]* and nothing else): left alone, with a
	// line saying so, since the cache's variable will not cross sudo for it.
	GroupUnrecognised
	// GroupCustomised: a tacctl header over a body that is none of those
	// (an administrator's edit, or a forged header): left alone, with a
	// warning.
	GroupCustomised
)

// ClassifyGroupSudoers reads a drop-in's text: the group its header names
// and which kind of file it is.
func ClassifyGroupSudoers(text string) (string, GroupFile) {
	group, ok := GroupOfSudoers(text)
	if !ok {
		if strings.Contains(text, "# Managed by tacctl") {
			return "", GroupUnrecognised
		}
		return "", GroupForeign
	}
	if text == GroupSudoers(group) {
		return group, GroupCurrent
	}
	for _, old := range groupSudoersEarlier(group) {
		if text == old {
			return group, GroupOlder
		}
	}
	return group, GroupCustomised
}
