package tier

import (
	"regexp"
	"strings"
)

// GroupSudoers is the drop-in 'config sudoers install <group>' writes:
// passwordless tacctl for the members of group, with the environment the
// tiers drop-in keeps (EnvKeep, the password cache's variable for the
// command lines that use it and the editor's variables for the two that open
// one). Upgrade writes it again from the
// group's name (GroupOfSudoers), so a release that changes it reaches a
// host that installed it.
func GroupSudoers(group string) string {
	return "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		AskpassKeep(AskpassGroupAlias) + EditorKeep(EditorGroupAlias) + EnvKeep +
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
// 0.1.x and 0.2.0 drop-in (the rule alone), the 0.2.1 to 0.2.3 one (with
// the env_keep line for the agent socket, the console's marker and the
// display), the 0.2.4 to 0.2.6 one (with the password cache's alias too)
// the 0.2.7 one (with the editor's alias, before the colour variables
// joined the env_keep line), the 0.2.8 one (with them, before the cache's
// alias took the lines of 'device config apply', 'device config shapes
// seed', 'device onboard' and 'device collect') and the 0.2.9 to 0.2.16 one
// (before 'device enroll' joined them). Only a file that is exactly one of
// these (or the current text) is a file tacctl wrote and nobody has touched.
func groupSudoersEarlier(group string) []string {
	head := "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n"
	rule := "%" + group + " ALL=(ALL) NOPASSWD: " + Binary + "\n"
	return []string{
		head + rule,
		head + envKeep027 + rule,
		GroupSudoers026(group),
		GroupSudoers027(group),
		GroupSudoers028(group),
		GroupSudoers0216(group),
	}
}

// GroupSudoers0216 is the drop-in 'config sudoers install <group>' wrote in
// 0.2.9 to 0.2.16: this release's, with the password cache's alias before
// 'device enroll' joined its lines (0.2.17). 'tacctl rollback' puts 0.2.3's
// text back over it; the upgrade replaces it.
func GroupSudoers0216(group string) string {
	return strings.Replace(GroupSudoers(group), AskpassKeep(AskpassGroupAlias), askpassKeep0216(AskpassGroupAlias), 1)
}

// GroupSudoers026 is the drop-in 'config sudoers install <group>' wrote in
// 0.2.4 to 0.2.6: 0.2.3's, with the password cache's alias (before 'block
// adopt' joined its lines). 'tacctl rollback' puts 0.2.3's text back over it.
func GroupSudoers026(group string) string {
	return "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		groupAskpass026 + envKeep027 +
		"%" + group + " ALL=(ALL) NOPASSWD: " + Binary + "\n"
}

// GroupSudoers027 is the drop-in 'config sudoers install <group>' wrote in
// 0.2.7: 0.2.4's, with 'block adopt' among the cache's lines and the
// editor's alias, and the env_keep line without the colour variables.
// 'tacctl rollback' puts 0.2.3's text back over it. Frozen, as the alias
// texts below are: not what AskpassKeep and EditorKeep return now.
func GroupSudoers027(group string) string {
	return "# Managed by tacctl. Grants passwordless sudo on " + Binary + "\n" +
		"# to members of group '" + group + "'. Remove with: tacctl config sudoers remove\n" +
		groupAskpass027 + groupEditor027 + envKeep027 +
		"%" + group + " ALL=(ALL) NOPASSWD: " + Binary + "\n"
}

// groupAskpass027 and groupEditor027 are the password cache's and the
// editor's aliases and 'Defaults!' lines as the group drop-in of 0.2.7
// carries them. Frozen.
const (
	groupAskpass027 = "Cmnd_Alias " + AskpassGroupAlias + " = " +
		Binary + " device config pull *, " + Binary + " device config diff *, " + Binary + " device config plan *, \\\n" +
		"    " + Binary + " ssh *, " + Binary + " device ssh *, \\\n" +
		"    " + Binary + " scope block * adopt *, " + Binary + " device block * adopt *\n" +
		"Defaults!" + AskpassGroupAlias + " env_keep += \"" + AskpassVar + "\"\n"
	groupEditor027 = "Cmnd_Alias " + EditorGroupAlias + " = " +
		Binary + " scope block * edit *, " + Binary + " scope block * adopt *, \\\n" +
		"    " + Binary + " device block * edit *, " + Binary + " device block * adopt *\n" +
		"Defaults!" + EditorGroupAlias + " env_keep += \"" + EditorVars + "\"\n"
)

// groupAskpass026 is the password cache's alias and its 'Defaults!' line as
// the drop-ins of 0.2.4 to 0.2.6 carry them (the four 'device config' and
// 'ssh' lines, before 'block adopt' joined them in 0.2.7). Frozen: it is the
// text those releases wrote, not AskpassKeep, which moves on.
const groupAskpass026 = "Cmnd_Alias " + AskpassGroupAlias + " = " +
	Binary + " device config pull *, " + Binary + " device config diff *, " + Binary + " device config plan *, \\\n" +
	"    " + Binary + " ssh *, " + Binary + " device ssh *\n" +
	"Defaults!" + AskpassGroupAlias + " env_keep += \"" + AskpassVar + "\"\n"

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
