package lifecycle

// The management filter mode of a scope (0.2.20, scope_mgmt_acl.mode.<scope>)
// in a rollback. Every release before 0.2.20 refuses the key (conf.Added0220:
// its 'config validate' reports it and its 'backup restore' refuses a
// snapshot that has it), so each target removes it. The precedent is the one
// of the statements 0.2.19 added to the system blocks (blocksWarning): a
// warning, not a refusal. The rollback is not refused because removing the
// key does not touch a device, the key cannot stay (the older schema refuses
// it) and the older release plans the filter it knows, which a person reads
// and pastes: the warning says which scopes it is about and what the plan of
// the older release will then do.

import (
	"strings"
)

// mgmtModeWarning is the warning about the scopes whose management filter
// mode is strict: nil when none is.
func (p *RollbackPlan) mgmtModeWarning(target string) []RollbackWarning {
	scopes := p.in.Conf.MgmtACLStrictScopes()
	if len(scopes) == 0 {
		return nil
	}
	return []RollbackWarning{{
		Title: "Scopes with a strict management filter lose the mode",
		Lines: []string{
			target + " has no management filter mode (0.2.20): " + pluralScopes(scopes) + " " + strings.Join(scopes, ", ") + " " +
				plural(len(scopes), "is", "are") + " strict, and its walkthroughs and plans render the ssh-only filter, which ends in a default-accept term.",
			"scope_mgmt_acl.mode.<scope> is removed from tacctl.yaml (" + target + "'s schema refuses it); it stays in the snapshot --apply takes first (tacctl backup list).",
			"A device that holds the strict filter keeps it: nothing here contacts a device. " + target + "'s 'device config plan' and 'device config apply' would put the ssh-only filter back on it, deleting the strict terms and adding the default-accept term, so the device would accept by default again, and they cannot tell you so.",
			"To stay deny by default, keep this release, or do not plan or apply the management filter of those scopes with " + target + ".",
		}}}
}

func pluralScopes(scopes []string) string {
	return plural(len(scopes), "scope", "scopes")
}
