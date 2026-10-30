package lifecycle

// The rollback to 0.2.19 (the release before 0.2.20): the part of
// PlanRollback that runs when RollbackInput.Target is RollbackTarget0219.
// What 0.2.20 changed that a 0.2.19 binary reads, checked against the sources
// of the 0.2.19 tag and, where a test can, against that release built from
// the tag (internal/cli TestRollbackRealOldBinary0219):
//
//	tacctl.yaml       the management filter mode of a scope
//	                  (scope_mgmt_acl.mode.<scope>, conf.Added0220): 0.2.19's
//	                  schema refuses it, so it is removed after a snapshot and
//	                  mgmtModeWarning names the scopes that were strict. The
//	                  emergency lockdown record is 0.2.19's own and unchanged,
//	                  so a lockdown that stands does not refuse this target
//	                  (it does every older one) and the record stays. A 'root'
//	                  break-glass entry (0.2.20) is one 0.2.19's schema
//	                  accepts: it stays, and rootBreakGlassWarning says what
//	                  0.2.19 makes of it (every target).
//	store.yaml        password_change_required (0.2.20): removed for every
//	                  target (rollback_pwchange.go). A user name with a
//	                  period refuses every target (DottedUsersRefusal).
//	console.yaml      settings.color, settings.system_shell_users (the
//	                  values 'disable' and 'enable:<tier>' alike),
//	                  settings.password_cache_users and a list_max of -1 are
//	                  refused by 0.2.19's parser ("settings: unknown key"):
//	                  removed for every target (console.RollbackSince0220).
//	                  settings.system_shell_tiers, which now always holds
//	                  superuser, is a list 0.2.19 reads. The 'tiers' and
//	                  'users' switches this release ignores stay, and 0.2.19
//	                  reads them as it always did: consoleWideningWarning
//	                  names who gains a system shell (bash at 0.2.19's next
//	                  host sync of the server) or the password cache.
//	sudoers           the per-tier drop-in grants the engineer 'scope mgmt-acl
//	                  * mode' and the operator the read forms of 'console
//	                  system-shell' and 'console password-cache [on|off]'; a
//	                  file that is exactly this release's text is rewritten
//	                  with 0.2.19's (tier.Sudoers0219, through 'visudo -cf'),
//	                  any other is left. 'man' and 'completion' are tier rows
//	                  without a sudoers line. The group drop-in is unchanged.
//	VarLib records    devices-config.json is version 1 with no new field, and
//	                  the plan's 'kept' and 'own' are output only, never
//	                  stored. The sections files of a Junos device hold the
//	                  root statements in the breakglass section (0.2.20's
//	                  pull), which 0.2.19 compares as extra statements: every
//	                  target that reads the records takes them out
//	                  (rollback_rootleaves.go).
//	devices.yaml      unchanged (the host keys are pinned in the same form,
//	                  however they were read); left.
//	hosts             the registry and what is written on an enrolled host
//	                  are unchanged; the login shells of the server's own
//	                  accounts are set by 0.2.19's next host sync of the
//	                  server (see the console warning).
//	what else         the blocks, the SNMP credentials, the apply state
//	                  directory and the rendered backend files (a '#
//	                  tacctl-carved' comment is a comment there) are in
//	                  formats 0.2.19 reads; the manual page carried by the
//	                  binary goes with it (0.2.19's upgrade installs its own).

import (
	"slices"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/tier"
)

// planRollback0219 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before 0.2.20.
func planRollback0219(p *RollbackPlan) (*RollbackPlan, error) {
	in := p.in
	pt := in.Paths
	p.keys = slices.DeleteFunc(in.Conf.RollbackKeys0218(), func(k string) bool { return !conf.Added0220Key(k) && !conf.Added0221Key(k) && !conf.Added0222Key(k) })
	tiers := p.tiersPlan(tier.Sudoers0219(), tier.Sudoers())
	p.sudoers = []sudoersPlan{tiers}
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0219), p.tiersStep(RollbackTarget0219, tiers,
		"the engineer's rule of 'scope mgmt-acl * mode' and the operator's rules of 'console system-shell' and 'console password-cache' are taken out"),
		RollbackStep{Title: "leave every other file untouched",
			Lines: []string{pt.DevicesFile + ", " + pt.ConsoleFile + ", " + pt.StoreFile + ", the group sudoers drop-in, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0219 + " reads;",
				"an emergency lockdown and the break-glass entries stay (" + RollbackTarget0219 + " has both; 'root': see the warning, if any);",
				"nothing is re-rendered or restarted, and no device is contacted"}})
	if in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0219 + ": 0.2.20 changed nothing on the enrolled hosts (the login shells of this server's own accounts are " + RollbackTarget0219 + "'s next host sync's: see the warning, if any); no host is synced"}})
	}
	p.Warnings = append(p.mgmtModeWarning(RollbackTarget0219), p.consoleWideningWarning()...)
	return p, nil
}
