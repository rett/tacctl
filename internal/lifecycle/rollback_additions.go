package lifecycle

// The one place that lists what a release changed in a stored file and every
// older rollback target has to undo.
//
// A target's own plan (rollback0222.go, rollback0221.go, ...) says what that
// target converts, and several of them return before the generic steps run
// (0.2.22, 0.2.21 and 0.2.20 read most of what this release writes). A change
// that every older release refuses, such as the timing scale, does not belong
// in each of those plans: it is one entry of rollbackAdditions, and
// PlanRollback adds its steps, warnings and notes after the target's plan, for
// each target older than the release that made the change, the early ones
// included. A release that adds such a change appends an entry here and
// nothing else in the plans; a target that is that release or newer is left
// alone (the 0.2.22 target keeps the timing scale, the 0.2.21 one drops it).
//
// An entry has two functions. Read looks at the state and keeps what it found
// in the plan (it writes nothing and runs before Add); Add completes the
// plan: its steps go before "leave every other file untouched" when the
// target has that step, its notes and warnings at the end. ApplyRollback does
// the writes from what Read kept, as for any other conversion. The command
// asks RollbackUndoes (below) whether a target undoes a release's change, for
// the text it prints after the apply.

import (
	"strconv"
	"strings"
)

// rollbackAddition is the rollback side of one release's change to a stored
// file.
type rollbackAddition struct {
	// Release is the release that made the change ("0.2.22"). Every target
	// older than it undoes the change; that release's own target and the
	// newer ones do not.
	Release string
	// Read finds what the change left in the state, in the plan.
	Read func(*RollbackPlan) error
	// Add puts the steps and notes into the plan.
	Add func(*RollbackPlan)
}

// rollbackAdditions is the list: the changes of the releases from 0.2.22 on,
// in the order of their release. The timing scale is rollback_timeoutscale.go,
// the users' email addresses are rollback_email.go and the SNMPv3 user pool
// is rollback_snmp_pool.go and the lockdown on hosts is
// rollback_lockdown_hosts.go.
var rollbackAdditions = []rollbackAddition{
	{Release: "0.2.22", Read: (*RollbackPlan).planTimeoutScale, Add: (*RollbackPlan).addTimeoutScale},
	{Release: "0.2.23", Read: (*RollbackPlan).planEmail, Add: (*RollbackPlan).addEmail},
	{Release: "0.2.23", Read: (*RollbackPlan).planSNMPPool, Add: (*RollbackPlan).addSNMPPool},
	{Release: "0.2.23", Read: (*RollbackPlan).planLockdownHosts},
}

// addReleaseChanges runs the entries of additions that apply to p's target.
func (p *RollbackPlan) addReleaseChanges(additions []rollbackAddition) error {
	for _, a := range additions {
		if !RollbackUndoes(p.target(), a.Release) {
			continue
		}
		if a.Read != nil {
			if err := a.Read(p); err != nil {
				return err
			}
		}
		if a.Add != nil {
			a.Add(p)
		}
	}
	return nil
}

// RollbackUndoes reports whether the rollback to target undoes what release
// changed: target is older than release. A version that is not of the form
// 0.2.N reports false.
func RollbackUndoes(target, release string) bool {
	t, r := releaseNumbers(target), releaseNumbers(release)
	if t == nil || r == nil {
		return false
	}
	for i := range t {
		if t[i] != r[i] {
			return t[i] < r[i]
		}
	}
	return false
}

// releaseNumbers is the three numbers of a version ("0.2.22"), nil for
// anything else.
func releaseNumbers(v string) []int {
	m := reVersion.FindStringSubmatch(strings.TrimPrefix(v, "v"))
	if m == nil {
		return nil
	}
	out := make([]int, 3)
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}
