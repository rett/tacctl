package cli

// The superuser's reach into other users' reports (docs/plans/0.2.26-plan.md
// D328, D329): 'list --user <name>' and 'list --all-users', and
// '<user>/<report>' for show, export, rename and remove, and 'prune --user' and
// 'prune --all-users'. Every access to
// another user's reports writes one audit line (who, whose, which report and
// the verb, never the contents) before anything is read or changed. No verb
// writes a report into another user's home (D329).

import (
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/reports"
	"github.com/rett/tacctl/internal/tier"
)

// reportsSuper says whether the caller is a superuser.
func (inv *invocation) reportsSuper() bool {
	return tierPermits(inv.tierGate().Caller(inv.ctx), tier.Superuser)
}

// reportsDenied is the refusal of another user's reports to a caller who is
// not a superuser.
func (inv *invocation) reportsDenied(what string) error {
	return inv.deniedUsage(reasonSuperuser, what+" is the superuser's: you reach your own reports only. Nothing was done.")
}

// reportsAccess writes the audit line of one access to another user's
// reports. It is a reveal: under audit.strict an access whose line cannot be
// written is refused before anything is shown.
func (inv *invocation) reportsAccess(verb, owner, report string) {
	inv.app.Audit().Reveal(audit.Notice, "device reports access",
		kvp("verb", verb), kvp("owner", owner), kvp("report", report), audit.Pair("by", inv.sudoUser()))
}

// reportsPruneAccess writes the audit line of a prune of another user's
// reports, listed (verb prune-dry-run) or removed (prune): who, whose and how
// many, never a name. It is written before the reports are listed or
// removed, and is a reveal, so that under audit.strict a line that cannot be
// written refuses the prune.
func (inv *invocation) reportsPruneAccess(verb, owner string, n int) {
	inv.app.Audit().Reveal(audit.Notice, "device reports access",
		kvp("verb", verb), kvp("owner", owner), kvp("count", strconv.Itoa(n)), audit.Pair("by", inv.sudoUser()))
}

// reportTarget is the report a verb works on.
type reportTarget struct {
	pl    reportPlace
	owner string
	// cross: the report is another user's.
	cross bool
	dir   reportDir
	f     *reportFile
}

// reportTargetOf finds the report ref names: <report> in the caller's own
// directory, or <user>/<report>, which only a superuser may name (a user's
// own name is the caller's own directory). The verb is audited when the
// report is another user's.
func (inv *invocation) reportTargetOf(verb, ref string) (reportTarget, error) {
	t := reportTarget{owner: inv.sudoUser()}
	name := ref
	if u, r, ok := strings.Cut(ref, "/"); ok {
		t.owner, name = u, r
	}
	t.cross = t.owner != inv.sudoUser()
	if t.cross && !inv.reportsSuper() {
		return t, inv.reportsDenied("A report of another user")
	}
	if name == "" || strings.Contains(name, "/") || strings.HasSuffix(name, ".meta") || reports.ValidName(name) != nil {
		return t, inv.usageErr("'" + ref + "' is not the name of a report: use the name from 'tacctl device reports list'" +
			" (a superuser names another user's as <user>/<report>).")
	}
	var err error
	if t.pl, err = inv.reportPlaceOf(t.owner); err != nil {
		return t, inv.usageErr(err.Error() + ".")
	}
	if t.cross {
		inv.reportsAccess(verb, t.owner, name)
	}
	if t.dir, err = t.pl.read(); err != nil {
		return t, inv.usageErr(err.Error())
	}
	if t.f, err = t.dir.find(name); err != nil {
		return t, inv.usageErr(err.Error() + ".")
	}
	return t, nil
}

// reportOwners are the users whose reports 'list --all-users' looks at: the
// users tacctl knows.
func (inv *invocation) reportOwners() ([]string, error) {
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	names := m.UserNames()
	sort.Strings(names)
	return names, nil
}
