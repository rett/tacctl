package cli

// The limits of 'device reports' (docs/plans/0.2.26-plan.md D326): the
// largest report a user may store and the most reports a user may keep.

import "github.com/rett/tacctl/internal/reports"

// reportLimits are the caps in force for user: the size of one report in
// bytes and the number of reports kept (0 is no cap). generate refuses a
// report over either; nothing deletes a report by age.
func reportLimits(_ *invocation, _ string) (maxSize int64, maxCount int) {
	return reports.DefaultMaxSize, reports.DefaultMaxCount
}
