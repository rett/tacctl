package cli

// The limits of 'device reports' (docs/plans/0.2.26-plan.md D326): the
// largest report a user may store and the most reports a user may keep.

// reportLimits are the caps in force for user: the size of one report in
// bytes and the number of reports kept (0 is no cap). They are the global
// settings of 'config reports' unless the user has an own limit (see
// effectiveReportLimits). generate refuses a report over either; nothing
// deletes a report by age but 'prune'.
func reportLimits(inv *invocation, user string) (maxSize int64, maxCount int) {
	return inv.effectiveReportLimits(user)
}
