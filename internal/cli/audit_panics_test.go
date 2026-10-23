package cli

// The Go tests find a command classified read that reaches a write: it
// panics (audit.go, docs/plans/0.2.17-plan.md D249).
func init() { auditPanics = true }
