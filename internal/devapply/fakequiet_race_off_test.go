//go:build !race

package devapply

import "time"

// fakeQuiet is the quiet period the harness gives every fake device
// session: the product's is 150 ms, and the fake answers in microseconds.
// 25 ms was too short on a loaded CI runner; the likely cause was a late
// answer to the login's empty lines leaking into the first command's
// answer, which devssh now reads whatever the gaps (late_internal_test.go).
// That was never reproduced locally, so the constant stays at 60 ms until a
// CI run shows 25 ms holds.
// The race build gives it more (fakequiet_race_on_test.go).
const fakeQuiet = 60 * time.Millisecond
