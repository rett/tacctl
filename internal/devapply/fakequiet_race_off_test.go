//go:build !race

package devapply

import "time"

// fakeQuiet is the quiet period the harness gives every fake device
// session: the product's is 150 ms, and the fake answers in microseconds.
// A late answer to the login's empty lines used to leak into the first
// command's answer at this length on a loaded runner; devssh reads it
// whatever the gaps now (late_internal_test.go).
// The race build gives it more (fakequiet_race_on_test.go).
const fakeQuiet = 25 * time.Millisecond
