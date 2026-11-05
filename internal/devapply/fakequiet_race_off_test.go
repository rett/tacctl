//go:build !race

package devapply

import "time"

// fakeQuiet is the quiet period the harness gives every fake device
// session: the product's is 150 ms, and the fake answers in microseconds.
// The race build gives it more (fakequiet_race_on_test.go).
const fakeQuiet = 25 * time.Millisecond
