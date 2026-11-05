//go:build !race

package cli

import "time"

// fakeQuiet is the quiet period the boxes give every device session: the
// in-process fake device has nothing more to say after a prompt, so devssh's
// 150 ms default is dead time (internal/devapply's harness uses the same
// 60 ms against the same fake). 25 ms was too short for a loaded CI runner,
// where a gap between the fake's output and its prompt passed for the end of
// the answer. The race build gives it more (fakequiet_race_on_test.go).
const fakeQuiet = 60 * time.Millisecond
