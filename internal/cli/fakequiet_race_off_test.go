//go:build !race

package cli

import "time"

// fakeQuiet is the quiet period the boxes give every device session: the
// in-process fake device has nothing more to say after a prompt, so devssh's
// 150 ms default is dead time (internal/devapply's harness uses the same
// 60 ms against the same fake). 25 ms was too short on a loaded CI runner;
// the likely cause was the answer to the login's second empty line arriving
// late and leaking into the first command's answer, which devssh now reads
// whatever the gaps (late_internal_test.go). That was never reproduced
// locally, so the constant stays at 60 ms until a CI run shows 25 ms holds.
// The race build gives it more (fakequiet_race_on_test.go).
const fakeQuiet = 60 * time.Millisecond
