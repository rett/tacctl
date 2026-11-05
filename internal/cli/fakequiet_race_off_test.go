//go:build !race

package cli

import "time"

// fakeQuiet is the quiet period the boxes give every device session: the
// in-process fake device has nothing more to say after a prompt, so devssh's
// 150 ms default is dead time (internal/devapply's harness uses the same
// 25 ms against the same fake). The race build gives it more
// (fakequiet_race_on_test.go).
const fakeQuiet = 25 * time.Millisecond
