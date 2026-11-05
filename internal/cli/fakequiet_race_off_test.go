//go:build !race

package cli

import "time"

// fakeQuiet is the quiet period the boxes give every device session: the
// in-process fake device has nothing more to say after a prompt, so devssh's
// 150 ms default is dead time (internal/devapply's harness uses the same
// 25 ms against the same fake). A device answering the login's empty lines
// later than that used to leak its prompt into the first command's answer
// (devssh now reads that answer whatever the gaps, late_internal_test.go),
// which a loaded CI runner showed at 25 ms and 60 ms hid. The race build gives
// it more (fakequiet_race_on_test.go).
const fakeQuiet = 25 * time.Millisecond
