//go:build race

package cli

import "time"

// fakeQuiet under the race detector, which slows the fake device's writes
// and the client's reads several times over while the cli tests run
// sixteen at a time: at 25 ms a gap between the fake's output and its
// prompt could pass for the end of the answer, and the rest leaked into
// the next command's (a 'configure exclusive' read the login's prompt).
const fakeQuiet = 75 * time.Millisecond
