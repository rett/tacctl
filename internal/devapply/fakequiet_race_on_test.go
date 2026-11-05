//go:build race

package devapply

import "time"

// fakeQuiet under the race detector, which slows the fake device's writes
// and the client's reads several times over while the tests run in
// parallel: at 25 ms a gap between the fake's output and its prompt could
// pass for the end of the answer (the same as in internal/cli).
const fakeQuiet = 75 * time.Millisecond
