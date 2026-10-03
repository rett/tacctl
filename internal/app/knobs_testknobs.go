//go:build testknobs

package app

// TestKnobs reports whether this binary was built with -tags testknobs
// ('make build'), which compiles in the test-only environment knobs
// (TACCTL_TEST_NOW, TACCTL_TEST_RANDOM, TACCTL_FAULT; docs/plans/go-rewrite.md
// 3.6, Decision 17). 'tacctl version --long' prints it.
const TestKnobs = true
