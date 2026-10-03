//go:build !testknobs

package app

import "github.com/rett/tacctl/internal/paths"

// TestKnobs reports whether this binary was built with -tags testknobs; a
// production build (the shim, 'tacctl upgrade') never is, so it reads none
// of the test-only environment knobs.
const TestKnobs = false

// loadKnobs reads nothing: a production binary has no knobs.
func loadKnobs(paths.Env) (Knobs, error) {
	return Knobs{}, nil
}
