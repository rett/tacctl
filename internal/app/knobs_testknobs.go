//go:build testknobs

package app

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/paths"
)

// TestKnobs reports whether this binary was built with -tags testknobs
// ('make build'), which compiles in the test-only environment knobs
// (TACCTL_TEST_NOW, TACCTL_TEST_RANDOM, TACCTL_FAULT, TACCTL_TEST_ROOT; docs/plans/go-rewrite.md
// 3.6, Decision 17). 'tacctl version --long' prints it.
const TestKnobs = true

// loadKnobs is the only place the knob variables are read.
func loadKnobs(env paths.Env) (Knobs, error) {
	var k Knobs
	if v := env.Get(EnvTestNow); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Knobs{}, fmt.Errorf("%s=%q: not an RFC 3339 time (2025-01-02T03:04:05Z)", EnvTestNow, v)
		}
		k.now = t.In(time.Local)
	}
	if v := env.Get(EnvTestRandom); v != "" {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) == 0 {
			return Knobs{}, fmt.Errorf("%s=%q: not hex bytes (an even number of 0-9a-f)", EnvTestRandom, v)
		}
		k.random = b
	}
	if v := env.Get(EnvFault); v != "" {
		k.faults = map[string]bool{}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				k.faults[p] = true
			}
		}
	}
	if v := env.Get(EnvTestRoot); v != "" {
		if !filepath.IsAbs(v) {
			return Knobs{}, fmt.Errorf("%s=%q: not an absolute path", EnvTestRoot, v)
		}
		k.root = v
	}
	if v := env.Get(EnvTestProc); v != "" {
		if !filepath.IsAbs(v) {
			return Knobs{}, fmt.Errorf("%s=%q: not an absolute path", EnvTestProc, v)
		}
		k.proc = v
	}
	return k, nil
}
