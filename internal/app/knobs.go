package app

import (
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/rett/tacctl/internal/paths"
)

// The test-only knobs of docs/plans/go-rewrite.md 3.6 (Decision 17). They
// let a test fix what a command would otherwise take from the world:
//
//	TACCTL_TEST_NOW=<RFC3339>    the clock: Now returns that instant
//	TACCTL_TEST_RANDOM=<hex>     the random source: Rand yields these bytes,
//	                             repeated from the start when more are read
//	TACCTL_FAULT=<point>[,...]   the named steps fail: Fault(point) errors
//	TACCTL_TEST_ROOT=<dir>       tacctl's fixed host locations (the deploy
//	                             clone, /usr/local/bin/tacctl, Go, the
//	                             completion, the man page, /root) move
//	                             under <dir> (paths.Paths.Reroot), so a test
//	                             can run install, upgrade and uninstall
//
// They are read from the environment only by a binary built with
// -tags testknobs ('make build', which the bats harness and the differential
// runner use); knobs_testknobs.go reads them, knobs_off.go does not. A
// production binary (the shim, 'tacctl upgrade') therefore has no clock,
// randomness or fault override reachable from the environment, whatever the
// variables hold, and 'tacctl version --long' says which kind it is.
//
// Code that needs the time, random bytes or an injectable failure takes a
// Knobs (from LoadKnobs, held by the App's owner) and calls these methods
// instead of time.Now, crypto/rand and a bare error. The zero Knobs is a
// production one: real clock, real randomness, no faults.
const (
	// EnvTestNow, EnvTestRandom and EnvFault name the knob variables.
	EnvTestNow    = "TACCTL_TEST_NOW"
	EnvTestRandom = "TACCTL_TEST_RANDOM"
	EnvFault      = "TACCTL_FAULT"
	EnvTestRoot   = "TACCTL_TEST_ROOT"
)

// Knobs is the resolved set of test knobs.
type Knobs struct {
	now    time.Time // zero: the real clock
	random []byte    // empty: crypto/rand
	faults map[string]bool
	root   string // "": the host's own locations
}

// Root is the directory TACCTL_TEST_ROOT names ("" when unset): App.New
// moves tacctl's fixed host locations under it.
func (k Knobs) Root() string { return k.root }

// LoadKnobs reads the knobs from env. Without -tags testknobs it reads
// nothing and returns the zero Knobs. With it, a variable that is set and
// malformed is an error naming the variable (a test that sets a knob wants
// to know it did not take effect); an empty variable is the same as unset.
func LoadKnobs(env paths.Env) (Knobs, error) {
	return loadKnobs(env)
}

// Now is the time: the instant of TACCTL_TEST_NOW in the local zone when
// the knob is set, else time.Now().
func (k Knobs) Now() time.Time {
	if !k.now.IsZero() {
		return k.now
	}
	return time.Now()
}

// Rand is the source of random bytes: the bytes of TACCTL_TEST_RANDOM,
// repeated as often as needed, when the knob is set, else crypto/rand. Every
// call returns a reader that starts at the first byte, as each process of
// the differential runner's stubs does ('openssl rand -hex 16', python's
// os.urandom): two draws from one reader continue, two calls of Rand do not.
func (k Knobs) Rand() io.Reader {
	if len(k.random) == 0 {
		return rand.Reader
	}
	return &cycle{b: k.random}
}

// RandBytes returns n random bytes from Rand.
func (k Knobs) RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(k.Rand(), b); err != nil {
		return nil, err
	}
	return b, nil
}

// Fault is nil unless point is one of the TACCTL_FAULT points, then a
// *FaultError. A step that can be made to fail calls it where the real
// failure would arise and returns its error as it would the real one.
func (k Knobs) Fault(point string) error {
	if k.faults[point] {
		return &FaultError{Point: point}
	}
	return nil
}

// Faults returns the injected fault points, sorted.
func (k Knobs) Faults() []string {
	out := make([]string, 0, len(k.faults))
	for p := range k.faults {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// FaultError is the error of an injected fault.
type FaultError struct{ Point string }

func (e *FaultError) Error() string {
	return fmt.Sprintf("injected fault %q (TACCTL_FAULT)", e.Point)
}

// cycle reads b over and over: a deterministic stand-in for a random source
// that never runs dry.
type cycle struct {
	b   []byte
	pos int
}

func (c *cycle) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.b[c.pos]
		c.pos = (c.pos + 1) % len(c.b)
	}
	return len(p), nil
}
