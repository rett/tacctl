//go:build !testknobs

package app

import (
	"bytes"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/paths"
)

// A production build reads none of the knob variables, whatever they hold,
// malformed ones included.
func TestKnobsIgnoredWithoutTag(t *testing.T) {
	if TestKnobs {
		t.Fatal("TestKnobs is true in a build without -tags testknobs")
	}
	env := paths.NewEnv([]string{
		EnvTestNow + "=2001-02-03T04:05:06Z",
		EnvTestRandom + "=00ff",
		EnvFault + "=render,commit",
	})
	k, err := LoadKnobs(env)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(k.Now()) > time.Minute {
		t.Errorf("Now = %v: the clock knob took effect", k.Now())
	}
	a, _ := k.RandBytes(8)
	b, _ := k.RandBytes(8)
	if bytes.Equal(a, b) || bytes.Equal(a, []byte{0, 255, 0, 255, 0, 255, 0, 255}) {
		t.Error("the random knob took effect")
	}
	if k.Fault("render") != nil || len(k.Faults()) != 0 {
		t.Error("the fault knob took effect")
	}
	if _, err := LoadKnobs(paths.NewEnv([]string{EnvTestNow + "=garbage"})); err != nil {
		t.Errorf("malformed knob must be ignored, got %v", err)
	}
}
