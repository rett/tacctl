//go:build testknobs

package app

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/paths"
)

func load(t *testing.T, kv ...string) (Knobs, error) {
	t.Helper()
	return LoadKnobs(paths.NewEnv(kv))
}

func TestLoadKnobs(t *testing.T) {
	k, err := load(t,
		EnvTestNow+"=2025-06-07T08:09:10+02:00",
		EnvTestRandom+"=0a0B0c",
		EnvFault+"=store.commit, backend.render ,,store.commit")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2025, 6, 7, 6, 9, 10, 0, time.UTC)
	if !k.Now().Equal(want) {
		t.Errorf("Now = %v, want %v", k.Now(), want)
	}
	if k.Now().Location() != time.Local {
		t.Errorf("Now is in %v, want the local zone (date.today(), date)", k.Now().Location())
	}
	if b, _ := k.RandBytes(5); !bytes.Equal(b, []byte{0x0a, 0x0b, 0x0c, 0x0a, 0x0b}) {
		t.Errorf("RandBytes = %x", b)
	}
	if !reflect.DeepEqual(k.Faults(), []string{"backend.render", "store.commit"}) {
		t.Errorf("Faults = %v", k.Faults())
	}
	var fe *FaultError
	if err := k.Fault("backend.render"); !errors.As(err, &fe) {
		t.Errorf("Fault = %v", err)
	}
	if k.Fault("backend.stage") != nil {
		t.Error("unlisted point failed")
	}
}

func TestLoadKnobsUnset(t *testing.T) {
	// Unset and empty are the same: the production behaviour.
	for _, kv := range [][]string{nil, {EnvTestNow + "=", EnvTestRandom + "=", EnvFault + "="}} {
		k, err := load(t, kv...)
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(k.Now()) > time.Minute || len(k.Faults()) != 0 {
			t.Errorf("%v: knobs took effect", kv)
		}
		if a, _ := k.RandBytes(8); bytes.Equal(a, make([]byte, 8)) {
			t.Errorf("%v: random is constant", kv)
		}
	}
}

func TestLoadKnobsMalformed(t *testing.T) {
	for _, tc := range []struct{ kv, want string }{
		{EnvTestNow + "=yesterday", EnvTestNow},
		{EnvTestNow + "=2025-06-07", EnvTestNow},
		{EnvTestRandom + "=xyz", EnvTestRandom},
		{EnvTestRandom + "=abc", EnvTestRandom},
	} {
		_, err := load(t, tc.kv)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.kv, err)
		}
	}
}

func TestTestKnobsTrue(t *testing.T) {
	if !TestKnobs {
		t.Fatal("TestKnobs is false in a build with -tags testknobs")
	}
}
