package app

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestZeroKnobsAreProduction(t *testing.T) {
	var k Knobs
	before := time.Now()
	if got := k.Now(); got.Before(before) || time.Since(got) > time.Minute {
		t.Errorf("Now = %v, want the real clock", got)
	}
	a, err := k.RandBytes(16)
	if err != nil || len(a) != 16 {
		t.Fatalf("RandBytes = %x %v", a, err)
	}
	if b, _ := k.RandBytes(16); bytes.Equal(a, b) {
		t.Error("two crypto/rand draws are equal")
	}
	if err := k.Fault("render"); err != nil {
		t.Errorf("Fault = %v", err)
	}
	if len(k.Faults()) != 0 {
		t.Errorf("Faults = %v", k.Faults())
	}
}

func TestKnobValues(t *testing.T) {
	fixed := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	k := Knobs{now: fixed, random: []byte{1, 2, 3}, faults: map[string]bool{"b.step": true, "a.step": true}}
	if !k.Now().Equal(fixed) || !k.Now().Equal(k.Now()) {
		t.Errorf("Now = %v", k.Now())
	}
	// The bytes repeat from the start, across reads of any size.
	r := k.Rand()
	var got []byte
	for _, n := range []int{2, 5, 1} {
		b := make([]byte, n)
		if m, err := r.Read(b); m != n || err != nil {
			t.Fatalf("Read(%d) = %d %v", n, m, err)
		}
		got = append(got, b...)
	}
	if want := []byte{1, 2, 3, 1, 2, 3, 1, 2}; !bytes.Equal(got, want) {
		t.Errorf("Rand = %v, want %v", got, want)
	}
	// RandBytes starts over with each call's reader.
	if b, _ := k.RandBytes(4); !bytes.Equal(b, []byte{1, 2, 3, 1}) {
		t.Errorf("RandBytes = %v", b)
	}
	err := k.Fault("a.step")
	var fe *FaultError
	if !errors.As(err, &fe) || fe.Point != "a.step" || err.Error() == "" {
		t.Errorf("Fault = %v", err)
	}
	if k.Fault("c.step") != nil {
		t.Error("an unlisted point must not fail")
	}
	if !reflect.DeepEqual(k.Faults(), []string{"a.step", "b.step"}) {
		t.Errorf("Faults = %v", k.Faults())
	}
}
