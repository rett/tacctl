//go:build testknobs

package app

import (
	"bytes"
	"context"
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
		{EnvTestRoot + "=relative/dir", EnvTestRoot},
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

// TACCTL_TEST_ROOT moves tacctl's fixed host locations under it, and only
// those.
func TestTestRootReroots(t *testing.T) {
	a := New(nil, paths.NewEnv([]string{EnvTestRoot + "=/sb"}), "", 0, Stdio{}, nil)
	if a.Paths.Command != "/sb/usr/local/bin/tacctl" || a.Paths.GoBin != "/sb/usr/local/go/bin/go" ||
		a.Paths.Deploy != "/sb/opt/tacctl" || a.Paths.ArchiveDir != "/sb/root" || a.Paths.Etc != "/etc/tacquito" {
		t.Errorf("paths %+v", a.Paths)
	}
}

// The device knobs of the configuration pull: a loopback host:port to dial
// and the password to log in with.
func TestDeviceKnobs(t *testing.T) {
	k, err := load(t, EnvTestDeviceDial+"=127.0.0.1:2222", EnvTestDevicePassword+"=fakedev-password")
	if err != nil {
		t.Fatal(err)
	}
	if k.DeviceDial() != "127.0.0.1:2222" || k.DevicePassword() != "fakedev-password" {
		t.Errorf("dial %q, password %q", k.DeviceDial(), k.DevicePassword())
	}
	k, err = load(t, EnvTestDeviceDial+"=[::1]:830")
	if err != nil || k.DeviceDial() != "[::1]:830" {
		t.Errorf("ipv6 loopback: %q %v", k.DeviceDial(), err)
	}
	k, err = load(t, EnvTestDeviceDial+"=localhost:2222")
	if err != nil || k.DeviceDial() != "localhost:2222" {
		t.Errorf("localhost: %q %v", k.DeviceDial(), err)
	}
	// Anything that is not loopback is refused: a test knob must not be a
	// way to send a login anywhere.
	for _, bad := range []string{"192.0.2.10:22", "10.0.0.1:22", "example.net:22", "127.0.0.1", "127.0.0.1:", ":22", "garbage"} {
		_, err := load(t, EnvTestDeviceDial+"="+bad)
		if err == nil || !strings.Contains(err.Error(), EnvTestDeviceDial) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	k, err = load(t)
	if err != nil || k.DeviceDial() != "" || k.DevicePassword() != "" {
		t.Errorf("unset: %q %q %v", k.DeviceDial(), k.DevicePassword(), err)
	}
}

// The quiet knob is a Go duration of at most one second; unset is zero (the
// devssh default).
func TestDeviceQuietKnob(t *testing.T) {
	k, err := load(t, EnvTestDeviceQuiet+"=25ms")
	if err != nil || k.DeviceQuiet() != 25*time.Millisecond {
		t.Errorf("25ms: %v %v", k.DeviceQuiet(), err)
	}
	k, err = load(t, EnvTestDeviceQuiet+"=1s")
	if err != nil || k.DeviceQuiet() != time.Second {
		t.Errorf("1s: %v %v", k.DeviceQuiet(), err)
	}
	for _, bad := range []string{"25", "garbage", "-5ms", "1.5s", "2s", "1001ms"} {
		_, err := load(t, EnvTestDeviceQuiet+"="+bad)
		if err == nil || !strings.Contains(err.Error(), EnvTestDeviceQuiet) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	k, err = load(t)
	if err != nil || k.DeviceQuiet() != 0 {
		t.Errorf("unset: %v %v", k.DeviceQuiet(), err)
	}
}

// The resolve knob is a fixed name table: a name it lacks does not resolve.
func TestResolveKnob(t *testing.T) {
	k, err := load(t, EnvTestResolve+"=a.example.net=192.0.2.1,192.0.2.2; B.example.net=192.0.2.3")
	if err != nil {
		t.Fatal(err)
	}
	r := k.Resolver()
	if r == nil {
		t.Fatal("no resolver")
	}
	got, err := r(context.Background(), "A.example.net.")
	if err != nil || len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "192.0.2.2" {
		t.Errorf("a: %v %v", got, err)
	}
	if got, err = r(context.Background(), "b.example.net"); err != nil || len(got) != 1 || got[0] != "192.0.2.3" {
		t.Errorf("b: %v %v", got, err)
	}
	if _, err = r(context.Background(), "c.example.net"); err == nil {
		t.Error("an unlisted name resolved")
	}
	if _, err = load(t, EnvTestResolve+"=garbage"); err == nil || !strings.Contains(err.Error(), EnvTestResolve) {
		t.Errorf("malformed: %v", err)
	}
	if k, err = load(t); err != nil || k.Resolver() != nil {
		t.Errorf("unset: %v", err)
	}
}

func TestApplyPauseKnob(t *testing.T) {
	// The pause is long against the scheduler's stalls on a loaded -race shard:
	// a no-op takes microseconds, and a pause wrongly taken at "open" would
	// last the whole second, so the one-second bound separates the two with
	// no reliance on the machine being quick.
	const pauseSeconds = 1
	k, err := load(t, EnvTestApplyPause+"=gate:1")
	if err != nil {
		t.Fatal(err)
	}
	pause := k.ApplyPause()
	if pause == nil {
		t.Fatal("no pause for a set knob")
	}
	start := time.Now()
	pause("open")
	if d := time.Since(start); d >= pauseSeconds*time.Second {
		t.Errorf("paused for %v at a point the knob does not name", d)
	}
	start = time.Now()
	pause("gate")
	if d := time.Since(start); d < pauseSeconds*time.Second {
		t.Errorf("gate pause was %v", d)
	}
	if k, _ := load(t); k.ApplyPause() != nil {
		t.Error("a pause without the knob")
	}
	for _, bad := range []string{"gate", "gate:", "gate:x", "gate:-1", "gate:9999", ":5"} {
		if _, err := load(t, EnvTestApplyPause+"="+bad); err == nil || !strings.Contains(err.Error(), EnvTestApplyPause) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// The home knob is the caller's home for the paths a command writes: an
// absolute path, else an error naming the variable.
func TestHomeKnob(t *testing.T) {
	k, err := load(t, EnvTestHome+"=/home/user")
	if err != nil || k.Home() != "/home/user" {
		t.Errorf("home: %q %v", k.Home(), err)
	}
	if _, err = load(t, EnvTestHome+"=user"); err == nil || !strings.Contains(err.Error(), EnvTestHome) {
		t.Errorf("relative: %v", err)
	}
	if k, err = load(t); err != nil || k.Home() != "" {
		t.Errorf("unset: %q %v", k.Home(), err)
	}
}
