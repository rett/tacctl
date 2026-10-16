//go:build testknobs

package app

import (
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/paths"
)

// TestKnobs reports whether this binary was built with -tags testknobs
// ('make build'), which compiles in the test-only environment knobs
// (TACCTL_TEST_NOW, TACCTL_TEST_RANDOM, TACCTL_FAULT, TACCTL_TEST_ROOT; docs/plans/go-rewrite.md
// 3.6, Decision 17). 'tacctl version --long' prints it.
const TestKnobs = true

// The device knobs of 'tacctl device config pull' (internal/app/knobs.go).
// The names are here and nowhere else: a build without the tag has neither
// the variables nor their spelling.
const (
	// EnvTestDeviceDial is the loopback host:port every device is dialled at.
	EnvTestDeviceDial = "TACCTL_TEST_DEVICE_DIAL"
	// EnvTestDevicePassword is the password a pull logs in with.
	EnvTestDevicePassword = "TACCTL_TEST_DEVICE_PASSWORD"
	// EnvTestLocalPassword is the password of the local account of
	// '--login' and 'device onboard'.
	EnvTestLocalPassword = "TACCTL_TEST_LOCAL_PASSWORD"
	// EnvTestApplyPause is <point>:<seconds>: 'device config apply' waits
	// that long at the point ("gate": between the gate and the open of its
	// session), so a second session can commit in that window.
	EnvTestApplyPause = "TACCTL_TEST_APPLY_PAUSE"
	// EnvTestResolve is the fixed host name table the lookups of 'device
	// sync' and --server answer from: name=address[,address][;name=...].
	EnvTestResolve = "TACCTL_TEST_RESOLVE"
)

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
	if v := env.Get(EnvTestDeviceDial); v != "" {
		host, port, err := net.SplitHostPort(v)
		ip := net.ParseIP(host)
		if err != nil || port == "" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return Knobs{}, fmt.Errorf("%s=%q: not a loopback host:port (127.0.0.1:2222)", EnvTestDeviceDial, v)
		}
		k.dial = v
	}
	if v := env.Get(EnvTestResolve); v != "" {
		k.resolve = map[string][]string{}
		for _, ent := range strings.Split(v, ";") {
			name, addrs, ok := strings.Cut(strings.TrimSpace(ent), "=")
			if !ok || name == "" {
				return Knobs{}, fmt.Errorf("%s=%q: not name=address[,address][;name=...]", EnvTestResolve, v)
			}
			var l []string
			for _, a := range strings.Split(addrs, ",") {
				if a = strings.TrimSpace(a); a != "" {
					l = append(l, a)
				}
			}
			k.resolve[strings.ToLower(name)] = l
		}
	}
	if v := env.Get(EnvTestApplyPause); v != "" {
		point, secs, ok := strings.Cut(v, ":")
		n, err := strconv.ParseFloat(secs, 64)
		if !ok || point == "" || err != nil || n <= 0 || n > 600 {
			return Knobs{}, fmt.Errorf("%s=%q: not <point>:<seconds> (gate:20, at most 600)", EnvTestApplyPause, v)
		}
		k.applyPause.point, k.applyPause.wait = point, time.Duration(n*float64(time.Second))
	}
	k.devPass = env.Get(EnvTestDevicePassword)
	k.localPass = env.Get(EnvTestLocalPassword)
	return k, nil
}

// ConsoleTestEnv reports whether env sets TACCTL_TEST_CONSOLE_ENV=1: the
// console then keeps TACCTL_* and PATH (console.Scrub's keepTest).
func ConsoleTestEnv(env paths.Env) bool { return env.Get(EnvTestConsoleEnv) == "1" }
