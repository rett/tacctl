package conf

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devssh"
)

// The timing scale of 0.2.22: device.timeout_scale for the whole server and
// timeout_scale_scope.<scope> for a scope, whole numbers from 1 to 10.

func TestTimeoutScaleKeysAreBounded(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, path := range []string{TimeoutScaleKey, TimeoutScaleScopePath("lab"), "timeout_scale_scope.site-a"} {
		for _, v := range []any{1, 2, 10} {
			if p := s.Validate(path, v, false); p != "" {
				t.Errorf("%s = %v: %s", path, v, p)
			}
		}
		for _, v := range []any{0, -1, 11, 100, "3", "fast", 2.5, true} {
			if p := s.Validate(path, v, false); p == "" {
				t.Errorf("%s = %#v is accepted", path, v)
			}
		}
	}
	// the scale of the whole server has the default 1; a scope's has none
	if v, ok := s.ImplicitDefault(TimeoutScaleKey); !ok || v != 1 {
		t.Errorf("default of %s = %v, %v", TimeoutScaleKey, v, ok)
	}
	if _, ok := s.ImplicitDefault(TimeoutScaleScopePath("lab")); ok {
		t.Error("a scope's scale has a default: unset must follow the server's")
	}
	// the wildcard is exactly one scope name deep
	for _, bad := range []string{"timeout_scale_scope", "timeout_scale_scope.", "timeout_scale_scope.lab.extra"} {
		if _, ok := s.RuleFor(bad); ok {
			t.Errorf("%q is a schema key", bad)
		}
	}
}

// The bounds are the scale's (internal/devssh): a copy that drifts would let
// a setting hold what another refuses.
func TestTimeoutScaleBoundsAreDevsshs(t *testing.T) {
	if TimeoutScaleMin != devssh.MinTimeoutScale || TimeoutScaleMax != devssh.MaxTimeoutScale {
		t.Errorf("conf has %d-%d, devssh %d-%d", TimeoutScaleMin, TimeoutScaleMax, devssh.MinTimeoutScale, devssh.MaxTimeoutScale)
	}
}

// Every older release refuses both keys, so every rollback lists them, and
// UnsetMany removes them and nothing else.
func TestRollbackKeysOfTheTimeoutScale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	text := "audit:\n  strict: true\nserver:\n  addresses: [192.0.2.10]\ndevice:\n  timeout_scale: 3\ntimeout_scale_scope:\n  lab: 5\n  site-a: 2\n"
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	want := []string{"device.timeout_scale", "timeout_scale_scope.lab", "timeout_scale_scope.site-a"}
	for name, got := range map[string][]string{"0.2.21": c.RollbackKeys0221(), "0.2.20": c.RollbackKeys0220(), "0.2.18": c.RollbackKeys0218(),
		"0.2.16": c.RollbackKeys0216(), "0.2.9": c.RollbackKeys029(), "0.2.3": c.RollbackKeys023(), "0.2.2": c.RollbackKeys022()} {
		for _, k := range want {
			if !slices.Contains(got, k) {
				t.Errorf("RollbackKeys for %s = %v, lacks %s", name, got, k)
			}
		}
	}
	if got := c.RollbackKeys0221(); !slices.Equal(got, want) {
		t.Errorf("RollbackKeys0221 = %v, want only the scale: server.addresses is 0.2.21's own", got)
	}
	if !Added0222Key("device.timeout_scale") || !Added0222Key("timeout_scale_scope.lab") || Added0222Key("device.timeout") || Added0222Key("timeout_scale") {
		t.Error("Added0222Key is not the timeout scale")
	}
	if err := c.UnsetMany(c.RollbackKeys0221()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "timeout_scale") || !strings.Contains(string(got), "192.0.2.10") || !strings.Contains(string(got), "strict: true") {
		t.Errorf("after:\n%s", got)
	}
}
