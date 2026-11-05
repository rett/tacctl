package cli

import (
	"testing"
	"time"
)

// The wait after a backend's start is the product's 2 s unless a test's
// hook shortens it.
func TestBackendStartWaitDefault(t *testing.T) {
	var none *hooks
	for name, h := range map[string]*hooks{"no hooks": none, "empty hooks": {}} {
		if d := h.startWait(); d != 2*time.Second {
			t.Errorf("%s: %v, want 2s", name, d)
		}
	}
	if d := (&hooks{backendStartWait: time.Millisecond}).startWait(); d != time.Millisecond {
		t.Errorf("hook: %v, want 1ms", d)
	}
}
