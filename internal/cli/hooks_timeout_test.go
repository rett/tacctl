package cli

import (
	"testing"
	"time"
)

// A typed --timeout counts real seconds unless a test's hook shortens them.
func TestTypedTimeoutSecondDefault(t *testing.T) {
	var none *hooks
	for name, h := range map[string]*hooks{"no hooks": none, "empty hooks": {}} {
		if d := h.typedTimeout(10); d != 10*time.Second {
			t.Errorf("%s: %v, want 10s", name, d)
		}
	}
	if d := (&hooks{timeoutSecond: 100 * time.Millisecond}).typedTimeout(10); d != time.Second {
		t.Errorf("hook: %v, want 1s", d)
	}
}
