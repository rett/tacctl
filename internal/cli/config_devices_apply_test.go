package cli

import (
	"strings"
	"testing"
)

// The settings of 'device config apply' (D140) read as their defaults when a
// hand-edited file holds a value the schema refuses, and 'config validate'
// is where that is said.
func TestApplySettingsOutOfRangeReadAsDefaults(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "device:\n  apply:\n    confirm_timeout: 2\n    pause: 99999\n", 0o600)
	out := plain(sb.cfgRun("", []string{"config", "devices", "show"}, nil))
	for _, w := range []string{"apply-confirm-timeout: 10 min", "apply-pause:           60 s"} {
		if sb.code != 0 || !strings.Contains(out, w) {
			t.Errorf("show lacks %q: %d\n%s", w, sb.code, out)
		}
	}
	sb.cfgRun("", []string{"config", "validate"}, nil)
	if sb.code == 0 || !strings.Contains(sb.stderr()+sb.out.String(), "device.apply.confirm_timeout") {
		t.Errorf("validate: %d %q %q", sb.code, sb.stderr(), sb.out.String())
	}
}
