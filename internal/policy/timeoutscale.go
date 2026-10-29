package policy

// A scope's timing scale and the default of the whole server in
// tacctl.yaml (timeout_scale_scope.<scope> and device.timeout_scale, 0.2.22),
// read and written for 'tacctl scope timeout-scale', 'tacctl config devices
// timeout-scale' and the timing of every access to a device. The keys are
// written only when set: a tacctl.yaml that never had one does not change,
// and a scope with none follows the default.

import (
	"strconv"

	"github.com/rett/tacctl/internal/conf"
)

// readScale is the scale at path when it is set in the file and in range;
// anything else is 0, "not set at this level" (a hand-edited value the
// schema refuses is reported by 'config validate', not obeyed).
func readScale(c *conf.Config, path string) int {
	if !c.HasOverride(path) {
		return 0
	}
	v, _ := c.Get(path, "")
	n, err := strconv.Atoi(v)
	if err != nil || n < conf.TimeoutScaleMin || n > conf.TimeoutScaleMax {
		return 0
	}
	return n
}

// TimeoutScaleDefault is the scale of the whole server (device.timeout_scale),
// 0 when it is not set.
func TimeoutScaleDefault(c *conf.Config) int { return readScale(c, conf.TimeoutScaleKey) }

// TimeoutScaleOfScope is the scale the scope decided, 0 when it did not.
func TimeoutScaleOfScope(c *conf.Config, scope string) int {
	if scope == "" {
		return 0
	}
	return readScale(c, conf.TimeoutScaleScopePath(scope))
}

// TimeoutScaleScopeSet reports whether tacctl.yaml holds a scale of the scope
// (valid or not).
func TimeoutScaleScopeSet(c *conf.Config, scope string) bool {
	return c.HasOverride(conf.TimeoutScaleScopePath(scope))
}

// SetTimeoutScaleScope stores the scope's scale (the schema refuses a value
// outside the bounds).
func SetTimeoutScaleScope(c *conf.Config, scope string, n int) error {
	return c.Set(conf.TimeoutScaleScopePath(scope), strconv.Itoa(n))
}

// ClearTimeoutScaleScope removes the scope's scale: it follows the default
// again.
func ClearTimeoutScaleScope(c *conf.Config, scope string) error {
	return c.Unset(conf.TimeoutScaleScopePath(scope))
}
