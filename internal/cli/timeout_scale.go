package cli

// The timing scale of a device (0.2.22): one whole number from 1 to 10 that
// multiplies every network timing tacctl uses to reach it, for a device
// behind a long round trip or with a slow CPU. The device's own value
// (devices.yaml timeout_scale), else its scope's (tacctl.yaml
// timeout_scale_scope.<scope>), else the server's (device.timeout_scale),
// else 1: the order of the NETCONF service setting. 1 is every timing as it
// was, so a server that never set a scale behaves and prints as before.
//
// What a scale multiplies: the host-key scans (ssh-keyscan's -T and the
// built-in client's connect, handshake and per-type attempt), the connect
// and handshake budget of every device session (pull, apply, onboard,
// collect) and of 'tacctl ssh', the SNMP timeout (never above its maximum),
// and the per-device default of a pull or an apply (device.config.timeout,
// kept inside its bounds). An option typed on the command line (--timeout)
// wins over the scale. The confirmed-commit windows are safety timers on the
// device and are never scaled.

import (
	"strconv"
	"time"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/snmp"
)

// Where the scale in force comes from.
const (
	scaleFromDevice  = "device"
	scaleFromScope   = "scope"
	scaleFromGlobal  = "global"
	scaleFromBuiltIn = "built-in"
)

// The bounds of the per-device timeout of a pull and an apply
// (device.config.timeout, 10 to 600 seconds): a scaled default stays inside.
const (
	deviceTimeoutMin = 10 * time.Second
	deviceTimeoutMax = 600 * time.Second
)

// timeoutScale is the scale in force and where it comes from.
type timeoutScale struct {
	N    int
	From string
}

// resolveTimeoutScale layers the device's own scale over its scope's, the
// scope's over the server's, and that over 1. 0 is "not set at this level".
func resolveTimeoutScale(own, scope, global int) timeoutScale {
	for _, l := range []struct {
		n    int
		from string
	}{{own, scaleFromDevice}, {scope, scaleFromScope}, {global, scaleFromGlobal}} {
		if devssh.ValidTimeoutScale(l.n) {
			return timeoutScale{N: l.n, From: l.from}
		}
	}
	return timeoutScale{N: devssh.MinTimeoutScale, From: scaleFromBuiltIn}
}

// timeoutScaleOf is the scale of a device of scope with its own value (0 for
// none).
func (inv *invocation) timeoutScaleOf(scope string, own int) timeoutScale {
	c := inv.app.Conf()
	return resolveTimeoutScale(own, policy.TimeoutScaleOfScope(c, scope), policy.TimeoutScaleDefault(c))
}

// scaledDeviceTimeout is base (the per-device default, device.config.timeout)
// times scale, kept inside 10 to 600 seconds.
func scaledDeviceTimeout(base time.Duration, scale int) time.Duration {
	return min(max(devssh.ScaleDuration(base, scale), deviceTimeoutMin), deviceTimeoutMax)
}

// scaledSNMPTimeout is the SNMP timeout in seconds times scale, never above
// snmp.MaxTimeout.
func scaledSNMPTimeout(seconds, scale int) int {
	return min(seconds*max(scale, devssh.MinTimeoutScale), snmp.MaxTimeout)
}

// timeoutScaleJSON is the scale as 'device show --json' prints it.
type timeoutScaleJSON struct {
	// Scale is the number in force; From is device, scope, global or built-in.
	Scale int    `json:"scale"`
	From  string `json:"from"`
}

func (s timeoutScale) json() *timeoutScaleJSON { return &timeoutScaleJSON{Scale: s.N, From: s.From} }

// text is a scale in a row: "3", with where it comes from.
func (s timeoutScale) text(scope string) string {
	return strconv.Itoa(s.N) + "  (" + s.fromText(scope) + ")"
}

// fromText says where the scale comes from.
func (s timeoutScale) fromText(scope string) string {
	switch s.From {
	case scaleFromDevice:
		return "the device's own"
	case scaleFromScope:
		if scope == "" {
			return "the scope's own"
		}
		return "scope '" + scope + "'"
	case scaleFromGlobal:
		return "the default of the whole server, device.timeout_scale"
	}
	return "built in: no scale is set"
}
