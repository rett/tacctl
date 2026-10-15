package cli

// The NETCONF service setting of a Junos device (D145 of docs/plans/0.2.10-
// plan.md): the device's own value (devices.yaml), else its scope's
// (tacctl.yaml netconf_scope.<scope>.*), else leave. State and each limit
// layer on their own, as the SNMP settings do. Only a state of enable or
// disable plans anything: leave is the default, and tacctl then renders,
// plans and compares nothing of 'system services netconf'.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/policy"
)

// Where a layered value comes from.
const (
	netconfFromDevice  = "device"
	netconfFromScope   = "scope"
	netconfFromDefault = "default"
)

// netconfEffective is the setting a device is rendered with and where each
// value comes from.
type netconfEffective struct {
	devices.NetconfSetting
	// Leave is set when the setting is leave (State is then "").
	Leave bool
	// StateFrom, ConnectionFrom and RateFrom are netconfFromDevice,
	// netconfFromScope or netconfFromDefault ("" for a limit that is not
	// set).
	StateFrom, ConnectionFrom, RateFrom string
}

// resolveNetconf layers the device's own setting over its scope's. The
// limits mean something only for an enabled service, so a state of leave or
// disable has none.
func resolveNetconf(sc policy.NetconfScope, own devreg.Netconf) netconfEffective {
	var e netconfEffective
	state, from := sc.State, netconfFromScope
	if state == "" {
		from = netconfFromDefault
	}
	if own.State != "" {
		state, from = own.State, netconfFromDevice
	}
	e.StateFrom = from
	if state != conf.NetconfEnable && state != conf.NetconfDisable {
		e.Leave = true
		return e
	}
	e.State = state
	if state != conf.NetconfEnable {
		return e
	}
	if sc.ConnectionLimit > 0 {
		e.ConnectionLimit, e.ConnectionFrom = sc.ConnectionLimit, netconfFromScope
	}
	if own.ConnectionLimit > 0 {
		e.ConnectionLimit, e.ConnectionFrom = own.ConnectionLimit, netconfFromDevice
	}
	if sc.RateLimit > 0 {
		e.RateLimit, e.RateFrom = sc.RateLimit, netconfFromScope
	}
	if own.RateLimit > 0 {
		e.RateLimit, e.RateFrom = own.RateLimit, netconfFromDevice
	}
	return e
}

// netconfOf is the effective setting of a device of a scope with its own
// values (the zero Netconf for none).
func (inv *invocation) netconfOf(scope string, own devreg.Netconf) netconfEffective {
	var sc policy.NetconfScope
	if scope != "" {
		sc = policy.NetconfSettings(inv.app.Conf(), scope)
	}
	return resolveNetconf(sc, own)
}

// parseNetconfLimit reads a limit: a whole number from conf.NetconfMinLimit
// to conf.NetconfMaxLimit, or "none" (0: not set here).
func parseNetconfLimit(flag, s string) (int, error) {
	if strings.EqualFold(s, "none") {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || strconv.Itoa(n) != s || n < conf.NetconfMinLimit || n > conf.NetconfMaxLimit {
		return 0, &limitError{flag: flag, got: s}
	}
	return n, nil
}

type limitError struct{ flag, got string }

func (e *limitError) Error() string {
	return e.flag + " takes a number from " + strconv.Itoa(conf.NetconfMinLimit) + " to " +
		strconv.Itoa(conf.NetconfMaxLimit) + ", or none: '" + e.got + "'"
}

// limitText is how a limit is shown ("-" for none).
func limitText(n int) string {
	if n == 0 {
		return "-"
	}
	return strconv.Itoa(n)
}

// netconfWords describe the setting in a sentence of a message.
func (e netconfEffective) words() string {
	switch {
	case e.Leave:
		return "leave (tacctl plans and compares nothing of the service)"
	case e.State == conf.NetconfDisable:
		return "disable (the service is deleted)"
	}
	s := "enable"
	var lim []string
	if e.ConnectionLimit > 0 {
		lim = append(lim, "connection limit "+strconv.Itoa(e.ConnectionLimit))
	}
	if e.RateLimit > 0 {
		lim = append(lim, "rate limit "+strconv.Itoa(e.RateLimit))
	}
	if len(lim) > 0 {
		s += " (" + strings.Join(lim, ", ") + ")"
	}
	return s
}

// netconfJSON is the setting as 'device show --json' prints it, for a Junos
// device that has one.
type netconfJSON struct {
	// State is enable, disable or leave.
	State           string `json:"state"`
	StateFrom       string `json:"state_from"`
	ConnectionLimit int    `json:"connection_limit,omitempty"`
	RateLimit       int    `json:"rate_limit,omitempty"`
}

// sourceText says where the state comes from, for a row.
func (e netconfEffective) sourceText(scope string) string {
	switch e.StateFrom {
	case netconfFromDevice:
		return "the device's own"
	case netconfFromScope:
		return "scope '" + scope + "'"
	}
	return "the default"
}

// netconfShown reports whether a device's setting is worth a row: a Junos
// device whose setting is not the default.
func (e netconfEffective) shown(own devreg.Netconf) bool {
	return !e.Leave || !own.Empty() || e.StateFrom == netconfFromScope
}

func (e netconfEffective) json() *netconfJSON {
	st := e.State
	if st == "" {
		st = conf.NetconfLeave
	}
	return &netconfJSON{State: st, StateFrom: e.StateFrom, ConnectionLimit: e.ConnectionLimit, RateLimit: e.RateLimit}
}
