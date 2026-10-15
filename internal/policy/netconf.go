package policy

// A scope's NETCONF service setting in tacctl.yaml (netconf_scope.<scope>.*,
// D145 of docs/plans/0.2.10-plan.md), read and written for 'tacctl scope
// netconf' and the device renderings. The keys are written only when set: a
// tacctl.yaml that never had one does not change, and a scope with none is
// "leave" (tacctl plans and compares nothing of the service).

import (
	"strconv"

	"github.com/rett/tacctl/internal/conf"
)

// NetconfScope is what netconf_scope.<scope> holds; the zero value of a
// field is "not set in the scope" (State "" is leave).
type NetconfScope struct {
	// State is conf.NetconfEnable or conf.NetconfDisable, or "".
	State string
	// ConnectionLimit and RateLimit are the optional limits of 'system
	// services netconf ssh', 0 when not set.
	ConnectionLimit, RateLimit int
}

// NetconfSettings reads the setting of scope.
func NetconfSettings(c *conf.Config, scope string) NetconfScope {
	num := func(key string) int {
		v, ok := c.Get(conf.NetconfPath(scope, key), "")
		if !ok {
			return 0
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	}
	st, _ := c.Get(conf.NetconfPath(scope, conf.NetconfKeyState), "")
	return NetconfScope{State: st, ConnectionLimit: num(conf.NetconfKeyConnectionLimit), RateLimit: num(conf.NetconfKeyRateLimit)}
}

// SetNetconfState stores the scope's state (conf.NetconfEnable or
// conf.NetconfDisable; the schema refuses anything else).
func SetNetconfState(c *conf.Config, scope, state string) error {
	return c.Set(conf.NetconfPath(scope, conf.NetconfKeyState), state)
}

// SetNetconfLimit stores one of the scope's limits (key is
// conf.NetconfKeyConnectionLimit or conf.NetconfKeyRateLimit); n 0 removes it.
func SetNetconfLimit(c *conf.Config, scope, key string, n int) error {
	if n == 0 {
		return c.Unset(conf.NetconfPath(scope, key))
	}
	return c.Set(conf.NetconfPath(scope, key), strconv.Itoa(n))
}

// NetconfSet reports whether tacctl.yaml holds any NETCONF setting of the
// scope.
func NetconfSet(c *conf.Config, scope string) bool {
	for _, k := range conf.NetconfKeys {
		if c.HasOverride(conf.NetconfPath(scope, k)) {
			return true
		}
	}
	return false
}

// MoveNetconfScope moves every NETCONF setting of old to new, or drops them
// when newName is empty (a scope renamed or removed). Settings a rename
// cannot carry over (a value the schema refuses) are returned as lost.
func MoveNetconfScope(c *conf.Config, old, newName string) (lost []string, err error) {
	for _, k := range conf.NetconfKeys {
		from := conf.NetconfPath(old, k)
		if !c.HasOverride(from) {
			continue
		}
		v, _ := c.Value(from)
		if err := c.Unset(from); err != nil {
			return lost, err
		}
		if newName == "" {
			continue
		}
		if err := c.SetValue(conf.NetconfPath(newName, k), v); err != nil {
			lost = append(lost, from)
		}
	}
	return lost, nil
}
