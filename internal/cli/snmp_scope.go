package cli

// The SNMP settings a scope or the default is read with (D46 of
// docs/plans/0.2.3-plan.md): the scope's own value, then the default's
// (snmp.* and StateDir/snmp.yaml), then the built-in; and, for a registered
// device that has settings of its own (D72 of docs/plans/0.2.4-plan.md,
// device_snmp_override.go), the device's value first. The users of the
// credentials (the sysName lookup of 'device add' and 'device check', the
// walkthroughs, 'scope snmp test') all go through snmpEffective and
// snmpEffectiveOwn, so there is one place that says which one wins.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/snmpcred"
)

// snmpLayerNum reads a number setting that is set in the file and valid;
// anything else is "not set at this level".
func (inv *invocation) snmpLayerNum(path string, lo, hi int) int {
	if !inv.app.Conf().HasOverride(path) {
		return 0
	}
	if n, err := strconv.Atoi(inv.confGet(path, "")); err == nil && n >= lo && n <= hi {
		return n
	}
	return 0
}

// snmpDefaultLayer is the default: snmp.* and snmp.yaml.
func (inv *invocation) snmpDefaultLayer() (snmpcred.Layer, error) {
	creds, err := snmpcred.Load(inv.app.Paths.SNMPFile)
	if err != nil {
		return snmpcred.Layer{}, err
	}
	str := func(path string) string {
		if !inv.app.Conf().HasOverride(path) {
			return ""
		}
		return inv.confGet(path, "")
	}
	return snmpcred.Layer{
		Version: str("snmp.version"),
		Port:    inv.snmpLayerNum("snmp.port", 1, 65535),
		Timeout: inv.snmpLayerNum("snmp.timeout", snmp.MinTimeout, snmp.MaxTimeout),
		Auth:    str("snmp.v3.auth"), Priv: str("snmp.v3.priv"),
		Creds: creds,
	}, nil
}

// snmpScopeLayer is the scope's own settings: snmp_scope.<scope>.* and
// StateDir/snmp/<scope>.yaml.
func (inv *invocation) snmpScopeLayer(scope string) (snmpcred.Layer, error) {
	if scope == "" {
		return snmpcred.Layer{}, nil
	}
	creds, err := snmpcred.LoadScope(inv.app.Paths.SNMPDir, scope)
	if err != nil {
		return snmpcred.Layer{}, err
	}
	s := policy.SNMPSettings(inv.app.Conf(), scope)
	return snmpcred.Layer{Version: s.Version, Port: s.Port, Timeout: s.Timeout, Auth: s.Auth, Priv: s.Priv, Creds: creds}, nil
}

// snmpEffective is what a device of scope is read with; scope "" (a device
// in no scope, or the default itself) is the default alone.
func (inv *invocation) snmpEffective(scope string) (snmpcred.Effective, error) {
	return inv.snmpEffectiveOwn(scope, deviceSNMPOwn{})
}

// snmpEffectiveOwn is what a device of scope that has the settings own is
// read with: its own value, then the scope's, then the default's, then the
// built-in. The zero own is snmpEffective.
func (inv *invocation) snmpEffectiveOwn(scope string, own deviceSNMPOwn) (snmpcred.Effective, error) {
	def, err := inv.snmpDefaultLayer()
	if err != nil {
		return snmpcred.Effective{}, err
	}
	sc, err := inv.snmpScopeLayer(scope)
	if err != nil {
		return snmpcred.Effective{}, err
	}
	return snmpcred.ResolveDevice(own.layer(), sc, def), nil
}

// snmpSetter is the verb family that sets what a lookup of scope needs (the
// text of the hint that ends a fragment).
func snmpSetter(scope string) string {
	if scope == "" {
		return "tacctl config snmp"
	}
	return "tacctl scope snmp " + scope
}

// snmpConfigFor is the lookup the settings make for a device of scope, or
// why there is none (a fragment that ends in the command that fixes it).
func (inv *invocation) snmpConfigFor(scope string) (snmp.Config, string) {
	return inv.snmpConfigOwn(scope, deviceSNMPOwn{})
}

// snmpConfigOwn is snmpConfigFor for a device that has the settings own.
func (inv *invocation) snmpConfigOwn(scope string, own deviceSNMPOwn) (snmp.Config, string) {
	def, err := inv.snmpDefaultLayer()
	if err != nil {
		return snmp.Config{Port: snmp.DefaultPort, Retries: 1}, strings.Join(msgs(err), " ")
	}
	sc, err := inv.snmpScopeLayer(scope)
	if err != nil {
		return snmp.Config{Port: snmp.DefaultPort, Retries: 1}, strings.Join(msgs(err), " ")
	}
	// A scope that sets nothing of its own is set up through the default;
	// one that has begun is finished through its own verbs; a device that
	// has chosen a version or credentials is finished through its own.
	setter := snmpSetter(scope)
	if sc == (snmpcred.Layer{}) {
		setter = snmpSetter("")
	}
	if own.chosen() {
		setter = "tacctl device snmp " + shellquote.Q(own.Name)
	}
	return snmpcred.ResolveDevice(own.layer(), sc, def).Config(setter)
}

// snmpGetterFor is how this invocation reads sysName from a device of
// scope: the App's stub, else the settings; problem says why there is none.
func (inv *invocation) snmpGetterFor(scope string) (g snmp.Getter, problem string) {
	return inv.snmpGetterOwn(scope, deviceSNMPOwn{})
}

// snmpGetterOwn is snmpGetterFor for a device that has the settings own.
func (inv *invocation) snmpGetterOwn(scope string, own deviceSNMPOwn) (g snmp.Getter, problem string) {
	if inv.app.SNMP != nil {
		return inv.app.SNMP, ""
	}
	c, problem := inv.snmpConfigOwn(scope, own)
	if problem != "" {
		return nil, problem
	}
	return c, ""
}

// snmpGetterForAddr is how this invocation reads sysName from the device at
// addr: the settings of the device's scope, and the device's own over them
// when the registry has a device there with some (D72).
func (inv *invocation) snmpGetterForAddr(addr string) (g snmp.Getter, problem string) {
	scope := inv.scopeOfAddress(addr)
	if d := inv.deviceAt(addr); d != nil {
		own, err := inv.deviceSNMPOwnOf(*d)
		if err != nil {
			return nil, strings.Join(msgs(err), " ")
		}
		return inv.snmpGetterOwn(scope, own)
	}
	return inv.snmpGetterFor(scope)
}

// scopeOfAddress is the scope that answers addr (the device's scope), or
// "" when none does or the model cannot be read.
func (inv *invocation) scopeOfAddress(addr string) string {
	m, err := inv.model()
	if err != nil {
		return ""
	}
	if info, ok := m.LookupAddr(addr); ok {
		return info.Scope
	}
	return ""
}

// walkthroughSNMP is the SNMP input of a walkthrough for scope: the
// effective settings of the scope with the default beneath (D46), the
// scope's contact and ranges, and the device's own values when it is
// named, with the settings of its own it has (D72) over them. Version stays
// empty when SNMP is not configured.
func (inv *invocation) walkthroughSNMP(scope string, dev devices.SNMPInput) (devices.SNMPInput, error) {
	var own deviceSNMPOwn
	if dev.DeviceName != "" {
		if d := inv.deviceNamed(dev.DeviceName); d != nil {
			var err error
			if own, err = inv.deviceSNMPOwnOf(*d); err != nil {
				return dev, err
			}
		}
	}
	return inv.walkthroughSNMPOwn(scope, dev, own)
}

// walkthroughSNMPOwn is walkthroughSNMP for a device whose own settings are
// loaded: the device's version, credentials and ranges win over the
// scope's.
func (inv *invocation) walkthroughSNMPOwn(scope string, dev devices.SNMPInput, own deviceSNMPOwn) (devices.SNMPInput, error) {
	e, err := inv.snmpEffectiveOwn(scope, own)
	if err != nil {
		return dev, err
	}
	in := dev
	in.Scope = scope
	in.Version = e.Version
	in.Community = e.Community
	in.V3User, in.V3Auth, in.V3Priv, in.V3AuthPass, in.V3PrivPass = e.User, e.Auth, e.Priv, e.AuthPass, e.PrivPass
	in.CredFrom = e.CredFrom()
	sc := policy.SNMPSettings(inv.app.Conf(), scope)
	in.Ranges = sc.Clients
	in.Contact = sc.Contact
	if len(own.SNMP.Clients) > 0 {
		in.Ranges, in.RangesFrom = slices.Clone(own.SNMP.Clients), snmpcred.FromDevice
	}
	return in, nil
}
