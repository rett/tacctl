package cli

// The SNMP settings a scope or the default is read with (D46 of
// docs/plans/0.2.3-plan.md): the scope's own value, then the default's
// (snmp.* and StateDir/snmp.yaml), then the built-in. The users of the
// credentials (the sysName lookup of 'device add' and 'device check', the
// walkthroughs, 'scope snmp test') all go through snmpEffective, so there
// is one place that says which one wins.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/policy"
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
	def, err := inv.snmpDefaultLayer()
	if err != nil {
		return snmpcred.Effective{}, err
	}
	own, err := inv.snmpScopeLayer(scope)
	if err != nil {
		return snmpcred.Effective{}, err
	}
	return snmpcred.Resolve(own, def), nil
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
	def, err := inv.snmpDefaultLayer()
	if err != nil {
		return snmp.Config{Port: snmp.DefaultPort, Retries: 1}, strings.Join(msgs(err), " ")
	}
	own, err := inv.snmpScopeLayer(scope)
	if err != nil {
		return snmp.Config{Port: snmp.DefaultPort, Retries: 1}, strings.Join(msgs(err), " ")
	}
	// A scope that sets nothing of its own is set up through the default;
	// one that has begun is finished through its own verbs.
	setter := snmpSetter(scope)
	if own == (snmpcred.Layer{}) {
		setter = snmpSetter("")
	}
	return snmpcred.Resolve(own, def).Config(setter)
}

// snmpGetterFor is how this invocation reads sysName from a device of
// scope: the App's stub, else the settings; problem says why there is none.
func (inv *invocation) snmpGetterFor(scope string) (g snmp.Getter, problem string) {
	if inv.app.SNMP != nil {
		return inv.app.SNMP, ""
	}
	c, problem := inv.snmpConfigFor(scope)
	if problem != "" {
		return nil, problem
	}
	return c, ""
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
// named. Version stays empty when SNMP is not configured.
func (inv *invocation) walkthroughSNMP(scope string, dev devices.SNMPInput) (devices.SNMPInput, error) {
	e, err := inv.snmpEffective(scope)
	if err != nil {
		return dev, err
	}
	in := dev
	in.Scope = scope
	in.Version = e.Version
	in.Community = e.Community
	in.V3User, in.V3Auth, in.V3Priv, in.V3AuthPass, in.V3PrivPass = e.User, e.Auth, e.Priv, e.AuthPass, e.PrivPass
	in.CredFrom = e.CredFrom()
	own := policy.SNMPSettings(inv.app.Conf(), scope)
	in.Ranges = own.Clients
	in.Contact = own.Contact
	return in, nil
}
